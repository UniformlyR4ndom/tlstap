package proxy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBuffering holds every chunk while holding is set and passes chunks through otherwise. Like
// the tamper interceptor, it releases under its own lock, over a channel of capacity 1, so a
// release blocks until the consumer has caught up.
type fakeBuffering struct {
	mu      sync.Mutex
	holding bool
	held    [][]byte
	relCh   chan ReleasedData
	once    sync.Once
}

func newFakeBuffering(holding bool) *fakeBuffering {
	return &fakeBuffering{holding: holding, relCh: make(chan ReleasedData, 1)}
}

func (f *fakeBuffering) Init(addr net.TCPAddr) error                { return nil }
func (f *fakeBuffering) Finalize(addr net.TCPAddr)                  {}
func (f *fakeBuffering) ConnectionEstablished(info *ConnInfo) error { return nil }
func (f *fakeBuffering) ConnectionUpgraded(info *ConnInfo) error    { return nil }

func (f *fakeBuffering) ConnectionTerminated(info *ConnInfo) error {
	f.once.Do(func() { close(f.relCh) })
	return nil
}

func (f *fakeBuffering) Intercept(info *ConnInfo, data []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.holding {
		return data, nil
	}

	f.held = append(f.held, append([]byte(nil), data...))
	return nil, nil
}

func (f *fakeBuffering) HasPending(info *ConnInfo) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.held) > 0
}

func (f *fakeBuffering) ReleaseChannel(info *ConnInfo) <-chan ReleasedData { return f.relCh }

func (f *fakeBuffering) heldCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.held)
}

// releaseLocked sends the first n held chunks (all if n < 0) as one release; the caller holds f.mu.
func (f *fakeBuffering) releaseLocked(n int) {
	if n < 0 || n > len(f.held) {
		n = len(f.held)
	}

	var data []byte
	for _, c := range f.held[:n] {
		data = append(data, c...)
	}

	f.held = f.held[n:]
	f.relCh <- ReleasedData{Data: data}
}

func (f *fakeBuffering) releaseAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseLocked(-1)
}

func (f *fakeBuffering) releaseOne() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseLocked(1)
}

// stopHolding releases everything held and lets later chunks pass, atomically (a mode switch).
func (f *fakeBuffering) stopHolding() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.holding = false
	f.releaseLocked(-1)
}

func (f *fakeBuffering) abort() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relCh <- ReleasedData{Err: ErrAbort}
}

func (f *fakeBuffering) waitHeld(t *testing.T, n int) {
	t.Helper()

	deadline := time.Now().Add(testIOTimeout)
	for f.heldCount() < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d held chunks, have %d", n, f.heldCount())
		}

		time.Sleep(time.Millisecond)
	}
}

// expectSilence expects that nothing (neither data nor EOF) arrives on conn for a short while.
func expectSilence(t *testing.T, conn net.Conn) {
	t.Helper()

	conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	n, err := conn.Read(make([]byte, 16))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected silence, got n=%d err=%v", n, err)
	}
}

// startBuffered runs a plain-mode handler between a client and an upstream server; the fake sits in the up chain.
func startBuffered(t *testing.T, fake *fakeBuffering, halfCloseTimeout time.Duration) (client, server net.Conn, done <-chan error) {
	t.Helper()

	upstream, front := listenTCP(t), listenTCP(t)
	up := []Interceptor{fake}
	h := &ConnHandler{
		Setting:        ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModePlain},
		InterceptorsUp: up,
		bufferingUp:    scanBuffering(up),
		logger:         testLogger(),

		halfCloseTimeout: halfCloseTimeout,
	}
	done = runHandler(front, h, nil)

	client = dialTCP(t, front)
	server = acceptConn(t, upstream)
	return client, server, done
}

// held chunks don't stall later ones, and everything is forwarded in order once released
func TestBuffering_HoldAndRelease(t *testing.T) {
	fake := newFakeBuffering(true)
	client, server, _ := startBuffered(t, fake, 0)

	client.Write([]byte("AAA"))
	fake.waitHeld(t, 1)
	client.Write([]byte("BBB")) // read although AAA is still held
	fake.waitHeld(t, 2)
	expectSilence(t, server)

	fake.stopHolding()
	if got := mustRead(t, server, 6); got != "AAABBB" {
		t.Fatalf("server got %q", got)
	}

	client.Write([]byte("CCC")) // passes through now
	if got := mustRead(t, server, 3); got != "CCC" {
		t.Fatalf("server got %q", got)
	}
}

// a release sent before a later chunk passed the interceptor is forwarded before that chunk
func TestBuffering_ReleaseNotOvertakenByLaterChunk(t *testing.T) {
	fake := newFakeBuffering(true)
	client, server, _ := startBuffered(t, fake, 0)

	for i := 0; i < 500; i++ {
		fake.mu.Lock()
		fake.holding = true
		fake.mu.Unlock()

		client.Write([]byte(fmt.Sprintf("H%04d", i)))
		fake.waitHeld(t, 1)

		fake.stopHolding()
		client.Write([]byte(fmt.Sprintf("P%04d", i)))

		if got, want := mustRead(t, server, 10), fmt.Sprintf("H%04dP%04d", i, i); got != want {
			t.Fatalf("iteration %d: server got %q, want %q", i, got, want)
		}
	}
}

// a close must not overtake held data
func TestBuffering_HalfCloseWaitsForHeldData(t *testing.T) {
	fake := newFakeBuffering(true)
	client, server, done := startBuffered(t, fake, 0)

	client.Write([]byte("held"))
	fake.waitHeld(t, 1)
	closeWriteOf(t, client)
	expectSilence(t, server)

	fake.releaseAll()
	if got := mustRead(t, server, 4); got != "held" {
		t.Fatalf("server got %q", got)
	}
	mustEOF(t, server)

	closeWriteOf(t, server)
	mustEOF(t, client)
	waitHandler(t, done)
}

// a close racing with the release of the last held data must never arrive before that data
func TestBuffering_CloseNeverOvertakesRelease(t *testing.T) {
	for i := 0; i < 100; i++ {
		fake := newFakeBuffering(true)
		client, server, done := startBuffered(t, fake, 0)

		client.Write([]byte("held"))
		fake.waitHeld(t, 1)
		closeWriteOf(t, client)
		fake.releaseAll()

		if got := mustRead(t, server, 4); got != "held" {
			t.Fatalf("iteration %d: server got %q", i, got)
		}
		mustEOF(t, server)

		closeWriteOf(t, server)
		mustEOF(t, client)
		waitHandler(t, done)
	}
}

func TestBuffering_AbortTerminates(t *testing.T) {
	fake := newFakeBuffering(true)
	client, _, done := startBuffered(t, fake, 0)

	client.Write([]byte("x"))
	fake.waitHeld(t, 1)
	fake.abort()

	waitHandler(t, done)
	client.SetReadDeadline(time.Now().Add(testIOTimeout))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the client connection to be closed")
	}
}

// releases that block on a full channel while a chunk enters the interceptor must not deadlock
func TestBuffering_NoDeadlockWithBlockingReleases(t *testing.T) {
	fake := newFakeBuffering(true)
	client, server, _ := startBuffered(t, fake, 0)

	var want strings.Builder
	for i := 0; i < 5; i++ {
		chunk := fmt.Sprintf("h%d", i)
		want.WriteString(chunk)
		client.Write([]byte(chunk))
		fake.waitHeld(t, i+1)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			fake.releaseOne()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			chunk := fmt.Sprintf("b%02d", i)
			want.WriteString(chunk)
			client.Write([]byte(chunk))
			time.Sleep(time.Millisecond)
		}
	}()

	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(testIOTimeout):
		t.Fatal("deadlock: releases and incoming chunks did not finish")
	}

	fake.waitHeld(t, 20)
	fake.releaseAll()
	if got := mustRead(t, server, want.Len()); got != want.String() {
		t.Fatalf("server got %q, want %q", got, want.String())
	}
}

// the half-close timeout must not end a connection while data is held
func TestBuffering_HalfCloseTimeoutWaitsForHeldData(t *testing.T) {
	const timeout = 100 * time.Millisecond

	fake := newFakeBuffering(true)
	client, server, done := startBuffered(t, fake, timeout)

	closeWriteOf(t, server) // the down direction ends, which starts the timeout
	client.Write([]byte("held"))
	fake.waitHeld(t, 1)

	time.Sleep(4 * timeout)
	select {
	case <-done:
		t.Fatal("connection was terminated while data was held")
	default:
	}

	fake.releaseAll()
	if got := mustRead(t, server, 4); got != "held" {
		t.Fatalf("server got %q", got)
	}

	closeWriteOf(t, client)
	mustEOF(t, server)
	waitHandler(t, done)
}

func TestStart_RejectsUnsupportedBufferingChains(t *testing.T) {
	connect := "127.0.0.1:1"
	config := ResolvedProxyConfig{ListenEndpoint: "127.0.0.1:0", ConnectEndpoint: &connect, Name: "test"}

	tests := []struct {
		name string
		mode Mode
		up   []Interceptor
		down []Interceptor
	}{
		{"two buffering interceptors in one chain", ModePlain, []Interceptor{newFakeBuffering(false), newFakeBuffering(false)}, nil},
		{"buffering interceptor in detecttls", ModeDetectTls, nil, []Interceptor{newFakeBuffering(false)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProxy(config, tc.mode, tc.up, tc.down, nil, *testLogger())
			if err := p.Start(); err == nil || !strings.Contains(err.Error(), "buffering") {
				t.Fatalf("expected a buffering related error, got %v", err)
			}
		})
	}
}
