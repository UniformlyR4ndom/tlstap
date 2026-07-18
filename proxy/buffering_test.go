package proxy

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"tlstap/logging"
)

// fakeBuffering is a minimal Interceptor + BufferingInterceptor: it holds every chunk it sees
// (Intercept always returns empty) until the test explicitly releases it via release(). Existing
// purely to exercise ConnHandler's generic buffering plumbing end-to-end, independent of any real
// interceptor implementation.
type fakeBuffering struct {
	mu      sync.Mutex
	holding [][]byte

	relCh chan ReleasedData
	seen  chan []byte // every chunk Intercept was called with, for the test to observe
}

func newFakeBuffering() *fakeBuffering {
	return &fakeBuffering{
		relCh: make(chan ReleasedData, 4),
		seen:  make(chan []byte, 16),
	}
}

func (f *fakeBuffering) Init(addr net.TCPAddr) error               { return nil }
func (f *fakeBuffering) Finalize(addr net.TCPAddr)                 {}
func (f *fakeBuffering) ConnectionEstablished(info *ConnInfo) error { return nil }
func (f *fakeBuffering) ConnectionUpgraded(info *ConnInfo) error    { return nil }

func (f *fakeBuffering) ConnectionTerminated(info *ConnInfo) error {
	close(f.relCh)
	return nil
}

func (f *fakeBuffering) Intercept(info *ConnInfo, data []byte) ([]byte, error) {
	cp := append([]byte(nil), data...)

	f.mu.Lock()
	f.holding = append(f.holding, cp)
	f.mu.Unlock()

	f.seen <- cp
	return nil, nil
}

func (f *fakeBuffering) HasPending(info *ConnInfo) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.holding) > 0
}

func (f *fakeBuffering) ReleaseChannel(info *ConnInfo) <-chan ReleasedData {
	return f.relCh
}

// release pops the oldest held chunk and sends it on the release channel.
func (f *fakeBuffering) release(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	if len(f.holding) == 0 {
		f.mu.Unlock()
		t.Fatal("release called with nothing held")
	}
	data := f.holding[0]
	f.holding = f.holding[1:]
	f.mu.Unlock()

	f.relCh <- ReleasedData{Data: data}
}

func testLogger() *logging.Logger {
	l := logging.NewLogger(io.Discard, nil, false)
	return &l
}

func recvString(t *testing.T, ch <-chan []byte, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if string(got) != want {
			t.Fatalf("expected interceptor to see %q, got %q", want, got)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for interceptor to see %q", want)
	}
}

func expectNoData(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 16)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("expected no data forwarded yet, got %q", buf[:n])
	}
}

func expectData(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected %q forwarded, got error: %v", want, err)
	}
	if string(buf[:n]) != want {
		t.Fatalf("expected %q forwarded, got %q", want, buf[:n])
	}
}

// TestBufferingHoldDoesNotStallSubsequentChunks is the core regression test for the bug that
// motivated this whole feature: with a plain (non-buffering) interceptor, holding one chunk
// blocks the read loop, so a second chunk on the same direction could never even be read. Here,
// the fake holds chunk 1, and the test asserts sending chunk 2 while chunk 1 is still held does
// not block — proving the lazy transition into the async pump+select phase actually happens.
func TestBufferingHoldDoesNotStallSubsequentChunks(t *testing.T) {
	client, srcConn := net.Pipe()
	dstConn, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()

	fake := newFakeBuffering()
	interceptors := []Interceptor{fake}
	buffering := scanBuffering(interceptors)
	if len(buffering) != 1 {
		t.Fatalf("expected scanBuffering to find the fake interceptor, got %d entries", len(buffering))
	}

	info := &ConnInfo{SrcEndpoint: "client:1", DstEndpoint: "server:2", ConnID: 1}
	h := &ConnHandler{
		logger:   testLogger(),
		ConnDown: srcConn,
		ConnUp:   dstConn,
	}
	h.wg.Add(1)

	done := make(chan error, 1)
	go func() {
		done <- h.forwardOneWay(srcConn, dstConn, make([]byte, 4096), interceptors, info, buffering)
	}()

	// Chunk 1 arrives and is held.
	if _, err := client.Write([]byte("chunk1")); err != nil {
		t.Fatalf("write chunk1: %v", err)
	}
	recvString(t, fake.seen, "chunk1")
	expectNoData(t, upstream)

	// Chunk 2 arrives while chunk 1 is still held. This write must not block — that's the bug
	// this feature exists to fix.
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("chunk2"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write chunk2: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("writing chunk2 blocked while chunk1 was still held — async transition did not happen")
	}
	recvString(t, fake.seen, "chunk2")
	expectNoData(t, upstream)

	// Release in order: chunk1 must reach upstream before chunk2, even though chunk2 was read
	// first by the pump.
	fake.release(t)
	expectData(t, upstream, "chunk1")
	fake.release(t)
	expectData(t, upstream, "chunk2")

	// ConnectionTerminated firing (closing the release channel) must unblock the async loop even
	// though the underlying connections are still open and the pump is still blocked in Read —
	// this is the only thing that can end the loop in this scenario, proving the fan-in's
	// close-propagation works and doesn't busy-loop.
	if err := fake.ConnectionTerminated(info); err != nil {
		t.Fatalf("ConnectionTerminated: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("forwardOneWayAsync did not return after the release channel closed")
	}
}

// TestBufferingNoInterceptorUnchanged is a sanity check that a chain with no BufferingInterceptor
// behaves exactly as before: data flows straight through, synchronously, never entering the async
// phase.
func TestBufferingNoInterceptorUnchanged(t *testing.T) {
	client, srcConn := net.Pipe()
	dstConn, upstream := net.Pipe()
	defer client.Close()
	defer srcConn.Close()
	defer dstConn.Close()
	defer upstream.Close()

	info := &ConnInfo{SrcEndpoint: "client:1", DstEndpoint: "server:2", ConnID: 2}
	h := &ConnHandler{
		logger:   testLogger(),
		ConnDown: srcConn,
		ConnUp:   dstConn,
	}
	h.wg.Add(1)

	go h.forwardOneWay(srcConn, dstConn, make([]byte, 4096), nil, info, nil)

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	expectData(t, upstream, "hello")
}
