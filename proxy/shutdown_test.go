package proxy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFinalizeTracker is a minimal Interceptor whose only interesting behavior is
// Finalize: it records how many times it was called and the addr it was given, optionally
// sleeping first — used to confirm notifyFinalize/Proxy.Finalize call every interceptor
// exactly once and don't serialize behind a slow one.
type fakeFinalizeTracker struct {
	delay    time.Duration
	calls    atomic.Int32
	lastAddr atomic.Value // net.TCPAddr
}

func newFakeFinalizeTracker() *fakeFinalizeTracker {
	return &fakeFinalizeTracker{}
}

func (f *fakeFinalizeTracker) Init(addr net.TCPAddr) error                { return nil }
func (f *fakeFinalizeTracker) ConnectionEstablished(info *ConnInfo) error { return nil }
func (f *fakeFinalizeTracker) ConnectionUpgraded(info *ConnInfo) error    { return nil }
func (f *fakeFinalizeTracker) ConnectionTerminated(info *ConnInfo) error  { return nil }
func (f *fakeFinalizeTracker) Intercept(info *ConnInfo, data []byte) ([]byte, error) {
	return data, nil
}

func (f *fakeFinalizeTracker) Finalize(addr net.TCPAddr) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.calls.Add(1)
	f.lastAddr.Store(addr)
}

func TestProxyStop_AcceptLoopReturns(t *testing.T) {
	connect := "127.0.0.1:1" // never dialed; ModePlain only needs it to be non-empty at Start()
	p := NewProxy(ResolvedProxyConfig{
		ListenEndpoint:  "127.0.0.1:0",
		ConnectEndpoint: &connect,
		Name:            "test",
	}, ModePlain, nil, nil, nil, *testLogger())

	startErr := make(chan error, 1)
	go func() { startErr <- p.Start() }()

	// Wait for the listener to actually be set (Start() races this test goroutine).
	deadline := time.Now().Add(time.Second)
	for l, _ := p.getListener(); l == nil; l, _ = p.getListener() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for listener to be set")
		}
		time.Sleep(time.Millisecond)
	}

	p.Stop()

	select {
	case err := <-startErr:
		if err != nil {
			t.Fatalf("expected Start() to return nil after Stop(), got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Start() to return after Stop()")
	}
}

func TestProxyWaitForConnections(t *testing.T) {
	p := &Proxy{}

	// No in-flight connections: returns true immediately.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if !p.WaitForConnections(ctx) {
		t.Fatal("expected WaitForConnections to return true with nothing in flight")
	}

	// One in-flight "connection" that doesn't finish before the context deadline.
	release := make(chan struct{})
	p.trackConnection(func() { <-release })

	shortCtx, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if p.WaitForConnections(shortCtx) {
		close(release)
		t.Fatal("expected WaitForConnections to return false while a connection is still in flight")
	}

	// Once released, a fresh (unhurried) wait succeeds.
	close(release)
	longCtx, cancelLong := context.WithTimeout(context.Background(), time.Second)
	defer cancelLong()
	if !p.WaitForConnections(longCtx) {
		t.Fatal("expected WaitForConnections to return true once the connection finished")
	}
}

func TestProxyFinalize(t *testing.T) {
	topLevel := newFakeFinalizeTracker()
	slow := newFakeFinalizeTracker()
	slow.delay = 300 * time.Millisecond
	handlerA := newFakeFinalizeTracker()
	handlerB := newFakeFinalizeTracker()

	mux := NewMux([]Handler{
		{Name: "a", InterceptorAll: []Interceptor{handlerA}},
		{Name: "b", InterceptorAll: []Interceptor{handlerB}},
	})

	p := &Proxy{
		InterceptorsAll: []Interceptor{topLevel, slow},
		Mux:             mux,
		listenAddr:      net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234},
	}

	start := time.Now()
	p.Finalize()
	elapsed := time.Since(start)

	for name, f := range map[string]*fakeFinalizeTracker{"topLevel": topLevel, "slow": slow, "handlerA": handlerA, "handlerB": handlerB} {
		if n := f.calls.Load(); n != 1 {
			t.Errorf("%s: expected Finalize called exactly once, got %d", name, n)
		}
		addr, _ := f.lastAddr.Load().(net.TCPAddr)
		if addr.String() != p.listenAddr.String() {
			t.Errorf("%s: expected Finalize called with %v, got %v", name, p.listenAddr, addr)
		}
	}

	// slow sleeps 300ms; if the others were serialized behind it (or it behind them) this
	// would take >= ~600ms. Generous margin to avoid flakiness while still catching a
	// regression to sequential calls.
	if elapsed > 450*time.Millisecond {
		t.Errorf("Finalize() took %v, expected interceptors to run concurrently (~%v)", elapsed, slow.delay)
	}
}

func TestProxyFinalize_EmptyIsNoop(t *testing.T) {
	p := &Proxy{}
	done := make(chan struct{})
	go func() { p.Finalize(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Finalize() on a Proxy with no interceptors should return immediately")
	}
}
