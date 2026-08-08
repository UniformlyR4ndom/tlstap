package dbdump

import (
	"net"
	"testing"

	"tlstap/proxy"
)

func newTestInterceptor(t *testing.T) *DbDumpInterceptor {
	t.Helper()
	return newTestInterceptorWithScripts(t, "")
}

func newTestInterceptorWithScripts(t *testing.T, scriptsDir string) *DbDumpInterceptor {
	t.Helper()
	d, err := NewDbDumpInterceptor(":memory:", false, scriptsDir, proxy.ResolvedProxyConfig{Name: "test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Init(net.TCPAddr{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Finalize(net.TCPAddr{}) })
	return d
}

func sessionCount(t *testing.T, d *DbDumpInterceptor) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func streamCount(t *testing.T, d *DbDumpInterceptor) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM stream`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func fakeConnInfo(connID uint32) *proxy.ConnInfo {
	return &proxy.ConnInfo{
		ConnID:      connID,
		SrcEndpoint: "1.2.3.4:1000",
		DstEndpoint: "5.6.7.8:443",
	}
}

// No connections at all → no session row.
func TestLazySession_NoTraffic(t *testing.T) {
	d := newTestInterceptor(t)
	if n := sessionCount(t, d); n != 0 {
		t.Fatalf("expected 0 sessions after Init, got %d", n)
	}
}

// Connection established then terminated with no data → no session row.
func TestLazySession_ConnectDisconnectNoData(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeConnInfo(1)
	if err := d.ConnectionEstablished(info); err != nil {
		t.Fatal(err)
	}
	if err := d.ConnectionTerminated(info); err != nil {
		t.Fatal(err)
	}
	if n := sessionCount(t, d); n != 0 {
		t.Fatalf("expected 0 sessions, got %d", n)
	}
	if n := streamCount(t, d); n != 0 {
		t.Fatalf("expected 0 stream rows, got %d", n)
	}
}

// First Intercept call creates the session and flushes the pending stream row.
func TestLazySession_CreatedOnFirstIntercept(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeConnInfo(1)

	if err := d.ConnectionEstablished(info); err != nil {
		t.Fatal(err)
	}
	if n := sessionCount(t, d); n != 0 {
		t.Fatalf("expected 0 sessions before first Intercept, got %d", n)
	}

	if _, err := d.Intercept(info, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	if n := sessionCount(t, d); n != 1 {
		t.Fatalf("expected 1 session after first Intercept, got %d", n)
	}
	if n := streamCount(t, d); n != 1 {
		t.Fatalf("expected 1 stream row after first Intercept, got %d", n)
	}
}

// Session is created only once regardless of how many Intercept calls follow.
func TestLazySession_OnlyOneSession(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeConnInfo(1)

	d.ConnectionEstablished(info)
	d.Intercept(info, []byte("a"))
	d.Intercept(info, []byte("b"))
	d.Intercept(info, []byte("c"))

	if n := sessionCount(t, d); n != 1 {
		t.Fatalf("expected exactly 1 session, got %d", n)
	}
}

// A connection that had no data is not written even if another connection
// on the same session did produce data.
func TestLazySession_SilentConnNotRecorded(t *testing.T) {
	d := newTestInterceptor(t)

	silent := fakeConnInfo(1)
	active := &proxy.ConnInfo{ConnID: 2, SrcEndpoint: "9.9.9.9:2000", DstEndpoint: "5.6.7.8:443"}

	d.ConnectionEstablished(silent)
	d.ConnectionEstablished(active)
	d.ConnectionTerminated(silent) // closed before any data

	if _, err := d.Intercept(active, []byte("data")); err != nil {
		t.Fatal(err)
	}

	if n := streamCount(t, d); n != 1 {
		t.Fatalf("expected 1 stream row (silent conn discarded), got %d", n)
	}
}

// ConnectionTerminated after data is written updates the stream end timestamp.
func TestLazySession_TerminatedAfterData(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeConnInfo(1)

	d.ConnectionEstablished(info)
	d.Intercept(info, []byte("x"))
	if err := d.ConnectionTerminated(info); err != nil {
		t.Fatal(err)
	}

	var end *int64
	if err := d.db.QueryRow(`SELECT end FROM stream WHERE id = 1`).Scan(&end); err != nil {
		t.Fatal(err)
	}
	if end == nil {
		t.Fatal("expected stream.end to be set after ConnectionTerminated, got NULL")
	}
}
