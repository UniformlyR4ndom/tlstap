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
	return newTestInterceptorWithScriptDirs(t, scriptsDir, "")
}

func newTestInterceptorWithDissectScripts(t *testing.T, dissectScriptsDir string) *DbDumpInterceptor {
	t.Helper()
	return newTestInterceptorWithScriptDirs(t, "", dissectScriptsDir)
}

func newTestInterceptorWithScriptDirs(t *testing.T, scriptsDir, dissectScriptsDir string) *DbDumpInterceptor {
	t.Helper()
	d, err := NewDbDumpInterceptor(":memory:", false, scriptsDir, dissectScriptsDir, proxy.ResolvedProxyConfig{Name: "test"}, nil)
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

func fakeTLSConnInfo(connID uint32) *proxy.ConnInfo {
	info := fakeConnInfo(connID)
	info.TLS = &proxy.TLSInfo{SNI: "example.test", ALPN: "h2", Version: 0x0304, CipherSuite: 0x1301}
	return info
}

func streamTLSColumns(t *testing.T, d *DbDumpInterceptor, id uint32) (sni, alpn *string, version, cipherSuite *int64) {
	t.Helper()
	if err := d.db.QueryRow(`SELECT sni, alpn, tls_version, cipher_suite FROM stream WHERE id = ?`, id).
		Scan(&sni, &alpn, &version, &cipherSuite); err != nil {
		t.Fatal(err)
	}
	return
}

// ConnectionUpgraded before the session exists buffers onto the pending stream entry,
// which then carries the TLS columns through ensureSession's flush.
func TestConnectionUpgraded_BeforeSessionCreated(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeTLSConnInfo(1)

	// Both directions, as the real proxy calls it, before any data (so the session isn't
	// created yet) — mirrors ConnectionEstablished's own "called once per direction"
	// doc comment on why pendingStreams can hold two entries for one ConnID.
	if err := d.ConnectionEstablished(info); err != nil {
		t.Fatal(err)
	}
	if err := d.ConnectionUpgraded(info); err != nil {
		t.Fatal(err)
	}
	if err := d.ConnectionUpgraded(info); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Intercept(info, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	sni, alpn, version, cipherSuite := streamTLSColumns(t, d, 1)
	if sni == nil || *sni != "example.test" {
		t.Errorf("expected sni %q, got %v", "example.test", sni)
	}
	if alpn == nil || *alpn != "h2" {
		t.Errorf("expected alpn %q, got %v", "h2", alpn)
	}
	if version == nil || *version != 0x0304 {
		t.Errorf("expected tls_version 0x0304, got %v", version)
	}
	if cipherSuite == nil || *cipherSuite != 0x1301 {
		t.Errorf("expected cipher_suite 0x1301, got %v", cipherSuite)
	}
}

// ConnectionUpgraded after the session already exists updates the row directly and bumps
// streamsVersion exactly once, even though it's called twice (once per direction).
func TestConnectionUpgraded_AfterSessionCreated(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeTLSConnInfo(1)

	d.ConnectionEstablished(info)
	if _, err := d.Intercept(info, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	versionBefore := d.streamsVersion
	if err := d.ConnectionUpgraded(info); err != nil {
		t.Fatal(err)
	}
	if d.streamsVersion != versionBefore+1 {
		t.Fatalf("expected streamsVersion to bump by 1, got %d -> %d", versionBefore, d.streamsVersion)
	}

	sni, _, _, _ := streamTLSColumns(t, d, 1)
	if sni == nil || *sni != "example.test" {
		t.Errorf("expected sni %q, got %v", "example.test", sni)
	}

	// Second call (the other direction's, carrying identical info.TLS): a no-op for the
	// version bump, since tls_version IS NULL no longer matches.
	if err := d.ConnectionUpgraded(info); err != nil {
		t.Fatal(err)
	}
	if d.streamsVersion != versionBefore+1 {
		t.Fatalf("expected the second ConnectionUpgraded call not to bump streamsVersion again, got %d", d.streamsVersion)
	}
}

// info.TLS == nil (plain mode, or a detecttls connection that never upgraded) leaves the
// TLS columns NULL and never bumps streamsVersion.
func TestConnectionUpgraded_NoTLS(t *testing.T) {
	d := newTestInterceptor(t)
	info := fakeConnInfo(1) // no .TLS set

	d.ConnectionEstablished(info)
	if _, err := d.Intercept(info, []byte("hello")); err != nil {
		t.Fatal(err)
	}

	versionBefore := d.streamsVersion
	if err := d.ConnectionUpgraded(info); err != nil {
		t.Fatal(err)
	}
	if d.streamsVersion != versionBefore {
		t.Fatalf("expected streamsVersion unchanged for a non-TLS connection, got %d -> %d", versionBefore, d.streamsVersion)
	}

	sni, alpn, version, cipherSuite := streamTLSColumns(t, d, 1)
	if sni != nil || alpn != nil || version != nil || cipherSuite != nil {
		t.Errorf("expected all TLS columns NULL, got sni=%v alpn=%v version=%v cipherSuite=%v", sni, alpn, version, cipherSuite)
	}
}
