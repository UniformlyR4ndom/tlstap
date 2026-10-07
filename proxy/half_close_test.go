package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"
)

func listenTCP(t *testing.T) net.Listener {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { l.Close() })
	return l
}

func dialTCP(t *testing.T, l net.Listener) net.Conn {
	t.Helper()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { c.Close() })
	return c
}

func acceptConn(t *testing.T, l net.Listener) net.Conn {
	t.Helper()

	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { c.Close() })
	return c
}

func closeWriteOf(t *testing.T, c net.Conn) {
	t.Helper()

	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
}

// runHandler hands the first connection accepted on l to h; the result is delivered on the returned channel.
func runHandler(l net.Listener, h *ConnHandler, prepare func(net.Conn)) <-chan error {
	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}

		if prepare != nil {
			prepare(conn)
		}

		done <- h.HandleConnection(conn)
	}()

	return done
}

// waitHandler expects the handler to finish well before halfCloseTimeout would end it.
func waitHandler(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("handler returned %v", err)
		}
	case <-time.After(testIOTimeout):
		t.Fatal("handler did not finish after both sides closed")
	}
}

// the client half-closes right after its request; the response must still arrive
func testHalfClose(t *testing.T, mode Mode) {
	upstream, front := listenTCP(t), listenTCP(t)
	h := &ConnHandler{Setting: ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: mode}, logger: testLogger()}
	done := runHandler(front, h, nil)

	client := dialTCP(t, front)
	server := acceptConn(t, upstream)

	client.Write([]byte("req"))
	closeWriteOf(t, client)

	if got := mustRead(t, server, 3); got != "req" {
		t.Fatalf("server got %q", got)
	}
	mustEOF(t, server)

	server.Write([]byte("resp"))
	closeWriteOf(t, server)

	if got := mustRead(t, client, 4); got != "resp" {
		t.Fatalf("client got %q", got)
	}
	mustEOF(t, client)

	waitHandler(t, done)
}

func TestHalfClose_Plain(t *testing.T) { testHalfClose(t, ModePlain) }

func TestHalfClose_DetectTlsPlain(t *testing.T) { testHalfClose(t, ModeDetectTls) }

func TestHalfClose_Tls(t *testing.T) {
	serverCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	upstream, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	front, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()

	h := &ConnHandler{
		Setting: ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModeTls, TlsClientConfig: clientCfg, TlsServerConfig: serverCfg},
		logger:  testLogger(),
	}
	done := runHandler(front, h, func(c net.Conn) { c.(*tls.Conn).Handshake() })

	client, err := tls.Dial("tcp", front.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := acceptConn(t, upstream).(*tls.Conn)
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}

	client.Write([]byte("req"))
	client.CloseWrite() // close_notify

	if got := mustRead(t, server, 3); got != "req" {
		t.Fatalf("server got %q", got)
	}
	mustEOF(t, server)

	server.Write([]byte("resp"))
	server.CloseWrite()

	if got := mustRead(t, client, 4); got != "resp" {
		t.Fatalf("client got %q", got)
	}
	mustEOF(t, client)

	waitHandler(t, done)
}

// two TLS sessions on one TCP connection, separated by close_notify and plaintext, then a half-close
func TestDetectTls_UpgradeDowngradeCycles(t *testing.T) {
	serverCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	upstream, front := listenTCP(t), listenTCP(t)
	h := &ConnHandler{
		Setting: ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModeDetectTls, TlsClientConfig: clientCfg, TlsServerConfig: serverCfg},
		logger:  testLogger(),
	}
	done := runHandler(front, h, nil)

	rawC := dialTCP(t, front)
	rawS := acceptConn(t, upstream)

	plain := func(c2s, s2c string) {
		t.Helper()

		rawC.Write([]byte(c2s))
		if got := mustRead(t, rawS, len(c2s)); got != c2s {
			t.Fatalf("server got %q, want %q", got, c2s)
		}

		rawS.Write([]byte(s2c))
		if got := mustRead(t, rawC, len(s2c)); got != s2c {
			t.Fatalf("client got %q, want %q", got, s2c)
		}
	}

	secure := func(c2s, s2c string) {
		t.Helper()

		cTLS := tls.Client(rawC, clientCfg)
		sTLS := tls.Server(rawS, serverCfg)

		serverHandshake := make(chan error, 1)
		go func() { serverHandshake <- sTLS.Handshake() }()
		if err := cTLS.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		if err := <-serverHandshake; err != nil {
			t.Fatalf("server handshake: %v", err)
		}

		cTLS.Write([]byte(c2s))
		if got := mustRead(t, sTLS, len(c2s)); got != c2s {
			t.Fatalf("server got %q, want %q", got, c2s)
		}

		sTLS.Write([]byte(s2c))
		if got := mustRead(t, cTLS, len(s2c)); got != s2c {
			t.Fatalf("client got %q, want %q", got, s2c)
		}

		// each side waits for the other's close_notify before sending plaintext
		cTLS.CloseWrite()
		mustEOF(t, sTLS)
		sTLS.CloseWrite()
		mustEOF(t, cTLS)

		// CloseWrite leaves the write deadline of the underlying conn in the past
		rawC.SetWriteDeadline(time.Time{})
		rawS.SetWriteDeadline(time.Time{})
	}

	plain("p1", "p2")
	secure("s1", "s2")
	plain("p3", "p4")
	secure("s3", "s4")
	plain("p5", "p6")

	closeWriteOf(t, rawC)
	mustEOF(t, rawS)
	closeWriteOf(t, rawS)
	mustEOF(t, rawC)

	waitHandler(t, done)
}

// one direction can fall back to plaintext while the other is still TLS: the server closes its TLS write
// side and continues in plaintext, while the client keeps sending inside its TLS session
func TestDetectTls_DirectionsDowngradeIndependently(t *testing.T) {
	serverCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	upstream, front := listenTCP(t), listenTCP(t)
	h := &ConnHandler{
		Setting: ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModeDetectTls, TlsClientConfig: clientCfg, TlsServerConfig: serverCfg},
		logger:  testLogger(),
	}
	done := runHandler(front, h, nil)

	rawC := dialTCP(t, front)
	rawS := acceptConn(t, upstream)

	cTLS := tls.Client(rawC, clientCfg)
	sTLS := tls.Server(rawS, serverCfg)
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- sTLS.Handshake() }()
	if err := cTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// the server ends its side of the TLS session; the client sees the translated close_notify
	sTLS.CloseWrite()
	rawS.SetWriteDeadline(time.Time{})
	mustEOF(t, cTLS)

	// from now on the server sends plaintext, while the client keeps using TLS
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("plain%d", i)
		rawS.Write([]byte(msg))
		if got := mustRead(t, rawC, len(msg)); got != msg {
			t.Fatalf("client got %q, want %q", got, msg)
		}

		msg = fmt.Sprintf("tls%d", i)
		cTLS.Write([]byte(msg))
		if got := mustRead(t, sTLS, len(msg)); got != msg {
			t.Fatalf("server got %q, want %q", got, msg)
		}
	}

	// the client ends its TLS session as well; afterwards both directions are plaintext
	cTLS.CloseWrite()
	rawC.SetWriteDeadline(time.Time{})
	mustEOF(t, sTLS)

	rawC.Write([]byte("last"))
	if got := mustRead(t, rawS, 4); got != "last" {
		t.Fatalf("server got %q", got)
	}

	closeWriteOf(t, rawC)
	mustEOF(t, rawS)
	closeWriteOf(t, rawS)
	mustEOF(t, rawC)
	waitHandler(t, done)
}

// a peer may send plaintext in the same TCP segment as its close_notify; the proxy must not lose it,
// in either direction
func TestDetectTls_PlaintextRightAfterCloseNotify(t *testing.T) {
	serverCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	upstream, front := listenTCP(t), listenTCP(t)
	h := &ConnHandler{
		Setting: ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModeDetectTls, TlsClientConfig: clientCfg, TlsServerConfig: serverCfg},
		logger:  testLogger(),
	}
	done := runHandler(front, h, nil)

	rawC := dialTCP(t, front)
	rawS := acceptConn(t, upstream)

	// the peers' own tls.Conn would read ahead past the close_notify as well; keep it from doing so
	batchC, batchS := &batchConn{Conn: rawC}, &batchConn{Conn: rawS}
	cTLS := tls.Client(&tlsRecordConn{Conn: batchC}, clientCfg)
	sTLS := tls.Server(&tlsRecordConn{Conn: batchS}, serverCfg)

	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- sTLS.Handshake() }()
	if err := cTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// server: close_notify and plaintext leave in one write
	batchS.batching = true
	sTLS.CloseWrite()
	batchS.Write([]byte("S2C-PLAIN"))
	batchS.flush()

	mustEOF(t, cTLS)
	if got := mustRead(t, rawC, 9); got != "S2C-PLAIN" {
		t.Fatalf("client got %q", got)
	}

	// client: the same in the other direction
	batchC.batching = true
	cTLS.CloseWrite()
	batchC.Write([]byte("C2S-PLAIN"))
	batchC.flush()

	mustEOF(t, sTLS)
	if got := mustRead(t, rawS, 9); got != "C2S-PLAIN" {
		t.Fatalf("server got %q", got)
	}

	closeWriteOf(t, rawC)
	mustEOF(t, rawS)
	closeWriteOf(t, rawS)
	mustEOF(t, rawC)
	waitHandler(t, done)
}

// a ClientHello that arrives after the upstream side has ended must not leave the connection waiting
// for the half-close timeout
func TestDetectTls_UpgradeAfterUpstreamEndedDoesNotHang(t *testing.T) {
	serverCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	upstream, front := listenTCP(t), listenTCP(t)
	h := &ConnHandler{
		Setting:          ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModeDetectTls, TlsClientConfig: clientCfg, TlsServerConfig: serverCfg},
		logger:           testLogger(),
		halfCloseTimeout: time.Minute, // a hang must not be mistaken for the timeout ending the connection
	}
	done := runHandler(front, h, nil)

	rawC := dialTCP(t, front)
	rawS := acceptConn(t, upstream)

	closeWriteOf(t, rawS)
	mustEOF(t, rawC) // the down direction has ended

	go tls.Client(rawC, clientCfg).Handshake()
	waitHandler(t, done)
}

// a new ClientHello while the server side is still in its TLS session cannot be honored: the connection ends
func TestDetectTls_UpgradeWhileServerStillTlsEndsConnection(t *testing.T) {
	serverCfg := &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	clientCfg := &tls.Config{InsecureSkipVerify: true}

	upstream, front := listenTCP(t), listenTCP(t)
	h := &ConnHandler{
		Setting:          ConnSettings{ConnectEndpoint: upstream.Addr().String(), Mode: ModeDetectTls, TlsClientConfig: clientCfg, TlsServerConfig: serverCfg},
		logger:           testLogger(),
		halfCloseTimeout: time.Minute, // a hang must not be mistaken for the timeout ending the connection
	}
	done := runHandler(front, h, nil)

	rawC := dialTCP(t, front)
	rawS := acceptConn(t, upstream)

	cTLS := tls.Client(rawC, clientCfg)
	sTLS := tls.Server(rawS, serverCfg)
	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- sTLS.Handshake() }()
	if err := cTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// the client ends its TLS session and immediately starts a new one, while the server keeps its own
	cTLS.CloseWrite()
	rawC.SetWriteDeadline(time.Time{})
	mustEOF(t, sTLS)

	go tls.Client(rawC, clientCfg).Handshake()
	waitHandler(t, done)
}
