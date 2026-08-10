package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCert generates a minimal ECDSA self-signed certificate for TLS handshake
// tests — no existing cert-generation test helper elsewhere in this repo to reuse.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tlstap-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestTlsInfoFromConn_NonTLS confirms a plain net.Conn (ModePlain, or a not-yet-upgraded
// detecttls connection) reports no TLS info.
func TestTlsInfoFromConn_NonTLS(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	if info := tlsInfoFromConn(clientConn); info != nil {
		t.Fatalf("expected nil for a plain net.Conn, got %+v", info)
	}
}

// TestTlsInfoFromConn_TLS performs a real handshake over net.Pipe() and confirms
// tlsInfoFromConn extracts the negotiated SNI/ALPN/version/cipher suite correctly on the
// server (downstream) side — the side this package always reports (see ConnInfo.TLS's
// doc comment).
func TestTlsInfoFromConn_TLS(t *testing.T) {
	cert := selfSignedCert(t)

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.test",
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	tlsClient := tls.Client(clientConn, clientConfig)
	tlsServer := tls.Server(serverConn, serverConfig)

	errCh := make(chan error, 1)
	go func() { errCh <- tlsClient.Handshake() }()
	if err := tlsServer.Handshake(); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	info := tlsInfoFromConn(tlsServer)
	if info == nil {
		t.Fatal("expected non-nil TLSInfo for a handshaked *tls.Conn")
	}
	if info.SNI != "example.test" {
		t.Errorf("expected SNI %q, got %q", "example.test", info.SNI)
	}
	if info.ALPN != "h2" {
		t.Errorf("expected ALPN %q, got %q", "h2", info.ALPN)
	}
	if info.Version != tls.VersionTLS13 {
		t.Errorf("expected version %#x, got %#x", tls.VersionTLS13, info.Version)
	}
	if info.CipherSuite != tlsServer.ConnectionState().CipherSuite {
		t.Errorf("expected cipher suite %#x, got %#x", tlsServer.ConnectionState().CipherSuite, info.CipherSuite)
	}
}
