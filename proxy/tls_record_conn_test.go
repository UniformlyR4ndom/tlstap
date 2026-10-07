package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// batchConn holds back writes while batching is on, so several writes leave as one.
type batchConn struct {
	net.Conn
	batching bool
	buf      bytes.Buffer
}

func (b *batchConn) Write(p []byte) (int, error) {
	if b.batching {
		return b.buf.Write(p)
	}

	return b.Conn.Write(p)
}

func (b *batchConn) flush() error {
	b.batching = false
	b.Conn.SetWriteDeadline(time.Time{}) // CloseWrite leaves the write deadline in the past
	_, err := b.Conn.Write(b.buf.Bytes())
	return err
}

// bytes that follow a close_notify in the same read must stay readable on the transport
func TestTlsRecordConn_KeepsBytesAfterCloseNotify(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	peer := &batchConn{Conn: b}
	go func() {
		srv := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, SessionTicketsDisabled: true})
		if err := srv.Handshake(); err != nil {
			return
		}

		peer.batching = true
		srv.Write([]byte("hello"))
		srv.CloseWrite()
		peer.Write([]byte("PLAIN")) // plaintext right behind close_notify
		peer.flush()
	}()

	cli := tls.Client(&tlsRecordConn{Conn: a}, &tls.Config{InsecureSkipVerify: true})
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}

	if data, err := io.ReadAll(cli); err != nil || string(data) != "hello" {
		t.Fatalf("TLS data: got %q, %v", data, err)
	}

	if got := mustRead(t, a, len("PLAIN")); got != "PLAIN" {
		t.Fatalf("plaintext after close_notify: got %q", got)
	}
}
