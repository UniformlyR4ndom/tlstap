package proxy

import (
	"io"
	"net"
	"testing"
	"time"

	"tlstap/logging"
)

const testIOTimeout = 3 * time.Second

func testLogger() *logging.Logger {
	l := logging.NewLogger(io.Discard, nil, false)
	return &l
}

// mustRead reads exactly n bytes from conn.
func mustRead(t *testing.T, conn net.Conn, n int) string {
	t.Helper()

	conn.SetReadDeadline(time.Now().Add(testIOTimeout))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("expected to read %d bytes, got error: %v", n, err)
	}

	return string(buf)
}

// mustEOF expects the next read on conn to fail with io.EOF.
func mustEOF(t *testing.T, conn net.Conn) {
	t.Helper()

	conn.SetReadDeadline(time.Now().Add(testIOTimeout))
	defer conn.SetReadDeadline(time.Time{})

	if n, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected io.EOF, got n=%d err=%v", n, err)
	}
}
