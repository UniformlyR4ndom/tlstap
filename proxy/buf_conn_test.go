package proxy

import (
	"io"
	"net"
	"os"
	"testing"
)

type readStep struct {
	data string
	err  error
}

// scriptedConn returns the scripted (data, error) pairs from Read, then io.EOF.
type scriptedConn struct {
	net.Conn
	steps []readStep
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if len(c.steps) == 0 {
		return 0, io.EOF
	}

	s := c.steps[0]
	c.steps = c.steps[1:]
	return copy(p, s.data), s.err
}

// data returned together with an error must reach the caller before the error does
func TestBufferedConn_DataWithError(t *testing.T) {
	bc := NewBufConn(&scriptedConn{steps: []readStep{{"hello", io.EOF}}}, 64)
	b := make([]byte, 16)

	if n, err := bc.Peek(b); err != nil || string(b[:n]) != "hello" {
		t.Fatalf("Peek: got %q, %v", b[:n], err)
	}
	if n, err := bc.Read(b); err != nil || string(b[:n]) != "hello" {
		t.Fatalf("Read: got %q, %v", b[:n], err)
	}
	if n, err := bc.Read(b); err != io.EOF || n != 0 {
		t.Fatalf("Read after drain: got n=%d, %v; want 0, io.EOF", n, err)
	}
}

// a pending error is reported once, so a retry (e.g. after a deadline reset) reads again
func TestBufferedConn_PendingErrorReportedOnce(t *testing.T) {
	bc := NewBufConn(&scriptedConn{steps: []readStep{{"ab", os.ErrDeadlineExceeded}, {"cd", nil}}}, 64)
	b := make([]byte, 1)

	for i, want := range []string{"a", "b"} {
		if n, err := bc.Read(b); err != nil || string(b[:n]) != want {
			t.Fatalf("read %d: got %q, %v; want %q", i, b[:n], err, want)
		}
	}
	if _, err := bc.Read(b); err != os.ErrDeadlineExceeded {
		t.Fatalf("expected the pending deadline error, got %v", err)
	}
	if n, err := bc.Read(b); err != nil || string(b[:n]) != "c" {
		t.Fatalf("read after the error: got %q, %v; want %q", b[:n], err, "c")
	}
}
