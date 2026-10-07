package proxy

import (
	"net"

	"github.com/smallnest/ringbuffer"

	"tlstap/assert"
)

type BufferedConn struct {
	net.Conn

	ReadBuf *ringbuffer.RingBuffer
	tmpBuf  []byte

	// error returned by the underlying Read together with data; reported once ReadBuf is drained
	pendingErr error
}

func NewBufConn(conn net.Conn, bufSize int) *BufferedConn {
	return &BufferedConn{
		Conn:    conn,
		ReadBuf: ringbuffer.NewBuffer(make([]byte, bufSize)),
		tmpBuf:  make([]byte, bufSize),
	}
}

func (bc *BufferedConn) Read(b []byte) (int, error) {
	if err := bc.fillBuf(); err != nil {
		return 0, err
	}

	return bc.ReadBuf.Read(b)
}

func (bc *BufferedConn) Peek(b []byte) (int, error) {
	if err := bc.fillBuf(); err != nil {
		return 0, err
	}

	return bc.ReadBuf.Peek(b)
}

// fillBuf refills ReadBuf if it is empty. A returned error means nothing is buffered.
func (bc *BufferedConn) fillBuf() error {
	if bc.ReadBuf.Length() > 0 {
		return nil
	}

	if err := bc.pendingErr; err != nil {
		bc.pendingErr = nil // reported once, so a retry (e.g. after a deadline reset) reads again
		return err
	}

	n, err := bc.Conn.Read(bc.tmpBuf)
	if n > 0 {
		_, werr := bc.ReadBuf.Write(bc.tmpBuf[:n])
		assert.Assertf(werr == nil, "Failed to buffer %d bytes into an empty buffer: %v. This is a bug.", n, werr)
		bc.pendingErr = err
		return nil
	}

	return err
}
