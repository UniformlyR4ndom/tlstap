package tlstap

import (
	"net"

	"github.com/smallnest/ringbuffer"
)

type BufferedConn struct {
	net.Conn

	ReadBuf *ringbuffer.RingBuffer
	tmpBuf  []byte
}

func NewBufConn(conn net.Conn, bufSize int) *BufferedConn {
	return &BufferedConn{
		Conn:    conn,
		ReadBuf: ringbuffer.NewBuffer(make([]byte, bufSize)),
		tmpBuf:  make([]byte, bufSize),
	}
}

func (bc *BufferedConn) Read(b []byte) (int, error) {
	if bc.ReadBuf.Length() == 0 {
		if n, err := bc.fillBuf(); err != nil {
			return n, err
		}
	}

	return bc.ReadBuf.Read(b)
}

func (bc *BufferedConn) Peek(b []byte) (int, error) {
	if bc.ReadBuf.Length() == 0 {
		if n, err := bc.fillBuf(); err != nil {
			return n, err
		}
	}

	return bc.ReadBuf.Peek(b)
}

func (bc *BufferedConn) fillBuf() (int, error) {
	n, err := bc.Conn.Read(bc.tmpBuf)
	if err != nil {
		return 0, err
	}

	return bc.ReadBuf.Write(bc.tmpBuf[:n])
}
