package proxy

import (
	"encoding/binary"
	"net"
)

const tlsRecordHeaderLen = 5

// tlsRecordConn wraps the transport of a tls.Conn so that a single Read never returns bytes beyond the TLS
// record it started in. tls.Conn buffers everything it reads past the current record in a private buffer; without
// this, bytes following a close_notify (plaintext or a new ClientHello) may be lost once the TLS connection ends.
type tlsRecordConn struct {
	net.Conn

	hdr       [tlsRecordHeaderLen]byte
	hdrLen    int // bytes of the current record header seen so far
	remaining int // body bytes of the current record not yet returned
}

func (c *tlsRecordConn) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	if c.remaining > 0 {
		n, err := c.Conn.Read(buf[:min(len(buf), c.remaining)])
		c.remaining -= n
		return n, err
	}

	n, err := c.Conn.Read(buf[:min(len(buf), tlsRecordHeaderLen-c.hdrLen)])
	c.hdrLen += copy(c.hdr[c.hdrLen:], buf[:n])
	if c.hdrLen == tlsRecordHeaderLen {
		c.remaining = int(binary.BigEndian.Uint16(c.hdr[3:]))
		c.hdrLen = 0
	}

	return n, err
}
