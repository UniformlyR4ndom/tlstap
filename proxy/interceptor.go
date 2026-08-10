package proxy

import (
	"errors"
	"net"
	"tlstap/assert"
)

// tell handler to drop the connection (e.g. to attmept TLS downgrade)
var ErrAbort = errors.New("drop connection")

type Interceptor interface {

	// called before the first connection is handled by the interceptor
	Init(addr net.TCPAddr) error

	// called once during shutdown
	Finalize(addr net.TCPAddr)

	// called once for each conneciton established
	ConnectionEstablished(info *ConnInfo) error

	// called when a connection is upgraded to TLS
	ConnectionUpgraded(info *ConnInfo) error

	// called once for each connection after it is terminated
	ConnectionTerminated(info *ConnInfo) error

	// Intercept the data sent via a proxy.
	// info:    info about the connection
	// data:    the data that is sent
	// return:  the data to be sent on to the next interceptor or upstream
	//          if empty, noting will be sent
	Intercept(info *ConnInfo, data []byte) ([]byte, error)
}

type ConnInfo struct {
	SrcIP   net.IP
	SrcPort uint16

	DstIP   net.IP
	DstPort uint16

	SrcEndpoint string
	DstEndpoint string
	ConnID      uint32

	// TLS is the downstream (client-facing) connection's negotiated TLS state — nil for
	// a plain connection, or a TLS one that hasn't (yet, or ever) completed its
	// downstream handshake at the point this ConnInfo was built. Always the downstream
	// side specifically, for both directions' ConnInfo alike, even though the proxy also
	// holds a second, independent TLS session upstream (which can legitimately differ,
	// e.g. without ALPN/SNI passthrough) — see tlsInfoFromConn (tls.go).
	TLS *TLSInfo
}

// TLSInfo is the subset of tls.ConnectionState an interceptor might find useful —
// e.g. distinguishing HTTP/1.1 from h2 via ALPN. CipherSuite is the raw ID; a script
// wanting the name looks it up itself.
type TLSInfo struct {
	SNI         string
	ALPN        string
	Version     uint16
	CipherSuite uint16
}

func NewConnInfo(lAddr, rAddr net.Addr, id uint32, tlsInfo *TLSInfo) ConnInfo {
	lTcpAddr, ok := lAddr.(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected type: %T. This is a bug.", lAddr)

	rTcpAddr, ok := rAddr.(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected type: %T. This is a bug.", rAddr)

	return ConnInfo{
		SrcIP:       lTcpAddr.IP,
		SrcPort:     uint16(lTcpAddr.Port),
		SrcEndpoint: lTcpAddr.String(),
		DstIP:       rTcpAddr.IP,
		DstPort:     uint16(rTcpAddr.Port),
		DstEndpoint: rTcpAddr.String(),
		ConnID:      id,
		TLS:         tlsInfo,
	}
}
