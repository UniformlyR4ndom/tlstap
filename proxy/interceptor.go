package tlstap

import (
	"net"
	"tlstap/assert"
)

type Interceptor interface {

	// called before the first connection is handled by the interceptor
	Init(addr net.TCPAddr) error

	// called once during shutdown
	Finalize(addr net.TCPAddr)

	// called once for each conneciton established
	ConnectionEstablished(info *ConnInfo) error

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
	SrcIp   net.IP
	SrcPort uint16

	DstIp   net.IP
	DstPort uint16

	SrcEndpoint string
	DstEndpoint string
	ConnID      uint32
}

func NewConnInfo(lAddr, rAddr net.Addr, id uint32) ConnInfo {
	lTcpAddr, ok := lAddr.(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected type: %T. This is a bug.", lAddr)

	rTcpAddr, ok := rAddr.(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected type: %T. This is a bug.", rAddr)

	return ConnInfo{
		SrcIp:       lTcpAddr.IP,
		SrcPort:     uint16(lTcpAddr.Port),
		SrcEndpoint: lTcpAddr.String(),
		DstIp:       rTcpAddr.IP,
		DstPort:     uint16(rTcpAddr.Port),
		DstEndpoint: rTcpAddr.String(),
		ConnID:      id,
	}
}
