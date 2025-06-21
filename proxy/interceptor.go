package tlstap

import (
	"net"
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
	SrcEndpoint string
	DstEndpoint string
	ConnID      uint32
}

func NewConnInfo(srcEndpoint, dstEndpoing string, id uint32) ConnInfo {
	return ConnInfo{
		SrcEndpoint: srcEndpoint,
		DstEndpoint: dstEndpoing,
		ConnID:      id,
	}
}
