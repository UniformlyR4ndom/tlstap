package tlstap

import (
	"net"
)

type NullInterceptor struct{}

func (i *NullInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *NullInterceptor) Finalize(addr net.TCPAddr) {}

func (i *NullInterceptor) ConnectionEstablished(info *ConnInfo) error {
	return nil
}

func (i *NullInterceptor) ConnectionTerminated(info *ConnInfo) error {
	return nil
}

func (i *NullInterceptor) Intercept(info *ConnInfo, data []byte) ([]byte, error) {
	return data, nil
}
