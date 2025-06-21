package interceptors

import (
	"net"

	proxy "tlstap/proxy"
)

// The NullInterceptor does nothing.
// It can serve as a base for other interceptors in which it can be embedded to avoid implementing
// methods that are not needed.
type NullInterceptor struct{}

func (i *NullInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *NullInterceptor) Finalize(addr net.TCPAddr) {}

func (i *NullInterceptor) ConnectionEstablished(info *proxy.ConnInfo) error {
	return nil
}

func (i *NullInterceptor) ConnectionTerminated(info *proxy.ConnInfo) error {
	return nil
}

func (i *NullInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	return data, nil
}
