package interceptors

import (
	"net"

	tlstap "tlstap/proxy"
)

// The NullInterceptor does nothing.
// It can serve as a base for other interceptors in which it can be embedded to avoid implementing
// methods that are not needed.
type NullInterceptor struct{}

func (i *NullInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *NullInterceptor) Finalize(addr net.TCPAddr) {}

func (i *NullInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	return nil
}

func (i *NullInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	return nil
}

func (i *NullInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	return data, nil
}
