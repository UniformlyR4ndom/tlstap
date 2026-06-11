package drop

import (
	"net"

	"tlstap/logging"
	"tlstap/proxy"
)

// Drop connection on TLS upgrade.
// Might be useful to attempt TLS downgrades in DetectTls mode.
type DropTlsInterceptor struct {
	Logger *logging.Logger
}

func (i *DropTlsInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *DropTlsInterceptor) Finalize(addr net.TCPAddr) {}

func (i *DropTlsInterceptor) ConnectionEstablished(info *proxy.ConnInfo) error {
	return nil
}

func (i *DropTlsInterceptor) ConnectionUpgraded(info *proxy.ConnInfo) error {
	return proxy.ErrAbort
}

func (i *DropTlsInterceptor) ConnectionTerminated(info *proxy.ConnInfo) error {
	return nil
}

func (i *DropTlsInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	return data, nil
}
