package intercept

import (
	"net"

	"tlstap/logging"
	tlstap "tlstap/proxy"
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

func (i *DropTlsInterceptor) ConnectionEstablished(info *tlstap.ConnInfo) error {
	return nil
}

func (i *DropTlsInterceptor) ConnectionUpgraded(info *tlstap.ConnInfo) error {
	return tlstap.ErrAbort
}

func (i *DropTlsInterceptor) ConnectionTerminated(info *tlstap.ConnInfo) error {
	return nil
}

func (i *DropTlsInterceptor) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	return data, nil
}
