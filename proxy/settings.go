package tlstap

import "crypto/tls"

type ConnSettings struct {
	ConnectEndpoint string

	Mode Mode

	TlsClientConfig *tls.Config
	TlsServerConfig *tls.Config
}
