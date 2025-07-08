package tlstap

type ProxyConfig struct {
	// where the server should listen for incoming connections (e.g. 127.0.0.1:1234 or [::1]:1234)
	ListenEndpoint string `json:"listen"`

	// where clients should connect to (e.g. 127.0.0.1:1234 or [::1]:1234)
	ConnectEndpoint string `json:"connect"`

	// mode of the proxy; acceptable values: plain, tls, detecttls (default)
	Mode string `json:"mode"`

	// log level; possible values: debug, info (default), warn, error
	LogLevel string `json:"loglevel"`

	// path to log file; if none given, log is written to stdout
	LogFile string `json:"logfile"`

	// intercpetors
	Interceptors []InterceptorConfig `json:"interceptors"`

	// configuration for the server part of the proxy
	Server TlsServerConfig `json:"server"`

	// configuration for the client part of the proxy
	Client TlsClientConfig `json:"client"`
}

type InterceptorConfig struct {
	// name of the interceptor
	Name string `json:"name"`

	// disable the interceptor
	Disable bool `json:"disable"`

	// direction in whicht the interceptor is active
	// possible values: up, down, both (default)
	Direction string `json:"direction"`

	// aruments to pass to custom interceptors
	Args map[string]any `json:"args"`

	// same as InterceptorArgs but the bytes representing the JSON string
	// useful to pass to json.Unmarshal directly to recover custom structs
	ArgsJson []byte `json:"args-json"`
}

type TlsServerConfig struct {
	// Path to server certificate (or chain) and key.
	// Server certificate is required.
	CertPem string `json:"cert-pem"`
	CertKey string `json:"cert-key"`

	// Comma-serparated list of paths to PEM files that.
	// constitute the pool of trust roots for verifying client certificates.
	ClientRoots string `json:"client-roots"`

	// The client authentication policy.
	// Available values: none (default), request, require-any, verify-if-given, require-and-verify.
	// Correspond to the appropriate values of https://pkg.go.dev/crypto/tls#ClientAuthType
	ClientAuthPolicy string `json:"client-auth"`

	// Minimum and maximums TLS version that will be negotiated.
	MinVersion string `json:"min-version"`
	MaxVersion string `json:"max-version"`

	// Path to file to which TLS pre-master secrets should be written (for the client <-> proxy connection).
	// See KeyLogWriter in https://pkg.go.dev/crypto/tls#Config
	KeyLogFile string `json:"keylog"`

	// Whether the key log file should be truncated upon start.
	KeyLogTruncate bool `json:"truncate-keylog"`
}

type TlsClientConfig struct {
	// Path to client certificate (or chain) and key.
	// If none is given, no client authentiation is available.
	CertPem string `json:"cert-pem"`
	CertKey string `json:"cert-key"`

	// Comma-serparated list of paths to PEM files that
	// constitute the trust roots.
	// If none are given, the system trust store is used.
	// See RootCAs in https://pkg.go.dev/crypto/tls#Config
	Roots string `json:"roots"`

	// Server name (SNI)
	// See ServerName in https://pkg.go.dev/crypto/tls#Config
	ServerName string `json:"server-name"`

	// ALPN strings
	// See NextProtos in https://pkg.go.dev/crypto/tls#Config
	ALPN []string `json:"alpn"`

	// Do not verify the server certificate
	SkipVerify bool `json:"skip-verify"`

	// Minimum and maximums TLS version that will be negotiated.
	MinVersion string `json:"min-version"`
	MaxVersion string `json:"max-version"`

	// Path to file to which TLS pre-master secrets should be written (for the client <-> proxy connection).
	// See KeyLogWriter in https://pkg.go.dev/crypto/tls#Config
	KeyLogFile string `json:"keylog"`

	// Whether the key log file should be truncated upon start
	KeyLogTruncate bool `json:"truncate-keylog"`
}
