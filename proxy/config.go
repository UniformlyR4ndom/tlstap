package tlstap

import "regexp"

type ConfigFile struct {
	// The available proxy configurations.
	Proxies map[string]ProxyConfig `json:"proxies"`

	// The available TLS server configurations.
	TlsServerConfigs map[string]TlsServerConfig `json:"tls-server-configs"`

	// The available TLS server configurations.
	TlsClientConfigs map[string]TlsClientConfig `json:"tls-client-configs"`

	// The available interceptors.
	Interceptors map[string]InterceptorConfig `json:"interceptors"`
}

type ProxyConfig struct {
	// Where the server should listen for incoming connections (e.g. 127.0.0.1:1234 or [::1]:1234).
	ListenEndpoint string `json:"listen"`

	// Where clients should connect to (e.g. 127.0.0.1:1234 or [::1]:1234).
	ConnectEndpoint string `json:"connect"`

	// Mode of the proxy; acceptable values: plain, tls, detecttls (default), mux.
	// In mux mode, TLS multiplexing is available but mode for all TLS proxies
	// of the multiplexer is fixed to 'tls'.
	Mode string `json:"mode"`

	// Log level; possible values: debug, info (default), warn, error.
	LogLevel string `json:"loglevel"`

	// Whether to include timestamps in the log.
	LogTime bool `json:"logtime"`

	// Path to log file; if none given, log is written to stdout.
	LogFile string `json:"logfile"`

	// Configuration for the server part of the proxy.
	ServerRef string `json:"server"`

	// Configuration for the client part of the proxy.
	ClientRef string `json:"client"`

	// References to interceptors to use
	InterceptorRefs []string `json:"interceptors"`

	// TLS multiplexer (only available in mode 'mux').
	// Depending on the SNI information different TLS configurations can be used
	// and traffic can be forwarded to different upstream targets.
	Mux map[string]MuxHandler `json:"mux"`
}

type InterceptorConfig struct {
	// Name of the interceptor.
	Name string `json:"name"`

	// Disable the interceptor.
	Disable bool `json:"disable"`

	// Direction in which the interceptor is active.
	// Avaliable options: up, down, both (default).
	Direction string `json:"direction"`

	// Aruments to pass to custom interceptors.
	Args map[string]any `json:"args"`

	// Same as InterceptorArgs but the bytes representing the JSON string.
	// Useful to pass to json.Unmarshal directly to recover custom structs
	// do not set directly, instead use Args option.
	ArgsJson []byte `json:"args-json"`
}

type TlsServerConfig struct {
	// Path to server certificate (or chain) and key.
	// A server certificate is always required.
	CertPem string `json:"cert-pem"`
	CertKey string `json:"cert-key"`

	// Comma-serparated list of paths to PEM files that.
	// Constitutes the pool of trust roots for verifying client certificates.
	ClientRoots string `json:"client-roots"`

	// The client authentication policy.
	// Available values: none (default), request, require-any, verify-if-given, require-and-verify.
	// Correspond to the appropriate values of https://pkg.go.dev/crypto/tls#ClientAuthType
	ClientAuthPolicy string `json:"client-auth"`

	// Minimum and maximums TLS version that will be negotiated.
	MinVersion string `json:"min-version"`
	MaxVersion string `json:"max-version"`

	// List of acceptable next protocols.
	// The server will select the first mutually acceptable protocol (i.e. the first
	// protocol in the server ALPN list that is also offered by the client; if any).
	ALPN []string `json:"alpn"`

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

	// Comma-serparated list of paths to PEM files that constitute the trust roots.
	// If none are given, the system trust store is used.
	// See RootCAs in https://pkg.go.dev/crypto/tls#Config
	Roots string `json:"roots"`

	// Do not verify the server certificate.
	SkipVerify bool `json:"skip-verify"`

	// Minimum and maximums TLS version that will be negotiated.
	MinVersion string `json:"min-version"`
	MaxVersion string `json:"max-version"`

	// Server name (SNI).
	// See ServerName in https://pkg.go.dev/crypto/tls#Config
	ServerName string `json:"server-name"`

	// If no server name is given, pass the server name provided by the client (if any).
	SniPassthroug bool `json:"sni-passthrough"`

	// Next protocol (ALPN) values.
	// Overrides ALPN passthrough behavior.
	// See NextProtos in https://pkg.go.dev/crypto/tls#Config
	ALPN []string `json:"alpn"`

	// If no ALPN values are given, pass the application protocol selected by the (tlstap) server
	// on to the upstream server.
	// Note that at most one ALPN value is passed instead of all protocols offered by the client.
	// Use the (server-side) ALPN option to configure the order of preferred application protocols.
	ALPNPassthrough bool `json:"alpn-passthrough"`

	// Cipher suites to offer.
	// See https://pkg.go.dev/crypto/tls#CipherSuites for supported cipher suites and corresponding names.
	CipherSuitesOverride []string `json:"ciphersuites-override"`

	// Path to file to which TLS pre-master secrets should be written (for the client <-> proxy connection).
	// See KeyLogWriter in https://pkg.go.dev/crypto/tls#Config
	KeyLogFile string `json:"keylog"`

	// Whether the key log file should be truncated upon start (don't use when sharing keylog file between multiple instances).
	KeyLogTruncate bool `json:"truncate-keylog"`
}

type MuxHandler struct {
	// Match patterns.
	// When the encountered server name matches one of these patterns, this handler is used.
	Matchers []string `json:"sni-matches"`

	// Where clients should connect to.
	ConnectEndpoint string `json:"connect"`

	// Reference to TLS server config.
	ServerRef string `json:"server"`

	// Reference to TLS client config.
	ClientRef string `json:"client"`

	// References to interceptors.
	InterceptorRefs []string `json:"interceptors"`

	// Log level; possible values: debug, info (default), warn, error.
	// Overwrites LogLevel option of containing proxy configuration.
	LogLevel string `json:"loglevel"`

	// Path to log file; if none given, log is written to stdout.
	// Overwrites LogFile option of containing proxy configuration.
	LogFile string `json:"logfile"`
}

type ResolvedProxyConfig struct {
	ListenEndpoint  string
	ConnectEndpoint *string
	Mode            string

	LogLevel string
	LogTime  bool
	LogFile  string

	Interceptors []InterceptorConfig
	Server       *TlsServerConfig
	Client       *TlsClientConfig

	Name string
}

type ResolvedMuxHandler struct {
	Name            string
	ConnectEndpoint string
	Matchers        []*regexp.Regexp

	LogLevel string
	LogTime  bool
	LogFile  string

	Interceptors []InterceptorConfig
	Server       *TlsServerConfig
	Client       *TlsClientConfig
}
