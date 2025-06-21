package tlstap

type ProxyConfig struct {
	// mode of the proxy; acceptable values: plain, tls, detecttls (default)
	Mode string `json:"mode"`

	// log level; possible values: debug, info (default), warn, error
	LogLevel string `json:"loglevel"`

	// path to log file; if none given, log is written to stdout
	LogFile string `json:"logfile"`

	// intercpetors
	Interceptors []InterceptorConfig `json:"interceptors"`

	// configuration for the server part of the proxy
	Server ServerConfig `json:"server"`

	// configuration for the client part of the proxy
	Client ClientConfig `json:"client"`
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

type ServerConfig struct {
	// where the server should listen for incoming connections (e.g. 127.0.0.1:1234 or [::1]:1234)
	ListenEndpoint string `json:"listen"`

	// server certificate in PEM format
	// the PEM file can contain pa whole chain (leaf first, then intermediates up to and excluding the root)
	CertPem string `json:"cert-pem"`
	// key corresponding to the server certificate (only the leaf if whole chain is provided)
	CertKey string `json:"cert-key"`

	// the minimum and maximum TLS version the server will accept for incoming connections
	// see MinVersion/MaxVersion in https://pkg.go.dev/crypto/tls#Config
	TlsMin string `json:"tls-min"`
	TlsMax string `json:"tls-max"`

	// client authentication policy
	// possible values: none (or empty), request-cert, require-any, verify-if-given, require-and-verify
	// corresponds to https://pkg.go.dev/crypto/tls#ClientAuthType
	// if no value is provided, the default is NoClientCert
	ClientAuth string `json:"client-auth"`

	// path to file to which TLS pre-master secrets should be written (for the client <-> proxy connection)
	// see KeyLogWriter in https://pkg.go.dev/crypto/tls#Config
	KeyLogFile string `json:"key-logfile"`
}

type ClientConfig struct {
	// where clients should connect to (e.g. 127.0.0.1:1234 or [::1]:1234)
	ConnectEndpoint string `json:"connect"`

	// specifies whether clients should verify server certificates
	// if no value is provided, the default is false
	VerifyCert bool `json:"verify-cert"`

	// server name used for SNI and to verify the server name (if VerifyCert is true)
	// see ServerName in https://pkg.go.dev/crypto/tls#Config
	ServerName string `json:"server-name"`

	// ALPN strings
	// see NextProtos in https://pkg.go.dev/crypto/tls#Config
	ALPN []string `json:"alpn"`

	// the minimum and maximum TLS version clients will attempt to negotiate for incoming connections
	// see MinVersion/MaxVersion in https://pkg.go.dev/crypto/tls#Config
	TlsMin string `json:"tls-min"`
	TlsMax string `json:"tls-max"`

	CertPem string `json:"cert-pem"`
	CertKey string `json:"cert-key"`

	// path to file to which TLS pre-master secrets should be written (for the proxy <-> server connection)
	// see KeyLogWriter in https://pkg.go.dev/crypto/tls#Config
	KeyLogFile string `json:"key-logfile"`
}
