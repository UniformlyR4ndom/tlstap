package test

type TlsServerConfig struct {
	// Path to server certificate (or chain) and key.
	// Server certificate is required.
	CertPem string `json:"cert-pem"`
	CertKey string `json:"cert-key"`

	// Comma-serparated list of paths to PEM files that
	// constitute the pool of trust roots for verifying client certificates
	ClientRoots string `json:"client-roots"`

	// The client authentication policy.
	// Available values: none (default), request, require-any, verify-if-given, require-and-verify
	// Correspond to the appropriate values of https://pkg.go.dev/crypto/tls#ClientAuthType
	ClientAuthPolicy string `json:"client-auth"`

	// Minimum and maximums TLS version that will be negotiated
	MinVersion string `json:"min-version"`
	MaxVersion string `json:"max-version"`
}

type TlsClientConfig struct {
	// Path to client certificate (or chain) and key.
	// If none is given, no client authentiation is available.
	CertPem string `json:"cert-pem"`
	CertKey string `json:"cert-key"`

	// Comma-serparated list of paths to PEM files that
	// constitute the trust roots.
	// If none are given, the system trust store is used.
	Roots string `json:"roots"`

	// Server name (SNI)
	ServerName string `json:"server-name"`

	// Do not verify the server certificate
	SkipVerify bool `json:"skip-verify"`

	// Minimum and maximums TLS version that will be negotiated
	MinVersion string `json:"min-version"`
	MaxVersion string `json:"max-version"`
}
