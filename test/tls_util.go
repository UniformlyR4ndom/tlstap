package test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func ParseServerConfig(config *TlsServerConfig) (*tls.Config, error) {
	if config.CertPem == "" || config.CertKey == "" {
		return nil, fmt.Errorf("path to certificate and key (both in PEM format) must be provided")
	}

	cert, err := tls.LoadX509KeyPair(config.CertPem, config.CertKey)
	if err != nil {
		return nil, err
	}

	var clientCAs *x509.CertPool = nil
	if config.ClientRoots != "" {
		if clientCAs, err = LoadCertPool(config.ClientRoots); err != nil {
			return nil, err
		}
	}

	clientAuthType, err := ParseClientAuthPoicy(config.ClientAuthPolicy)
	if err != nil {
		return nil, err
	}

	minVersion := uint16(tls.VersionTLS10)
	if config.MinVersion != "" {
		if v, err := ParseTlsVersion(config.MinVersion); err == nil {
			minVersion = v
		} else {
			return nil, err
		}
	}

	maxVersion := uint16(tls.VersionTLS13)
	if config.MaxVersion != "" {
		if v, err := ParseTlsVersion(config.MaxVersion); err == nil {
			maxVersion = v
		} else {
			return nil, err
		}
	}

	if minVersion > maxVersion {
		return nil, fmt.Errorf("minimal version (%d) cannot exceed maximum version (%d)", minVersion, maxVersion)
	}

	serverConf := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   clientAuthType,
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
	}

	return &serverConf, nil
}

func ParseClientConfig(config *TlsClientConfig) (*tls.Config, error) {
	var certificate *tls.Certificate = nil
	switch cert, key := config.CertPem, config.CertKey; {
	case cert != "" && key == "":
		return nil, fmt.Errorf("certificate needs key")
	case cert == "" && key != "":
		return nil, fmt.Errorf("stray certificate key: %s", key)
	case cert != "" && key != "":
		c, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}

		certificate = &c
	}

	var err error
	var roots *x509.CertPool = nil
	if config.Roots != "" {
		if roots, err = LoadCertPool(config.Roots); err != nil {
			return nil, err
		}
	}

	minVersion := uint16(tls.VersionTLS10)
	if config.MinVersion != "" {
		if v, err := ParseTlsVersion(config.MinVersion); err == nil {
			minVersion = v
		} else {
			return nil, err
		}
	}

	maxVersion := uint16(tls.VersionTLS13)
	if config.MaxVersion != "" {
		if v, err := ParseTlsVersion(config.MaxVersion); err == nil {
			maxVersion = v
		} else {
			return nil, err
		}
	}

	if minVersion > maxVersion {
		return nil, fmt.Errorf("minimal version (%d) cannot exceed maximum version (%d)", minVersion, maxVersion)
	}

	clientConf := tls.Config{
		RootCAs:            roots,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.SkipVerify,
	}

	if certificate != nil {
		clientConf.Certificates = []tls.Certificate{*certificate}
	}

	return &clientConf, nil
}

func LoadCertPool(pathList string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	paths := strings.Split(pathList, ",")
	for _, p := range paths {
		cleanPath := filepath.Clean(strings.TrimSpace(p))
		pemData, err := os.ReadFile(cleanPath)
		if err != nil {
			return nil, err
		}

		pool.AppendCertsFromPEM(pemData)
	}

	return pool, nil
}

func ParseClientAuthPoicy(policy string) (tls.ClientAuthType, error) {
	switch p := strings.TrimSpace(strings.ToLower(policy)); p {
	case "none":
		return tls.NoClientCert, nil
	case "request":
		return tls.RequestClientCert, nil
	case "require-any":
		return tls.RequireAnyClientCert, nil
	case "verify-if-given":
		return tls.VerifyClientCertIfGiven, nil
	case "require-and-verify":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return -1, fmt.Errorf("unknown client certificate validation policy")
	}
}

func ParseTlsVersion(versionStr string) (uint16, error) {
	v := strings.TrimSpace(strings.ToLower(versionStr))
	v = strings.TrimSpace(strings.TrimPrefix(v, "tls"))
	switch {
	case v == "1" || v == "1.0" || v == "10":
		return tls.VersionTLS10, nil
	case v == "1.1" || v == "11":
		return tls.VersionTLS11, nil
	case v == "1.2" || v == "12":
		return tls.VersionTLS12, nil
	case v == "1.3" || v == "13":
		return tls.VersionTLS13, nil
	}

	return 0, fmt.Errorf("unknown TLS version: %s", versionStr)
}

func CheckFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
