package tlstap

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"tlstap/assert"
	"tlstap/logging"
)

var extKeyUsageMap = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "anyExtendedKeyUsage",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "msSGC",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "nsSGC",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "msCodeCom",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "msKernelCode",
}

var cipherSuiteMap = genCipherSuiteMap()

func ParseServerConfig(config *TlsServerConfig) (*tls.Config, []string, error) {
	if config.CertPem == "" || config.CertKey == "" {
		return nil, nil, fmt.Errorf("path to certificate and key (both in PEM format) must be provided")
	}

	cert, err := tls.LoadX509KeyPair(config.CertPem, config.CertKey)
	if err != nil {
		return nil, nil, err
	}

	var clientCAs *x509.CertPool = nil
	if config.ClientRoots != "" {
		if clientCAs, err = LoadCertPool(config.ClientRoots); err != nil {
			return nil, nil, err
		}
	}

	clientAuthType := tls.NoClientCert
	if config.ClientAuthPolicy != "" {
		if clientAuthType, err = ParseClientAuthPolicy(config.ClientAuthPolicy); err != nil {
			return nil, nil, err
		}
	}

	minVersion := uint16(tls.VersionTLS10)
	if config.MinVersion != "" {
		if v, err := ParseTlsVersion(config.MinVersion); err == nil {
			minVersion = v
		} else {
			return nil, nil, err
		}
	}

	maxVersion := uint16(tls.VersionTLS13)
	if config.MaxVersion != "" {
		if v, err := ParseTlsVersion(config.MaxVersion); err == nil {
			maxVersion = v
		} else {
			return nil, nil, err
		}
	}

	if minVersion > maxVersion {
		return nil, nil, fmt.Errorf("minimum version (%d) cannot exceed maximum version (%d)", minVersion, maxVersion)
	}

	var keylogWriter io.WriteCloser = nil
	if config.KeyLogFile != "" {
		keylogWriter, err = OpenKelogWriter(config.KeyLogFile, config.KeyLogTruncate)
		if err != nil {
			return nil, nil, err
		}
	}

	serverConf := tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clientCAs,
		ClientAuth:   clientAuthType,
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		KeyLogWriter: keylogWriter,
	}

	return &serverConf, config.ALPN, nil
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
		return nil, fmt.Errorf("minimum version (%d) cannot exceed maximum version (%d)", minVersion, maxVersion)
	}

	var keylogWriter io.WriteCloser = nil
	if config.KeyLogFile != "" {
		keylogWriter, err = OpenKelogWriter(config.KeyLogFile, config.KeyLogTruncate)
		if err != nil {
			return nil, err
		}
	}

	clientConf := tls.Config{
		RootCAs:            roots,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		ServerName:         config.ServerName,
		NextProtos:         config.ALPN,
		InsecureSkipVerify: config.SkipVerify,
		KeyLogWriter:       keylogWriter,
	}

	if len(config.CipherSuitesOverride) > 0 {
		var cipherSuites []uint16
		for _, cs := range config.CipherSuitesOverride {
			id, err := cipherSuiteNameToId(cs)
			if err != nil {
				return nil, err
			}

			cipherSuites = append(cipherSuites, id)
		}

		clientConf.CipherSuites = cipherSuites
	}

	if certificate != nil {
		clientConf.Certificates = []tls.Certificate{*certificate}
	}

	return &clientConf, nil
}

func OpenKelogWriter(path string, truncate bool) (io.WriteCloser, error) {
	mode := os.O_APPEND
	if truncate {
		mode = os.O_TRUNC
	}

	return os.OpenFile(path, mode|os.O_CREATE|os.O_RDWR, 0600)
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

func ParseClientAuthPolicy(policy string) (tls.ClientAuthType, error) {
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

func getModifiedConfig(config *tls.Config, defaultServerName string, defaultAlpn []string) *tls.Config {
	overrideSni := config.ServerName == "" && defaultServerName != ""
	overrideAlpn := len(config.NextProtos) == 0 && len(defaultAlpn) > 0
	if !(overrideSni || overrideAlpn) {
		return config
	}

	c := config.Clone()
	if overrideSni {
		c.ServerName = defaultServerName
	}

	if overrideAlpn {
		c.NextProtos = defaultAlpn
	}

	return c
}

func tryReadUint8(data []byte, offset int) (uint8, bool) {
	if offset+1 <= len(data) {
		return uint8(data[offset]), true
	}

	return 0, false
}

func tryReadUint16(data []byte, offset int) (uint16, bool) {
	if offset+2 <= len(data) {
		return binary.BigEndian.Uint16(data[offset : offset+2]), true
	}

	return 0, false
}

func readUint16(data []byte, offset int) uint16 {
	return binary.BigEndian.Uint16(data[offset : offset+2])
}

// find the first element of supported that is contained in the offered strings
func getFirstMatch(offered, supported []string) (string, bool) {
	for _, s := range supported {
		if slices.Contains(offered, s) {
			return s, true
		}
	}

	return "", false
}

func selectNextProto(info *tls.ClientHelloInfo, acceptableProtos []string, logger *logging.Logger) (string, bool) {
	if len(info.SupportedProtos) == 0 {
		return "", false
	}

	offered := info.SupportedProtos
	offeredStr := strings.Join(offered, ", ")
	if len(acceptableProtos) == 0 {
		logger.Warn("Client offered next protocols [%s] but server does not support ALPN", offeredStr)
		return "", false
	}

	selectedProto, ok := getFirstMatch(info.SupportedProtos, acceptableProtos)
	if !ok {
		supportedStr := strings.Join(acceptableProtos, ", ")
		logger.Warn("No mutual next protocol (ALPN): client offered [%s], server accepts [%s]", offeredStr, supportedStr)
		return "", false
	}

	return selectedProto, true
}

func certToString(cert *x509.Certificate, indent string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%sSubject: %s\n", indent, cert.Subject))
	sb.WriteString(fmt.Sprintf("%sIssuer: %s\n", indent, cert.Issuer))
	sb.WriteString(fmt.Sprintf("%sDNS names: %v\n", indent, strings.Join(cert.DNSNames, ", ")))
	sb.WriteString(fmt.Sprintf("%sValidity: %v - %v\n", indent, cert.NotBefore, cert.NotAfter))

	keyUsages := decodeKeyUsage(cert.KeyUsage)

	var extKeyUsages []string
	for _, e := range cert.ExtKeyUsage {
		eku, ok := extKeyUsageMap[e]
		if !ok {
			eku = fmt.Sprintf("? (%v)", eku)
		}

		extKeyUsages = append(extKeyUsages, eku)
	}

	kus := "none"
	if len(keyUsages) > 0 {
		kus = strings.Join(keyUsages, ", ")
	}

	ekus := "none"
	if len(extKeyUsages) > 0 {
		ekus = strings.Join(extKeyUsages, ", ")
	}

	sb.WriteString(fmt.Sprintf("%sKey usages: %s (extended: %s)\n", indent, kus, ekus))
	sb.WriteString(fmt.Sprintf("%sSerial: %v\n", indent, cert.SerialNumber))

	fingerprint := sha256.Sum256(cert.Raw)
	sb.WriteString(fmt.Sprintf("%sFingerprint (SHA256): %s", indent, hex.EncodeToString(fingerprint[:])))
	return sb.String()
}

func chainToStringX509(certs []*x509.Certificate, indent string) string {
	if len(certs) == 0 {
		return "none"
	}

	var sb strings.Builder
	for i, c := range certs {
		sb.WriteString(fmt.Sprintf("Certificate %d:\n%s\n", i, certToString(c, indent)))
	}

	return sb.String()
}

func chainToString(certs []tls.Certificate, indent string) string {
	if len(certs) == 0 {
		return "none"
	}

	var sb strings.Builder
	for i, certPair := range certs {
		cert, err := x509.ParseCertificate(certPair.Certificate[0])
		assert.Assertf(err == nil, "Unexpected error parsing certificate: %v", err)

		sb.WriteString(fmt.Sprintf("Certificate %d:\n%s", i, certToString(cert, indent)))
	}

	return sb.String()
}

func clientHelloInfoToString(info *tls.ClientHelloInfo, indent string) string {
	var sb strings.Builder

	var sniInfo = indent + "No server name (SNI) present\n"
	if info.ServerName != "" {
		sniInfo = fmt.Sprintf("%sServer name (SNI): %s\n", indent, info.ServerName)
	}
	sb.WriteString(sniInfo)

	var alpnInfo = indent + "No supported protocols (ALPN) present\n"
	if len(info.SupportedProtos) > 0 {
		alpnInfo = fmt.Sprintf("%s%d Supported protocols (ALPN): %s\n", indent, len(info.SupportedProtos), strings.Join(info.SupportedProtos, ", "))
	}
	sb.WriteString(alpnInfo)

	var versions []string
	for _, v := range info.SupportedVersions {
		versions = append(versions, tls.VersionName(v))
	}
	sb.WriteString(fmt.Sprintf("%s%d supported versions: %s\n", indent, len(versions), strings.Join(versions, ", ")))

	var ciphersuites []string
	for _, cs := range info.CipherSuites {
		ciphersuites = append(ciphersuites, translateCipherSuite(cs))
	}
	sb.WriteString(fmt.Sprintf("%s%d supported cipher suites: %s", indent, len(ciphersuites), strings.Join(ciphersuites, ", ")))

	return sb.String()
}

func translateCipherSuite(code uint16) string {
	name := tls.CipherSuiteName(code)
	if strings.HasPrefix(name, "0x") {
		name = fmt.Sprintf("? (%s)", name)
	}

	return name
}

func certRequestInfoToString(info *tls.CertificateRequestInfo, indent string) string {
	var cas []string
	for i, ca := range info.AcceptableCAs {
		caStr, err := decodeAsn1Value(ca)
		if err == nil {
			cas = append(cas, fmt.Sprintf("%s%d: %s", indent, i, caStr))
		} else {
			cas = append(cas, fmt.Sprintf("%s%d: name parsing failed; raw (hex): %s", indent, i, hex.EncodeToString(ca)))
		}
	}

	return strings.Join(cas, "\n")
}

func decodeKeyUsage(ku x509.KeyUsage) []string {
	var kus []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		kus = append(kus, "digitalSignature")
	}

	if ku&x509.KeyUsageContentCommitment != 0 {
		kus = append(kus, "contentCommitment")
	}

	if ku&x509.KeyUsageKeyEncipherment != 0 {
		kus = append(kus, "keyEncipherment")
	}

	if ku&x509.KeyUsageDataEncipherment != 0 {
		kus = append(kus, "dataEncipherment")
	}

	if ku&x509.KeyUsageKeyAgreement != 0 {
		kus = append(kus, "keyAgreement")
	}

	if ku&x509.KeyUsageCertSign != 0 {
		kus = append(kus, "keyCertSign")
	}

	if ku&x509.KeyUsageCRLSign != 0 {
		kus = append(kus, "cRLSign")
	}

	if ku&x509.KeyUsageEncipherOnly != 0 {
		kus = append(kus, "encipherOnly")
	}

	if ku&x509.KeyUsageDecipherOnly != 0 {
		kus = append(kus, "decipherOnly")
	}

	return kus
}

func genExtKeyUsageMap() map[x509.ExtKeyUsage]string {
	m := make(map[x509.ExtKeyUsage]string)
	m[x509.ExtKeyUsageAny] = "anyExtendedKeyUsage"
	m[x509.ExtKeyUsageServerAuth] = "serverAuth"
	m[x509.ExtKeyUsageClientAuth] = "clientAuth"
	m[x509.ExtKeyUsageCodeSigning] = "codeSigning"
	m[x509.ExtKeyUsageEmailProtection] = "emailProtection"
	m[x509.ExtKeyUsageIPSECEndSystem] = "ipsecEndSystem"
	m[x509.ExtKeyUsageIPSECTunnel] = "ipsecTunnel"
	m[x509.ExtKeyUsageIPSECUser] = "ipsecUser"
	m[x509.ExtKeyUsageTimeStamping] = "timeStamping"
	m[x509.ExtKeyUsageOCSPSigning] = "OCSPSigning"
	m[x509.ExtKeyUsageMicrosoftServerGatedCrypto] = "msSGC"
	m[x509.ExtKeyUsageNetscapeServerGatedCrypto] = "nsSGC"
	m[x509.ExtKeyUsageMicrosoftCommercialCodeSigning] = "msCodeCom"
	m[x509.ExtKeyUsageMicrosoftKernelCodeSigning] = "msKernelCode"
	return m
}

func genCipherSuiteMap() map[string]uint16 {
	m := make(map[string]uint16)
	for _, c := range tls.CipherSuites() {
		name := strings.ToLower(c.Name)
		m[name] = c.ID
	}

	return m
}

func cipherSuiteNameToId(name string) (uint16, error) {
	cleanName := strings.TrimSpace(strings.ToLower(name))
	if id, ok := cipherSuiteMap[cleanName]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("unknown cipher suite: %s", name)
}
