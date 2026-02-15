package tlstap

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

type DetectionResult struct {
	StartIndex        int
	SupportedVersions []uint16
	ClientHello       []byte
}

// Determine wheter the message contained in the buffer is consistent with a TLS ClientHello.
// If so, the supported TLS versions are returned alongside the start index of the ClientHello
// candidate. Otherwise an empty slice is returned alongside -1.
// If thorough is set to true, the TLS extensions are paresed. Any non-standard extension present
// lead to the message being classified as not representing a TLS ClientHello.
// If search is set to true, the whole buffer is searched, otherwise the beginning of data must be
// consistent with a TLS ClientHello in order for it to be classified as such.
func DetectClientHello(data []byte, thorough, search bool) *DetectionResult {
	var tlsVersions []uint16
	chStart := 0
	if search {
		for i := 0; ; {
			idx := bytes.IndexByte(data[i:], 0x16)
			if idx < 0 {
				return nil
			}

			idx += i
			candidate := data[idx:]
			if tlsVersions = getTLSVersions(candidate, thorough); len(tlsVersions) > 0 {
				chStart = idx
				break
			}

			i = idx + 1
		}
	} else {
		tlsVersions = getTLSVersions(data, thorough)
		if len(tlsVersions) == 0 {
			return nil
		}
	}

	chLength := readUint16(data[chStart:], 3)
	result := DetectionResult{
		StartIndex:        chStart,
		SupportedVersions: tlsVersions,
		ClientHello:       append([]byte{}, data[chStart:chStart+int(chLength)]...),
	}

	return &result
}

func isValidTLSVersion(version uint16) bool {
	major, minor := uint8(version>>8), uint8(version)
	return (major == 2 && minor == 0) || (major == 3 && minor <= 4)
}

func getTLSVersions(data []byte, thorough bool) []uint16 {
	if !isPossibleClientHello(data) {
		return []uint16{}
	}

	clientHelloLen := readUint16(data, 3)
	if int(clientHelloLen+5) != len(data) {
		return []uint16{}
	}

	// parse and validate handshake header (data[5:9])
	handshakeHeaer := data[5:9]
	chLen := (uint32(handshakeHeaer[1]) << 16) | (uint32(handshakeHeaer[2]) << 8) | uint32(handshakeHeaer[3])
	if chLen+4 != uint32(clientHelloLen) {
		return []uint16{}
	}

	// parse client version (is already validated by isPossibleClientHello)
	clientVersion := readUint16(data, 9)
	// TLS1.2 and TLS1.3 have the same client version (0x03,0x03 -> TLS1.2+)
	sessIDLen, ok := tryReadUint8(data, 43)
	if !ok {
		return []uint16{}
	}

	o := 44 + int(sessIDLen)
	cipherSuitesLen, ok := tryReadUint16(data, o)
	if !ok {
		return []uint16{}
	}

	o += (2 + int(cipherSuitesLen)) // skip cipher suite description
	compressionLen, ok := tryReadUint8(data, o)
	if !ok {
		return []uint16{}
	}

	o += 1 + int(compressionLen)
	extLen, ok := tryReadUint16(data, o)
	if !ok {
		return []uint16{}
	}

	o += 2
	if o+int(extLen) > len(data) {
		return []uint16{}
	}

	extensionBuf := data[o : o+int(extLen)]
	versions, err := parseExtensions(extensionBuf, thorough)
	if err != nil {
		if clientVersion < tls.VersionTLS12 { // fallback for TLS versions before 1.2
			return []uint16{clientVersion}
		} else {
			return []uint16{}
		}
	} else {
		return versions
	}
}

// sieve out most random byte slices quickly
func isPossibleClientHello(data []byte) bool {
	// check magic bytes of record heade and handshake header
	if len(data) < 11 || data[0] != 0x16 || data[5] != 0x01 {
		return false
	}

	// check versions in record header and client version
	if !isValidTLSVersion(readUint16(data, 1)) || !isValidTLSVersion(readUint16(data, 9)) {
		return false
	}

	return true
}

// parse TLS extensions for more precise detection of ClientHello
func parseExtensions(extBuf []byte, strictValidation bool) ([]uint16, error) {
	supportedVersions := make([]uint16, 0)

	for o := 0; ; {
		if o+4 >= len(extBuf) {
			return supportedVersions, nil
		}

		extID := readUint16(extBuf, o)
		extLen := int(readUint16(extBuf, o+2))
		if strictValidation && !isValidTLSExtensionID(extID) {
			return []uint16{}, fmt.Errorf("invalid TLS externsion ID: %v", extID)
		}

		if extID == 0x002b { // supported version extension
			numBytes, ok := tryReadUint8(extBuf, o+4)
			if !ok {
				return []uint16{}, fmt.Errorf("length violation during parsing of TLS supported verions extension")
			}

			for i := 0; i < int(numBytes); i += 2 {
				version, ok := tryReadUint16(extBuf, o+5+i)
				if !ok {
					return []uint16{}, fmt.Errorf("length violation during parsing of TLS supported verions extension")
				}

				supportedVersions = append(supportedVersions, version)
			}
		}

		o += 4 + extLen // extension ID (2), extension length (2) and payload (extLen)
	}
}

func isValidTLSExtensionID(extensionID uint16) bool {
	return extensionID <= 61 || extensionID == 64768 || extensionID == 65037 || extensionID == 65281
}

func X509CertToString(cert *tls.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("cannot parse nil value")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Subject: %s\n", x509Cert.Subject))
	sb.WriteString(fmt.Sprintf("Issuer: %s\n", x509Cert.Issuer))
	sb.WriteString(fmt.Sprintf("Not Before: %s\n", x509Cert.NotBefore))
	sb.WriteString(fmt.Sprintf("Not After: %s\n", x509Cert.NotAfter))
	sb.WriteString(fmt.Sprintf("DNS Names: %v\n", x509Cert.DNSNames))
	sb.WriteString(fmt.Sprintf("IP Addresses: %v\n", x509Cert.IPAddresses))
	sb.WriteString(fmt.Sprintf("Serial Number: %s\n", x509Cert.SerialNumber))
	sb.WriteString(fmt.Sprintf("Public Key Algorithm: %s\n", x509Cert.PublicKeyAlgorithm))
	sb.WriteString(fmt.Sprintf("Signature Algorithm: %s\n", x509Cert.SignatureAlgorithm))

	return sb.String(), nil
}

func SummarizeTlsConn(tlsConn *tls.Conn) string {
	var sb strings.Builder

	state := tlsConn.ConnectionState()
	suite := tls.CipherSuiteName(state.CipherSuite)
	version := TLSVersionToString(state.Version)

	sb.WriteString(fmt.Sprintf("%s, %s", version, suite))
	var parts []string
	if state.ServerName != "" {
		parts = append(parts, fmt.Sprintf("Server: %s", state.ServerName))
	}

	if state.NegotiatedProtocol != "" {
		parts = append(parts, fmt.Sprintf("ALPN: %s", state.NegotiatedProtocol))
	}

	if len(parts) > 0 {
		sb.WriteString(fmt.Sprintf(", %s", strings.Join(parts, ", ")))
	}

	return sb.String()
}

func TLSVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unkown TLS Version: %v", version)
	}
}

func TlsVersionFromString(v string) (uint16, error) {
	vStr := strings.TrimSpace(strings.ToLower(v))
	switch vStr {
	case "1":
	case "10":
		fallthrough
	case "1.0":
		fallthrough
	case "tls1.0":
		return tls.VersionTLS10, nil
	case "11":
		fallthrough
	case "1.1":
		fallthrough
	case "tls1.1":
		return tls.VersionTLS11, nil
	case "12":
		fallthrough
	case "1.2":
		fallthrough
	case "tls1.2":
		return tls.VersionTLS12, nil
	case "13":
		fallthrough
	case "1.3":
		fallthrough
	case "tls1.3":
		return tls.VersionTLS10, nil
	}

	return 0, fmt.Errorf("invalid TLS version: %s", v)
}
