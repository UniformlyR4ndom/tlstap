package tlstap

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"strings"
	"tlstap/logging"
)

type Handler struct {
	Name     string
	Patterns []*regexp.Regexp
	Connect  string

	InterceptorsDown []Interceptor
	InterceptorsUp   []Interceptor
	InterceptorAll   []Interceptor
	ClientConfig     *tls.Config
	ServerConfig     *tls.Config
	ServerNextProtos []string

	Logger *logging.Logger
}

func (h *Handler) MatchesSni(sni string) bool {
	for _, p := range h.Patterns {
		if p.Match([]byte(sni)) {
			return true
		}
	}

	return false
}

func (h *Handler) getClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	h.Logger.Debug("Received Certificate Request:\n%s", certRequestInfoToString(info, "  "))
	var cert *tls.Certificate
	if h.ClientConfig != nil && len(h.ClientConfig.Certificates) > 0 {
		cert = &h.ClientConfig.Certificates[0]
		chain := []tls.Certificate{*cert}
		h.Logger.Debug("Using client certificate:\n%s", chainToString(chain, "  "))
	} else {
		h.Logger.Error("No client certificate provided")
	}

	return cert, nil
}

type Mux struct {
	handlers []Handler
	proxy    *Proxy
}

func NewMux(handlers []Handler) *Mux {
	var mHandlers []Handler
	for _, h := range handlers {
		mHandlers = append(mHandlers, h)
	}

	return &Mux{handlers: mHandlers}
}

func (m *Mux) SetProxy(p *Proxy) {
	m.proxy = p
}

func (m *Mux) GetMatch(serverName string) (*Handler, error) {
	var matches []Handler
	for _, e := range m.handlers {
		if e.MatchesSni(serverName) {
			matches = append(matches, e)
		}
	}

	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		return &matches[0], nil
	default:
		matchNames := make([]string, len(matches))
		for i, m := range matches {
			matchNames[i] = m.Name
		}
		return nil, fmt.Errorf("mulitiple matches for server name %s: %s", serverName, strings.Join(matchNames, ", "))
	}
}

func (m *Mux) getServerConfig(info *tls.ClientHelloInfo) (*tls.Config, error) {
	h, err := m.GetMatch(info.ServerName)
	serverConfig := h.ServerConfig
	serverNextProtos := h.ServerNextProtos
	logger := h.Logger
	switch {
	case err != nil:
		return nil, err
	case h == nil:
		serverConfig = m.proxy.serverConfig
		serverNextProtos = m.proxy.serverNextProtos
		logger = &m.proxy.logger
	}

	logger.Debug("Received Client Hello:\n%s", clientHelloInfoToString(info, "  "))
	if selectedNextProto, ok := selectNextProto(info, serverNextProtos, logger); ok {
		logger.Debug("Selected application protocol: %s", selectedNextProto)
		config := serverConfig.Clone()
		config.NextProtos = []string{selectedNextProto}
		return config, nil
	}

	return serverConfig, nil
}
