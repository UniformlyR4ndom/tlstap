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

	ALPNPreference []string
	ALPNProbe      bool

	Logger *logging.Logger

	Prober Prober
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
		h.Logger.Error("No client certificate configured")
	}

	var err error
	if cert == nil {
		err = fmt.Errorf("Cannot provide cert")
	}

	return cert, err
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
	if err != nil {
		return nil, err
	}

	serverConfig := m.proxy.serverConfig
	clientConfig := m.proxy.clientConfig
	alpnPreference := m.proxy.Config.Server.ALPNPreference
	alpnProbe := m.proxy.Config.Server.ALPNProbe
	prober := &m.proxy.prober
	connectEndpoint := m.proxy.Config.ConnectEndpoint
	logger := &m.proxy.logger
	if h != nil {
		if h.ServerConfig != nil {
			serverConfig = h.ServerConfig
		}

		if h.ClientConfig != nil {
			clientConfig = h.ClientConfig
		}

		if h.Logger != nil {
			logger = h.Logger
		}

		alpnPreference = h.ALPNPreference
		alpnProbe = h.ALPNProbe
		prober = &h.Prober
		connectEndpoint = &h.Connect
	}

	logger.Debug("Received Client Hello:\n%s", clientHelloInfoToString(info, "  "))
	return negotiateALPN(info, serverConfig, clientConfig, alpnPreference, alpnProbe, prober, *connectEndpoint, logger)
}
