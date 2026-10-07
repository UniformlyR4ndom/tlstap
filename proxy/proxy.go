package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"tlstap/assert"
	"tlstap/logging"
)

type Proxy struct {
	Config ResolvedProxyConfig

	Mode Mode
	Mux  *Mux

	InterceptorsUp   []Interceptor
	InterceptorsDown []Interceptor
	InterceptorsAll  []Interceptor

	logger logging.Logger

	nextConnId uint32

	clientConfig     *tls.Config
	serverConfig     *tls.Config
	serverNextProtos []string

	prober Prober

	listenerMu sync.Mutex     // guards listener and listenAddr: Stop() and Finalize() run on other goroutines than the accept loop
	listener   net.Listener   // set once the accept loop starts; closed by Stop()
	listenAddr net.TCPAddr    // set alongside listener, reused by Finalize()
	connWg     sync.WaitGroup // tracks in-flight HandleConnection goroutines, for WaitForConnections
}

// NewProxy returns a *Proxy, not a Proxy, since Proxy now embeds a sync.WaitGroup
// (connWg) — copying it by value after construction is what go vet's copylocks check
// (rightly) flags, even though the copy itself would only ever happen before connWg is
// first used.
func NewProxy(config ResolvedProxyConfig, mode Mode, iUp, iDown, iAll []Interceptor, logger logging.Logger) *Proxy {
	proxy := &Proxy{
		Config:           config,
		Mode:             mode,
		InterceptorsUp:   iUp,
		InterceptorsDown: iDown,
		InterceptorsAll:  iAll,
		logger:           logger,
	}

	switch mode {
	case ModeTls, ModeMux:
		proxy.prober = NewProber(config.Server.ALPNProbeCache)
	}

	return proxy
}

func (p *Proxy) Start() error {
	if p.Config.ListenEndpoint == "" {
		return fmt.Errorf("listen endpoint must be specified")
	}

	if p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "" {
		return fmt.Errorf("connect endpoint must be specified")
	}

	if err := p.validateBufferingChains(); err != nil {
		return err
	}

	var tlsServerConfig, tlsClientConfig *tls.Config
	var tlsServerNextProtos []string
	var err error

	switch m := p.Mode; m {
	case ModePlain:
		if p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "" {
			p.logger.Fatal("A connect endpoint is required in mode %s.", m.String())
		}

	case ModeTls, ModeDetectTls:
		switch {
		case p.Config.Server == nil:
			p.logger.Fatal("A TLS server configuration is required in mode %s.", m.String())
		case p.Config.Client == nil:
			p.logger.Fatal("A TLS client configuration is required in mode %s.", m.String())
		case p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "":
			p.logger.Fatal("A connect endpoint is required in mode %s.", m.String())
		}

		if tlsServerConfig, tlsServerNextProtos, err = ParseServerConfig(p.Config.Server); err != nil {
			return err
		}

		tlsServerConfig.GetConfigForClient = p.getServerConfig

		if tlsClientConfig, err = ParseClientConfig(p.Config.Client); err != nil {
			return err
		}

		if tlsClientConfig != nil {
			tlsClientConfig.GetClientCertificate = p.getClientCertificate
		}

	case ModeMux:
		if p.Config.Server == nil {
			p.logger.Warn("No default TLS server configuration available. No fallback for mux possible.")
		} else if tlsServerConfig, tlsServerNextProtos, err = ParseServerConfig(p.Config.Server); err != nil {
			return err
		}

		if tlsServerConfig == nil {
			tlsServerConfig = &tls.Config{}
		}

		tlsServerConfig.GetConfigForClient = p.Mux.getServerConfig

		if p.Config.Client == nil {
			p.logger.Warn("No default TLS client configuration available. No fallback for mux possible.")
		} else if tlsClientConfig, err = ParseClientConfig(p.Config.Client); err != nil {
			return err
		}

		if tlsClientConfig != nil {
			tlsClientConfig.GetClientCertificate = p.getClientCertificate
		}

		for _, h := range p.Mux.handlers {
			if h.ServerConfig == nil && p.serverConfig == nil {
				return fmt.Errorf("neither TLS server config nor fallback config defined for mux handler %s", h.Name)
			}

			if h.ClientConfig != nil {
				h.ClientConfig.GetClientCertificate = h.getClientCertificate
			}
		}

		if p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "" {
			p.logger.Warn("No default connect endpoint available. No fallback for mux possible.")
		}

	default:
		p.logger.Fatal("Invalid proxy mode %d", m)
	}

	// must be called after initialization of TLS client config
	p.warnPassthroughUnsupported()
	p.clientConfig = tlsClientConfig
	p.serverConfig = tlsServerConfig
	p.serverNextProtos = tlsServerNextProtos
	switch p.Mode {
	case ModePlain:
		return p.startPlainProxy()
	case ModeTls:
		return p.startTlsProxy()
	case ModeDetectTls:
		return p.startDetectTlsProxy()
	case ModeMux:
		return p.startTlsMuxProxy(p.Mux)
	default:
		return fmt.Errorf("unknown proxy mode: %d", p.Mode)
	}
}

func (p *Proxy) startPlainProxy() error {
	listener, err := net.Listen("tcp", p.Config.ListenEndpoint)
	if err != nil {
		return err
	}

	p.logStartupInfo()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	p.setListener(listener, *tcpAddr)
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.Info("Listener closed, stopping accept loop.")
				return nil
			}
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		handler, err := p.newHandler(ModePlain, nil, "")
		CheckFatal(err)

		p.trackConnection(func() { handler.HandleConnection(conn) })
	}
}

func (p *Proxy) startTlsProxy() error {
	listener, err := tls.Listen("tcp", p.Config.ListenEndpoint, p.serverConfig)
	if err != nil {
		return err
	}

	p.logStartupInfo()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	p.setListener(listener, *tcpAddr)
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.Info("Listener closed, stopping accept loop.")
				return nil
			}
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		assert.Assertf(ok, "Expected instance of tls.Conn but got %T. This is a bug.", conn)
		if err = tlsConn.Handshake(); err != nil {
			p.logger.Error("downstream connection setup failed: %v", err)
			continue
		}

		handler, err := p.newHandler(ModeTls, nil, "")
		CheckFatal(err)

		// handle SNI and ALPN passthrough
		if p.Config.Client.SniPassthroug || p.Config.Client.ALPNPassthrough {
			connState := tlsConn.ConnectionState()
			serverName := connState.ServerName
			if serverName != "" {
				p.logger.Debug("Picked up server name (SNI) form client: %s", serverName)
			}

			var protos []string
			if connState.NegotiatedProtocol != "" {
				protos = []string{connState.NegotiatedProtocol}
				p.logger.Debug("Picked up next protocol (ALPN) from client: %s", connState.NegotiatedProtocol)
			}

			// only if current config does not specify SNI or ALPN respectively the overrides are applied
			handler.Setting.TlsClientConfig = getModifiedConfig(p.clientConfig, serverName, protos)
		}

		logClientConfigInfo(handler.ConnId, handler.logger, handler.Setting.TlsClientConfig)
		p.trackConnection(func() { handler.HandleConnection(tlsConn) })
	}
}

func (p *Proxy) startDetectTlsProxy() error {
	listener, err := net.Listen("tcp", p.Config.ListenEndpoint)
	if err != nil {
		return err
	}

	p.logStartupInfo()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	p.setListener(listener, *tcpAddr)
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.Info("Listener closed, stopping accept loop.")
				return nil
			}
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		handler, err := p.newHandler(ModeDetectTls, nil, "")
		CheckFatal(err)

		p.trackConnection(func() { handler.HandleConnection(conn) })
	}
}

func (p *Proxy) startTlsMuxProxy(mux *Mux) error {
	tlsServerConfig := p.serverConfig
	tlsClientConfig := p.clientConfig
	if mux == nil {
		return fmt.Errorf("mux must not be nil")
	}

	listener, err := tls.Listen("tcp", p.Config.ListenEndpoint, tlsServerConfig)
	if err != nil {
		return err
	}

	p.logStartupInfo()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	p.setListener(listener, *tcpAddr)
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for _, h := range mux.handlers {
		notifyInit(h.InterceptorAll, *tcpAddr)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				p.logger.Info("Listener closed, stopping accept loop.")
				return nil
			}
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		assert.Assertf(ok, "Expected instance of tls.Conn but got %T. This is a bug.", conn)
		if err = tlsConn.Handshake(); err != nil {
			p.logger.Error("downstream connection setup failed: %v", err)
			continue
		}

		connState := tlsConn.ConnectionState()
		serverName := connState.ServerName
		handler, err := p.newHandler(ModeMux, mux, serverName)
		CheckFatal(err)

		// if no specific config is provided by the mux handler, set the default one
		if handler.Setting.TlsServerConfig == nil {
			assert.Assertf(tlsServerConfig != nil, "Neither mux handler nor default TLS server config provided. This is a bug.")
			handler.Setting.TlsServerConfig = tlsServerConfig
		}

		if handler.Setting.TlsClientConfig == nil {
			handler.Setting.TlsClientConfig = tlsClientConfig
		}

		// handle SNI and ALPN passthrough
		if p.Config.Client.SniPassthroug || p.Config.Client.ALPNPassthrough {
			// protos := append([]string{}, p.lastClientHelloInfo.SupportedProtos...)
			protos := []string{connState.NegotiatedProtocol}

			// only if current config does not specify SNI or ALPN respectively the overrides are applied
			handler.Setting.TlsClientConfig = getModifiedConfig(tlsClientConfig, serverName, protos)
		}

		logClientConfigInfo(handler.ConnId, handler.logger, handler.Setting.TlsClientConfig)
		p.trackConnection(func() { handler.HandleConnection(conn) })
	}
}

// validateBufferingChains rejects interceptor chains that ConnHandler can't drive: more than one
// buffering interceptor per direction, and any buffering interceptor in detecttls mode.
func (p *Proxy) validateBufferingChains() error {
	check := func(what string, chain []Interceptor) error {
		n := len(scanBuffering(chain))
		switch {
		case n > 1:
			return fmt.Errorf("%s: at most one buffering interceptor is supported per direction, got %d", what, n)
		case n > 0 && p.Mode == ModeDetectTls:
			return fmt.Errorf("%s: buffering interceptors are not supported in detecttls mode", what)
		}

		return nil
	}

	if err := check("up chain", p.InterceptorsUp); err != nil {
		return err
	}

	if err := check("down chain", p.InterceptorsDown); err != nil {
		return err
	}

	if p.Mux != nil {
		for _, h := range p.Mux.handlers {
			if err := check("mux handler "+h.Name+" up chain", h.InterceptorsUp); err != nil {
				return err
			}

			if err := check("mux handler "+h.Name+" down chain", h.InterceptorsDown); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *Proxy) newHandler(mode Mode, mux *Mux, serverName string) (*ConnHandler, error) {
	var connect string
	if p.Config.ConnectEndpoint != nil {
		connect = *p.Config.ConnectEndpoint
	}

	logger := &p.logger
	iUp := p.InterceptorsUp
	iDown := p.InterceptorsDown
	clientConfig := p.clientConfig
	serverConfig := p.serverConfig
	if mux != nil && serverName != "" {
		h, err := mux.GetMatch(serverName)
		if err != nil {
			return nil, err
		}

		if h != nil {
			connect = h.Connect
			iUp = h.InterceptorsUp
			iDown = h.InterceptorsDown
			clientConfig = h.ClientConfig
			serverConfig = h.ServerConfig
			logger = h.Logger
		}
	}

	handler := ConnHandler{
		Setting: ConnSettings{
			ConnectEndpoint: connect,
			Mode:            mode,
			TlsClientConfig: clientConfig,
			TlsServerConfig: serverConfig,
		},
		InterceptorsUp:   iUp,
		InterceptorsDown: iDown,
		bufferingUp:      scanBuffering(iUp),
		bufferingDown:    scanBuffering(iDown),
		logger:           logger,
		ConnId:           p.nextConnId,
	}

	p.nextConnId++
	return &handler, nil
}

func notifyInit(interceptors []Interceptor, listenAddress net.TCPAddr) error {
	for _, i := range interceptors {
		if err := i.Init(listenAddress); err != nil {
			return err
		}
	}

	return nil
}

// trackConnection runs fn (a connection handler) in a new goroutine, tracked by connWg so
// WaitForConnections can observe when every in-flight connection has finished.
func (p *Proxy) trackConnection(fn func()) {
	p.connWg.Add(1)
	go func() {
		defer p.connWg.Done()
		fn()
	}()
}

// Stop closes the proxy's listener, causing its accept loop to return nil. Safe to call
// once Start() has set up the listener; a no-op before that.
func (p *Proxy) Stop() {
	if l, _ := p.getListener(); l != nil {
		l.Close()
	}
}

func (p *Proxy) setListener(l net.Listener, addr net.TCPAddr) {
	p.listenerMu.Lock()
	defer p.listenerMu.Unlock()
	p.listener, p.listenAddr = l, addr
}

func (p *Proxy) getListener() (net.Listener, net.TCPAddr) {
	p.listenerMu.Lock()
	defer p.listenerMu.Unlock()
	return p.listener, p.listenAddr
}

// WaitForConnections blocks until every in-flight connection handler has returned, or ctx
// is done, whichever comes first. Returns true if every connection finished, false on
// timeout/cancellation — some connections may still be running in that case.
func (p *Proxy) WaitForConnections(ctx context.Context) bool {
	done := make(chan struct{})
	go func() {
		p.connWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// Finalize calls Finalize on every interceptor this proxy owns — its own InterceptorsAll,
// plus every mux handler's own InterceptorAll in ModeMux — exactly once each, concurrently
// so one slow interceptor doesn't delay its siblings. Only meaningful to call after the
// accept loop has stopped (or at least after Stop() was called); listenAddr is set once,
// when the accept loop starts, and never mutated again.
func (p *Proxy) Finalize() {
	var wg sync.WaitGroup
	_, listenAddr := p.getListener()
	notifyFinalize(&wg, p.InterceptorsAll, listenAddr)
	if p.Mux != nil {
		for _, h := range p.Mux.handlers {
			notifyFinalize(&wg, h.InterceptorAll, listenAddr)
		}
	}
	wg.Wait()
}

func notifyFinalize(wg *sync.WaitGroup, interceptors []Interceptor, listenAddress net.TCPAddr) {
	for _, i := range interceptors {
		wg.Add(1)
		go func(i Interceptor) {
			defer wg.Done()
			i.Finalize(listenAddress)
		}(i)
	}
}

func (p *Proxy) getServerConfig(info *tls.ClientHelloInfo) (*tls.Config, error) {
	p.logger.Debug("Received Client Hello:\n%s", clientHelloInfoToString(info, "  "))
	alpnPreference := p.Config.Server.ALPNPreference
	alpnProbe := p.Config.Server.ALPNProbe
	return negotiateALPN(info, p.serverConfig, p.clientConfig, alpnPreference, alpnProbe, &p.prober, *p.Config.ConnectEndpoint, &p.logger)
}

func negotiateALPN(info *tls.ClientHelloInfo, serverConfig, clientConfig *tls.Config, alpnPreference []string, alpnProbe bool,
	prober *Prober, connectEndpoint string, logger *logging.Logger) (*tls.Config, error) {
	offeredProtos := info.SupportedProtos
	if len(alpnPreference) > 0 {
		if selectedNextProto, ok := selectNextProto(info, offeredProtos, logger); ok {
			logger.Debug("Selected application protocol: %s", selectedNextProto)
			config := serverConfig.Clone()
			config.NextProtos = []string{selectedNextProto}
			return config, nil
		}

		return serverConfig, nil
	}

	switch len(offeredProtos) {
	case 0:
		return serverConfig, nil
	case 1:
		selected := offeredProtos[0]
		config := serverConfig.Clone()
		config.NextProtos = []string{selected}

		logger.Debug("Only one next protcol offered: %s; accepting it", selected)
		return config, nil
	}

	if alpnProbe {
		logger.Debug("Probing for accepted next protocol (offered: %v)", offeredProtos)
		selected, cached, err := prober.Probe(connectEndpoint, clientConfig, offeredProtos)
		if err != nil {
			logger.Warn("ALPN probe failed: %v", err)
			return serverConfig, nil
		}

		logger.Debug("ALPN probe returned protocol choice %s (cached: %v)", selected, cached)
		config := serverConfig.Clone()
		config.NextProtos = []string{selected}
		return config, nil
	}

	logger.Warn("Multiple next protocols offered by client but neither alpn-preference nor alpn-probe configured")
	return serverConfig, nil
}

func (p *Proxy) getClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	p.logger.Debug("Received Certificate Request:\n%s", certRequestInfoToString(info, "  "))
	var cert *tls.Certificate
	if p.clientConfig != nil && len(p.clientConfig.Certificates) > 0 {
		cert = &p.clientConfig.Certificates[0]
		chain := []tls.Certificate{*cert}
		p.logger.Debug("Using client certificate:\n%s", chainToString(chain, "  "))
	} else {
		p.logger.Error("No client certificate configured")
	}

	var err error
	if cert == nil {
		err = fmt.Errorf("Cannot provide cert")
	}

	return cert, err
}

func logSni(connId uint32, logger *logging.Logger, config *tls.Config) {
	if config.ServerName == "" {
		logger.Debug("Connection %d: not using server name (SNI)", connId)
	} else {
		logger.Debug("Connection %d: using server name (SNI): %s", connId, config.ServerName)
	}
}

func logAlpn(connId uint32, logger *logging.Logger, config *tls.Config) {
	if len(config.NextProtos) == 0 {
		logger.Debug("Connection %d: not using ALPN", connId)
	} else {
		logger.Debug("Connection %d: using ALPN values: %s", connId, strings.Join(config.NextProtos, ", "))
	}
}

func logClientConfigInfo(connId uint32, logger *logging.Logger, config *tls.Config) {
	logSni(connId, logger, config)
	logAlpn(connId, logger, config)
}

func (p *Proxy) warnPassthroughUnsupported() {
	switch mode := p.Mode; mode {
	case ModeTls, ModeMux:
		return
	case ModePlain:
		if p.Config.Server != nil {
			p.logger.Warn("Ignoring TLS server configuration (not supported in mode %s).", mode.String())
		}

		if p.Config.Client != nil {
			p.logger.Warn("Ignoring TLS client configuration (not supported in mode %s).", mode.String())
		}

	case ModeDetectTls:
		if p.Config.Client != nil && p.Config.Client.ALPNPassthrough {
			p.logger.Warn("Ignoring ALPN passthrough (not supported in mode %s).", mode.String())
		}

		if p.Config.Client != nil && p.Config.Client.SniPassthroug {
			p.logger.Warn("Ignoring SNI passthrough (not supported in mode %s).", mode.String())
		}
	}
}

func (p *Proxy) logStartupInfo() {
	p.logger.Info("################ Config %s start ################", p.Config.Name)

	switch p.Mode {
	case ModeMux:
		if p.Config.ConnectEndpoint == nil {
			p.logger.Info("Proxy (mode %s) listening at %s", p.Mode.String(), p.Config.ListenEndpoint)
			p.logger.Warn("No default connect endpoint specified. Only forwarding to targets definded by mux handlers")
		} else {
			p.logger.Info("proxy (mode mux) listening at %s and forwarding to %s by default", p.Config.ListenEndpoint, *p.Config.ConnectEndpoint)
		}

		p.logger.Info("Available mux handlers:")
		for _, h := range p.Mux.handlers {
			p.logger.Info("%s: %v -> %s", h.Name, h.Patterns, h.Connect)
			if p.serverConfig != nil && len(p.serverConfig.Certificates) > 0 {
				p.logger.Debug("Server certificate chain:\n%s", chainToString(p.serverConfig.Certificates, "  "))
			} else {
				p.logger.Debug("No default server certificate given")
			}

			if p.clientConfig != nil && len(p.clientConfig.Certificates) > 0 {
				p.logger.Debug("Client certificate chain:\n%s", chainToString(p.serverConfig.Certificates, "  "))
			} else {
				p.logger.Debug("No default client certificate given")
			}

		}

	case ModeTls, ModeDetectTls:
		p.logger.Info("Proxy (mode %s) listening at %s and forwarding to %s", p.Mode.String(), p.Config.ListenEndpoint, *p.Config.ConnectEndpoint)
		p.logger.Debug("Server certificate chain:\n%s", chainToString(p.serverConfig.Certificates, "  "))
		if len(p.clientConfig.Certificates) > 0 {
			p.logger.Debug("Client certificate chain:\n%s", chainToString(p.clientConfig.Certificates, "  "))
		} else {
			p.logger.Debug("No TLS client authentication supported")
		}

	default:
		p.logger.Info("Proxy (mode %s) listening at %s and forwarding to %s", p.Mode.String(), p.Config.ListenEndpoint, *p.Config.ConnectEndpoint)
	}

	p.logger.Info("################ Config %s end ################", p.Config.Name)
}
