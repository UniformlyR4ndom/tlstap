package tlstap

import (
	"crypto/tls"
	"fmt"
	"net"

	"tlstap/assert"
	"tlstap/logging"
)

type Proxy struct {
	Config ProxyConfig

	Mode Mode

	InterceptorsUp   []Interceptor
	InterceptorsDown []Interceptor
	InterceptorsAll  []Interceptor

	logger logging.Logger

	nextConnId uint32
}

func NewProxy(config ProxyConfig, mode Mode, iUp, iDown, iAll []Interceptor, logger logging.Logger) Proxy {
	return Proxy{
		Config:           config,
		Mode:             mode,
		InterceptorsUp:   iUp,
		InterceptorsDown: iDown,
		InterceptorsAll:  iAll,
		logger:           logger,
	}
}

func (p *Proxy) Start() error {
	if p.Config.ListenEndpoint == "" {
		return fmt.Errorf("listen endpoint must be specified")
	}

	if p.Config.ConnectEndpoint == "" {
		return fmt.Errorf("connect endpoint must be specified")
	}

	var tlsServerConfig, tlsClientconfig *tls.Config
	var err error
	switch p.Mode {
	case ModeTls:
		fallthrough
	case ModeDetectTls:
		if tlsServerConfig, err = ParseServerConfig(&p.Config.Server); err != nil {
			return err
		}

		if tlsClientconfig, err = ParseClientConfig(&p.Config.Client); err != nil {
			return err
		}
	}

	switch p.Mode {
	case ModePlain:
		return p.startPlainProxy()
	case ModeTls:
		return p.startTlsProxy(tlsServerConfig, tlsClientconfig)
	case ModeDetectTls:
		return p.startDetectTlsProxy(tlsServerConfig, tlsClientconfig)
	default:
		return fmt.Errorf("unknown proxy mode: %d", p.Mode)
	}
}

/*
func (p *Proxy) getTlsServerConfig() (*tls.Config, error) {
	serverConfig := p.Config.Server

	var err error
	serverTlsMin := uint16(tls.VersionTLS10)
	if serverConfig.MinVersion != "" {
		if serverTlsMin, err = TlsVersionFromString(serverConfig.MinVersion); err != nil {
			return nil, err
		}
	}

	serverTlsMax := uint16(tls.VersionTLS13)
	if serverConfig.MaxVersion != "" {
		if serverTlsMax, err = TlsVersionFromString(serverConfig.MaxVersion); err != nil {
			return nil, err
		}
	}

	cert, err := p.loadCert(serverConfig.CertPem, serverConfig.CertKey)
	if err != nil {
		return nil, err
	}

	var clientAuth tls.ClientAuthType
	switch clientAuthStr := strings.ToLower(strings.TrimSpace(serverConfig.ClientAuthPolicy)); clientAuthStr {
	case "":
		fallthrough
	case "none":
		clientAuth = tls.NoClientCert
	case "request-cert":
		clientAuth = tls.RequestClientCert
	case "require-any":
		clientAuth = tls.RequireAnyClientCert
	case "verify-if-given":
		clientAuth = tls.VerifyClientCertIfGiven
	case "require-and-verify":
		clientAuth = tls.RequireAndVerifyClientCert
	default:
		return nil, fmt.Errorf("invalid client auth type: %s", serverConfig.ClientAuthPolicy)
	}

	var keyLogWriter io.Writer = nil
	if serverConfig.KeyLogFile != "" {
		if keyLogWriter, err = os.OpenFile(serverConfig.KeyLogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644); err != nil {
			return nil, err
		}
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   serverTlsMin,
		MaxVersion:   serverTlsMax,
		ClientAuth:   clientAuth,
		KeyLogWriter: keyLogWriter,
	}

	return &tlsConfig, nil
}
*/

/*
func (p *Proxy) getTlsClientConfig() (*tls.Config, error) {
	clientConfig := p.Config.Client

	var err error
	clientTlsMin := uint16(tls.VersionTLS10)
	clientTlsMax := uint16(tls.VersionTLS13)
	if clientConfig.MinVersion != "" {
		if clientTlsMin, err = TlsVersionFromString(clientConfig.MinVersion); err != nil {
			return nil, err
		}
	}

	if clientConfig.MaxVersion != "" {
		if clientTlsMax, err = TlsVersionFromString(clientConfig.MaxVersion); err != nil {
			return nil, err
		}
	}

	var alpnStrings []string = nil
	if len(clientConfig.ALPN) > 0 {
		alpnStrings = clientConfig.ALPN
	}

	var keyLogWriter io.Writer = nil
	if clientConfig.KeyLogFile != "" {
		if keyLogWriter, err = os.OpenFile(clientConfig.KeyLogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644); err != nil {
			return nil, err
		}
	}

	tlsConfig := tls.Config{
		InsecureSkipVerify: clientConfig.SkipVerify,
		MinVersion:         clientTlsMin,
		MaxVersion:         clientTlsMax,
		ServerName:         p.Config.Client.ServerName,
		NextProtos:         alpnStrings,
		KeyLogWriter:       keyLogWriter,
	}

	return &tlsConfig, nil
}
*/

func (p *Proxy) startPlainProxy() error {
	listener, err := net.Listen("tcp", p.Config.ListenEndpoint)
	if err != nil {
		return err
	}

	p.logger.Info("proxy (mode plain) listening at %s and forwarding to %s", p.Config.ListenEndpoint, p.Config.ConnectEndpoint)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		handler := p.newHandler(ModePlain)
		go handler.HandleConnection(conn)
	}
}

/*
func (p *Proxy) loadCert(certPath, keyPath string) (tls.Certificate, error) {
	if certPath == "" || keyPath == "" {
		return tls.Certificate{}, fmt.Errorf("server certificate pem and key path must be provided")
	}

	return tls.LoadX509KeyPair(certPath, keyPath)
}
*/

func (p *Proxy) startTlsProxy(tlsServerConfig, tlsClientConfig *tls.Config) error {
	listener, err := tls.Listen("tcp", p.Config.ListenEndpoint, tlsServerConfig)
	if err != nil {
		return err
	}

	p.logger.Info("proxy (mode TLS) listening at %s and forwarding to %s", p.Config.ListenEndpoint, p.Config.ConnectEndpoint)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		handler := p.newHandler(ModeTls)
		handler.Setting.TlsServerConfig = tlsServerConfig
		handler.Setting.TlsClientConfig = tlsClientConfig
		go handler.HandleConnection(conn)
	}
}

func (p *Proxy) startDetectTlsProxy(tlsServerConfig, tlsClientconfig *tls.Config) error {
	listener, err := net.Listen("tcp", p.Config.ListenEndpoint)
	if err != nil {
		return err
	}

	p.logger.Info("proxy (mode detecttls) listening at %s and forwarding to %s", p.Config.ListenEndpoint, p.Config.ConnectEndpoint)
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	assert.Assertf(ok, "Unexpected address type: %T. This is a bug.", listener.Addr())
	notifyInit(p.InterceptorsAll, *tcpAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			p.logger.Error("failed to establish connection: %v", err)
			continue
		}

		handler := p.newHandler(ModeDetectTls)
		handler.Setting.TlsServerConfig = tlsServerConfig
		handler.Setting.TlsClientConfig = tlsClientconfig
		go handler.HandleConnection(conn)
	}
}

func (p *Proxy) newHandler(mode Mode) *ConnHandler {
	handler := ConnHandler{
		Setting: ConnSettings{
			ConnectEndpoint: p.Config.ConnectEndpoint,
			Mode:            mode,
		},
		InterceptorsUp:   p.InterceptorsUp,
		InterceptorsDown: p.InterceptorsDown,
		logger:           &p.logger,
		ConnId:           p.nextConnId,
	}

	p.nextConnId++
	return &handler
}

func notifyInit(interceptors []Interceptor, listenAddress net.TCPAddr) error {
	for _, i := range interceptors {
		if err := i.Init(listenAddress); err != nil {
			return err
		}
	}

	return nil
}
