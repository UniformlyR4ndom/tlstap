package tlstap

import (
	"crypto/tls"
	"fmt"
	"net"

	"tlstap/assert"
	"tlstap/logging"
)

type Proxy struct {
	Config ResolvedProxyConfig

	Mode Mode

	InterceptorsUp   []Interceptor
	InterceptorsDown []Interceptor
	InterceptorsAll  []Interceptor

	logger logging.Logger

	nextConnId uint32
}

func NewProxy(config ResolvedProxyConfig, mode Mode, iUp, iDown, iAll []Interceptor, logger logging.Logger) Proxy {
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

	if p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "" {
		return fmt.Errorf("connect endpoint must be specified")
	}

	var tlsServerConfig, tlsClientconfig *tls.Config
	var err error

	switch p.Mode {
	case ModeTls, ModeDetectTls:
		switch {
		case p.Config.Server == nil:
			p.logger.Fatal("A TLS server configuration is required in this mode.")
		case p.Config.Client == nil:
			p.logger.Fatal("A TLS client configuration is required in this mode.")
		case p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "":
			p.logger.Fatal("A connect endpoint is required in this mode.")
		}

		if tlsServerConfig, err = ParseServerConfig(p.Config.Server); err != nil {
			return err
		}

		if tlsClientconfig, err = ParseClientConfig(p.Config.Client); err != nil {
			return err
		}
	case ModePlain:
		if p.Config.ConnectEndpoint == nil || *p.Config.ConnectEndpoint == "" {
			p.logger.Fatal("A connect endpoint is required in this mode.")
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

func (p *Proxy) startPlainProxy() error {
	listener, err := net.Listen("tcp", p.Config.ListenEndpoint)
	if err != nil {
		return err
	}

	p.logger.Info("proxy (mode plain) listening at %s and forwarding to %s", p.Config.ListenEndpoint, *p.Config.ConnectEndpoint)
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

func (p *Proxy) startTlsProxy(tlsServerConfig, tlsClientConfig *tls.Config) error {
	listener, err := tls.Listen("tcp", p.Config.ListenEndpoint, tlsServerConfig)
	if err != nil {
		return err
	}

	p.logger.Info("proxy (mode TLS) listening at %s and forwarding to %s", p.Config.ListenEndpoint, *p.Config.ConnectEndpoint)
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

	p.logger.Info("proxy (mode detecttls) listening at %s and forwarding to %s", p.Config.ListenEndpoint, *p.Config.ConnectEndpoint)
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
			ConnectEndpoint: *p.Config.ConnectEndpoint,
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
