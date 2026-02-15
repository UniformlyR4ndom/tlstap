package cli

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"tlstap/intercept"
	"tlstap/logging"
	tlstap "tlstap/proxy"
)

// known interceptor
const (
	InterceptorHexdump      = "hexdump"
	InterceptorPcapdump     = "pcapdump"
	InterceptorMatchReplace = "match-replace"
	InterceptorBridge       = "bridge"
)

type InterceptorCallback func(config tlstap.ResolvedProxyConfig, iConfig tlstap.InterceptorConfig, logger *logging.Logger) (tlstap.Interceptor, error)

func StartWithCli(interceptorCallback InterceptorCallback) {
	optEnable := flag.String("enable", "", `Comma-separated list of proxy configurations to enable (e.g. "myconfig-a,myconfig-b")`)
	optConfig := flag.String("config", "config.json", "Path to configuration file (JSON)")
	flag.Parse()

	mainLogger := logging.NewLogger(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}, true)
	configPath := strings.TrimSpace(*optConfig)
	if configPath == "" {
		mainLogger.Fatal("Path to config file cannot be empty")
	}

	configData, err := os.ReadFile(configPath)
	checkFatal(&mainLogger, err)

	var configFile tlstap.ConfigFile
	checkFatal(&mainLogger, json.Unmarshal(configData, &configFile))

	var enabledConfigs []string
	enabledList := strings.TrimSpace(*optEnable)
	if enabledList == "" {
		for k := range configFile.Proxies {
			enabledConfigs = append(enabledConfigs, k)
		}

		slices.Sort(enabledConfigs)
		mainLogger.Info("No configurations enabled - enabling all: %s", strings.Join(enabledConfigs, ","))
	} else {
		enabledConfigs = strings.Split(enabledList, ",")
	}

	for _, configName := range enabledConfigs {
		config, ok := configFile.Proxies[configName]
		if !ok {
			mainLogger.Fatal("Unknown config: %s", configName)
		}

		pConfig := tlstap.ResolvedProxyConfig{
			ListenEndpoint: config.ListenEndpoint,
			Mode:           config.Mode,
			LogFile:        config.LogFile,
			LogLevel:       config.LogLevel,
			LogTime:        config.LogTime,
		}

		if config.ConnectEndpoint != "" {
			pConfig.ConnectEndpoint = &config.ConnectEndpoint
		}

		if config.ServerRef != "" {
			server, ok := configFile.TlsServerConfigs[config.ServerRef]
			if !ok {
				mainLogger.Fatal("TLS server config '%s' not defined.", config.ServerRef)
			}

			pConfig.Server = &server
		}

		if config.ClientRef != "" {
			client, ok := configFile.TlsClientConfigs[config.ClientRef]
			if !ok {
				mainLogger.Fatal("TLS client config '%s' not defined.", config.ServerRef)
			}

			pConfig.Client = &client
		}

		if len(config.InterceptorRefs) > 0 {
			interceptors := make([]tlstap.InterceptorConfig, len(config.InterceptorRefs))
			for i, iConfigRef := range config.InterceptorRefs {
				iConfig, ok := configFile.Interceptors[iConfigRef]
				if !ok {
					mainLogger.Fatal("Interceptor '%s' not defined.", config.ServerRef)
				}

				iArgsJson, err := json.Marshal(iConfig.Args)
				checkFatal(&mainLogger, err)
				iConfig.ArgsJson = iArgsJson

				interceptors[i] = iConfig
			}

			pConfig.Interceptors = interceptors
		}

		var proxy *tlstap.Proxy
		if pConfig.Mode == "tls-mux" {
			resolvedHandlers, err := resolveMuxHandlers(&config, &configFile, &mainLogger)
			checkFatal(&mainLogger, err)
			proxy, err = proxyFromConfig(&pConfig, resolvedHandlers, &mainLogger, interceptorCallback)
			checkFatal(&mainLogger, err)
		} else {
			proxy, err = proxyFromConfig(&pConfig, nil, &mainLogger, interceptorCallback)
			checkFatal(&mainLogger, err)
		}

		go startProxy(proxy, &mainLogger)
	}

	// TODO: can we do better?
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

func resolveMuxHandlers(config *tlstap.ProxyConfig, configFile *tlstap.ConfigFile, mainLogger *logging.Logger) ([]tlstap.ResolvedMuxHandler, error) {
	var resolvedHandlers []tlstap.ResolvedMuxHandler
	for hName, h := range config.Mux {
		var matchers []*regexp.Regexp
		for _, m := range h.Matchers {
			r, err := regexp.Compile(m)
			if err != nil {
				return nil, err
			}

			matchers = append(matchers, r)
		}

		if len(matchers) == 0 {
			mainLogger.Warn("No matchers defined for mux handler %s. This handler will not be used.", hName)
		}

		interceptors := make([]tlstap.InterceptorConfig, len(h.InterceptorRefs))
		for i, iRef := range h.InterceptorRefs {
			interceptor, ok := configFile.Interceptors[iRef]
			if !ok {
				return nil, fmt.Errorf("Interceptor '%s' not defined.", iRef)
			}

			interceptors[i] = interceptor
		}

		var server *tlstap.TlsServerConfig
		if h.ServerRef != "" {
			s, ok := configFile.TlsServerConfigs[h.ServerRef]
			if !ok {
				return nil, fmt.Errorf("TLS server config '%s' not defined.", h.ServerRef)
			}

			server = &s
		} else {
			mainLogger.Warn("No TLS server config provided for mux handler %s.", hName)
		}

		var client *tlstap.TlsClientConfig
		if h.ClientRef != "" {
			c, ok := configFile.TlsClientConfigs[h.ClientRef]
			if !ok {
				return nil, fmt.Errorf("TLS client config '%s' not defined.", h.ClientRef)
			}

			client = &c
		} else {
			mainLogger.Warn("No TLS client config provided for mux handler %s.", hName)
		}

		resolvedHandler := tlstap.ResolvedMuxHandler{
			Name:            hName,
			ConnectEndpoint: h.ConnectEndpoint,
			Matchers:        matchers,
			LogLevel:        h.LogLevel,
			LogFile:         h.LogFile,
			Interceptors:    interceptors,
			Server:          server,
			Client:          client,
		}

		resolvedHandlers = append(resolvedHandlers, resolvedHandler)
	}

	return resolvedHandlers, nil
}

func proxyFromConfig(config *tlstap.ResolvedProxyConfig, muxHandlers []tlstap.ResolvedMuxHandler, mainLogger *logging.Logger, cb InterceptorCallback) (*tlstap.Proxy, error) {
	logWriter := os.Stdout
	if config.LogFile != "" {
		logFile, err := os.OpenFile(config.LogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return nil, err
		}
		logWriter = logFile
	}

	logLevel, err := parseLogLevel(config.LogLevel)
	if err != nil {
		return nil, err
	}

	proxyLogger := logging.NewLogger(logWriter, &slog.HandlerOptions{Level: logLevel}, config.LogTime)

	var mode tlstap.Mode
	var handlers []tlstap.Handler
	switch m := strings.ToLower(strings.TrimSpace(config.Mode)); m {
	case "plain":
		mode = tlstap.ModePlain
	case "tls":
		mode = tlstap.ModeTls
	case "detecttls":
		mode = tlstap.ModeDetectTls
	case "tls-mux":
		mode = tlstap.ModeMux
		for _, h := range muxHandlers {
			handler, err := buildMuxHandler(h, config, mainLogger, &proxyLogger, cb)
			if err != nil {
				return nil, err
			}

			handlers = append(handlers, handler)
		}
	default:
		return nil, fmt.Errorf("invalid proxy mode: %s", config.Mode)
	}

	var interceptorsUp []tlstap.Interceptor
	var interceptorsDown []tlstap.Interceptor
	var interceptorsAll []tlstap.Interceptor
	if config.Interceptors != nil {
		for _, iConfig := range config.Interceptors {
			if iConfig.Disable {
				mainLogger.Warn("interceptor %s disabled", iConfig.Name)
				continue
			}

			interceptor, err := buildInterceptor(&iConfig, config, mainLogger, cb)
			checkFatal(mainLogger, err)

			switch dir := strings.ToLower(iConfig.Direction); dir {
			case "up":
				interceptorsUp = append(interceptorsUp, interceptor)
			case "down":
				interceptorsDown = append(interceptorsDown, interceptor)
			case "any", "":
				interceptorsUp = append(interceptorsUp, interceptor)
				interceptorsDown = append(interceptorsDown, interceptor)
			default:
				return nil, fmt.Errorf("invalid direction: %s", dir)
			}

			interceptorsAll = append(interceptorsAll, interceptor)
		}
	}

	p := tlstap.NewProxy(*config, mode, interceptorsUp, interceptorsDown, interceptorsAll, proxyLogger)
	if mode == tlstap.ModeMux {
		mux := tlstap.NewMux(handlers)
		p.Mux = mux
		mux.SetProxy(&p)
	}

	return &p, nil
}

func buildInterceptor(iConfig *tlstap.InterceptorConfig, pConfig *tlstap.ResolvedProxyConfig, logger *logging.Logger, cb InterceptorCallback) (tlstap.Interceptor, error) {
	var interceptor tlstap.Interceptor
	switch iConfig.Name {
	case InterceptorHexdump:
		interceptor = &intercept.HexDumpInterceptor{Logger: logger}
	case InterceptorPcapdump:
		var pcapConfig intercept.PcapConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &pcapConfig); err != nil {
			return nil, err
		}

		i := intercept.NewPcapDumpInterceptor(pcapConfig.FilePath, pcapConfig.Truncate)
		interceptor = &i
	case InterceptorMatchReplace:
		var matchReplaceConfig intercept.MatchReplaceConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &matchReplaceConfig); err != nil {
			return nil, err
		}

		if i, err := intercept.NewMatchReplaceInterceptor(&matchReplaceConfig); err != nil {
			return nil, err
		} else {
			interceptor = &i
		}
	case InterceptorBridge:
		var bridgeConf intercept.BridgeConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &bridgeConf); err != nil {
			return nil, err
		}

		i := intercept.NewBridgeInterceptor(bridgeConf.Connect, logger)
		interceptor = &i
	default:
		var err error
		if cb != nil {
			interceptor, err = cb(*pConfig, *iConfig, logger)
		}

		switch {
		case err != nil:
			return nil, err
		case interceptor == nil:
			return nil, fmt.Errorf("unknown interceptor: %s", iConfig.Name)
		}
	}

	return interceptor, nil
}

func buildMuxHandler(muxSpec tlstap.ResolvedMuxHandler, pConfig *tlstap.ResolvedProxyConfig, mainLogger, proxyLogger *logging.Logger, cb InterceptorCallback) (tlstap.Handler, error) {
	logFile := pConfig.LogFile
	if muxSpec.LogFile != "" {
		logFile = muxSpec.LogFile
	}

	logLevel := pConfig.LogLevel
	if muxSpec.LogLevel != "" {
		logLevel = muxSpec.LogLevel
	}

	localLogger := proxyLogger
	if logFile != pConfig.LogFile || logLevel != pConfig.LogLevel {
		level, err := parseLogLevel(logLevel)
		if err != nil {
			return tlstap.Handler{}, err
		}

		logWriter, err := os.OpenFile(logFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return tlstap.Handler{}, err
		}

		l := logging.NewLogger(logWriter, &slog.HandlerOptions{Level: level}, pConfig.LogTime)
		localLogger = &l
	}

	var iUp []tlstap.Interceptor
	var iDown []tlstap.Interceptor
	var iAll []tlstap.Interceptor
	for _, iConfig := range muxSpec.Interceptors {
		if iConfig.Disable {
			localLogger.Warn("Interceptor %s disabled", iConfig.Name)
			continue
		}

		interceptor, err := buildInterceptor(&iConfig, pConfig, localLogger, cb)
		if err != nil {
			return tlstap.Handler{}, err
		}

		switch dir := iConfig.Direction; dir {
		case "up":
			iUp = append(iUp, interceptor)
		case "down":
			iDown = append(iDown, interceptor)
		case "any", "":
			iUp = append(iUp, interceptor)
			iDown = append(iDown, interceptor)
		default:
			return tlstap.Handler{}, fmt.Errorf("invalid direction: %s", dir)
		}

		iAll = append(iAll, interceptor)
	}

	var clientConfig *tls.Config
	var serverConfig *tls.Config
	var serverNextProtos []string
	var err error
	if muxSpec.Server != nil {
		if serverConfig, serverNextProtos, err = tlstap.ParseServerConfig(muxSpec.Server); err != nil {
			return tlstap.Handler{}, err
		}
	}

	if muxSpec.Client != nil {
		if clientConfig, err = tlstap.ParseClientConfig(muxSpec.Client); err != nil {
			return tlstap.Handler{}, err
		}
	}

	handler := tlstap.Handler{
		Name:             muxSpec.Name,
		Connect:          muxSpec.ConnectEndpoint,
		Patterns:         muxSpec.Matchers,
		InterceptorsUp:   iUp,
		InterceptorsDown: iDown,
		InterceptorAll:   iAll,
		ClientConfig:     clientConfig,
		ServerConfig:     serverConfig,
		ServerNextProtos: serverNextProtos,
		Logger:           localLogger,
	}

	if clientConfig != nil {
		clientConfig.GetClientCertificate = handler.ClientConfig.GetClientCertificate
	}

	return handler, nil
}

func parseLogLevel(level string) (slog.Level, error) {
	switch l := strings.ToLower(strings.TrimSpace(level)); l {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level: %s", level)
	}
}

func startProxy(p *tlstap.Proxy, logger *logging.Logger) {
	if p == nil {
		logger.Fatal("Cannot start nil proxy.")
	}

	err := p.Start()
	checkFatal(logger, err)
}

func checkFatal(logger *logging.Logger, err error) {
	if err != nil {
		logger.Fatal("Fatal error: %v", err)
	}
}
