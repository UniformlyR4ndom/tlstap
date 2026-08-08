package cli

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"tlstap/intercept/bridge"
	"tlstap/intercept/dbdump"
	"tlstap/intercept/drop"
	"tlstap/intercept/hexdump"
	replace "tlstap/intercept/match_replace"
	"tlstap/intercept/pcapdump"
	"tlstap/intercept/tamper"
	"tlstap/logging"
	"tlstap/proxy"
	tlstapweb "tlstap/web"
)

// known interceptor
const (
	InterceptorHexdump      = "hexdump"
	InterceptorPcapdump     = "pcapdump"
	InterceptorMatchReplace = "match-replace"
	InterceptorBridge       = "bridge"
	InterceptorDropTls      = "droptls"
	InterceptorDbDump       = "dbdump"
	InterceptorTamper       = "tamper"
)

type InterceptorCallback func(config proxy.ResolvedProxyConfig, iConfig proxy.InterceptorConfig, logger *logging.Logger) (proxy.Interceptor, error)

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

	var configFile proxy.ConfigFile
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

	canonicalRegistered := make(map[string]bool)
	apiMux := http.NewServeMux()

	sub, _ := fs.Sub(tlstapweb.FS, ".")
	apiMux.Handle("/ui/", http.StripPrefix("/ui", http.FileServer(http.FS(sub))))
	apiMux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	for _, configName := range enabledConfigs {
		config, ok := configFile.Proxies[configName]
		if !ok {
			mainLogger.Fatal("Unknown config: %s", configName)
		}

		pConfig := proxy.ResolvedProxyConfig{
			ListenEndpoint: config.ListenEndpoint,
			Mode:           config.Mode,
			LogFile:        config.LogFile,
			LogLevel:       config.LogLevel,
			LogTime:        config.LogTime,
			Name:           configName,
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
				mainLogger.Fatal("TLS client config '%s' not defined.", config.ClientRef)
			}

			pConfig.Client = &client
		}

		if len(config.InterceptorRefs) > 0 {
			interceptors := make([]proxy.InterceptorConfig, len(config.InterceptorRefs))
			for i, iConfigRef := range config.InterceptorRefs {
				iConfig, ok := configFile.Interceptors[iConfigRef]
				if !ok {
					mainLogger.Fatal("Interceptor '%s' not defined.", iConfigRef)
				}

				iArgsJson, err := json.Marshal(iConfig.Args)
				checkFatal(&mainLogger, err)
				iConfig.ArgsJson = iArgsJson

				interceptors[i] = iConfig
			}

			pConfig.Interceptors = interceptors
		}

		var proxy *proxy.Proxy
		if pConfig.Mode == "tls-mux" {
			resolvedHandlers, err := resolveMuxHandlers(&config, &configFile, &mainLogger)
			checkFatal(&mainLogger, err)
			proxy, err = proxyFromConfig(&pConfig, resolvedHandlers, &mainLogger, interceptorCallback, apiMux, canonicalRegistered)
			checkFatal(&mainLogger, err)
		} else {
			proxy, err = proxyFromConfig(&pConfig, nil, &mainLogger, interceptorCallback, apiMux, canonicalRegistered)
			checkFatal(&mainLogger, err)
		}

		go startProxy(proxy, &mainLogger)
	}

	if configFile.Api != nil && configFile.Api.Listen != "" {
		mainLogger.Info("Starting API server at %s", configFile.Api.Listen)
		go func() {
			if err := http.ListenAndServe(configFile.Api.Listen, apiMux); err != nil {
				mainLogger.Error("API server: %v", err)
			}
		}()
	}

	// TODO: can we do better?
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

func resolveMuxHandlers(config *proxy.ProxyConfig, configFile *proxy.ConfigFile, mainLogger *logging.Logger) ([]proxy.ResolvedMuxHandler, error) {
	var resolvedHandlers []proxy.ResolvedMuxHandler
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

		interceptors := make([]proxy.InterceptorConfig, len(h.InterceptorRefs))
		for i, iRef := range h.InterceptorRefs {
			interceptor, ok := configFile.Interceptors[iRef]
			if !ok {
				return nil, fmt.Errorf("Interceptor '%s' not defined.", iRef)
			}

			iArgsJson, err := json.Marshal(interceptor.Args)
			if err != nil {
				return nil, err
			}
			interceptor.ArgsJson = iArgsJson

			interceptors[i] = interceptor
		}

		var server *proxy.TlsServerConfig
		if h.ServerRef != "" {
			s, ok := configFile.TlsServerConfigs[h.ServerRef]
			if !ok {
				return nil, fmt.Errorf("TLS server config '%s' not defined.", h.ServerRef)
			}

			server = &s
		} else {
			mainLogger.Warn("No TLS server config provided for mux handler %s.", hName)
		}

		var client *proxy.TlsClientConfig
		if h.ClientRef != "" {
			c, ok := configFile.TlsClientConfigs[h.ClientRef]
			if !ok {
				return nil, fmt.Errorf("TLS client config '%s' not defined.", h.ClientRef)
			}

			client = &c
		} else {
			mainLogger.Warn("No TLS client config provided for mux handler %s.", hName)
		}

		resolvedHandler := proxy.ResolvedMuxHandler{
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

func proxyFromConfig(config *proxy.ResolvedProxyConfig, muxHandlers []proxy.ResolvedMuxHandler, mainLogger *logging.Logger, cb InterceptorCallback, apiMux *http.ServeMux, canonicalRegistered map[string]bool) (*proxy.Proxy, error) {
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

	var mode proxy.Mode
	var handlers []proxy.Handler
	switch m := strings.ToLower(strings.TrimSpace(config.Mode)); m {
	case "plain":
		mode = proxy.ModePlain
	case "tls":
		mode = proxy.ModeTls
	case "detecttls":
		mode = proxy.ModeDetectTls
	case "tls-mux":
		mode = proxy.ModeMux
		for _, h := range muxHandlers {
			handler, err := buildMuxHandler(h, config, mainLogger, &proxyLogger, cb, apiMux, canonicalRegistered)
			if err != nil {
				return nil, err
			}

			handlers = append(handlers, handler)
		}
	default:
		return nil, fmt.Errorf("invalid proxy mode: %s", config.Mode)
	}

	var interceptorsUp []proxy.Interceptor
	var interceptorsDown []proxy.Interceptor
	var interceptorsAll []proxy.Interceptor
	if config.Interceptors != nil {
		for _, iConfig := range config.Interceptors {
			if iConfig.Disable {
				mainLogger.Warn("interceptor %s disabled", iConfig.Name)
				continue
			}

			interceptor, err := buildInterceptor(&iConfig, config, &proxyLogger, cb, apiMux, canonicalRegistered)
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

	p := proxy.NewProxy(*config, mode, interceptorsUp, interceptorsDown, interceptorsAll, proxyLogger)
	if mode == proxy.ModeMux {
		mux := proxy.NewMux(handlers)
		p.Mux = mux
		mux.SetProxy(&p)
	}

	return &p, nil
}

func buildInterceptor(iConfig *proxy.InterceptorConfig, pConfig *proxy.ResolvedProxyConfig, logger *logging.Logger, cb InterceptorCallback, apiMux *http.ServeMux, canonicalRegistered map[string]bool) (proxy.Interceptor, error) {
	var interceptor proxy.Interceptor
	switch iConfig.Name {
	case InterceptorHexdump:
		interceptor = &hexdump.HexDumpInterceptor{Logger: logger}
	case InterceptorPcapdump:
		var pcapConfig pcapdump.PcapConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &pcapConfig); err != nil {
			return nil, err
		}

		i := pcapdump.NewPcapDumpInterceptor(pcapConfig.FilePath, pcapConfig.Truncate)
		interceptor = &i
	case InterceptorMatchReplace:
		var matchReplaceConfig replace.MatchReplaceConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &matchReplaceConfig); err != nil {
			return nil, err
		}

		if i, err := replace.NewMatchReplaceInterceptor(&matchReplaceConfig); err != nil {
			return nil, err
		} else {
			interceptor = &i
		}
	case InterceptorBridge:
		var bridgeConf bridge.BridgeConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &bridgeConf); err != nil {
			return nil, err
		}

		i := bridge.NewBridgeInterceptor(bridgeConf.Connect, logger)
		interceptor = &i
	case InterceptorDropTls:
		interceptor = &drop.DropTlsInterceptor{
			Logger: logger,
		}
	case InterceptorDbDump:
		var dbDumpConf dbdump.DbDumpConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &dbDumpConf); err != nil {
			return nil, err
		}

		i, err := dbdump.NewDbDumpInterceptor(dbDumpConf.FilePath, dbDumpConf.Truncate, dbDumpConf.ScriptsDir, *pConfig, logger)
		if err != nil {
			return nil, err
		}
		interceptor = i
	case InterceptorTamper:
		var tamperConf tamper.TamperConfig
		if err := json.Unmarshal(iConfig.ArgsJson, &tamperConf); err != nil {
			return nil, err
		}

		ti, err := tamper.NewTamperInterceptor(&tamperConf, logger)
		if err != nil {
			return nil, err
		}
		interceptor = ti
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

	if ap, ok := interceptor.(proxy.ApiProvider); ok {
		basePath := fmt.Sprintf("/%s/api/i/%s", pConfig.Name, iConfig.Name)
		ap.RegisterRoutes(apiMux, basePath)

		canonicalPath := fmt.Sprintf("/api/i/%s", iConfig.Name)
		if !canonicalRegistered[canonicalPath] {
			ap.RegisterRoutes(apiMux, canonicalPath)
			canonicalRegistered[canonicalPath] = true
		}
	}

	return interceptor, nil
}

func buildMuxHandler(muxSpec proxy.ResolvedMuxHandler, pConfig *proxy.ResolvedProxyConfig, mainLogger, proxyLogger *logging.Logger, cb InterceptorCallback, apiMux *http.ServeMux, canonicalRegistered map[string]bool) (proxy.Handler, error) {
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
			return proxy.Handler{}, err
		}

		logWriter, err := os.OpenFile(logFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return proxy.Handler{}, err
		}

		l := logging.NewLogger(logWriter, &slog.HandlerOptions{Level: level}, pConfig.LogTime)
		localLogger = &l
	}

	var iUp []proxy.Interceptor
	var iDown []proxy.Interceptor
	var iAll []proxy.Interceptor
	for _, iConfig := range muxSpec.Interceptors {
		if iConfig.Disable {
			localLogger.Warn("Interceptor %s disabled", iConfig.Name)
			continue
		}

		interceptor, err := buildInterceptor(&iConfig, pConfig, localLogger, cb, apiMux, canonicalRegistered)
		if err != nil {
			return proxy.Handler{}, err
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
			return proxy.Handler{}, fmt.Errorf("invalid direction: %s", dir)
		}

		iAll = append(iAll, interceptor)
	}

	var clientConfig *tls.Config
	var serverConfig *tls.Config
	var serverNextProtos []string
	var err error
	if muxSpec.Server != nil {
		if serverConfig, serverNextProtos, err = proxy.ParseServerConfig(muxSpec.Server); err != nil {
			return proxy.Handler{}, err
		}
	}

	if muxSpec.Client != nil {
		if clientConfig, err = proxy.ParseClientConfig(muxSpec.Client); err != nil {
			return proxy.Handler{}, err
		}
	}

	handler := proxy.Handler{
		Name:             muxSpec.Name,
		Connect:          muxSpec.ConnectEndpoint,
		Patterns:         muxSpec.Matchers,
		InterceptorsUp:   iUp,
		InterceptorsDown: iDown,
		InterceptorAll:   iAll,
		ClientConfig:     clientConfig,
		ServerConfig:     serverConfig,
		ALPNPreference:   serverNextProtos,
		Logger:           localLogger,
		Prober:           proxy.NewProber(muxSpec.Server.ALPNProbeCache),
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

func startProxy(p *proxy.Proxy, logger *logging.Logger) {
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
