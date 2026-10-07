package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	corefs "tlstap/core/fs"
	corekv "tlstap/core/kv"
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

// Graceful-shutdown timeouts. Hardcoded rather than exposed in config.json for now — easy
// to make configurable later if these prove wrong in practice.
const (
	drainTimeout       = 10 * time.Second // waiting for in-flight proxy connections to finish
	finalizeTimeout    = 5 * time.Second  // waiting for every interceptor's Finalize()
	apiShutdownTimeout = 5 * time.Second  // waiting for the API server's Shutdown()
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

// InstanceInfo describes one interceptor instance reachable over the REST API, for the
// GET /api/instances discovery endpoint. Populated for every interceptor that implements
// proxy.ApiProvider, regardless of type, so the web frontend can pick among multiple
// proxies' instances of the same interceptor (e.g. dbdump, tamper) instead of only ever
// reaching whichever one claimed the canonical /api/i/<name> alias.
type InstanceInfo struct {
	Proxy       string `json:"proxy"`
	Interceptor string `json:"interceptor"`
	BasePath    string `json:"basePath"`
}

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
	instances := []InstanceInfo{}
	apiMux := http.NewServeMux()

	sub, _ := fs.Sub(tlstapweb.FS, ".")
	apiMux.Handle("/ui/", http.StripPrefix("/ui", http.FileServer(http.FS(sub))))
	apiMux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusFound)
	})

	// Core services: like /ui/ above, registered directly here rather than discovered
	// from a proxy's interceptor list, since they aren't tied to any one proxy or
	// interceptor chain. Nested under Api (api.core-services in config.json) since they
	// have no purpose except being reached through this same API server. See
	// doc/design/core-kv-store.md.
	var coreServices []CoreService
	var coreConfig *proxy.CoreConfig
	if configFile.Api != nil {
		coreConfig = configFile.Api.CoreServices
	}
	if coreConfig != nil && coreConfig.Kv != nil {
		kvStore, err := corekv.New(coreConfig.Kv.File)
		checkFatal(&mainLogger, err)
		kvStore.RegisterRoutes(apiMux, "/api/core/kv")
		coreServices = append(coreServices, kvStore)
	}
	if coreConfig != nil && coreConfig.Fs != nil {
		fsStore, err := corefs.New(coreConfig.Fs.Dir)
		checkFatal(&mainLogger, err)
		fsStore.RegisterRoutes(apiMux, "/api/core/fs")
		coreServices = append(coreServices, fsStore)
	}

	var allProxies []*proxy.Proxy

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
			proxy, err = proxyFromConfig(&pConfig, resolvedHandlers, &mainLogger, interceptorCallback, apiMux, canonicalRegistered, &instances)
			checkFatal(&mainLogger, err)
		} else {
			proxy, err = proxyFromConfig(&pConfig, nil, &mainLogger, interceptorCallback, apiMux, canonicalRegistered, &instances)
			checkFatal(&mainLogger, err)
		}

		allProxies = append(allProxies, proxy)
		go startProxy(proxy, &mainLogger)
	}

	// Lets the web frontend discover every interceptor instance's own proxy-scoped base
	// path, rather than only ever reaching whichever one claimed the canonical
	// /api/i/<name> alias above.
	apiMux.HandleFunc("GET /api/instances", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(instances)
	})

	var apiServers []*http.Server
	if configFile.Api != nil {
		// Built once, shared by every "https" entry below (a single cert/client-auth
		// policy for the whole API server, not one per URL) — cheap prefix scan first so
		// a missing/invalid cert fails fast, before any listener (http or https) has
		// been opened.
		var tlsConfig *tls.Config
		for _, baseUrl := range configFile.Api.BaseUrls {
			if strings.HasPrefix(baseUrl, "https://") {
				tlsConfig = buildApiTlsConfig(configFile.Api, &mainLogger)
				break
			}
		}

		for _, baseUrl := range configFile.Api.BaseUrls {
			addr, scheme := parseApiBaseUrl(baseUrl, &mainLogger)
			apiServer := &http.Server{Addr: addr, Handler: apiMux}
			if scheme == "https" {
				apiServer.TLSConfig = tlsConfig
			}
			apiServers = append(apiServers, apiServer)
			mainLogger.Info("Starting API server at %s (%s)", addr, baseUrl)
			go func(apiServer *http.Server, scheme, baseUrl string) {
				var err error
				if scheme == "https" {
					err = apiServer.ListenAndServeTLS("", "")
				} else {
					err = apiServer.ListenAndServe()
				}
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					mainLogger.Error("API server (%s): %v", baseUrl, err)
				}
			}(apiServer, scheme, baseUrl)
		}
	}

	// sigCh receives every SIGINT/SIGTERM for the rest of the process's life: the first
	// one (blocked on below) starts the graceful sequence; shutdown() itself keeps reading
	// from the same channel so a second one, received at any point, forces an immediate exit.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	mainLogger.Info("Shutdown signal received, shutting down gracefully...")

	shutdown(allProxies, coreServices, apiServers, sigCh, &mainLogger)
}

// parseApiBaseUrl validates baseUrl (must have an "http"/"https" scheme, a host:port, and
// no path — see ApiConfig.BaseUrls) and returns the host:port to listen on and the
// scheme ("http" or "https"), the latter deciding whether that listener needs the shared
// TLS config (see buildApiTlsConfig).
func parseApiBaseUrl(baseUrl string, logger *logging.Logger) (addr, scheme string) {
	// Checked as a plain prefix before parsing so the common mistake (a bare host:port,
	// with no scheme at all) gets this clear message instead of url.Parse's own — a bare
	// "host:port" parses as a URL whose "scheme" is the host and whose "path" starts with
	// the port, rejected for containing a colon, which reads as a non sequitur here.
	if !strings.HasPrefix(baseUrl, "http://") && !strings.HasPrefix(baseUrl, "https://") {
		logger.Fatal(`api base-url %q must start with "http://" or "https://"`, baseUrl)
	}
	u, err := url.Parse(baseUrl)
	if err != nil {
		logger.Fatal("Invalid api base-url %q: %v", baseUrl, err)
	}
	if u.Host == "" {
		logger.Fatal("api base-url %q is missing a host:port", baseUrl)
	}
	if u.Path != "" && u.Path != "/" {
		logger.Fatal("api base-url %q must not include a path", baseUrl)
	}
	return u.Host, u.Scheme
}

// buildApiTlsConfig builds the tls.Config shared by every "https" api.base-urls entry
// (one config for the whole API server, not one per URL): the server certificate
// (required — see ApiConfig.CertPem/CertKey) and, if configured, a client-certificate
// trust pool plus authentication policy for optional or mandatory mutual TLS
// (ApiConfig.ClientRoots/ClientAuthPolicy — same shape as TlsServerConfig's own fields,
// reusing proxy.LoadCertPool/ParseClientAuthPolicy directly). Fatal on any load/parse
// failure, since at least one base-urls entry has already committed to https by the time
// this is called. Any explicitly-set ClientAuthPolicy other than "require-and-verify"
// (including "none") logs a warning — every other policy either skips verification
// entirely, doesn't cryptographically verify the chain, or doesn't require a cert at all.
func buildApiTlsConfig(apiConfig *proxy.ApiConfig, logger *logging.Logger) *tls.Config {
	if apiConfig.CertPem == "" || apiConfig.CertKey == "" {
		logger.Fatal("api.cert-pem and api.cert-key are required when any api.base-urls entry uses https")
	}
	cert, err := tls.LoadX509KeyPair(apiConfig.CertPem, apiConfig.CertKey)
	checkFatal(logger, err)

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	if apiConfig.ClientRoots != "" {
		clientCAs, err := proxy.LoadCertPool(apiConfig.ClientRoots)
		checkFatal(logger, err)
		tlsConfig.ClientCAs = clientCAs
	}
	if apiConfig.ClientAuthPolicy != "" {
		clientAuthType, err := proxy.ParseClientAuthPolicy(apiConfig.ClientAuthPolicy)
		checkFatal(logger, err)
		tlsConfig.ClientAuth = clientAuthType
		if clientAuthType != tls.RequireAndVerifyClientCert {
			logger.Warn(`api.client-auth is %q, not "require-and-verify"; client certificates are not both required and cryptographically verified`, apiConfig.ClientAuthPolicy)
		}
	}

	return tlsConfig
}

// shutdown runs the graceful-shutdown sequence: stop accepting new work everywhere (close
// every proxy's listener, start every API server's Shutdown), let it all drain
// concurrently bounded by their own timeouts, then finalize every interceptor and core
// service. A second SIGINT/SIGTERM arriving on sigCh at any point during this forces an
// immediate os.Exit(1) instead of waiting for the sequence to finish on its own.
func shutdown(proxies []*proxy.Proxy, coreServices []CoreService, apiServers []*http.Server, sigCh <-chan os.Signal, logger *logging.Logger) {
	go func() {
		<-sigCh
		logger.Warn("Second shutdown signal received, forcing immediate exit.")
		os.Exit(1)
	}()

	for _, p := range proxies {
		p.Stop()
	}

	var drainWg sync.WaitGroup
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), drainTimeout)
	defer cancelDrain()

	drainWg.Add(len(proxies))
	for _, p := range proxies {
		go func(p *proxy.Proxy) {
			defer drainWg.Done()
			if !p.WaitForConnections(drainCtx) {
				logger.Warn("Timed out waiting for in-flight connections on %s to finish.", p.Config.Name)
			}
		}(p)
	}

	drainWg.Add(len(apiServers))
	for _, apiServer := range apiServers {
		go func(apiServer *http.Server) {
			defer drainWg.Done()
			apiCtx, cancelApi := context.WithTimeout(context.Background(), apiShutdownTimeout)
			defer cancelApi()
			if err := apiServer.Shutdown(apiCtx); err != nil {
				logger.Warn("API server shutdown: %v", err)
			}
		}(apiServer)
	}
	drainWg.Wait()

	finalizeDone := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		wg.Add(len(proxies) + len(coreServices))
		for _, p := range proxies {
			go func(p *proxy.Proxy) {
				defer wg.Done()
				p.Finalize()
			}(p)
		}
		for _, cs := range coreServices {
			go func(cs CoreService) {
				defer wg.Done()
				cs.Finalize()
			}(cs)
		}
		wg.Wait()
		close(finalizeDone)
	}()

	select {
	case <-finalizeDone:
		logger.Info("All interceptors and core services finalized.")
	case <-time.After(finalizeTimeout):
		logger.Warn("Timed out waiting for interceptors and core services to finalize; exiting anyway.")
	}

	logger.Info("Shutdown complete.")
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

func proxyFromConfig(config *proxy.ResolvedProxyConfig, muxHandlers []proxy.ResolvedMuxHandler, mainLogger *logging.Logger, cb InterceptorCallback, apiMux *http.ServeMux, canonicalRegistered map[string]bool, instances *[]InstanceInfo) (*proxy.Proxy, error) {
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
			handler, err := buildMuxHandler(h, config, mainLogger, &proxyLogger, cb, apiMux, canonicalRegistered, instances)
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

			interceptor, err := buildInterceptor(&iConfig, config, &proxyLogger, cb, apiMux, canonicalRegistered, instances)
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
		mux.SetProxy(p)
	}

	return p, nil
}

func buildInterceptor(iConfig *proxy.InterceptorConfig, pConfig *proxy.ResolvedProxyConfig, logger *logging.Logger, cb InterceptorCallback, apiMux *http.ServeMux, canonicalRegistered map[string]bool, instances *[]InstanceInfo) (proxy.Interceptor, error) {
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

		i, err := dbdump.NewDbDumpInterceptor(dbDumpConf.FilePath, dbDumpConf.Truncate, dbDumpConf.ScriptsDir, dbDumpConf.DissectScriptsDir, *pConfig, logger)
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
		*instances = append(*instances, InstanceInfo{Proxy: pConfig.Name, Interceptor: iConfig.Name, BasePath: basePath})

		canonicalPath := fmt.Sprintf("/api/i/%s", iConfig.Name)
		if !canonicalRegistered[canonicalPath] {
			ap.RegisterRoutes(apiMux, canonicalPath)
			canonicalRegistered[canonicalPath] = true
		}
	}

	return interceptor, nil
}

func buildMuxHandler(muxSpec proxy.ResolvedMuxHandler, pConfig *proxy.ResolvedProxyConfig, mainLogger, proxyLogger *logging.Logger, cb InterceptorCallback, apiMux *http.ServeMux, canonicalRegistered map[string]bool, instances *[]InstanceInfo) (proxy.Handler, error) {
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

		interceptor, err := buildInterceptor(&iConfig, pConfig, localLogger, cb, apiMux, canonicalRegistered, instances)
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
