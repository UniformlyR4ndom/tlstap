package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"

	"tlstap/intercept"
	"tlstap/logging"
	tlstap "tlstap/proxy"
)

type InterceptorCallback func(config tlstap.ResolvedProxyConfig, iConfig tlstap.InterceptorConfig, logger *logging.Logger) (tlstap.Interceptor, error)

// TODO: add callback mechanism
func StartWithCli(interceptorCallback InterceptorCallback) {
	optEnable := flag.String("enable", "", `Comma-separated list of proxy configurations to enable (e.g. "myconfig-a,myconfig-b")`)
	optConfig := flag.String("config", "config.json", "Path to configuration file (JSON)")
	flag.Parse()

	mainLogger := logging.NewLogger(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
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

		if len(config.InterceptorsRefs) > 0 {
			interceptors := make([]tlstap.InterceptorConfig, len(config.InterceptorsRefs))
			for i, iConfigRef := range config.InterceptorsRefs {
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

		proxy, err := proxyFromConfig(&pConfig, &mainLogger, interceptorCallback)
		checkFatal(&mainLogger, err)
		go startProxy(proxy, &mainLogger)
	}

	// TODO: can we do better?
	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}

func proxyFromConfig(config *tlstap.ResolvedProxyConfig, logger *logging.Logger, cb InterceptorCallback) (*tlstap.Proxy, error) {
	var mode tlstap.Mode
	switch m := strings.ToLower(strings.TrimSpace(config.Mode)); m {
	case "plain":
		mode = tlstap.ModePlain
	case "tls":
		mode = tlstap.ModeTls
	case "detecttls":
		mode = tlstap.ModeDetectTls
	case "tls-mux":
		logger.Error("TODO: implement tls-mux")
	default:
		return nil, fmt.Errorf("invalid proxy mode: %s", config.Mode)
	}

	logWriter := os.Stdout
	if config.LogFile != "" {
		logFile, err := os.OpenFile(config.LogFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return nil, err
		}
		logWriter = logFile
	}

	logLevel := slog.LevelInfo
	switch l := strings.TrimSpace(strings.ToLower(config.LogLevel)); l {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	proxyLogger := logging.NewLogger(logWriter, &slog.HandlerOptions{Level: logLevel})
	var interceptorsUp []tlstap.Interceptor
	var interceptorsDown []tlstap.Interceptor
	var interceptorsAll []tlstap.Interceptor
	if config.Interceptors != nil {
		for _, iConfig := range config.Interceptors {
			if iConfig.Disable {
				logger.Warn("interceptor %s disabled", iConfig.Name)
				continue
			}

			var interceptor tlstap.Interceptor
			switch iConfig.Name {
			case "hexdump":
				interceptor = &intercept.HexDumpInterceptor{Logger: &proxyLogger}
			case "bridge":
				var bridgeConf intercept.BridgeConfig
				if err := json.Unmarshal(iConfig.ArgsJson, &bridgeConf); err != nil {
					return nil, err
				}

				i := intercept.NewBridgeInterceptor(bridgeConf.Connect, logger)
				interceptor = &i
			case "pcapdump":
				var pcapConfig intercept.PcapConfig
				if err := json.Unmarshal(iConfig.ArgsJson, &pcapConfig); err != nil {
					return nil, err
				}

				i := intercept.NewPcapDumpInterceptor(pcapConfig.FilePath, pcapConfig.Truncate)
				interceptor = &i
			case "none", "null", "nil", "":
				// ignore
			default:
				var err error
				if cb != nil {
					interceptor, err = cb(*config, iConfig, logger)
				}

				switch {
				case err != nil:
					return nil, err
				case interceptor == nil:
					return nil, fmt.Errorf("unknown (custom) interceptor: %s", iConfig.Name)
				}
			}

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
	return &p, nil
}

func startProxy(p *tlstap.Proxy, logger *logging.Logger) {
	err := p.Start()
	checkFatal(logger, err)
}

func checkFatal(logger *logging.Logger, err error) {
	if err != nil {
		logger.Fatal("Fatal error: %v", err)
	}
}
