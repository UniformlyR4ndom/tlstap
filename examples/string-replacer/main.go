package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"tlstap/cli"
	"tlstap/logging"
	tlstap "tlstap/proxy"
)

type StringReplacer struct {
	// implements unused boilerplate (Init, Finalize, ConnectionEstablished, ConnectionTerminated)
	tlstap.NullInterceptor

	replacements map[string]string
}

type ReplacerConfig struct {
	Replacements map[string]string `json:"replacements"`
}

func (i *StringReplacer) Intercept(info *tlstap.ConnInfo, data []byte) ([]byte, error) {
	str := string(data)
	for k, v := range i.replacements {
		str = strings.ReplaceAll(str, k, v)
	}

	return []byte(str), nil
}

func configCallback(config tlstap.ProxyConfig, logger *logging.Logger) (tlstap.Interceptor, error) {
	if config.Interceptor != "replacer" {
		return nil, fmt.Errorf("unexpected interceptor name: %s", config.Interceptor)
	}

	var rConf ReplacerConfig
	checkFatal(json.Unmarshal(config.InterceptorArgsJson, &rConf))

	logger.Info("Replacer config: %v", rConf)
	i := StringReplacer{
		replacements: rConf.Replacements,
	}

	return &i, nil
}

func main() {
	cli.StartWithCli(configCallback)
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
