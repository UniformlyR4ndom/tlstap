package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"tlstap/cli"
	"tlstap/intercept"
	"tlstap/logging"
	proxy "tlstap/proxy"
)

type StringReplacer struct {
	// implements unused boilerplate (Init, Finalize, ConnectionEstablished, ConnectionTerminated)
	intercept.NullInterceptor

	replacements map[string]string
}

type ReplacerConfig struct {
	Replacements map[string]string `json:"replacements"`
}

func (i *StringReplacer) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	str := string(data)
	for k, v := range i.replacements {
		str = strings.ReplaceAll(str, k, v)
	}

	return []byte(str), nil
}

func configCallback(config proxy.ResolvedProxyConfig, iConfig proxy.InterceptorConfig, logger *logging.Logger) (proxy.Interceptor, error) {
	if iConfig.Name != "replacer" {
		return nil, fmt.Errorf("unexpected interceptor name: %s", iConfig.Name)
	}

	var rConf ReplacerConfig
	err := json.Unmarshal(iConfig.ArgsJson, &rConf)
	checkFatal(err)

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
