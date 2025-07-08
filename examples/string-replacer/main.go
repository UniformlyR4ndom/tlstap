package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	main1 "tlstap/cli"
	"tlstap/intercept"
	"tlstap/logging"
	tlstap "tlstap/proxy"
)

type StringReplacer struct {
	// implements unused boilerplate (Init, Finalize, ConnectionEstablished, ConnectionTerminated)
	intercept.NullInterceptor

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

func configCallback(config tlstap.ProxyConfig, iConfig tlstap.InterceptorConfig, logger *logging.Logger) (tlstap.Interceptor, error) {
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
	main1.StartWithCli(configCallback)
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
