package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"tlstap/proxy"
	"tlstap/test"
)

type EchoServerConfig struct {
	Listen           string `json:"listen"`
	TriggerUpgrade   string `json:"trigger-upgrade"`
	TriggerDowngrade string `json:"trigger-downgrade"`

	// downgrade only the client->server / server->client direction
	TriggerDowngradeC2s string `json:"trigger-downgrade-c2s"`
	TriggerDowngradeS2c string `json:"trigger-downgrade-s2c"`

	BufferSize int `json:"buffer-size"`

	TlsServerConfig proxy.TlsServerConfig `json:"tls-config"`
}

func main() {
	optConfig := flag.String("config", "server-config.json", "Path to server config")
	optEnable := flag.String("enable", "", "Name of enabled config")
	flag.Parse()

	data, err := os.ReadFile(*optConfig)
	proxy.CheckFatal(err)

	var configs map[string]EchoServerConfig
	err = json.Unmarshal(data, &configs)
	proxy.CheckFatal(err)

	config, ok := configs[*optEnable]
	if !ok {
		log.Fatalf("config %s not found", *optEnable)
	}

	bufSize := 8192
	if config.BufferSize > 0 {
		bufSize = config.BufferSize
	}

	triggerUpgrade := "starttls"
	if config.TriggerUpgrade != "" {
		triggerUpgrade = config.TriggerUpgrade
	}

	triggerDowngrade := "stoptls"
	if config.TriggerDowngrade != "" {
		triggerDowngrade = config.TriggerDowngrade
	}

	triggerDowngradeC2s := "c2s-plain"
	if config.TriggerDowngradeC2s != "" {
		triggerDowngradeC2s = config.TriggerDowngradeC2s
	}

	triggerDowngradeS2c := "s2c-plain"
	if config.TriggerDowngradeS2c != "" {
		triggerDowngradeS2c = config.TriggerDowngradeS2c
	}

	tlsConfig, _, err := proxy.ParseServerConfig(&config.TlsServerConfig)
	proxy.CheckFatal(err)

	server := test.NewFramedEchoServer(config.Listen, bufSize, tlsConfig, []byte(triggerUpgrade), []byte(triggerDowngrade), []byte(triggerDowngradeC2s), []byte(triggerDowngradeS2c))
	proxy.CheckFatal(server.Start())
}
