package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	tlstap "tlstap/proxy"
	"tlstap/test"
)

type EchoServerConfig struct {
	Listen     string `json:"listen"`
	Trigger    string `json:"trigger"`
	BufferSize int    `json:"buffer-size"`

	TlsServerConfig tlstap.TlsServerConfig `json:"tls-config"`
}

func main() {
	optConfig := flag.String("config", "server-config.json", "Path to server config")
	optEnable := flag.String("enable", "", "Name of enabled config")
	flag.Parse()

	data, err := os.ReadFile(*optConfig)
	tlstap.CheckFatal(err)

	var configs map[string]EchoServerConfig
	err = json.Unmarshal(data, &configs)
	tlstap.CheckFatal(err)

	config, ok := configs[*optEnable]
	if !ok {
		log.Fatalf("config %s not found", *optEnable)
	}

	bufSize := 8192
	if config.BufferSize > 0 {
		bufSize = config.BufferSize
	}

	trigger := "starttls"
	if config.Trigger != "" {
		trigger = config.Trigger
	}

	tlsConfig, _, err := tlstap.ParseServerConfig(&config.TlsServerConfig)
	tlstap.CheckFatal(err)

	server := test.NewEchoServer(config.Listen, bufSize, tlsConfig, []byte(trigger))
	tlstap.CheckFatal(server.Start())
}
