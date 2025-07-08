package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	tlstap "tlstap/proxy"
	"tlstap/test"
)

type EchoClientConfig struct {
	Connect    string `json:"connect"`
	Trigger    string `json:"trigger"`
	BufferSize int    `json:"buffer-size"`

	TlsClientConfig tlstap.TlsClientConfig `json:"tls-config"`
}

func main() {
	optConfig := flag.String("config", "client-config.json", "Path to server config")
	optEnable := flag.String("enable", "", "Name of enabled config")
	flag.Parse()

	data, err := os.ReadFile(*optConfig)
	tlstap.CheckFatal(err)

	var configs map[string]EchoClientConfig
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

	tlsConfig, err := tlstap.ParseClientConfig(&config.TlsClientConfig)
	tlstap.CheckFatal(err)

	client := test.NewEchoClient(config.Connect, bufSize, []byte(trigger), tlsConfig)
	client.Start()
}
