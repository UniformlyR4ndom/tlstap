package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"tlstap/test"
)

type EchoClientConfig struct {
	Connect    string `json:"connect"`
	Trigger    string `json:"trigger"`
	BufferSize int    `json:"buffer-size"`

	TlsClientConfig test.TlsClientConfig `json:"tls-config"`
}

func main() {
	optConfig := flag.String("config", "client-config.json", "Path to server config")
	optEnable := flag.String("enable", "", "Name of enabled config")
	flag.Parse()

	data, err := os.ReadFile(*optConfig)
	test.CheckFatal(err)

	var configs map[string]EchoClientConfig
	err = json.Unmarshal(data, &configs)
	test.CheckFatal(err)

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

	tlsConfig, err := test.ParseClientConfig(&config.TlsClientConfig)
	test.CheckFatal(err)

	client := test.NewEchoClient(config.Connect, bufSize, []byte(trigger), tlsConfig)
	client.Start()
}
