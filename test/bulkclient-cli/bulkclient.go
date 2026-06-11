package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"tlstap/proxy"
)

type BulkClientConfig struct {
	Connect      string `json:"connect"`
	MessageSizes []int  `json:"msg-sizes"`
}

func main() {
	optConfig := flag.String("config", "bulkclient-config.json", "Path to server config")
	optEnable := flag.String("enable", "", "Name of enabled config")
	flag.Parse()

	data, err := os.ReadFile(*optConfig)
	proxy.CheckFatal(err)

	var configs map[string]BulkClientConfig
	err = json.Unmarshal(data, &configs)
	proxy.CheckFatal(err)

	config, ok := configs[*optEnable]
	if !ok {
		log.Fatalf("config %s not found", *optEnable)
	}

	conn, err := net.Dial("tcp", config.Connect)
	proxy.CheckFatal(err)

	for i, s := range config.MessageSizes {
		msg := buildMessage(s, i)
		_, err := conn.Write(msg)
		proxy.CheckFatal(err)

		_, err = io.ReadFull(conn, msg)
		proxy.CheckFatal(err)
	}

	log.Printf("Exchanged %d messages", len(config.MessageSizes))
}

func buildMessage(size, id int) []byte {
	prefix := fmt.Sprintf("#%08d", id)
	if size < len(prefix) {
		prefix = ""
	}

	return append([]byte(prefix), make([]byte, size-len(prefix))...)
}
