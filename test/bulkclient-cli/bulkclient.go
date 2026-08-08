package main

import (
	"encoding/binary"
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
	optLengthPrefix := flag.Bool("length-prefix", false, "Prefix each message with its own 4-byte big-endian length, for testing length-prefixed framer scripts (see examples/dbdump/framer/length-prefix-framer.js)")
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
		msg := buildMessage(s, i, *optLengthPrefix)
		_, err := conn.Write(msg)
		proxy.CheckFatal(err)

		_, err = io.ReadFull(conn, msg)
		proxy.CheckFatal(err)
	}

	log.Printf("Exchanged %d messages", len(config.MessageSizes))
}

// buildMessage's returned payload is always exactly `size` bytes, length-prefix or not —
// the prefix (when present) covers just that payload length and is additive on top.
func buildMessage(size, id int, lengthPrefix bool) []byte {
	prefix := fmt.Sprintf("#%08d", id)
	if size < len(prefix) {
		prefix = ""
	}

	payload := append([]byte(prefix), make([]byte, size-len(prefix))...)
	if !lengthPrefix {
		return payload
	}

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	return append(header, payload...)
}
