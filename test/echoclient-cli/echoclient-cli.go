package main

import (
	"crypto/tls"
	"flag"
	"log"

	"tlstap/test"
)

func main() {
	optConnect := flag.String("c", "", "connect endpoint (e.g. 127.0.0.1:8000)")
	optTrigger := flag.String("trigger", "starttls", "trigger to start TLS upgrade")
	optBufSize := flag.Int("bs", 8192, "buffer size")
	flag.Parse()

	if *optConnect == "" {
		log.Fatal("Connect endpoint must be provided")
	}

	tlsConfig := tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	client := test.NewEchoClient(*optConnect, *optBufSize, []byte(*optTrigger), &tlsConfig)
	client.Start()
}
