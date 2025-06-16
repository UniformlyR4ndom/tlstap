package main

import (
	"crypto/tls"
	"flag"
	"log"

	"tlstap/test"
)

func main() {
	optListen := flag.String("l", "", "listen endpoint (e.g. 127.0.0.1:8000)")
	optTrigger := flag.String("trigger", "starttls", "trigger to start TLS upgrade")
	optBufSize := flag.Int("bs", 8192, "buffer size")
	optCertPem := flag.String("cert-pem", "", "path to certificate (in PEM format)")
	optCertKey := flag.String("cert-key", "", "path to certificate key")
	flag.Parse()

	if *optListen == "" {
		log.Fatal("Listen endpoint must be provided")
	}

	if *optCertPem == "" || *optCertKey == "" {
		log.Fatal("Certificate and corresponding key must be provided")
	}

	cert, err := tls.LoadX509KeyPair(*optCertPem, *optCertKey)
	checkFatal(err)

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS13,
	}

	server := test.NewEchoServer(*optListen, *optBufSize, &tlsConfig, []byte(*optTrigger))
	checkFatal(server.Start())
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
