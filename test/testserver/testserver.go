package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"strings"
)

const (
	BufSize = 1 << 16
)

func main() {
	optListen := flag.String("l", "", "listen endpoint")
	optMode := flag.String("mode", "", "mode (plain, tls, or starttls)")
	optCertPem := flag.String("cert-pem", "", "path to certificate file (in PEM format)")
	optCertKey := flag.String("cert-key", "", "path to certificate key (in PEM format)")
	optClientAuth := flag.Bool("client-auth", false, "require client auth")
	acceptProto := flag.String("accept-proto", "", "ALPN value to accept")
	flag.Parse()

	switch mode := strings.ToLower(*optMode); mode {
	case "plain":
		startPlainEchoServer(*optListen)
	case "tls":
		if *optCertPem == "" || *optCertKey == "" {
			log.Fatalf("certificate and key must be provided")
		}

		cert, err := tls.LoadX509KeyPair(*optCertPem, *optCertKey)
		checkFatal(err)
		startTlsEchoServer(*optListen, &cert, *optClientAuth, *acceptProto)
	default:
		log.Fatalf("invalid mode: %s", mode)
	}

	log.Printf("Testserver listening at %s", *optListen)

}

func startPlainEchoServer(listenEndpoint string) {
	listener, err := net.Listen("tcp", listenEndpoint)
	checkFatal(err)
	for {
		conn, err := listener.Accept()
		checkFatal(err)
		go handleEcho(conn)
	}
}

func startTlsEchoServer(listenEndpoint string, cert *tls.Certificate, requireClientAuth bool, proto string) {
	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS10,
	}

	if requireClientAuth {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	if proto != "" {
		config.NextProtos = []string{proto}
	}

	listener, err := tls.Listen("tcp", listenEndpoint, config)
	checkFatal(err)
	for {
		conn, err := listener.Accept()
		checkFatal(err)
		go handleEcho(conn)
	}
}

func handleEcho(conn net.Conn) {
	buf := make([]byte, BufSize)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Error handling connection: %v", err)
			return
		}

		conn.Write(buf[:n])
	}
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
