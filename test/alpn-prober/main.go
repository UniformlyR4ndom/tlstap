package main

import (
	"crypto/tls"
	"flag"
	"log"
)

func main() {
	buf := make([]byte, 1<<10)

	optConnect := flag.String("connect", "", "Connect endpoint")
	flag.Parse()

	if *optConnect == "" {
		log.Fatalf("Connect endpoint must be given")
	}

	config := &tls.Config{
		NextProtos:         []string{"a", "b", "c"},
		InsecureSkipVerify: true,
	}

	tlsConn, err := tls.Dial("tcp", *optConnect, config)
	if err != nil {
		log.Printf("(0) next proto: %s", tlsConn.ConnectionState().NegotiatedProtocol)
		log.Fatalf("Fatal error: %v", err)
	}

	log.Printf("(1) next proto: %s", tlsConn.ConnectionState().NegotiatedProtocol)

	err = tlsConn.Handshake()
	log.Printf("(2) next proto: %s", tlsConn.ConnectionState().NegotiatedProtocol)
	checkFatal(err)

	_, err = tlsConn.Write([]byte("hi"))
	checkFatal(err)

	n, err := tlsConn.Read(buf)
	checkFatal(err)

	log.Printf("Received reply: %s", string(buf[:n]))
}

func checkFatal(err error) {
	if err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
