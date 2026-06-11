package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"tlstap/proxy"
)

const BufferSize = 1 << 16

func main() {
	listenAddr := flag.String("listen", "localhost:8000", "TCP listen address (e.g., localhost:8080)")
	flag.Parse()

	listener, err := net.Listen("tcp", *listenAddr)
	proxy.CheckFatal(err)
	defer listener.Close()

	fmt.Printf("Echo server listening on %s\n", *listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, BufferSize)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}

		_, err = conn.Write(buffer[:n])
		if err != nil {
			log.Printf("Error writing to connection: %v", err)
			return
		}
	}
}
