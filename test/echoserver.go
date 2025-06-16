package test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

type EchoServer struct {
	listenEndpoint string
	bufSize        int
	trigger        []byte
	tlsConfig      *tls.Config
}

func NewEchoServer(listen string, bufSize int, config *tls.Config, trigger []byte) EchoServer {
	return EchoServer{
		listenEndpoint: listen,
		bufSize:        bufSize,
		tlsConfig:      config,
		trigger:        trigger,
	}
}

func (s *EchoServer) Start() error {
	listener, err := net.Listen("tcp", s.listenEndpoint)
	if err != nil {
		return err
	}

	log.Printf("Echo server (tigger %s) listening at %s", string(s.trigger), s.listenEndpoint)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(conn)
	}
}

func (s *EchoServer) handleConn(conn net.Conn) error {
	var upgraded bool
	log.Printf("Hanndling new connection: %s <-> %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	var frameSize uint32
	buf := make([]byte, s.bufSize)
	for {
		if err := binary.Read(conn, binary.LittleEndian, &frameSize); err != nil {
			log.Printf("Error: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
			return err
		}

		if frameSize > uint32(s.bufSize) {
			log.Printf("Error: frame too large (%d bytes). Terminating connection %s <-> %s", frameSize, conn.LocalAddr().String(), conn.RemoteAddr().String())
			return fmt.Errorf("frame too large")
		}

		if _, err := io.ReadFull(conn, buf[:frameSize]); err != nil {
			log.Printf("Error: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
			return err
		}

		data := buf[:frameSize]
		log.Printf("Received frame of size %d: %s", frameSize, string(data))

		binary.Write(conn, binary.LittleEndian, frameSize)
		conn.Write(data)
		if !upgraded && bytes.Contains(data, s.trigger) {
			tlsConn := tls.Server(conn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("Error on TLS upgrade: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
				return err
			}

			conn = tlsConn
			upgraded = true
		}
	}
}
