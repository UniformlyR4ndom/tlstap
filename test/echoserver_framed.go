package test

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type FramedEchoServer struct {
	listenEndpoint      string
	bufSize             int
	upgradeTrigger      []byte
	downgradeTrigger    []byte
	downgradeC2sTrigger []byte
	downgradeS2cTrigger []byte
	tlsConfig           *tls.Config
}

func NewFramedEchoServer(listen string, bufSize int, config *tls.Config, upgradeTrigger, downgradeTrigger, downgradeC2sTrigger, downgradeS2cTrigger []byte) FramedEchoServer {
	return FramedEchoServer{
		listenEndpoint:      listen,
		bufSize:             bufSize,
		tlsConfig:           config,
		upgradeTrigger:      upgradeTrigger,
		downgradeTrigger:    downgradeTrigger,
		downgradeC2sTrigger: downgradeC2sTrigger,
		downgradeS2cTrigger: downgradeS2cTrigger,
	}
}

func (s *FramedEchoServer) Start() error {
	listener, err := net.Listen("tcp", s.listenEndpoint)
	if err != nil {
		return err
	}

	log.Printf("Echo server (upgrade trigger %s, downgrade trigger %s, c2s trigger %s, s2c trigger %s) listening at %s",
		string(s.upgradeTrigger), string(s.downgradeTrigger), string(s.downgradeC2sTrigger), string(s.downgradeS2cTrigger), s.listenEndpoint)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(conn)
	}
}

func (s *FramedEchoServer) handleConn(conn net.Conn) error {
	rawConn := conn
	defer rawConn.Close()
	readConn, writeConn := conn, conn
	var tlsConn *tls.Conn
	var readTLS, writeTLS, clientCloseExpected bool
	log.Printf("Handling new connection: %s <-> %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	var frameSize uint32
	buf := make([]byte, s.bufSize)
	for {
		if err := binary.Read(readConn, binary.LittleEndian, &frameSize); err != nil {
			if clientCloseExpected && errors.Is(err, io.EOF) {
				log.Printf("Client ended its TLS session. Reading plaintext from now on. Connection %s <-> %s", conn.LocalAddr().String(), conn.RemoteAddr().String())
				readConn, readTLS, clientCloseExpected = rawConn, false, false
				continue
			}

			log.Printf("Error: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
			return err
		}

		if frameSize > uint32(s.bufSize) {
			log.Printf("Error: frame too large (%d bytes). Terminating connection %s <-> %s", frameSize, conn.LocalAddr().String(), conn.RemoteAddr().String())
			return fmt.Errorf("frame too large")
		}

		if _, err := io.ReadFull(readConn, buf[:frameSize]); err != nil {
			log.Printf("Error: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
			return err
		}

		data := buf[:frameSize]
		log.Printf("Received frame of size %d: %s", frameSize, string(data))

		binary.Write(writeConn, binary.LittleEndian, frameSize)
		writeConn.Write(data)
		switch {
		case !readTLS && !writeTLS && hasTrigger(data, s.upgradeTrigger):
			tlsConn = tls.Server(rawConn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("Error on TLS upgrade: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
				return err
			}

			readConn, writeConn = tlsConn, tlsConn
			readTLS, writeTLS = true, true
		case readTLS && writeTLS && hasTrigger(data, s.downgradeTrigger):
			if err := tlsConn.CloseWrite(); err != nil {
				log.Printf("Error on TLS downgrade: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
				return err
			}
			for {
				_, err := tlsConn.Read(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Printf("Error draining close_notify: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
					return err
				}
			}

			if err := rawConn.SetWriteDeadline(time.Time{}); err != nil {
				log.Printf("Error clearing write deadline after downgrade: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
				return err
			}

			readConn, writeConn = rawConn, rawConn
			readTLS, writeTLS = false, false
		case writeTLS && hasTrigger(data, s.downgradeS2cTrigger):
			if err := tlsConn.CloseWrite(); err != nil {
				log.Printf("Error ending the server's TLS session: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
				return err
			}

			if err := rawConn.SetWriteDeadline(time.Time{}); err != nil {
				log.Printf("Error clearing write deadline after ending the server's TLS session: %v. Terminating connection %s <-> %s", err, conn.LocalAddr().String(), conn.RemoteAddr().String())
				return err
			}

			log.Printf("Ended the server's TLS session. Writing plaintext from now on. Connection %s <-> %s", conn.LocalAddr().String(), conn.RemoteAddr().String())
			writeConn, writeTLS = rawConn, false
		case readTLS && hasTrigger(data, s.downgradeC2sTrigger):
			clientCloseExpected = true
		}
	}
}
