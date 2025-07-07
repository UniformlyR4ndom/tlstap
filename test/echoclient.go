package test

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

type EchoClient struct {
	connect   string
	bufSize   int
	trigger   []byte
	tlsConfig *tls.Config

	lastMsgSent     int
	lastMsgReceived int
	upgradeAfter    int

	lock sync.Mutex

	upgraded    atomic.Bool
	upgradeChan chan net.Conn
}

func NewEchoClient(connect string, bufSize int, trigger []byte, config *tls.Config) EchoClient {
	return EchoClient{
		connect:      connect,
		bufSize:      bufSize,
		trigger:      trigger,
		tlsConfig:    config,
		upgradeAfter: -1,
		upgradeChan:  make(chan net.Conn, 1),
	}
}

func (c *EchoClient) Start() error {
	conn, err := net.Dial("tcp", c.connect)
	CheckFatal(err)

	go c.forwardText(conn)
	c.readReplies(conn)
	return nil
}

func (c *EchoClient) msgSent() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.lastMsgSent++
}

func (c *EchoClient) msgReceived() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.lastMsgReceived++
}

func (c *EchoClient) markForUpgrade() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.upgradeAfter = c.lastMsgSent
}

func (c *EchoClient) shouldUpgrade() bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.upgraded.Load() {
		return false
	}

	return c.upgradeAfter == c.lastMsgReceived
}

func (c *EchoClient) readReplies(conn net.Conn) {
	buf := make([]byte, c.bufSize)
	var frameSize uint32
	for {
		binary.Read(conn, binary.LittleEndian, &frameSize)
		if int(frameSize) > len(buf) {
			log.Fatalf("Frame too large")
		}

		_, err := io.ReadFull(conn, buf[:frameSize])
		CheckFatal(err)
		c.msgReceived()

		fmt.Print(string(buf[:frameSize]))

		if c.shouldUpgrade() {
			tlsConn := tls.Client(conn, c.tlsConfig)
			CheckFatal(tlsConn.Handshake())

			conn = tlsConn
			c.upgradeChan <- tlsConn
			c.upgraded.Store(true)
		}
	}
}

func (c *EchoClient) forwardText(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	for {
		text, err := reader.ReadString(byte('\n'))
		data := []byte(text)
		CheckFatal(err)

		frameSize := uint32(len(data))
		binary.Write(conn, binary.LittleEndian, frameSize)
		conn.Write(data)
		c.msgSent()

		if (!c.upgraded.Load()) && bytes.Contains(data, c.trigger) {
			c.markForUpgrade()
			conn = <-c.upgradeChan
		}
	}
}
