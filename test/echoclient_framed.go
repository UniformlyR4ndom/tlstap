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
	"tlstap/proxy"
)

type FramedEchoClient struct {
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

func NewFramedEchoClient(connect string, bufSize int, trigger []byte, config *tls.Config) FramedEchoClient {
	return FramedEchoClient{
		connect:      connect,
		bufSize:      bufSize,
		trigger:      trigger,
		tlsConfig:    config,
		upgradeAfter: -1,
		upgradeChan:  make(chan net.Conn, 1),
	}
}

func (c *FramedEchoClient) Start() error {
	conn, err := net.Dial("tcp", c.connect)
	proxy.CheckFatal(err)

	go c.forwardText(conn)
	c.readReplies(conn)
	return nil
}

func (c *FramedEchoClient) msgSent() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.lastMsgSent++
}

func (c *FramedEchoClient) msgReceived() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.lastMsgReceived++
}

func (c *FramedEchoClient) markForUpgrade() {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.upgradeAfter = c.lastMsgSent
}

func (c *FramedEchoClient) shouldUpgrade() bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.upgraded.Load() {
		return false
	}

	return c.upgradeAfter == c.lastMsgReceived
}

func (c *FramedEchoClient) readReplies(conn net.Conn) {
	buf := make([]byte, c.bufSize)
	var frameSize uint32
	for {
		binary.Read(conn, binary.LittleEndian, &frameSize)
		if int(frameSize) > len(buf) {
			log.Fatalf("Frame too large")
		}

		_, err := io.ReadFull(conn, buf[:frameSize])
		proxy.CheckFatal(err)
		c.msgReceived()

		fmt.Print(string(buf[:frameSize]))

		if c.shouldUpgrade() {
			tlsConn := tls.Client(conn, c.tlsConfig)
			proxy.CheckFatal(tlsConn.Handshake())

			conn = tlsConn
			c.upgradeChan <- tlsConn
			c.upgraded.Store(true)
		}
	}
}

func (c *FramedEchoClient) forwardText(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	for {
		text, err := reader.ReadString(byte('\n'))
		data := []byte(text)
		proxy.CheckFatal(err)

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
