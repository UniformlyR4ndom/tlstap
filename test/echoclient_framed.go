package test

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"tlstap/proxy"
)

type echoAction int

const (
	actNone echoAction = iota
	actUpgrade
	actDowngrade
	actDowngradeC2s
	actDowngradeS2c
)

type FramedEchoClient struct {
	connect             string
	bufSize             int
	upgradeTrigger      []byte
	downgradeTrigger    []byte
	downgradeC2sTrigger []byte
	downgradeS2cTrigger []byte
	tlsConfig           *tls.Config
	rawConn             net.Conn

	lastMsgSent     int
	lastMsgReceived int
	after           map[echoAction]int // message whose echo completes the action

	lock sync.Mutex

	// whether the client->server (writeTLS) and server->client (readTLS) direction currently use TLS
	readTLS  atomic.Bool
	writeTLS atomic.Bool

	upgradeChan   chan net.Conn
	downgradeChan chan net.Conn
	c2sChan       chan struct{}
	s2cChan       chan struct{}
}

func NewFramedEchoClient(connect string, bufSize int, upgradeTrigger, downgradeTrigger, downgradeC2sTrigger, downgradeS2cTrigger []byte, config *tls.Config) FramedEchoClient {
	return FramedEchoClient{
		connect:             connect,
		bufSize:             bufSize,
		upgradeTrigger:      upgradeTrigger,
		downgradeTrigger:    downgradeTrigger,
		downgradeC2sTrigger: downgradeC2sTrigger,
		downgradeS2cTrigger: downgradeS2cTrigger,
		tlsConfig:           config,
		after:               map[echoAction]int{},
		upgradeChan:         make(chan net.Conn, 1),
		downgradeChan:       make(chan net.Conn, 1),
		c2sChan:             make(chan struct{}, 1),
		s2cChan:             make(chan struct{}, 1),
	}
}

func (c *FramedEchoClient) Start() error {
	conn, err := net.Dial("tcp", c.connect)
	proxy.CheckFatal(err)
	c.rawConn = conn

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

// actionFor determines which action, if any, the message about to be sent triggers in the current TLS state.
func (c *FramedEchoClient) actionFor(data []byte) echoAction {
	read, write := c.readTLS.Load(), c.writeTLS.Load()
	switch {
	case !read && !write && hasTrigger(data, c.upgradeTrigger):
		return actUpgrade
	case read && write && hasTrigger(data, c.downgradeTrigger):
		return actDowngrade
	case read && hasTrigger(data, c.downgradeS2cTrigger):
		return actDowngradeS2c
	case write && hasTrigger(data, c.downgradeC2sTrigger):
		return actDowngradeC2s
	}

	return actNone
}

// arm records that the echo of the message about to be sent completes the action; must happen before sending.
func (c *FramedEchoClient) arm(action echoAction) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.after[action] = c.lastMsgSent + 1
}

// echoCompletes reports whether the echo that was just received completes the action.
func (c *FramedEchoClient) echoCompletes(action echoAction) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	after, ok := c.after[action]
	return ok && after == c.lastMsgReceived
}

// drainTLS reads until the peer's close_notify.
func drainTLS(conn *tls.Conn, buf []byte) {
	for {
		_, err := conn.Read(buf)
		if err == io.EOF {
			return
		}

		proxy.CheckFatal(err)
	}
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

		switch {
		case c.echoCompletes(actUpgrade):
			tlsConn := tls.Client(conn, c.tlsConfig)
			proxy.CheckFatal(tlsConn.Handshake())

			conn = tlsConn
			c.readTLS.Store(true)
			c.writeTLS.Store(true)
			c.upgradeChan <- tlsConn
		case c.echoCompletes(actDowngrade):
			tlsConn := conn.(*tls.Conn)
			proxy.CheckFatal(tlsConn.CloseWrite())
			drainTLS(tlsConn, buf)

			proxy.CheckFatal(c.rawConn.SetWriteDeadline(time.Time{}))
			conn = c.rawConn
			c.readTLS.Store(false)
			c.writeTLS.Store(false)
			c.downgradeChan <- conn
		case c.echoCompletes(actDowngradeS2c):
			// the server ends its TLS write side; what follows is plaintext, while our writes stay TLS
			drainTLS(conn.(*tls.Conn), buf)

			conn = c.rawConn
			c.readTLS.Store(false)
			c.s2cChan <- struct{}{}
		case c.echoCompletes(actDowngradeC2s):
			c.c2sChan <- struct{}{}
		}
	}
}

// endTLSWrite ends the client->server half of the TLS session and returns the conn to continue on in plaintext.
func (c *FramedEchoClient) endTLSWrite(tlsConn *tls.Conn) net.Conn {
	proxy.CheckFatal(tlsConn.CloseWrite())
	proxy.CheckFatal(c.rawConn.SetWriteDeadline(time.Time{}))
	c.writeTLS.Store(false)

	// the peer's tls.Conn reads ahead; give it time to see the close_notify before plaintext follows
	time.Sleep(200 * time.Millisecond)
	return c.rawConn
}

func (c *FramedEchoClient) forwardText(conn net.Conn) {
	reader := bufio.NewReader(os.Stdin)
	for {
		text, err := reader.ReadString(byte('\n'))
		data := []byte(text)
		proxy.CheckFatal(err)

		action := c.actionFor(data)
		if action != actNone {
			c.arm(action)
		}

		frameSize := uint32(len(data))
		binary.Write(conn, binary.LittleEndian, frameSize)
		conn.Write(data)
		c.msgSent()

		switch action {
		case actUpgrade:
			conn = <-c.upgradeChan
		case actDowngrade:
			conn = <-c.downgradeChan
		case actDowngradeS2c:
			<-c.s2cChan
		case actDowngradeC2s:
			<-c.c2sChan
			conn = c.endTLSWrite(conn.(*tls.Conn))
		}
	}
}
