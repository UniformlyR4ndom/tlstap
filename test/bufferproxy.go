package test

import (
	"bytes"
	"encoding/hex"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type BufferHandler struct {
	connDown net.Conn
	connUp   net.Conn

	bufSize   int
	maxHoldMs int

	terminator sync.Once
	terminated atomic.Bool

	forwardBufDown bytes.Buffer
	forwardBufUp   bytes.Buffer

	lockBufDown sync.Mutex
	lockBufUp   sync.Mutex
}

func NewBufferHandler(connDown, connUp net.Conn, bufSize, maxHoldMs int) BufferHandler {
	return BufferHandler{
		connDown:  connDown,
		connUp:    connUp,
		bufSize:   bufSize,
		maxHoldMs: maxHoldMs,
	}
}

type BufferProxy struct {
	listen        string
	connect       string
	maxHoldTimeMs int
	bufSize       int
}

func NewBufferProxy(listen, connect string, bufSize, maxHoldMs int) BufferProxy {
	return BufferProxy{
		listen:        listen,
		connect:       connect,
		maxHoldTimeMs: maxHoldMs,
		bufSize:       bufSize,
	}
}

func (p *BufferProxy) Start() error {
	listener, err := net.Listen("tcp", p.listen)
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error establishing connection: %v", err)
			continue
		}

		go p.handleConn(conn)
	}
}

func (p *BufferProxy) handleConn(connDown net.Conn) {
	connUp, err := net.Dial("tcp", p.connect)
	if err != nil {
		log.Printf("Failed to connect to %s", p.connect)
		return
	}

	log.Printf("Established connection: %s <-> %s", connUp.LocalAddr().String(), connUp.RemoteAddr().String())

	handler := NewBufferHandler(connDown, connUp, p.bufSize, p.maxHoldTimeMs)
	handler.HandleConn()

}

func (h *BufferHandler) HandleConn() {
	defer h.connDown.Close()
	defer h.connUp.Close()

	go h.queueOneWay(h.connUp, &h.lockBufDown, &h.forwardBufDown)
	go h.queueOneWay(h.connDown, &h.lockBufUp, &h.forwardBufUp)

	for !h.terminated.Load() {
		h.forwardQueued(&h.lockBufDown, &h.forwardBufDown, h.connDown)
		h.forwardQueued(&h.lockBufUp, &h.forwardBufUp, h.connUp)
		time.Sleep(time.Duration(h.maxHoldMs) * time.Millisecond)
	}
}

func (h *BufferHandler) forwardQueued(lock *sync.Mutex, buf *bytes.Buffer, outConn net.Conn) {
	lock.Lock()
	defer lock.Unlock()
	if buf.Len() > 0 {
		log.Printf("%s -> %s: forwarding %d bytes", outConn.LocalAddr().String(), outConn.RemoteAddr().String(), buf.Len())
		outConn.Write(buf.Bytes())
		buf.Reset()
	}
}

func (h *BufferHandler) queueToBuffer(lock *sync.Mutex, buf *bytes.Buffer, data []byte) {
	lock.Lock()
	defer lock.Unlock()
	log.Printf("queued %d bytes: %s", len(data), hex.EncodeToString(preview(data)))
	buf.Write(data)
}

func (h *BufferHandler) queueOneWay(inConn net.Conn, lock *sync.Mutex, b *bytes.Buffer) {
	rcvBuf := make([]byte, h.bufSize)
	for {
		read, err := inConn.Read(rcvBuf)
		if err != nil {
			log.Printf("Got error: %v. Terminating connection", err)
			h.terminate()
			return
		}

		if read > 0 {
			h.queueToBuffer(lock, b, rcvBuf[:read])
		}
	}
}

func (h *BufferHandler) terminate() {
	h.terminator.Do(
		func() {
			now := time.Now()
			h.connDown.SetDeadline(now)
			h.connUp.SetDeadline(now)
			h.terminated.Store(true)
		})
}

func preview(b []byte) []byte {
	n := min(10, len(b))
	return b[:n]
}
