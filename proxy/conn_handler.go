package tlstap

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"tlstap/assert"
	"tlstap/logging"
)

const (
	bufSize        = 1 << 16 // TODO: make configurable
	drainTimeoutMs = 10
)

type ConnHandler struct {
	Setting ConnSettings

	ConnId uint32

	InterceptorsUp   []Interceptor
	InterceptorsDown []Interceptor

	ConnUp   net.Conn
	ConnDown net.Conn

	logger *logging.Logger

	terminator sync.Once

	wg            sync.WaitGroup
	eofEncounterd atomic.Bool

	upgradeChan    chan bool
	upgradeAckChan chan bool
}

func (h *ConnHandler) HandleConnection(conn net.Conn) error {
	var err error
	switch h.Setting.Mode {
	case ModePlain:
		err = h.forwardPlain(conn)
	case ModeTls, ModeMux:
		c, ok := conn.(*tls.Conn)
		assert.Assertf(ok, "conn must be of type *tls.Conn")
		err = h.forwardTls(c)
	case ModeDetectTls:
		err = h.forwardDetectTls(conn)
	default:
		err = fmt.Errorf("invalid mode: %v", h.Setting.Mode)
	}

	if err != nil {
		h.logger.Error("%s", err)
	}

	return err
}

func (h *ConnHandler) forwardPlain(conn net.Conn) error {
	h.ConnDown = conn
	defer conn.Close()

	connUp, err := net.Dial("tcp", h.Setting.ConnectEndpoint)
	if err != nil {
		return err
	}

	h.ConnUp = connUp
	defer connUp.Close()

	return h.forwardGeneric()
}

func (h *ConnHandler) forwardTls(conn *tls.Conn) error {
	h.ConnDown = conn
	defer conn.Close()

	connUp, err := tls.Dial("tcp", h.Setting.ConnectEndpoint, h.Setting.TlsClientConfig)
	if err != nil {
		return err
	}

	h.ConnUp = connUp
	defer connUp.Close()

	lDown := h.ConnDown.LocalAddr().String()
	rDown := h.ConnDown.RemoteAddr().String()
	h.logger.Info("Downstream connection (%d): %s <-> %s (%s)", h.ConnId, rDown, lDown, SummarizeTlsConn(conn))

	lUp := h.ConnUp.LocalAddr().String()
	rUp := h.ConnUp.RemoteAddr().String()
	h.logger.Info("Upstream connection (%d): %s <-> %s (%s)", h.ConnId, lUp, rUp, SummarizeTlsConn(connUp))

	serverCerts := connUp.ConnectionState().PeerCertificates
	h.logger.Debug("Upstream server certificate chain:\n%s", chainToStringX509(serverCerts))

	return h.forwardGeneric()
}

func (h *ConnHandler) forwardDetectTls(conn net.Conn) error {
	h.upgradeChan = make(chan bool, 1)
	h.upgradeAckChan = make(chan bool, 1)

	bufConnDown := NewBufConn(conn, bufSize)
	h.ConnDown = bufConnDown
	defer conn.Close()

	connUp, err := net.Dial("tcp", h.Setting.ConnectEndpoint)
	if err != nil {
		return err
	}

	h.ConnUp = connUp
	defer connUp.Close()

	h.logger.Info("Forwarding %s <-> %s", h.ConnDown.RemoteAddr().String(), h.ConnUp.RemoteAddr().String())
	if err := h.notifyConnEstablished(); err != nil {
		return err
	}

	h.wg.Add(1)
	go h.forwardDetectTlsDown()
	h.forwardDetectTlsUp(bufConnDown, false)

	h.wg.Wait()
	h.notifyConnTerminated()
	return nil
}

func (h *ConnHandler) forwardDetectTlsUp(connDown *BufferedConn, search bool) error {
	buf := make([]byte, bufSize)
	connInfo := NewConnInfo(connDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	for {
		peeked, err := connDown.Peek(buf)
		if err != nil {
			h.logger.Error("Failed to peek downstream connection: %v", err)
			h.terminate()
			return err
		}

		if peeked == 0 {
			continue
		}

		result := DetectClientHello(buf[:peeked], true, search)
		if result == nil || len(result.SupportedVersions) == 0 {
			read, err := connDown.Read(buf[:peeked])
			assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)
			assert.Assertf(read == peeked, "Peeked %d bytes but read %d bytes. This is a bug.", peeked, read)

			if data := h.intercept(h.InterceptorsUp, buf[:read], &connInfo); len(data) > 0 {
				h.ConnUp.Write(data)
			}
			continue
		}

		// TLS client hello detected
		if result.StartIndex > 0 {
			read, err := connDown.Read(buf[:result.StartIndex])
			assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)
			assert.Assertf(read == result.StartIndex, "Expected to read %d bytes but read %d. This is a bug.", result.StartIndex, read)

			if data := h.intercept(h.InterceptorsUp, buf[:read], &connInfo); len(data) > 0 {
				h.ConnUp.Write(data)
			}
		}

		h.logger.Debug("%d: TLS Client hello detected: %s", h.ConnId, hex.EncodeToString(result.ClientHello))

		// signal start of TLS upgrade
		h.upgradeChan <- true
		h.ConnUp.SetReadDeadline(time.Now())

		// wait for other forwarder to stop reading from upstream connection
		<-h.upgradeAckChan

		// drain upstream connection in case there is outstanding data sent from the sever to the client
		info := NewConnInfo(h.ConnUp.RemoteAddr(), connDown.RemoteAddr(), h.ConnId)
		if err = h.drainConn(buf, h.ConnUp, h.ConnDown, h.InterceptorsDown, &info, drainTimeoutMs); err != nil {
			h.logger.Error("Error while draining upstream connection: %v", err)
			h.upgradeChan <- false
			h.terminate()
			return err
		}

		// perform TLS server handshake towards client
		tlsConnDown := tls.Server(connDown, h.Setting.TlsServerConfig)
		if err = tlsConnDown.Handshake(); err != nil {
			h.logger.Error("Error during TLS server handshake (towards client): %v", err)
			h.upgradeChan <- false
			h.terminate()
			return err
		}

		// perform TLS client handshake towards server
		tlsConnUp := tls.Client(h.ConnUp, h.Setting.TlsClientConfig)
		if err = tlsConnUp.Handshake(); err != nil {
			h.logger.Error("Error during TLS client handshake (towards server): %v", err)
			h.upgradeChan <- false

			h.terminate()
			return err
		}

		lDown := tlsConnDown.LocalAddr().String()
		rDown := tlsConnDown.RemoteAddr().String()
		h.logger.Info("Upgraded downstream connection (%d): %s <-> %s (%s)", h.ConnId, rDown, lDown, SummarizeTlsConn(tlsConnDown))

		lUp := tlsConnUp.LocalAddr().String()
		rUp := tlsConnUp.RemoteAddr().String()
		h.logger.Info("Upgraded upstream connection (%d): %s <-> %s (%s)", h.ConnId, lUp, rUp, SummarizeTlsConn(tlsConnUp))

		h.ConnDown = tlsConnDown
		h.ConnUp = tlsConnUp

		// signal completion of TLS upgrade
		h.upgradeChan <- true
		return h.forwardOneWay(tlsConnDown, tlsConnUp, buf, h.InterceptorsUp, &connInfo)
	}
}

func (h *ConnHandler) forwardDetectTlsDown() error {
	buf := make([]byte, bufSize)
	connInfo := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)

	for {
		read, err := h.ConnUp.Read(buf)
		switch {
		case err == nil:
			if data := h.intercept(h.InterceptorsDown, buf[:read], &connInfo); len(data) > 0 {
				h.ConnDown.Write(data)
			}
		case len(h.upgradeChan) > 0 && errors.Is(err, os.ErrDeadlineExceeded):
			<-h.upgradeChan

			// signal that this routine is no longer reading from the upstream connection
			h.upgradeAckChan <- true

			// wait for completion of the TLS upgrade
			<-h.upgradeChan
		default:
			h.logger.Error("Failed to read from upstream connection: %v", err)
			h.terminate()
			return err
		}
	}
}

// Drain connIn: read and forward data until no data was received for at least timeoutMs milliseconds.
// After no data was recieved for this time, assume that no more data is outstanding from this connection.
func (h *ConnHandler) drainConn(b []byte, connIn, connOut net.Conn, interceptors []Interceptor, info *ConnInfo, timeoutMs int) error {
	defer connIn.SetReadDeadline(time.Time{})
	for {
		connIn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Microsecond))
		read, err := connIn.Read(b)
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			return nil
		case err == nil:
			if data := h.intercept(interceptors, b[:read], info); len(data) > 0 {
				connOut.Write(data)
			}
		default:
			return err
		}
	}
}

// forward up and down through the respective interceptors
// works for both plain and TLS mode (but not tls TLS detection mode)
func (h *ConnHandler) forwardGeneric() error {
	bufDown := make([]byte, bufSize)
	bufUp := make([]byte, bufSize)
	connInfoUp := NewConnInfo(h.ConnDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	connInfoDown := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)

	h.logger.Info("Forwarding %s <-> %s", h.ConnDown.RemoteAddr().String(), h.ConnUp.RemoteAddr().String())
	if err := h.notifyConnEstablished(); err != nil {
		return err
	}

	h.wg.Add(1)
	go h.forwardOneWay(h.ConnDown, h.ConnUp, bufUp, h.InterceptorsUp, &connInfoUp)
	h.forwardOneWay(h.ConnUp, h.ConnDown, bufDown, h.InterceptorsDown, &connInfoDown)

	h.wg.Wait()
	h.notifyConnTerminated()
	return nil
}

// TODO: what to do on errors in ConnectionEstablished for any interceptor?
func (h *ConnHandler) notifyConnEstablished() error {
	connInfoUp := NewConnInfo(h.ConnDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	connInfoDown := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)
	h.notifyEstablished(h.InterceptorsUp, &connInfoUp)
	h.notifyEstablished(h.InterceptorsDown, &connInfoDown)
	return nil
}

func (h *ConnHandler) notifyConnTerminated() {
	connInfoUp := NewConnInfo(h.ConnDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	connInfoDown := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)
	h.notifyTerminated(h.InterceptorsUp, &connInfoUp)
	h.notifyTerminated(h.InterceptorsDown, &connInfoDown)
}

func (h *ConnHandler) forwardOneWay(srcConn, dstConn net.Conn, buf []byte, interceptors []Interceptor, info *ConnInfo) error {
	for {
		r, err := srcConn.Read(buf)
		switch {
		case err == nil:
			// ok
		case errors.Is(err, os.ErrDeadlineExceeded):
			if !h.eofEncounterd.Load() {
				h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			}
			return err
		default:
			h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			h.eofEncounterd.Store(true)
			h.terminate()
			return err
		}

		if r == 0 {
			continue
		}

		if data := h.intercept(interceptors, buf[:r], info); len(data) > 0 {
			dstConn.Write(data)
		}
	}
}

func (h *ConnHandler) intercept(interceptors []Interceptor, data []byte, info *ConnInfo) []byte {
	if interceptors == nil {
		return data
	}

	var err error
	var tmp []byte
	for _, i := range interceptors {
		if len(data) == 0 {
			break
		}

		tmp, err = i.Intercept(info, data)
		if err == nil {
			data = tmp
		} else {
			h.logger.Warn("Got error during intercetion of connection %d: %v. Forwarding original data.", h.ConnId, err)
		}
	}

	return data
}

func (h *ConnHandler) terminate() {
	h.terminator.Do(
		func() {
			now := time.Now()
			h.ConnDown.SetDeadline(now)
			h.ConnUp.SetDeadline(now)
			h.wg.Done()
		})
}

func (h *ConnHandler) notifyEstablished(interceptors []Interceptor, info *ConnInfo) {
	for _, i := range interceptors {
		if err := i.ConnectionEstablished(info); err != nil {
			h.logger.Warn("Error on established notification: %v", err)
		}
	}
}

func (h *ConnHandler) notifyTerminated(interceptors []Interceptor, info *ConnInfo) {
	for _, i := range interceptors {
		if err := i.ConnectionTerminated(info); err != nil {
			h.logger.Warn("Error on termination notification: %v", err)
		}
	}
}
