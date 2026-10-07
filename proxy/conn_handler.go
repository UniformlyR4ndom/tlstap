package proxy

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	drainTimeoutMs = 100
)

// how long one direction may keep running after the other one ended cleanly
const defaultHalfCloseTimeout = 5 * time.Second

type fwdState = uint32

const (
	fwdUnused         = fwdState(0)
	fwdPlain          = fwdState(1)
	fwdTls            = fwdState(2)
	fwdTlsCloseNotify = fwdState(3)
	fwdTerminated     = fwdState(4)
)

type ConnHandler struct {
	Setting ConnSettings

	ConnId uint32

	InterceptorsUp   []Interceptor
	InterceptorsDown []Interceptor

	bufferingUp   []bufferingEntry
	bufferingDown []bufferingEntry

	// treat reading and writing end separately to allow handling close_notify per direction
	// in all modes except detecttls the Read and Write parts of a connection are identical
	ConnUpRead    net.Conn
	ConnUpWrite   net.Conn
	ConnDownRead  net.Conn
	ConnDownWrite net.Conn

	// the raw TCP connections; only relevant in detecttls mode (except for cleanup in terminate)
	TcpConnUp   net.Conn
	TcpConnDown net.Conn

	logger *logging.Logger

	terminator sync.Once

	// closed by terminate(); lets goroutines parked on a channel handshake bail out
	done chan struct{}

	// reports whether a buffering interceptor currently holds data; nil if there is none in the chains
	holdPending func() bool

	// overrides defaultHalfCloseTimeout if set
	halfCloseTimeout time.Duration

	// counts forwarding goroutines other than the one running HandleConnection
	wg            sync.WaitGroup
	eofEncounterd atomic.Bool

	upgradeChan    chan struct{}
	upgradeAckChan chan struct{}

	// closed when the down flow returns; lets a pending upgrade stop waiting for its ack
	downEnded chan struct{}

	// downstream TLS info of the latest upgrade; written before the upgrade-completion signal, read by the down flow after it
	tlsInfoDown *TLSInfo

	// only relevant for shutdown capability in detecttls mode
	stateUp   atomic.Uint32
	stateDown atomic.Uint32
}

func (h *ConnHandler) HandleConnection(conn net.Conn) error {
	var err error
	h.done = make(chan struct{})
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
	h.ConnDownRead = conn
	h.ConnDownWrite = conn
	h.TcpConnDown = conn
	defer conn.Close()

	connUp, err := net.Dial("tcp", h.Setting.ConnectEndpoint)
	if err != nil {
		return err
	}

	h.ConnUpRead = connUp
	h.ConnUpWrite = connUp
	h.TcpConnUp = connUp
	defer connUp.Close()

	return h.forwardGeneric()
}

func (h *ConnHandler) forwardTls(conn *tls.Conn) error {
	h.ConnDownRead = conn
	h.ConnDownWrite = conn
	h.TcpConnDown = conn
	defer conn.Close()

	connUp, err := tls.Dial("tcp", h.Setting.ConnectEndpoint, h.Setting.TlsClientConfig)
	if err != nil {
		return err
	}

	h.ConnUpRead = connUp
	h.ConnUpWrite = connUp
	h.TcpConnUp = connUp
	defer connUp.Close()

	lDown := conn.LocalAddr().String()
	rDown := conn.RemoteAddr().String()
	h.logger.Info("Downstream connection (%d): %s <-> %s (%s)", h.ConnId, rDown, lDown, SummarizeTlsConn(conn))

	lUp := connUp.LocalAddr().String()
	rUp := connUp.RemoteAddr().String()
	h.logger.Info("Upstream connection (%d): %s <-> %s (%s)", h.ConnId, lUp, rUp, SummarizeTlsConn(connUp))

	serverCerts := connUp.ConnectionState().PeerCertificates
	h.logger.Debug("Upstream server certificate chain:\n%s", chainToStringX509(serverCerts, "  "))

	return h.forwardGeneric()
}

func (h *ConnHandler) forwardDetectTls(conn net.Conn) error {
	if len(h.bufferingUp)+len(h.bufferingDown) > 0 {
		return errors.New("buffering interceptors are not supported in detecttls mode")
	}

	h.stateUp.Store(fwdPlain)
	h.stateDown.Store(fwdPlain)

	h.upgradeChan = make(chan struct{}, 1)
	h.upgradeAckChan = make(chan struct{}, 1)
	h.downEnded = make(chan struct{})

	bufConnDown := NewBufConn(conn, bufSize)
	h.ConnDownRead = bufConnDown
	h.ConnDownWrite = bufConnDown
	defer conn.Close()

	connUp, err := net.Dial("tcp", h.Setting.ConnectEndpoint)
	if err != nil {
		return err
	}

	h.ConnUpRead = connUp
	h.ConnUpWrite = connUp
	defer connUp.Close()

	h.TcpConnDown = conn
	h.TcpConnUp = connUp

	h.logger.Info("Forwarding %s <-> %s", conn.RemoteAddr().String(), connUp.RemoteAddr().String())
	if err := h.notifyConnEstablished(); err != nil {
		return err
	}

	h.runFlows(
		func() error { return h.forwardDetectTlsUp(bufConnDown, false) },
		h.forwardDetectTlsDown,
	)
	h.notifyConnTerminated()
	return nil
}

func (h *ConnHandler) forwardDetectTlsUp(connDown *BufferedConn, search bool) error {
	buf := make([]byte, bufSize)
	connInfo := NewConnInfo(connDown.RemoteAddr(), h.ConnUpRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(connDown))
	for {
		peeked, err := connDown.Peek(buf)
		if errors.Is(err, io.EOF) {
			h.logger.Debug("Downstream connection %d closed its write side. Half-closing upstream.", h.ConnId)
			h.stateUp.Store(fwdTerminated)
			return closeWrite(h.TcpConnUp)
		}
		if err != nil {
			h.logger.Error("Failed to peek downstream connection: %v", err)
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
			h.stateUp.CompareAndSwap(fwdTlsCloseNotify, fwdPlain)

			switch data, err := h.intercept(h.InterceptorsUp, buf[:read], &connInfo); {
			case err != nil:
				return err
			case len(data) > 0:
				h.ConnUpWrite.Write(data)
			}

			continue
		}

		// TLS client hello detected
		if result.StartIndex > 0 {
			if st := h.stateUp.Load(); st != fwdPlain && st != fwdTlsCloseNotify {
				h.logger.Error("Got ClientHello for in unexpected state. Terminating connection.")
				return errors.New("got ClientHello in unexpected upstream-flow state")
			}

			if st := h.stateDown.Load(); st != fwdPlain && st != fwdTlsCloseNotify {
				h.logger.Error("Got ClientHello for in unexpected state. Terminating connection.")
				return errors.New("got ClientHello in unexpected downstream-flow state")
			}

			read, err := connDown.Read(buf[:result.StartIndex])
			assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)
			assert.Assertf(read == result.StartIndex, "Expected to read %d bytes but read %d. This is a bug.", result.StartIndex, read)
			h.stateUp.CompareAndSwap(fwdTlsCloseNotify, fwdPlain)

			switch data, err := h.intercept(h.InterceptorsUp, buf[:read], &connInfo); {
			case err != nil:
				return err
			case len(data) > 0:
				h.ConnUpWrite.Write(data)
			}
		}

		h.logger.Debug("%d: TLS Client hello detected: %s", h.ConnId, hex.EncodeToString(result.ClientHello))

		// signal start of TLS upgrade
		h.upgradeChan <- struct{}{}
		h.TcpConnUp.SetReadDeadline(time.Now())

		// wait for other forwarder to stop reading from upstream connection
		select {
		case <-h.upgradeAckChan:
		case <-h.done:
			return nil
		case <-h.downEnded:
			return errors.New("upstream closed while a TLS upgrade was pending")
		}

		// drain upstream connection in case there is outstanding data sent from the sever to the client
		info := NewConnInfo(h.ConnUpRead.RemoteAddr(), connDown.RemoteAddr(), h.ConnId, tlsInfoFromConn(connDown))
		if err = h.drainConn(buf, h.ConnUpRead, h.ConnDownWrite, h.InterceptorsDown, &info, drainTimeoutMs); err != nil {
			h.logger.Error("Error while draining upstream connection: %v", err)
			return err
		}

		// perform TLS server handshake towards client
		tlsConnDown := tls.Server(&tlsRecordConn{Conn: connDown}, h.Setting.TlsServerConfig)
		if err = tlsConnDown.Handshake(); err != nil {
			h.logger.Error("Error during TLS server handshake (towards client): %v", err)
			return err
		}

		// perform TLS client handshake towards server
		tlsConnUp := tls.Client(&tlsRecordConn{Conn: h.ConnUpRead}, h.Setting.TlsClientConfig)
		if err = tlsConnUp.Handshake(); err != nil {
			h.logger.Error("Error during TLS client handshake (towards server): %v", err)
			return err
		}

		h.stateDown.Store(fwdTls)
		h.stateUp.Store(fwdTls)

		h.ConnDownRead = tlsConnDown
		h.ConnDownWrite = tlsConnDown
		h.ConnUpRead = tlsConnUp
		h.ConnUpWrite = tlsConnUp

		if err = h.notifyConnUpgraded(); err != nil {
			return err
		}

		lDown := tlsConnDown.LocalAddr().String()
		rDown := tlsConnDown.RemoteAddr().String()
		h.logger.Info("Upgraded downstream connection (%d): %s <-> %s (%s)", h.ConnId, rDown, lDown, SummarizeTlsConn(tlsConnDown))

		lUp := tlsConnUp.LocalAddr().String()
		rUp := tlsConnUp.RemoteAddr().String()
		h.logger.Info("Upgraded upstream connection (%d): %s <-> %s (%s)", h.ConnId, lUp, rUp, SummarizeTlsConn(tlsConnUp))

		h.tlsInfoDown = tlsInfoFromConn(tlsConnDown)
		connInfo.TLS = h.tlsInfoDown

		// signal completion of TLS upgrade
		h.upgradeChan <- struct{}{}
		err = h.forwardTlsUpDowngradable(buf, &connInfo)
		if errors.Is(err, io.EOF) && h.stateUp.Load() == fwdTlsCloseNotify {
			continue
		} else {
			return err
		}
	}
}

func (h *ConnHandler) forwardDetectTlsDown() error {
	defer close(h.downEnded)

	buf := make([]byte, bufSize)
	connInfo := NewConnInfo(h.ConnUpRead.RemoteAddr(), h.ConnDownRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))

	for {
		read, err := h.ConnUpRead.Read(buf)

		// forward what we read, regardless of potential error
		if read > 0 {
			switch data, err := h.intercept(h.InterceptorsDown, buf[:read], &connInfo); {
			case err != nil:
				return err
			case len(data) > 0:
				h.ConnDownWrite.Write(data)
			}
		}

		switch {
		case err == nil:
			if read > 0 {
				// received data after close_notify; the connection continues in plain mode
				h.stateDown.CompareAndSwap(fwdTlsCloseNotify, fwdPlain)
			}

			continue
		case errors.Is(err, io.EOF):
			if h.stateDown.Load() == fwdTls {
				h.logger.Debug("Got EOF while reading from upstream connection %d in TLS state. This may indicate close_notify or full TCP connection teardown.", h.ConnId)

				// assuming close_notify from server here
				// if the EOF turns out to originate from a full TCP connection teardown, we will notice that later
				connDownWriteTls, ok := h.ConnDownWrite.(*tls.Conn)
				assert.Assertf(ok, "h.ConnDownWrite not an instance of tls.Conn although in TLS state. This is a bug.")
				h.stateDown.Store(fwdTlsCloseNotify)
				if err := connDownWriteTls.CloseWrite(); err != nil {
					h.logger.Error("Got EOF in connection %d while sending close_notify. Terminating connection.", h.ConnId)
					return err
				}

				connInfo.TLS = nil

				// from now on write plaintext (if any) to downstream
				h.ConnDownWrite = h.TcpConnDown
				h.ConnDownWrite.SetWriteDeadline(time.Time{})

				// from now on read plaintext (if any) from upstream
				h.ConnUpRead = h.TcpConnUp
			} else {
				h.logger.Debug("Upstream connection %d closed its write side. Half-closing downstream.", h.ConnId)
				h.stateDown.Store(fwdTerminated)
				return closeWrite(h.TcpConnDown)
			}

		case len(h.upgradeChan) > 0 && errors.Is(err, os.ErrDeadlineExceeded):
			<-h.upgradeChan

			// signal that this routine is no longer reading from the upstream connection
			h.upgradeAckChan <- struct{}{}

			// wait for completion of the TLS upgrade
			select {
			case <-h.upgradeChan:
			case <-h.done:
				return nil
			}

			connInfo.TLS = h.tlsInfoDown

		default:
			h.logger.Error("Failed to read from upstream connection: %v", err)
			return err
		}
	}
}

func (h *ConnHandler) forwardTlsUpDowngradable(buf []byte, info *ConnInfo) error {
	for {
		read, err := h.ConnDownRead.Read(buf)

		// forward what we read, regardless of potential error
		if read > 0 {
			switch data, err := h.intercept(h.InterceptorsUp, buf[:read], info); {
			case err != nil:
				return err
			case len(data) > 0:
				h.ConnUpWrite.Write(data)
			}
		}

		switch {
		case err == nil:
			// nothing to do since read data was already forwarded trough interceptors
		case errors.Is(err, os.ErrDeadlineExceeded):
			if !h.eofEncounterd.Load() {
				h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			}
			return err

		case errors.Is(err, io.EOF):
			assert.Assertf(h.stateUp.Load() == fwdTls, "Got EOF in upstream flow outside of TLS state. This is a bug.")
			h.logger.Debug("Got EOF while reading from downstream connection %d (%s <-> %s) in TLS state. This may indicate close_notify or full TCP connection teardown.", info.ConnID, info.SrcEndpoint, info.DstEndpoint)

			// assume close_notify from client
			// if the EOF turns out to originate from a full TCP connection teardown, we will notice that later
			connUpWriteTls, ok := h.ConnUpWrite.(*tls.Conn)
			assert.Assertf(ok, "h.ConnUpWrite not an instance of tls.Conn although in TLS state. This is a bug.")
			if err := connUpWriteTls.CloseWrite(); err != nil {
				h.logger.Error("Got EOF in connection %d (%s <-> %s) while sending close_notify. Terminating connection.", info.ConnID, info.SrcEndpoint, info.DstEndpoint)
				return err
			}

			info.TLS = nil

			// from now on write plaintext (if any) to upstream
			h.ConnUpWrite = h.TcpConnUp
			h.ConnUpWrite.SetWriteDeadline(time.Time{})

			// from now on read plaintext (if any) from downstream
			h.ConnDownRead = h.TcpConnDown

			h.stateUp.Store(fwdTlsCloseNotify)
			return err // back to forwardDetectTlsUp

		default:
			h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			h.eofEncounterd.Store(true)
			return err
		}

	}
}

// Drain connIn: read and forward data until no data was received for at least timeoutMs milliseconds.
// After no data was recieved for this time, assume that no more data is outstanding from this connection.
func (h *ConnHandler) drainConn(b []byte, connIn, connOut net.Conn, interceptors []Interceptor, info *ConnInfo, timeoutMs int) error {
	defer connIn.SetReadDeadline(time.Time{})
	for {
		connIn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMs) * time.Millisecond))
		read, err := connIn.Read(b)
		if read > 0 {
			switch data, err := h.intercept(interceptors, b[:read], info); {
			case err != nil:
				return err
			case len(data) > 0:
				connOut.Write(data)
			}
		}

		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			return nil
		case err == nil:
			continue
		default:
			return err
		}

	}
}

// forward up and down through the respective interceptors
func (h *ConnHandler) forwardGeneric() error {
	bufDown := make([]byte, bufSize)
	bufUp := make([]byte, bufSize)
	connInfoUp := NewConnInfo(h.ConnDownRead.RemoteAddr(), h.ConnUpRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	connInfoDown := NewConnInfo(h.ConnUpRead.RemoteAddr(), h.ConnDownRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))

	h.logger.Info("Forwarding %s <-> %s", h.ConnDownRead.RemoteAddr().String(), h.ConnUpRead.RemoteAddr().String())
	if err := h.notifyConnEstablished(); err != nil {
		return err
	}

	if err := h.notifyConnUpgraded(); err != nil {
		return err
	}

	fwdUp := h.newForwarder(h.InterceptorsUp, h.bufferingUp, &connInfoUp, h.ConnUpWrite)
	fwdDown := h.newForwarder(h.InterceptorsDown, h.bufferingDown, &connInfoDown, h.ConnDownWrite)
	if len(h.bufferingUp)+len(h.bufferingDown) > 0 {
		h.holdPending = func() bool { return fwdUp.hasHeld() || fwdDown.hasHeld() }
	}

	h.runFlows(
		func() error { return h.forwardOneWay(h.ConnUpRead, h.ConnDownWrite, bufDown, fwdDown, &connInfoDown) },
		func() error { return h.forwardOneWay(h.ConnDownRead, h.ConnUpWrite, bufUp, fwdUp, &connInfoUp) },
	)
	h.notifyConnTerminated()
	return nil
}

// TODO: what to do on errors in ConnectionEstablished for any interceptor?
func (h *ConnHandler) notifyConnEstablished() error {
	connInfoUp := NewConnInfo(h.ConnDownRead.RemoteAddr(), h.ConnUpRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	connInfoDown := NewConnInfo(h.ConnUpRead.RemoteAddr(), h.ConnDownRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	if err := h.notifyEstablished(h.InterceptorsUp, &connInfoUp); err != nil {
		return err
	}

	if err := h.notifyEstablished(h.InterceptorsDown, &connInfoDown); err != nil {
		return err
	}

	return nil
}

func (h *ConnHandler) notifyConnUpgraded() error {
	connInfoUp := NewConnInfo(h.ConnDownRead.RemoteAddr(), h.ConnUpRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	connInfoDown := NewConnInfo(h.ConnUpRead.RemoteAddr(), h.ConnDownRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	if err := h.notifyUpgraded(h.InterceptorsUp, &connInfoUp); err != nil {
		return err
	}

	if err := h.notifyUpgraded(h.InterceptorsDown, &connInfoDown); err != nil {
		return err
	}

	return nil
}

func (h *ConnHandler) notifyConnTerminated() error {
	connInfoUp := NewConnInfo(h.ConnDownRead.RemoteAddr(), h.ConnUpRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	connInfoDown := NewConnInfo(h.ConnUpRead.RemoteAddr(), h.ConnDownRead.RemoteAddr(), h.ConnId, tlsInfoFromConn(h.ConnDownRead))
	if err := h.notifyTerminated(h.InterceptorsUp, &connInfoUp); err != nil {
		return err
	}

	if err := h.notifyTerminated(h.InterceptorsDown, &connInfoDown); err != nil {
		return err
	}

	return nil
}

// forwardOneWay forwards srcConn to dstConn. A clean EOF on srcConn shuts down the write side of dstConn
// (FIN, or close_notify for a TLS conn) and ends this direction with a nil error.
func (h *ConnHandler) forwardOneWay(srcConn, dstConn net.Conn, buf []byte, fwd chainForwarder, info *ConnInfo) error {
	defer fwd.close()
	for {
		read, err := srcConn.Read(buf)
		if read > 0 {
			if err := fwd.forward(buf[:read]); err != nil {
				return err
			}
		}

		switch {
		case err == nil:
			// ok
		case errors.Is(err, os.ErrDeadlineExceeded):
			if !h.eofEncounterd.Load() {
				h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			}
			return err
		case errors.Is(err, io.EOF):
			h.logger.Debug("Connection %d (%s -> %s): source closed its write side. Half-closing destination.", info.ConnID, info.SrcEndpoint, info.DstEndpoint)

			// held data must not be overtaken by the close
			if err := fwd.waitDrained(); err != nil {
				return err
			}

			return closeWrite(dstConn)
		default:
			h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			h.eofEncounterd.Store(true)
			return err
		}
	}
}

// bufferingEntry records a BufferingInterceptor's position in an interceptor chain, resolved
// once per connection
type bufferingEntry struct {
	idx int
	bi  BufferingInterceptor
}

// scanBuffering finds every BufferingInterceptor in interceptors, in chain order and extracts it's index.
func scanBuffering(interceptors []Interceptor) []bufferingEntry {
	var out []bufferingEntry
	for idx, i := range interceptors {
		if bi, ok := i.(BufferingInterceptor); ok {
			out = append(out, bufferingEntry{idx, bi})
		}
	}
	return out
}

func (h *ConnHandler) intercept(interceptors []Interceptor, data []byte, info *ConnInfo) ([]byte, error) {
	return h.interceptFrom(0, interceptors, data, info)
}

// interceptFrom runs interceptors[startIdx:] over data in order
// used both for a normal full pass (startIdx 0, via intercept) and to resume the chain
// right after a buffering interceptor releases data (startIdx = that interceptor's index + 1).
func (h *ConnHandler) interceptFrom(startIdx int, interceptors []Interceptor, data []byte, info *ConnInfo) ([]byte, error) {
	if interceptors == nil {
		return data, nil
	}

	var err error
	var tmp []byte
	for _, i := range interceptors[startIdx:] {
		if len(data) == 0 {
			break
		}

		tmp, err = i.Intercept(info, data)
		switch {
		case err == nil:
			data = tmp
		case err == ErrAbort:
			return nil, err
		default:
			h.logger.Warn("Got error during intercetion of connection %d: %v. Forwarding original data.", h.ConnId, err)
		}
	}

	return data, nil
}

// runFlows runs asyncFlow in a goroutine and mainFlow on the caller; whichever ends first terminates the other.
func (h *ConnHandler) runFlows(mainFlow, asyncFlow func() error) {
	var graceOnce sync.Once
	var graceWg sync.WaitGroup
	stopGrace := make(chan struct{})

	endFlow := func(err error) {
		if err != nil {
			h.terminate()
			return
		}

		graceOnce.Do(func() {
			graceWg.Add(1)
			go func() {
				defer graceWg.Done()
				h.terminateAfterGrace(stopGrace)
			}()
		})
	}

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		endFlow(asyncFlow())
	}()

	endFlow(mainFlow())
	h.wg.Wait()

	// nothing may query the interceptors once the caller reports the connection as terminated
	close(stopGrace)
	graceWg.Wait()
}

// terminateAfterGrace terminates the connection once the half-close timeout has passed, but not while a
// buffering interceptor still holds data (a human may be deciding about it).
func (h *ConnHandler) terminateAfterGrace(stop <-chan struct{}) {
	timeout := h.halfCloseTimeout
	if timeout == 0 {
		timeout = defaultHalfCloseTimeout
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
		case <-stop:
			return
		}

		if h.holdPending == nil || !h.holdPending() {
			h.terminate()
			return
		}

		timer.Reset(timeout)
	}
}

// closeWrite shuts down the write side of a raw connection, signaling EOF to its peer.
func closeWrite(conn net.Conn) error {
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("%T does not support CloseWrite", conn)
	}

	return cw.CloseWrite()
}

func (h *ConnHandler) terminate() {
	h.terminator.Do(
		func() {
			now := time.Now()

			// TcpConnDown and TcpConnUp are set in any mode but only really used in detecttls mode
			h.TcpConnDown.SetDeadline(now)
			h.TcpConnUp.SetDeadline(now)
			close(h.done)
		})
}

func (h *ConnHandler) notifyEstablished(interceptors []Interceptor, info *ConnInfo) error {
	for _, i := range interceptors {
		if err := i.ConnectionEstablished(info); err != nil {
			h.logger.Warn("Error on established notification: %v", err)
			return err
		}
	}

	return nil
}

func (h *ConnHandler) notifyUpgraded(interceptor []Interceptor, info *ConnInfo) error {
	for _, i := range interceptor {
		if err := i.ConnectionUpgraded(info); err != nil {
			h.logger.Warn("Error on upgrade notification: %v", err)
			return err
		}
	}

	return nil
}

func (h *ConnHandler) notifyTerminated(interceptors []Interceptor, info *ConnInfo) error {
	for _, i := range interceptors {
		if err := i.ConnectionTerminated(info); err != nil {
			h.logger.Warn("Error on termination notification: %v", err)
			return err
		}
	}

	return nil
}
