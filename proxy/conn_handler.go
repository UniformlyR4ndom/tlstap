package proxy

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

	bufferingUp   []bufferingEntry
	bufferingDown []bufferingEntry

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
	h.logger.Debug("Upstream server certificate chain:\n%s", chainToStringX509(serverCerts, "  "))

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

			switch data, err := h.intercept(h.InterceptorsUp, buf[:read], &connInfo); {
			case err != nil:
				h.terminate()
				return err
			case len(data) > 0:
				h.ConnUp.Write(data)
			}

			continue
		}

		// TLS client hello detected
		if result.StartIndex > 0 {
			read, err := connDown.Read(buf[:result.StartIndex])
			assert.Assertf(err == nil, "Unexpected error: %v. This is a bug.", err)
			assert.Assertf(read == result.StartIndex, "Expected to read %d bytes but read %d. This is a bug.", result.StartIndex, read)

			switch data, err := h.intercept(h.InterceptorsUp, buf[:read], &connInfo); {
			case err != nil:
				h.terminate()
				return err
			case len(data) > 0:
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

		if err = h.notifyConnUpgraded(); err != nil {
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
		return h.forwardOneWay(tlsConnDown, tlsConnUp, buf, h.InterceptorsUp, &connInfo, h.bufferingUp)
	}
}

func (h *ConnHandler) forwardDetectTlsDown() error {
	buf := make([]byte, bufSize)
	connInfo := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)

	for {
		read, err := h.ConnUp.Read(buf)
		switch {
		case err == nil:
			switch data, err := h.intercept(h.InterceptorsDown, buf[:read], &connInfo); {
			case err != nil:
				h.terminate()
				return err
			case len(data) > 0:
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
			switch data, err := h.intercept(interceptors, b[:read], info); {
			case err != nil:
				return err
			case len(data) > 0:
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

	if err := h.notifyConnUpgraded(); err != nil {
		return err
	}

	h.wg.Add(1)
	go h.forwardOneWay(h.ConnDown, h.ConnUp, bufUp, h.InterceptorsUp, &connInfoUp, h.bufferingUp)
	h.forwardOneWay(h.ConnUp, h.ConnDown, bufDown, h.InterceptorsDown, &connInfoDown, h.bufferingDown)

	h.wg.Wait()
	h.notifyConnTerminated()
	return nil
}

// TODO: what to do on errors in ConnectionEstablished for any interceptor?
func (h *ConnHandler) notifyConnEstablished() error {
	connInfoUp := NewConnInfo(h.ConnDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	connInfoDown := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)
	if err := h.notifyEstablished(h.InterceptorsUp, &connInfoUp); err != nil {
		return err
	}

	if err := h.notifyEstablished(h.InterceptorsDown, &connInfoDown); err != nil {
		return err
	}

	return nil
}

func (h *ConnHandler) notifyConnUpgraded() error {
	connInfoUp := NewConnInfo(h.ConnDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	connInfoDown := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)
	if err := h.notifyUpgraded(h.InterceptorsUp, &connInfoUp); err != nil {
		return err
	}

	if err := h.notifyUpgraded(h.InterceptorsDown, &connInfoDown); err != nil {
		return err
	}

	return nil
}

func (h *ConnHandler) notifyConnTerminated() error {
	connInfoUp := NewConnInfo(h.ConnDown.RemoteAddr(), h.ConnUp.RemoteAddr(), h.ConnId)
	connInfoDown := NewConnInfo(h.ConnUp.RemoteAddr(), h.ConnDown.RemoteAddr(), h.ConnId)
	if err := h.notifyTerminated(h.InterceptorsUp, &connInfoUp); err != nil {
		return err
	}

	if err := h.notifyTerminated(h.InterceptorsDown, &connInfoDown); err != nil {
		return err
	}

	return nil
}

// forwardOneWay is phase 1 (synchronous) of one direction's forwarding loop: a direct blocking
// read, run the interceptor chain, write. Behavior and cost are unchanged from before buffering
// interceptors existed as long as buffering is empty (the common case for every interceptor in
// the codebase today) or none of them ever actually holds anything for this connection. The one
// exception is the lazy, one-way transition into forwardOneWayAsync (phase 2), taken the first
// time a buffering interceptor reports it's holding something — from that point on this goroutine
// never calls srcConn.Read directly again for the remainder of the connection.
func (h *ConnHandler) forwardOneWay(srcConn, dstConn net.Conn, buf []byte, interceptors []Interceptor, info *ConnInfo, buffering []bufferingEntry) error {
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

		data, err := h.intercept(interceptors, buf[:r], info)
		if err != nil {
			h.terminate()
			return err
		}
		if len(data) > 0 {
			dstConn.Write(data)
		}
		// Deliberately not exclusive with the write above: a buffering interceptor may forward
		// part of what it received and still be holding the rest (see the contract note on
		// BufferingInterceptor), so both a write and a transition can be warranted for the same
		// chunk. len(buffering) > 0 short-circuits anyPending away entirely whenever this
		// direction's chain has no buffering interceptor at all.
		if len(buffering) > 0 && anyPending(buffering, info) {
			return h.forwardOneWayAsync(srcConn, dstConn, interceptors, info, buffering)
		}
	}
}

type pumpMsg struct {
	data []byte
	err  error
}

// readPump owns all further srcConn.Read calls for this direction once forwardOneWayAsync starts
// it, so the outer select loop can wait on a channel instead of a blocking Read. Keeps its own
// scratch buffer, never shared with the consumer, and copies out a right-sized slice per read
// before sending — the consumer's slice is then safe to hold onto while the pump loops back to
// Read again, which is what lets the pump read ahead instead of lockstep-waiting on the consumer.
// Reuses the exact same EOF/deadline/other-error classification forwardOneWay uses, relayed to the
// consumer via pumpMsg instead of a direct return, so shutdown behavior doesn't diverge between
// the pre- and post-transition phases.
//
// Every send to out races against stop, closed by forwardOneWayAsync right before it returns —
// without this, a pump whose consumer already exited via the release-channel arm of the select
// would block forever handing off its next (or final, error) message to nobody, leaking the
// goroutine. Same discipline tamper's watcher teardown already uses for the same reason: close a
// dedicated stop channel, don't rely on the data channel itself or on buffering to save you.
func (h *ConnHandler) readPump(srcConn net.Conn, info *ConnInfo, out chan<- pumpMsg, stop <-chan struct{}) {
	scratch := make([]byte, bufSize)
	for {
		r, err := srcConn.Read(scratch)
		switch {
		case err == nil:
			if r > 0 {
				data := make([]byte, r)
				copy(data, scratch[:r])
				select {
				case out <- pumpMsg{data: data}:
				case <-stop:
					return
				}
			}
		case errors.Is(err, os.ErrDeadlineExceeded):
			if !h.eofEncounterd.Load() {
				h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			}
			select {
			case out <- pumpMsg{err: err}:
			case <-stop:
			}
			return
		default:
			h.logger.Info("Terminating connection %d (%s <-> %s). Reason: %v", info.ConnID, info.SrcEndpoint, info.DstEndpoint, err)
			h.eofEncounterd.Store(true)
			h.terminate()
			select {
			case out <- pumpMsg{err: err}:
			case <-stop:
			}
			return
		}
	}
}

type releaseMsg struct {
	chainIdx int
	data     []byte
	err      error
}

// fanInReleases merges every buffering interceptor's release channel for this direction into one,
// tagging each message with its originating chain index so the consumer knows where to resume the
// interceptor chain (see interceptFrom). Closes the returned channel only once every source
// channel has closed — i.e. once every buffering interceptor has torn down for this ConnID+info,
// per the BufferingInterceptor contract that it must close its channel on ConnectionTerminated.
//
// Both the receive from each source channel and the send to out race against stop for the same
// reason readPump does: once forwardOneWayAsync has returned via some other arm, nothing may be
// left trying to hand data to it.
func fanInReleases(buffering []bufferingEntry, info *ConnInfo, stop <-chan struct{}) <-chan releaseMsg {
	out := make(chan releaseMsg)
	var wg sync.WaitGroup
	wg.Add(len(buffering))
	for _, e := range buffering {
		idx, ch := e.idx, e.bi.ReleaseChannel(info)
		go func() {
			defer wg.Done()
			for {
				select {
				case rd, ok := <-ch:
					if !ok {
						return
					}
					select {
					case out <- releaseMsg{chainIdx: idx, data: rd.Data, err: rd.Err}:
					case <-stop:
						return
					}
				case <-stop:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// forwardOneWayAsync is phase 2 of one direction's forwarding loop, entered exactly once (see
// forwardOneWay) and never left: a select between the read pump (new inbound data) and the
// buffering interceptors' merged release channel (previously-held data ready to continue through
// the rest of the chain). Terminates and logs identically to forwardOneWay regardless of which
// arm triggers it, so shutdown behavior is the same whether or not a direction ever buffered
// anything.
func (h *ConnHandler) forwardOneWayAsync(srcConn, dstConn net.Conn, interceptors []Interceptor, info *ConnInfo, buffering []bufferingEntry) error {
	stop := make(chan struct{})
	defer close(stop) // lets readPump and fanInReleases's relay goroutines exit however they're
	// currently blocked, the moment this function returns via either select arm below.

	pumpCh := make(chan pumpMsg) // unbuffered: pump blocks handing off, preserving the same
	// backpressure the direct blocking-read loop provides today.
	go h.readPump(srcConn, info, pumpCh, stop)
	releaseCh := fanInReleases(buffering, info, stop)

	for {
		select {
		case msg := <-pumpCh:
			if msg.err != nil {
				return msg.err
			}
			data, err := h.intercept(interceptors, msg.data, info)
			if err != nil {
				h.terminate()
				return err
			}
			if len(data) > 0 {
				dstConn.Write(data)
			}

		case rel, ok := <-releaseCh:
			if !ok {
				// Every buffering interceptor for this (ConnID, direction) has torn down —
				// treat as connection-terminated, not as an empty release. Must be handled via
				// the two-value receive specifically: a closed channel is always ready to
				// receive, so failing to check ok here would busy-loop this select arm forever.
				h.terminate()
				return nil
			}
			if rel.err != nil {
				h.terminate()
				return rel.err
			}
			data, err := h.interceptFrom(rel.chainIdx+1, interceptors, rel.data, info)
			if err != nil {
				h.terminate()
				return err
			}
			if len(data) > 0 {
				dstConn.Write(data)
			}
		}
	}
}

// bufferingEntry records a BufferingInterceptor's position in an interceptor chain, resolved
// once per connection (see scanBuffering) so ConnHandler never needs to re-assert interceptor
// types on the hot path.
type bufferingEntry struct {
	idx int
	bi  BufferingInterceptor
}

// scanBuffering finds every BufferingInterceptor in interceptors, in chain order. Called once per
// connection (in newHandler, proxy.go) — interceptors chains are short, so this is negligible.
func scanBuffering(interceptors []Interceptor) []bufferingEntry {
	var out []bufferingEntry
	for idx, i := range interceptors {
		if bi, ok := i.(BufferingInterceptor); ok {
			out = append(out, bufferingEntry{idx, bi})
		}
	}
	return out
}

// anyPending reports whether any of the given buffering interceptors currently holds anything
// for info's (ConnID, direction).
func anyPending(buffering []bufferingEntry, info *ConnInfo) bool {
	for _, e := range buffering {
		if e.bi.HasPending(info) {
			return true
		}
	}
	return false
}

func (h *ConnHandler) intercept(interceptors []Interceptor, data []byte, info *ConnInfo) ([]byte, error) {
	return h.interceptFrom(0, interceptors, data, info)
}

// interceptFrom runs interceptors[startIdx:] over data in order, exactly like intercept but
// windowed — used both for a normal full pass (startIdx 0, via intercept) and to resume the chain
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

func (h *ConnHandler) terminate() {
	h.terminator.Do(
		func() {
			now := time.Now()
			h.ConnDown.SetDeadline(now)
			h.ConnUp.SetDeadline(now)
			h.wg.Done()
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
