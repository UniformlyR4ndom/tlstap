package tamper

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"tlstap/logging"
	"tlstap/proxy"
)

const (
	directionC2S = 0 // client -> server direction
	directionS2C = 1 // server -> client direction
)

type action string

const (
	actionForward        action = "forward"
	actionDrop           action = "drop"
	actionDropConnection action = "drop-connection"
)

// TamperConfig is the JSON args for the "tamper" interceptor.
type TamperConfig struct {
	// Milliseconds to wait for a decision on a held chunk before auto-forwarding it
	// unmodified. <= 0 means wait indefinitely (until resolved, or the control
	// connection disconnects).
	HoldTimeoutMs int `json:"hold-timeout-ms"`

	// If true, every chunk is held while no control client is connected (instead of
	// passing straight through), still bounded by HoldTimeoutMs. Guards against a
	// client attaching after traffic has already started flowing.
	HoldUntilConnected bool `json:"hold-until-connected"`
}

// resolution is delivered to a blocked Intercept() call once a held chunk's fate is
// decided (or synthesized on timeout/disconnect/mode-change).
type resolution struct {
	action action
	data   []byte
}

// pendingChunk is a chunk currently held awaiting a decision.
type pendingChunk struct {
	ch        chan resolution // buffered(1); never closed, only ever sent to once
	data      []byte          // original bytes, used if resolved without an edit or peeked
	direction int
	time      int64 // UnixMilli when it was registered
}

// mirrorFrame is one chunk queued for delivery to a /watch client.
type mirrorFrame struct {
	direction int
	timestamp int64
	data      []byte
}

// watcher is one attached /watch WebSocket client for a stream.
type watcher struct {
	conn *websocket.Conn
	ch   chan mirrorFrame // buffered; Intercept() sends non-blocking, drops on overflow
	stop chan struct{}    // closed exactly once to tear down the write loop; never sent to

	// writeMu serializes every write to conn: both watcherWriteLoop's mirror frames and
	// handlePeek's replies write to the same connection from different goroutines, and
	// gorilla websocket does not support concurrent writers (same reason
	// TamperInterceptor.controlWriteMu exists for the control connection).
	writeMu sync.Mutex
}

func (w *watcher) writeJSON(v any) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.conn.WriteJSON(v)
}

func (w *watcher) writeBinary(data []byte) error {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	return w.conn.WriteMessage(websocket.BinaryMessage, data)
}

type streamState struct {
	connID         uint32
	src, dst       string
	clientEndpoint string // the (proxy-local) client endpoint, for direction detection
	intercepting   bool
	watchers       map[*websocket.Conn]*watcher
	pending        map[int64]*pendingChunk
}

// TamperInterceptor lets a connected control client actively pause, inspect, edit,
// drop, or forward individual chunks of live traffic, or just live-watch it without
// holding anything up. See CLAUDE.md's "tamper Interceptor" section for the full
// protocol and design rationale.
//
// mu guards all fields below except controlWriteMu itself. controlWriteMu serializes
// writes to the control connection and must never be held at the same time as mu:
// state is gathered under mu, mu is released, and only then is a WebSocket write
// attempted under controlWriteMu.
type TamperInterceptor struct {
	holdTimeout        time.Duration
	holdUntilConnected bool
	logger             *logging.Logger

	mu               sync.Mutex
	control          *websocket.Conn
	controlDone      chan struct{} // closed when the control connection drops
	autoInterceptNew bool
	streams          map[uint32]*streamState

	controlWriteMu sync.Mutex

	nextChunkID atomic.Int64
}

func NewTamperInterceptor(config *TamperConfig, logger *logging.Logger) *TamperInterceptor {
	var holdTimeout time.Duration
	if config.HoldTimeoutMs > 0 {
		holdTimeout = time.Duration(config.HoldTimeoutMs) * time.Millisecond
	}

	return &TamperInterceptor{
		holdTimeout:        holdTimeout,
		holdUntilConnected: config.HoldUntilConnected,
		logger:             logger,
		streams:            make(map[uint32]*streamState),
	}
}

func (i *TamperInterceptor) Init(addr net.TCPAddr) error {
	return nil
}

func (i *TamperInterceptor) Finalize(addr net.TCPAddr) {}

func (i *TamperInterceptor) ConnectionUpgraded(info *proxy.ConnInfo) error {
	return nil
}

// ConnectionEstablished is called once per direction for "any" interceptors; the first
// call arrives with src=client, dst=server, which is what we record. This mirrors
// dbdump's exact technique for deriving the client endpoint used for direction
// detection in Intercept (see intercept/dbdump/dbdump.go).
func (i *TamperInterceptor) ConnectionEstablished(info *proxy.ConnInfo) error {
	i.mu.Lock()
	_, exists := i.streams[info.ConnID]
	if !exists {
		i.streams[info.ConnID] = &streamState{
			connID:         info.ConnID,
			src:            info.SrcEndpoint,
			dst:            info.DstEndpoint,
			clientEndpoint: info.SrcEndpoint,
			intercepting:   i.autoInterceptNew,
			watchers:       make(map[*websocket.Conn]*watcher),
			pending:        make(map[int64]*pendingChunk),
		}
	}
	i.mu.Unlock()

	if !exists {
		i.sendEvent(streamCreatedMsg{Type: "stream-created", Conn: info.ConnID, Src: info.SrcEndpoint, Dst: info.DstEndpoint})
	}

	return nil
}

// ConnectionTerminated is called once per direction; the exists-check guard (mirroring
// dbdump's INSERT OR IGNORE pattern) ensures only the first call does the actual
// cleanup and notification.
func (i *TamperInterceptor) ConnectionTerminated(info *proxy.ConnInfo) error {
	i.mu.Lock()
	st, exists := i.streams[info.ConnID]
	if exists {
		delete(i.streams, info.ConnID)
	}
	var watchersSnapshot []*watcher
	if exists {
		for _, w := range st.watchers {
			watchersSnapshot = append(watchersSnapshot, w)
		}
	}
	i.mu.Unlock()

	if !exists {
		return nil
	}

	for _, w := range watchersSnapshot {
		i.detachWatcher(st, w.conn)
	}

	i.sendEvent(streamTerminatedMsg{Type: "stream-terminated", Conn: info.ConnID})
	return nil
}

func (i *TamperInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	i.mu.Lock()
	st := i.streams[info.ConnID]
	if st == nil {
		i.mu.Unlock()
		// Established should always have registered the stream first; nothing to do.
		return data, nil
	}

	direction := directionS2C
	if info.SrcEndpoint == st.clientEndpoint {
		direction = directionC2S
	}

	// data is a view into the proxy's shared read buffer; copy it before the caller's
	// next Read() can overwrite it (both for mirroring and for a potential hold).
	dataCopy := append([]byte(nil), data...)

	watchers := make([]*watcher, 0, len(st.watchers))
	for _, w := range st.watchers {
		watchers = append(watchers, w)
	}

	intercepting := st.intercepting
	hasControl := i.control != nil
	controlDone := i.controlDone
	i.mu.Unlock()

	mirror(watchers, direction, dataCopy)

	// Hold if the stream is explicitly in intercept mode and someone's connected to
	// decide, OR if holdUntilConnected is set and nobody's connected at all (so traffic
	// is never silently missed while no client has attached yet).
	holdNow := (intercepting && hasControl) || (i.holdUntilConnected && !hasControl)
	if !holdNow {
		return data, nil
	}

	id := i.nextChunkID.Add(1)
	ch := make(chan resolution, 1)
	now := time.Now().UnixMilli()

	i.mu.Lock()
	// Re-check: state may have changed between the unlock above and here (e.g. the
	// control client (dis)connected, or the stream was switched back to watch mode).
	hasControlNow := i.control != nil
	if !((st.intercepting && hasControlNow) || (i.holdUntilConnected && !hasControlNow)) {
		i.mu.Unlock()
		return data, nil
	}
	st.pending[id] = &pendingChunk{ch: ch, data: dataCopy, direction: direction, time: now}
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		delete(st.pending, id)
		i.mu.Unlock()
	}()

	i.sendHeld(info.ConnID, id, direction, len(dataCopy))

	var timeoutC <-chan time.Time
	if i.holdTimeout > 0 {
		timer := time.NewTimer(i.holdTimeout)
		defer timer.Stop()
		timeoutC = timer.C
	}

	select {
	case res := <-ch:
		switch res.action {
		case actionDrop:
			return nil, nil
		case actionDropConnection:
			return nil, proxy.ErrAbort
		default: // forward
			return res.data, nil
		}
	case <-timeoutC:
		return data, nil
	case <-controlDone:
		return data, nil
	}
}

// mirror best-effort forwards a chunk to every attached watcher. It never blocks: a
// watcher whose channel is full (too slow to keep up) simply misses the frame.
func mirror(watchers []*watcher, direction int, data []byte) {
	if len(watchers) == 0 {
		return
	}

	frame := mirrorFrame{direction: direction, timestamp: time.Now().UnixMilli(), data: data}
	for _, w := range watchers {
		select {
		case w.ch <- frame:
		default:
		}
	}
}

// setMode switches a stream between watch and intercept mode. Turning interception off
// immediately force-resolves (forwards, unmodified) every chunk currently held for that
// stream, rather than leaving them to time out. Reports whether the stream existed, so
// the caller can ack or error the command that triggered it.
func (i *TamperInterceptor) setMode(connID uint32, intercepting bool) bool {
	i.mu.Lock()
	st := i.streams[connID]
	if st == nil {
		i.mu.Unlock()
		return false
	}
	st.intercepting = intercepting

	var toRelease []*pendingChunk
	if !intercepting {
		for id, pc := range st.pending {
			toRelease = append(toRelease, pc)
			delete(st.pending, id)
		}
	}
	i.mu.Unlock()

	for _, pc := range toRelease {
		select {
		case pc.ch <- resolution{action: actionForward, data: pc.data}:
		default:
		}
	}

	return true
}

// detachWatcher removes a watcher from its stream and tears down its write loop.
// Guarded so that concurrent callers (the /watch handler's own read-loop exit, and
// ConnectionTerminated) can never both try to close the same watcher's stop channel.
func (i *TamperInterceptor) detachWatcher(st *streamState, conn *websocket.Conn) {
	i.mu.Lock()
	w, existed := st.watchers[conn]
	if existed {
		delete(st.watchers, conn)
	}
	i.mu.Unlock()

	if existed {
		close(w.stop)
	}
}
