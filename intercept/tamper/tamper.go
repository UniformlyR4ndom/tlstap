package tamper

import (
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"tlstap/assert"
	"tlstap/logging"
	"tlstap/proxy"
)

// direction identifies which side of a connection a chunk or held buffer belongs to.
type direction int

const (
	directionC2S direction = 0 // client -> server
	directionS2C direction = 1 // server -> client
)

// valid reports whether d is one of the two legal direction values.
func (d direction) valid() bool {
	return d == directionC2S || d == directionS2C
}

// action is the "action" field of a "release" command.
type action string

const (
	actionForward action = "forward"
	actionDrop    action = "drop"
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

	// Directory user-editable/CLI-pushed scripts are stored in and served from. Empty
	// disables the scripts feature entirely — the REST endpoints still exist but reject
	// every request with 501, rather than silently defaulting to some implicit directory.
	ScriptsDir string `json:"scripts-dir"`

	// Directory scripts get read/write/list access to via REST. Empty disables the
	// feature entirely, same as ScriptsDir. Unlike ScriptsDir, this must already exist:
	// it exposes a directory the operator chose (e.g. test fixtures), so a typo'd path
	// fails interceptor construction loudly rather than silently creating one.
	FsRoot string `json:"fs-root"`

	// Path a connected control client's script log (tamper.log/ctx.log calls) is
	// persisted to, in addition to the browser's own in-memory log panel. Empty disables
	// persistence entirely. Always appended to; there is no truncate option.
	LogFile string `json:"log-file"`
}

// mirrorFrame is one chunk queued for delivery to a /watch client.
type mirrorFrame struct {
	direction direction
	timestamp int64
	data      []byte
}

// watcher is one attached /watch WebSocket client for a stream.
type watcher struct {
	conn *websocket.Conn
	ch   chan mirrorFrame // buffered; Intercept() sends non-blocking, drops on overflow
	stop chan struct{}    // closed exactly once to tear down the write loop; never sent to

	// writeMu serializes every write to conn: mirror frames and peek replies write to
	// the same connection from different goroutines, and gorilla websocket does not
	// support concurrent writers.
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
	held           [2]*heldBuffer // indexed by directionC2S/directionS2C
}

// directionOf classifies which direction info belongs to, by comparing against the client
// endpoint recorded on first sight of the stream.
func directionOf(st *streamState, info *proxy.ConnInfo) direction {
	if info.SrcEndpoint == st.clientEndpoint {
		return directionC2S
	}
	return directionS2C
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
	scripts            *scriptStore // nil if ScriptsDir wasn't configured
	fsRoot             *fsStore     // nil if FsRoot wasn't configured

	mu               sync.Mutex
	control          *websocket.Conn
	autoInterceptNew bool
	streams          map[uint32]*streamState

	controlWriteMu sync.Mutex

	// logFile persists a connected control client's script log. Opened in Init and
	// closed in Finalize; nil if LogFile wasn't configured. logFileMu guards every
	// read/write of logFile itself (not just the file write), and is never held
	// together with mu/controlWriteMu.
	logFilePath string
	logFile     *os.File
	logFileMu   sync.Mutex
}

// NewTamperInterceptor creates the interceptor and, if config.ScriptsDir is set, the
// scripts directory (returning an error if it can't be created). This has to happen here
// rather than in Init: RegisterRoutes is called synchronously while building the proxy,
// before Init runs asynchronously in the proxy's own start goroutine, so the scripts REST
// handlers must find i.scripts already usable the moment they're registered.
func NewTamperInterceptor(config *TamperConfig, logger *logging.Logger) (*TamperInterceptor, error) {
	var holdTimeout time.Duration
	if config.HoldTimeoutMs > 0 {
		holdTimeout = time.Duration(config.HoldTimeoutMs) * time.Millisecond
	}

	var scripts *scriptStore
	if config.ScriptsDir != "" {
		var err error
		scripts, err = newScriptStore(config.ScriptsDir)
		if err != nil {
			return nil, err
		}
	}

	var fsRoot *fsStore
	if config.FsRoot != "" {
		var err error
		fsRoot, err = newFsStore(config.FsRoot)
		if err != nil {
			return nil, err
		}
	}

	return &TamperInterceptor{
		holdTimeout:        holdTimeout,
		holdUntilConnected: config.HoldUntilConnected,
		logger:             logger,
		scripts:            scripts,
		fsRoot:             fsRoot,
		streams:            make(map[uint32]*streamState),
		logFilePath:        config.LogFile,
	}, nil
}

func (i *TamperInterceptor) Init(addr net.TCPAddr) error {
	if i.logFilePath == "" {
		return nil
	}

	f, err := os.OpenFile(i.logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	i.logFileMu.Lock()
	i.logFile = f
	i.logFileMu.Unlock()
	return nil
}

func (i *TamperInterceptor) Finalize(addr net.TCPAddr) {
	i.logFileMu.Lock()
	defer i.logFileMu.Unlock()
	if i.logFile != nil {
		i.logFile.Close()
	}
}

func (i *TamperInterceptor) ConnectionUpgraded(info *proxy.ConnInfo) error {
	return nil
}

// ConnectionEstablished is called once per direction for "any" interceptors; the first
// call arrives with src=client, dst=server, which is what we record as the stream's
// client endpoint for later direction detection.
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
			held: [2]*heldBuffer{
				directionC2S: newHeldBuffer(i.holdTimeout),
				directionS2C: newHeldBuffer(i.holdTimeout),
			},
		}
	}
	i.mu.Unlock()

	if !exists {
		i.sendEvent(streamCreatedMsg{Type: msgStreamCreated, Conn: info.ConnID, Src: info.SrcEndpoint, Dst: info.DstEndpoint})
	}

	return nil
}

// ConnectionTerminated is called once per direction; the exists-check guard ensures
// only the first call does the actual cleanup and notification.
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

	st.held[directionC2S].close()
	st.held[directionS2C].close()

	for _, w := range watchersSnapshot {
		i.detachWatcher(st, w.conn)
	}

	i.sendEvent(streamTerminatedMsg{Type: msgStreamTerminated, Conn: info.ConnID})
	return nil
}

// Intercept never blocks: when a chunk needs to be held, it's appended to that
// direction's heldBuffer and Intercept returns immediately with (nil, nil). Release —
// forwarding, dropping, or aborting the connection — happens later, asynchronously, via
// ConnHandler reading ReleaseChannel.
func (i *TamperInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	// data is a view into the proxy's shared read buffer; copy it before the caller's
	// next Read() can overwrite it (both for mirroring and for a potential hold).
	dataCopy := append([]byte(nil), data...)

	i.mu.Lock()
	st := i.streams[info.ConnID]
	if st == nil {
		i.mu.Unlock()
		// Established should always have registered the stream first; nothing to do.
		return data, nil
	}

	dir := directionOf(st, info)
	hasControl := i.control != nil
	// Hold if the stream is explicitly in intercept mode and someone's connected to decide,
	// OR if holdUntilConnected is set and nobody's connected at all (so traffic is never
	// silently missed while no client has attached yet).
	holdNow := (st.intercepting && hasControl) || (i.holdUntilConnected && !hasControl)

	var offset int
	if holdNow {
		// Deciding holdNow and appending happen under the same i.mu critical section, so a
		// concurrent setMode/control-disconnect sweep (which also takes i.mu) can never
		// interleave between the two — it either runs entirely before this append (and so
		// correctly doesn't release a chunk that isn't there yet) or entirely after (and so
		// correctly does release it).
		offset = st.held[dir].appendChunk(dataCopy)
	}

	watchers := make([]*watcher, 0, len(st.watchers))
	for _, w := range st.watchers {
		watchers = append(watchers, w)
	}
	i.mu.Unlock()

	mirror(watchers, dir, dataCopy)

	if !holdNow {
		return data, nil
	}

	i.sendHeld(info.ConnID, dir, offset, len(dataCopy))
	return nil, nil
}

// HasPending implements proxy.BufferingInterceptor.
func (i *TamperInterceptor) HasPending(info *proxy.ConnInfo) bool {
	i.mu.Lock()
	st := i.streams[info.ConnID]
	i.mu.Unlock()
	assert.Assertf(st != nil, "tamper: HasPending called for unknown stream %d", info.ConnID)
	return st.held[directionOf(st, info)].hasPending()
}

// ReleaseChannel implements proxy.BufferingInterceptor.
func (i *TamperInterceptor) ReleaseChannel(info *proxy.ConnInfo) <-chan proxy.ReleasedData {
	i.mu.Lock()
	st := i.streams[info.ConnID]
	i.mu.Unlock()
	assert.Assertf(st != nil, "tamper: ReleaseChannel called for unknown stream %d", info.ConnID)
	return st.held[directionOf(st, info)].relCh
}

// mirror best-effort forwards a chunk to every attached watcher. It never blocks: a
// watcher whose channel is full (too slow to keep up) simply misses the frame.
func mirror(watchers []*watcher, dir direction, data []byte) {
	if len(watchers) == 0 {
		return
	}

	frame := mirrorFrame{direction: dir, timestamp: time.Now().UnixMilli(), data: data}
	for _, w := range watchers {
		select {
		case w.ch <- frame:
		default:
		}
	}
}

// setMode switches a stream between watch and intercept mode. Turning interception off
// immediately force-releases (forwards, unmodified) everything currently held for that
// stream, rather than leaving it to time out. Reports whether the stream existed, so
// the caller can ack or error the command that triggered it.
func (i *TamperInterceptor) setMode(connID uint32, intercepting bool) bool {
	i.mu.Lock()
	st := i.streams[connID]
	if st == nil {
		i.mu.Unlock()
		return false
	}
	st.intercepting = intercepting
	i.mu.Unlock()

	if !intercepting {
		st.held[directionC2S].releaseAll()
		st.held[directionS2C].releaseAll()
	}

	return true
}

// detachWatcher removes a watcher from its stream and tears down its write loop.
// Guarded so that two concurrent callers can never both try to close the same watcher's
// stop channel.
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

// writeScriptLog appends one script-log line to logFile, if configured; a no-op
// otherwise. text is already fully formatted (prefix and args folded in, possibly
// multi-line) and is persisted as-is. The timestamp is the server's own receipt time,
// not anything embedded in text — a plain log call carries no timestamp of its own.
func (i *TamperInterceptor) writeScriptLog(level, text string) {
	header := "[" + time.Now().Format("2006-01-02 15:04:05.000") + "]"
	if level == "error" {
		header += " [ERROR]"
	}

	lines := strings.Split(text, "\n")
	var b strings.Builder
	b.WriteString(header)
	b.WriteString(" ")
	b.WriteString(lines[0])
	b.WriteString("\n")
	for _, l := range lines[1:] {
		b.WriteString("  ")
		b.WriteString(l)
		b.WriteString("\n")
	}

	i.logFileMu.Lock()
	defer i.logFileMu.Unlock()
	if i.logFile == nil {
		return
	}
	if _, err := i.logFile.WriteString(b.String()); err != nil {
		i.logger.Warn("tamper: failed to write script log: %v", err)
	}
}
