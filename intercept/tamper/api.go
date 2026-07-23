package tamper

import (
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// RegisterRoutes implements proxy.ApiProvider.
func (i *TamperInterceptor) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc(basePath+"/control", i.handleControl)
	mux.HandleFunc(basePath+"/watch", i.handleWatch)

	mux.HandleFunc("GET "+basePath+"/log-file", i.handleLogFileInfo)

	mux.HandleFunc("GET "+basePath+"/scripts", i.handleScriptsList)
	mux.HandleFunc("GET "+basePath+"/scripts/{name}", i.handleScriptGet)
	mux.HandleFunc("PUT "+basePath+"/scripts/{name}", i.handleScriptPut)
	mux.HandleFunc("DELETE "+basePath+"/scripts/{name}", i.handleScriptDelete)

	mux.HandleFunc("GET "+basePath+"/fs/list", i.handleFsList)
	mux.HandleFunc("GET "+basePath+"/fs/list/{path...}", i.handleFsList)
	mux.HandleFunc("GET "+basePath+"/fs/file/{path...}", i.handleFsGet)
	mux.HandleFunc("PUT "+basePath+"/fs/file/{path...}", i.handleFsPut)
	mux.HandleFunc("POST "+basePath+"/fs/file/{path...}", i.handleFsAppend)
}

// logFileInfoResponse is the reply to GET .../log-file — static for the interceptor's
// whole lifetime, so a plain REST GET is enough; no push event needed.
type logFileInfoResponse struct {
	Enabled  bool   `json:"enabled"`
	Filename string `json:"filename"` // basename only (not the full configured path); "" if !Enabled
}

// handleLogFileInfo reports whether a script log file is configured, and its display
// name, so the frontend can show "Logged to <name>" in place of a manual download button.
func (i *TamperInterceptor) handleLogFileInfo(w http.ResponseWriter, r *http.Request) {
	i.logFileMu.Lock()
	enabled := i.logFile != nil
	i.logFileMu.Unlock()

	resp := logFileInfoResponse{Enabled: enabled}
	if resp.Enabled {
		resp.Filename = filepath.Base(i.logFilePath)
	}
	writeJSONResponse(w, resp)
}

// handleControl accepts the single control WebSocket connection: stream lifecycle
// events and held-buffer notifications flow out, and every command (auto-intercept
// toggle, per-stream mode, release, drop-connection, stream listing) flows in. Only one
// control connection is allowed at a time; a second connection attempt is rejected.
func (i *TamperInterceptor) handleControl(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	i.mu.Lock()
	if i.control != nil {
		i.mu.Unlock()
		conn.WriteJSON(errorMsg{Type: msgError, Message: "a control connection is already active"})
		conn.Close()
		return
	}
	i.control = conn
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		i.control = nil
		streams := make([]*streamState, 0, len(i.streams))
		for _, st := range i.streams {
			streams = append(streams, st)
		}
		i.mu.Unlock()

		// Intercept never blocks waiting on the control connection, so releasing
		// everything held has to happen explicitly here on disconnect.
		for _, st := range streams {
			st.held[directionC2S].releaseAll()
			st.held[directionS2C].releaseAll()
		}

		conn.Close()
	}()

	for {
		var msg inboundMsg
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Type {
		case cmdSetAutoIntercept:
			if msg.Enabled == nil {
				i.sendEventTo(conn, errorMsg{Type: msgError, Message: "set-auto-intercept requires enabled"})
				break
			}
			i.mu.Lock()
			i.autoInterceptNew = *msg.Enabled
			i.mu.Unlock()
			i.sendEventTo(conn, okMsg{Type: msgOk, Command: cmdSetAutoIntercept})
		case cmdSetMode:
			if msg.Conn == nil || msg.Intercepting == nil {
				i.sendEventTo(conn, errorMsg{Type: msgError, Message: "set-mode requires conn and intercepting"})
				break
			}
			if !i.setMode(*msg.Conn, *msg.Intercepting) {
				i.sendEventTo(conn, errorMsg{Type: msgError, Message: "unknown stream"})
				break
			}
			i.sendEventTo(conn, okMsg{Type: msgOk, Command: cmdSetMode})
		case cmdRelease:
			i.handleRelease(conn, msg)
		case cmdDropConnection:
			i.handleDropConnection(conn, msg)
		case cmdListStreams:
			i.sendStreamList()
		case cmdScriptLog:
			if msg.Level != "log" && msg.Level != "error" {
				i.sendEventTo(conn, errorMsg{Type: msgError, Message: "script-log requires level \"log\" or \"error\""})
				break
			}
			i.writeScriptLog(msg.Level, msg.Text)
		default:
			i.sendEventTo(conn, errorMsg{Type: msgError, Message: "unknown message type: " + string(msg.Type)})
		}
	}
}

// lookupHeld resolves (conn, direction) from an inboundMsg to a *heldBuffer, sending conn
// the appropriate error and returning nil if either field is missing/invalid or the
// stream is unknown.
func (i *TamperInterceptor) lookupHeld(conn *websocket.Conn, msg inboundMsg, command string) *heldBuffer {
	if msg.Conn == nil || msg.Direction == nil {
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: command + " requires conn and direction"})
		return nil
	}
	dir := *msg.Direction
	if !dir.valid() {
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: "invalid direction"})
		return nil
	}

	i.mu.Lock()
	st := i.streams[*msg.Conn]
	i.mu.Unlock()
	if st == nil {
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: "unknown stream"})
		return nil
	}

	return st.held[dir]
}

// handleRelease implements the "release" command: an optional edit (Edited=true) of the
// buffer's first PrefixLength bytes, combined with releasing the resulting buffer's
// first ReleaseChunks chunks.
func (i *TamperInterceptor) handleRelease(conn *websocket.Conn, msg inboundMsg) {
	// The binary frame (if edited) is always consumed first, before any other
	// validation: a client that set edited:true has already committed to sending it, so
	// bailing out early here would leave it unread and desync the next ReadJSON call in
	// handleControl's loop, silently tearing down the whole control connection.
	edited := msg.Edited != nil && *msg.Edited
	var newData []byte
	prefixLen := 0
	var newBounds []int
	if edited {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			i.sendEventTo(conn, errorMsg{Type: msgError, Message: "expected a binary frame with the edited data"})
			return
		}
		newData = data
		prefixLen = msg.PrefixLength
		newBounds = msg.Bounds
	}

	if msg.Action == "" {
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: "release requires action"})
		return
	}
	var act releaseAct
	switch msg.Action {
	case actionForward:
		act = actForward
	case actionDrop:
		act = actDrop
	default:
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: "invalid action"})
		return
	}

	buf := i.lookupHeld(conn, msg, "release")
	if buf == nil {
		return
	}

	if !buf.performAction(prefixLen, newData, newBounds, msg.ReleaseChunks, act) {
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: "release rejected: the buffer has changed, peek to resync"})
		return
	}

	i.sendEventTo(conn, okMsg{Type: msgOk, Command: cmdRelease})
}

// handleDropConnection implements the "drop-connection" command — terminates the connection
// outright via the given direction's heldBuffer.abort(), independent of whatever's currently held.
func (i *TamperInterceptor) handleDropConnection(conn *websocket.Conn, msg inboundMsg) {
	buf := i.lookupHeld(conn, msg, "drop-connection")
	if buf == nil {
		return
	}

	if !buf.abort() {
		i.sendEventTo(conn, errorMsg{Type: msgError, Message: "stream already terminated"})
		return
	}

	i.sendEventTo(conn, okMsg{Type: msgOk, Command: cmdDropConnection})
}

// handleWatch attaches a read-only, best-effort live mirror of one stream's traffic.
// The only inbound command is "peek"; any other frame is discarded and used only to
// detect the client closing the tab.
func (i *TamperInterceptor) handleWatch(w http.ResponseWriter, r *http.Request) {
	connID64, err := strconv.ParseUint(r.URL.Query().Get("conn"), 10, 32)
	if err != nil {
		http.Error(w, "invalid or missing conn parameter", http.StatusBadRequest)
		return
	}
	connID := uint32(connID64)

	i.mu.Lock()
	st := i.streams[connID]
	i.mu.Unlock()
	if st == nil {
		http.Error(w, "unknown stream", http.StatusNotFound)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	wch := &watcher{conn: conn, ch: make(chan mirrorFrame, 8), stop: make(chan struct{})}

	i.mu.Lock()
	// The stream may have terminated between the lookup above and the upgrade.
	st = i.streams[connID]
	if st != nil {
		st.watchers[conn] = wch
	}
	i.mu.Unlock()
	if st == nil {
		conn.Close()
		return
	}

	go watcherWriteLoop(wch)

	for {
		var msg watchInboundMsg
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		if msg.Type == cmdPeek {
			i.handlePeek(st, wch, msg)
		}
	}

	i.detachWatcher(st, conn)
}

func watcherWriteLoop(w *watcher) {
	defer w.conn.Close()
	for {
		select {
		case frame := <-w.ch:
			meta := watchFrameMsg{Direction: frame.direction, Time: frame.timestamp, Length: len(frame.data)}
			if err := w.writeJSON(meta); err != nil {
				return
			}
			if err := w.writeBinary(frame.data); err != nil {
				return
			}
		case <-w.stop:
			return
		}
	}
}

// handlePeek replies to a "peek" command with a (possibly sliced) snapshot of one
// direction's held buffer, terminated by a peekDoneMsg. This is the only way to read
// held bytes — "held" on the control channel is metadata-only. An empty buffer isn't an
// error: a direction can legitimately have nothing held (e.g. the stream is in watch
// mode), so the reply is just a zero-length one.
func (i *TamperInterceptor) handlePeek(st *streamState, w *watcher, msg watchInboundMsg) {
	if msg.Direction == nil || !msg.Direction.valid() {
		w.writeJSON(errorMsg{Type: msgError, Message: "invalid direction"})
		return
	}
	dir := *msg.Direction

	data, bounds, lastActivity := st.held[dir].snapshot()

	offset := msg.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > int64(len(data)) {
		offset = int64(len(data))
	}
	end := int64(len(data))
	if msg.Length > 0 && offset+msg.Length < end {
		end = offset + msg.Length
	}
	slice := data[offset:end]

	meta := pendingChunkMsg{
		Type:        msgPending,
		Direction:   dir,
		Time:        lastActivity,
		Offset:      offset,
		Length:      len(slice),
		TotalLength: len(data),
		Bounds:      bounds,
	}
	if err := w.writeJSON(meta); err != nil {
		return
	}
	if err := w.writeBinary(slice); err != nil {
		return
	}

	w.writeJSON(peekDoneMsg{Type: msgPeekDone})
}

func (i *TamperInterceptor) sendEvent(msg any) {
	i.mu.Lock()
	conn := i.control
	i.mu.Unlock()
	if conn == nil {
		return
	}
	i.sendEventTo(conn, msg)
}

func (i *TamperInterceptor) sendEventTo(conn *websocket.Conn, msg any) {
	i.controlWriteMu.Lock()
	defer i.controlWriteMu.Unlock()
	conn.WriteJSON(msg)
}

// sendHeld announces that a new chunk was appended to one direction's held buffer. It
// carries only that chunk's own metadata — the bytes are fetched on demand via "peek"
// on that stream's /watch connection.
func (i *TamperInterceptor) sendHeld(connID uint32, dir direction, offset int, length int) {
	i.sendEvent(heldMsg{
		Type:      msgHeld,
		Conn:      connID,
		Direction: dir,
		Offset:    offset,
		Length:    length,
		Time:      time.Now().UnixMilli(),
	})
}

func (i *TamperInterceptor) sendStreamList() {
	i.mu.Lock()
	conn := i.control
	streams := make([]streamInfo, 0, len(i.streams))
	for _, st := range i.streams {
		pending := make([]pendingInfo, 0, 2)
		for _, d := range [2]direction{directionC2S, directionS2C} {
			chunks := st.held[d].numChunks()
			if chunks == 0 {
				continue
			}
			pending = append(pending, pendingInfo{Direction: d, Chunks: chunks, Length: st.held[d].length()})
		}
		streams = append(streams, streamInfo{Conn: st.connID, Src: st.src, Dst: st.dst, Intercepting: st.intercepting, Pending: pending})
	}
	i.mu.Unlock()
	if conn == nil {
		return
	}
	i.sendEventTo(conn, streamListMsg{Type: msgStreamList, Streams: streams})
}
