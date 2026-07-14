package tamper

import (
	"net/http"
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
}

// handleControl accepts the single control WebSocket connection: stream lifecycle
// events and held-chunk notifications flow out, and every command (auto-intercept
// toggle, per-stream mode, chunk resolution, stream listing) flows in. Only one control
// connection is allowed at a time; a second connection attempt is rejected.
func (i *TamperInterceptor) handleControl(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	i.mu.Lock()
	if i.control != nil {
		i.mu.Unlock()
		conn.WriteJSON(errorMsg{Type: "error", Message: "a control connection is already active"})
		conn.Close()
		return
	}

	done := make(chan struct{})
	i.control = conn
	i.controlDone = done
	i.mu.Unlock()

	defer func() {
		i.mu.Lock()
		i.control = nil
		i.controlDone = nil
		i.mu.Unlock()
		close(done)
		conn.Close()
	}()

	for {
		var msg inboundMsg
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}

		switch msg.Type {
		case "set-auto-intercept":
			if msg.Enabled == nil {
				i.sendEventTo(conn, errorMsg{Type: "error", Message: "set-auto-intercept requires enabled"})
				break
			}
			i.mu.Lock()
			i.autoInterceptNew = *msg.Enabled
			i.mu.Unlock()
			i.sendEventTo(conn, okMsg{Type: "ok", Command: "set-auto-intercept"})
		case "set-mode":
			if msg.Conn == nil || msg.Intercepting == nil {
				i.sendEventTo(conn, errorMsg{Type: "error", Message: "set-mode requires conn and intercepting"})
				break
			}
			if !i.setMode(*msg.Conn, *msg.Intercepting) {
				i.sendEventTo(conn, errorMsg{Type: "error", Message: "unknown stream"})
				break
			}
			i.sendEventTo(conn, okMsg{Type: "ok", Command: "set-mode"})
		case "resolve":
			i.handleResolve(conn, msg)
		case "list-streams":
			i.sendStreamList()
		default:
			i.sendEventTo(conn, errorMsg{Type: "error", Message: "unknown message type: " + msg.Type})
		}
	}
}

func (i *TamperInterceptor) handleResolve(conn *websocket.Conn, msg inboundMsg) {
	if msg.Conn == nil || msg.ID == nil {
		i.sendEventTo(conn, errorMsg{Type: "error", Message: "resolve requires conn and id"})
		return
	}

	var editedData []byte
	if msg.Edited != nil && *msg.Edited {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			i.sendEventTo(conn, errorMsg{Type: "error", Message: "expected a binary frame with the edited data"})
			return
		}
		editedData = data
	}

	i.mu.Lock()
	st := i.streams[*msg.Conn]
	var pc *pendingChunk
	if st != nil {
		pc = st.pending[*msg.ID]
	}
	i.mu.Unlock()
	if pc == nil {
		i.sendEventTo(conn, errorMsg{Type: "error", Message: "chunk not found or already resolved"})
		return
	}

	var res resolution
	switch action(msg.Action) {
	case actionDrop:
		res = resolution{action: actionDrop}
	case actionDropConnection:
		res = resolution{action: actionDropConnection}
	default:
		res = resolution{action: actionForward, data: pc.data}
		if editedData != nil {
			res.data = editedData
		}
	}

	select {
	case pc.ch <- res:
	default:
	}

	i.sendEventTo(conn, okMsg{Type: "ok", Command: "resolve"})
}

// handleWatch attaches a read-only, best-effort live mirror of one stream's traffic.
// No commands flow through this connection; any inbound frame is discarded and used
// only to detect the client closing the tab.
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

	// The only inbound command is "peek"; anything else (or a read error, meaning the
	// client closed the connection) just falls through / ends the loop.
	for {
		var msg watchInboundMsg
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}
		if msg.Type == "peek" {
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

// handlePeek replies to a "peek" command with the bytes of one (msg.ID given) or all
// (msg.ID omitted) currently-held chunks for st, terminated by a peekDoneMsg. This is
// the only way to read a held chunk's bytes — "held" on the control channel is
// metadata-only.
func (i *TamperInterceptor) handlePeek(st *streamState, w *watcher, msg watchInboundMsg) {
	type target struct {
		id int64
		pc *pendingChunk
	}

	i.mu.Lock()
	var targets []target
	if msg.ID != nil {
		if pc, ok := st.pending[*msg.ID]; ok {
			targets = append(targets, target{*msg.ID, pc})
		}
	} else {
		for id, pc := range st.pending {
			targets = append(targets, target{id, pc})
		}
	}
	i.mu.Unlock()

	if msg.ID != nil && len(targets) == 0 {
		w.writeJSON(errorMsg{Type: "error", Message: "chunk not found or no longer pending"})
		return
	}

	for _, t := range targets {
		data := t.pc.data
		offset := int64(0)
		if msg.ID != nil {
			offset = msg.Offset
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
			data = data[offset:end]
		}

		meta := pendingChunkMsg{
			Type:        "pending",
			ID:          t.id,
			Direction:   t.pc.direction,
			Time:        t.pc.time,
			Offset:      offset,
			Length:      len(data),
			TotalLength: len(t.pc.data),
		}
		if err := w.writeJSON(meta); err != nil {
			return
		}
		if err := w.writeBinary(data); err != nil {
			return
		}
	}

	w.writeJSON(peekDoneMsg{Type: "peek-done"})
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

// sendHeld announces that a chunk is now held, awaiting a decision. It carries only
// metadata — the chunk's bytes are fetched on demand via "peek" on that stream's
// /watch connection (see protocol.go).
func (i *TamperInterceptor) sendHeld(connID uint32, id int64, direction int, length int) {
	i.mu.Lock()
	conn := i.control
	i.mu.Unlock()
	if conn == nil {
		return
	}

	meta := heldMsg{
		Type:      "held",
		Conn:      connID,
		ID:        id,
		Direction: direction,
		Time:      time.Now().UnixMilli(),
		Length:    length,
	}

	i.sendEventTo(conn, meta)
}

func (i *TamperInterceptor) sendStreamList() {
	i.mu.Lock()
	conn := i.control
	streams := make([]streamInfo, 0, len(i.streams))
	for _, st := range i.streams {
		pending := make([]pendingInfo, 0, len(st.pending))
		for id, pc := range st.pending {
			pending = append(pending, pendingInfo{ID: id, Direction: pc.direction, Time: pc.time, Length: len(pc.data)})
		}
		streams = append(streams, streamInfo{Conn: st.connID, Src: st.src, Dst: st.dst, Intercepting: st.intercepting, Pending: pending})
	}
	i.mu.Unlock()
	if conn == nil {
		return
	}
	i.sendEventTo(conn, streamListMsg{Type: "stream-list", Streams: streams})
}
