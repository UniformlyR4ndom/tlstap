package tamper

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"tlstap/proxy"
)

func newTestServer(t *testing.T, holdTimeoutMs int) (*TamperInterceptor, string) {
	t.Helper()
	return newTestServerWithConfig(t, TamperConfig{HoldTimeoutMs: holdTimeoutMs})
}

func newTestServerWithConfig(t *testing.T, config TamperConfig) (*TamperInterceptor, string) {
	t.Helper()
	ti := NewTamperInterceptor(&config, nil)
	mux := http.NewServeMux()
	ti.RegisterRoutes(mux, "/api/i/tamper")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	return ti, wsURL
}

// dialControl connects the control WebSocket and waits for the server-side handler to
// finish registering it as i.control. This closes a real race: the client's Dial() can
// return as soon as the server writes the HTTP 101 response, which happens before the
// server-side handler goroutine actually reaches i.control = conn — without waiting
// here, a test that immediately triggers a notification (e.g. ConnectionEstablished)
// could race the server into silently dropping it (sendEvent sees i.control == nil).
func dialControl(t *testing.T, ti *TamperInterceptor, wsURL string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"/api/i/tamper/control", nil)
	if err != nil {
		t.Fatalf("dial control: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ti.mu.Lock()
		attached := ti.control != nil
		ti.mu.Unlock()
		if attached {
			return conn
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("control connection never registered server-side")
	return nil
}

func dialWatch(t *testing.T, wsURL string, connID uint32) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"/api/i/tamper/watch?conn="+strconv.FormatUint(uint64(connID), 10), nil)
	if err != nil {
		t.Fatalf("dial watch: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func fakeConnInfo(connID uint32) *proxy.ConnInfo {
	return &proxy.ConnInfo{
		ConnID:      connID,
		SrcEndpoint: "1.2.3.4:1000",
		DstEndpoint: "5.6.7.8:443",
	}
}

func writeJSON(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	if err := conn.WriteJSON(v); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
}

func readJSON(t *testing.T, conn *websocket.Conn, v any) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := conn.ReadJSON(v); err != nil {
		t.Fatalf("readJSON: %v", err)
	}
}

func readBinary(t *testing.T, conn *websocket.Conn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("readBinary: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("expected binary message, got type %d", mt)
	}
	return data
}

func boolPtr(b bool) *bool    { return &b }
func u32Ptr(u uint32) *uint32 { return &u }
func i64Ptr(i int64) *int64   { return &i }

// replyMsg is a superset of okMsg/errorMsg's fields, decoded generically since which
// one arrived is read from Type.
type replyMsg struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Message string `json:"message"`
}

// readAck reads one control-channel reply and requires it to be an "ok" or "error"
// acknowledgment — every set-mode/resolve/set-auto-intercept command sends exactly one.
func readAck(t *testing.T, control *websocket.Conn) replyMsg {
	t.Helper()
	var r replyMsg
	readJSON(t, control, &r)
	if r.Type != "ok" && r.Type != "error" {
		t.Fatalf("expected an ok/error acknowledgment, got %+v", r)
	}
	return r
}

func requireOK(t *testing.T, r replyMsg) {
	t.Helper()
	if r.Type != "ok" {
		t.Fatalf("expected ok, got %+v", r)
	}
}

// sendCommandOK writes msg to control and asserts the reply acknowledges success. Used
// for set-mode/resolve commands that carry no trailing binary frame; commands that do
// (an edited resolve) write the binary frame themselves and call readAck directly.
func sendCommandOK(t *testing.T, control *websocket.Conn, msg inboundMsg) {
	t.Helper()
	writeJSON(t, control, msg)
	requireOK(t, readAck(t, control))
}

// waitForWatcherAttached polls internal state until the /watch connection for connID
// has been registered server-side, avoiding a race between the client's dial returning
// and the server finishing registration.
func waitForWatcherAttached(t *testing.T, ti *TamperInterceptor, connID uint32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ti.mu.Lock()
		st := ti.streams[connID]
		n := 0
		if st != nil {
			n = len(st.watchers)
		}
		ti.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("watcher for conn %d never attached", connID)
}

// waitForPendingCount polls internal state until a stream's pending-chunk count
// reaches want, avoiding a race between registering a hold and observing it.
func waitForPendingCount(t *testing.T, ti *TamperInterceptor, connID uint32, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ti.mu.Lock()
		st := ti.streams[connID]
		n := 0
		if st != nil {
			n = len(st.pending)
		}
		ti.mu.Unlock()
		if n == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stream %d never reached %d pending chunk(s)", connID, want)
}

func findStreamInfo(list *streamListMsg, connID uint32) *streamInfo {
	for i := range list.Streams {
		if list.Streams[i].Conn == connID {
			return &list.Streams[i]
		}
	}
	return nil
}

// peekReply is a superset of pendingChunkMsg/errorMsg/peekDoneMsg's fields, so a single
// decode target can handle any reply a "peek" command produces.
type peekReply struct {
	Type        string `json:"type"`
	ID          int64  `json:"id"`
	Direction   int    `json:"direction"`
	Time        int64  `json:"time"`
	Offset      int64  `json:"offset"`
	Length      int    `json:"length"`
	TotalLength int    `json:"total_length"`
	Message     string `json:"message"`
}

// collectPeekReplies reads "pending" (+ its binary frame) messages until "peek-done" or
// "error", returning whichever terminated the sequence.
func collectPeekReplies(t *testing.T, watch *websocket.Conn) ([]peekReply, [][]byte, *peekReply) {
	t.Helper()
	var replies []peekReply
	var datas [][]byte
	for {
		var r peekReply
		readJSON(t, watch, &r)
		switch r.Type {
		case "pending":
			datas = append(datas, readBinary(t, watch))
			replies = append(replies, r)
		case "peek-done":
			return replies, datas, nil
		case "error":
			return replies, datas, &r
		default:
			t.Fatalf("unexpected peek reply: %+v", r)
		}
	}
}

type interceptResult struct {
	data []byte
	err  error
}

func interceptAsync(ti *TamperInterceptor, info *proxy.ConnInfo, data []byte) <-chan interceptResult {
	ch := make(chan interceptResult, 1)
	go func() {
		out, err := ti.Intercept(info, data)
		ch <- interceptResult{data: out, err: err}
	}()
	return ch
}

func recvResult(t *testing.T, ch <-chan interceptResult) interceptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("Intercept did not return in time")
		return interceptResult{}
	}
}

// No control client connected at all: traffic must pass straight through, and
// Intercept must never block waiting for anything.
func TestNoControl_PassThrough(t *testing.T) {
	ti := NewTamperInterceptor(&TamperConfig{}, nil)
	info := fakeConnInfo(1)
	if err := ti.ConnectionEstablished(info); err != nil {
		t.Fatal(err)
	}

	out, err := ti.Intercept(info, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello" {
		t.Fatalf("expected unchanged data, got %q", out)
	}
}

// Default per-stream mode is watch: chunks pass through immediately (non-blocking) and
// are mirrored to an attached /watch client.
func TestWatchMode_NonBlockingAndMirrored(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	if err := ti.ConnectionEstablished(info); err != nil {
		t.Fatal(err)
	}
	var created streamCreatedMsg
	readJSON(t, control, &created)
	if created.Type != "stream-created" {
		t.Fatalf("expected stream-created, got %+v", created)
	}

	watch := dialWatch(t, wsURL, 1)
	waitForWatcherAttached(t, ti, 1)

	out, err := ti.Intercept(info, []byte("watched"))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "watched" {
		t.Fatalf("watch mode must not alter data, got %q", out)
	}

	var frame watchFrameMsg
	readJSON(t, watch, &frame)
	if frame.Direction != directionC2S || frame.Length != len("watched") {
		t.Fatalf("unexpected mirror frame: %+v", frame)
	}
	if data := readBinary(t, watch); string(data) != "watched" {
		t.Fatalf("expected mirrored bytes %q, got %q", "watched", data)
	}
}

// A held chunk resolved with "forward" + edited bytes returns the edited bytes.
func TestHold_ResolveForwardEdited(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)

	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)
	if held.Type != "held" || held.Direction != directionC2S || held.Length != len("original") {
		t.Fatalf("unexpected held message: %+v", held)
	}

	writeJSON(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(held.ID), Action: "forward", Edited: boolPtr(true)})
	if err := control.WriteMessage(websocket.BinaryMessage, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	requireOK(t, readAck(t, control))

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "edited" {
		t.Fatalf("expected edited bytes, got %q", r.data)
	}
}

// A held chunk resolved with "forward" and no edit forwards the original bytes.
func TestHold_ResolveForwardUnedited(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(held.ID), Action: "forward", Edited: boolPtr(false)})

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "original" {
		t.Fatalf("expected original bytes, got %q", r.data)
	}
}

// A held chunk resolved with "drop" forwards nothing and does not error.
func TestHold_ResolveDrop(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(held.ID), Action: "drop"})

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if len(r.data) != 0 {
		t.Fatalf("expected no data forwarded on drop, got %q", r.data)
	}
}

// A held chunk resolved with "drop-connection" returns proxy.ErrAbort.
func TestHold_ResolveDropConnection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(held.ID), Action: "drop-connection"})

	r := recvResult(t, resCh)
	if r.err != proxy.ErrAbort {
		t.Fatalf("expected proxy.ErrAbort, got %v", r.err)
	}
}

// If nobody resolves a held chunk before the configured timeout, it is auto-forwarded
// unmodified.
func TestHold_Timeout(t *testing.T) {
	ti, wsURL := newTestServer(t, 50)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)
	// Deliberately never resolve.

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "original" {
		t.Fatalf("expected original bytes on timeout, got %q", r.data)
	}
}

// Disconnecting the control client immediately releases every chunk currently held,
// forwarding the original bytes, rather than waiting for individual timeouts.
func TestHold_ControlDisconnectReleases(t *testing.T) {
	ti, wsURL := newTestServer(t, 0) // infinite timeout: only disconnect can release this
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)

	control.Close()

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "original" {
		t.Fatalf("expected original bytes on control disconnect, got %q", r.data)
	}
}

// Switching a stream back to watch mode force-resolves any chunk currently held for
// it, rather than leaving it to time out.
func TestSetMode_ForceReleasesPending(t *testing.T) {
	ti, wsURL := newTestServer(t, 0) // infinite timeout: only the mode switch can release this
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("original"))

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(false)})

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "original" {
		t.Fatalf("expected original bytes forced-released, got %q", r.data)
	}
}

// Direction is derived from comparing SrcEndpoint against the client endpoint recorded
// on the first ConnectionEstablished call, exactly as dbdump does it.
func TestDirectionDetection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	up := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: "client:1000", DstEndpoint: "server:443"}
	down := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: "server:443", DstEndpoint: "client:1000"}

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(up) // first call: src=client -> records client endpoint
	var created streamCreatedMsg
	readJSON(t, control, &created)
	ti.ConnectionEstablished(down) // second call for the same ConnID: no-op, no event

	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	c2sCh := interceptAsync(ti, up, []byte("c2s"))
	var c2sHeld heldMsg
	readJSON(t, control, &c2sHeld)
	if c2sHeld.Direction != directionC2S {
		t.Fatalf("expected c2s direction for up info, got %d", c2sHeld.Direction)
	}
	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(c2sHeld.ID), Action: "forward"})
	recvResult(t, c2sCh)

	s2cCh := interceptAsync(ti, down, []byte("s2c"))
	var s2cHeld heldMsg
	readJSON(t, control, &s2cHeld)
	if s2cHeld.Direction != directionS2C {
		t.Fatalf("expected s2c direction for down info, got %d", s2cHeld.Direction)
	}
	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(s2cHeld.ID), Action: "forward"})
	recvResult(t, s2cCh)
}

// stream-list reports currently-held chunks inline, so reconnecting to control at any
// time (not just being connected at the moment a chunk was held) is enough to discover
// and act on everything outstanding.
func TestStreamList_PendingInfo(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	resCh := interceptAsync(ti, info, []byte("pending-data"))

	var held heldMsg
	readJSON(t, control, &held)

	writeJSON(t, control, inboundMsg{Type: "list-streams"})
	var list streamListMsg
	readJSON(t, control, &list)

	stream := findStreamInfo(&list, 1)
	if stream == nil {
		t.Fatal("stream 1 not found in stream-list")
	}
	if len(stream.Pending) != 1 {
		t.Fatalf("expected exactly 1 pending chunk, got %d", len(stream.Pending))
	}
	p := stream.Pending[0]
	if p.ID != held.ID || p.Direction != directionC2S || p.Length != len("pending-data") {
		t.Fatalf("unexpected pending info: %+v", p)
	}

	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(held.ID), Action: "forward"})
	recvResult(t, resCh)
}

// With no id given, /watch's "peek" command returns every currently-pending chunk for
// the stream (at most one per direction, since a single direction's forwarding loop
// only ever has one Intercept() call in flight at a time). Uses HoldUntilConnected so
// chunks get held without needing a control connection at all, isolating this test to
// just the watch/peek interaction.
func TestWatchPeek_AllPending(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true})
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	c2sCh := interceptAsync(ti, info, []byte("c2s-data"))
	s2cInfo := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: info.DstEndpoint, DstEndpoint: info.SrcEndpoint}
	s2cCh := interceptAsync(ti, s2cInfo, []byte("s2c-data"))
	waitForPendingCount(t, ti, 1, 2)

	watch := dialWatch(t, wsURL, 1)
	writeJSON(t, watch, watchInboundMsg{Type: "peek"})
	replies, datas, errReply := collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 2 {
		t.Fatalf("expected 2 pending chunks, got %d", len(replies))
	}

	seen := map[int]string{}
	for i, r := range replies {
		if r.Offset != 0 || r.Length != r.TotalLength {
			t.Fatalf("expected full chunk with offset 0, got %+v", r)
		}
		seen[r.Direction] = string(datas[i])
	}
	if seen[directionC2S] != "c2s-data" || seen[directionS2C] != "s2c-data" {
		t.Fatalf("unexpected pending contents: %+v", seen)
	}

	control := dialControl(t, ti, wsURL)
	writeJSON(t, control, inboundMsg{Type: "list-streams"})
	var list streamListMsg
	readJSON(t, control, &list)
	for _, p := range findStreamInfo(&list, 1).Pending {
		sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(p.ID), Action: "forward"})
	}
	recvResult(t, c2sCh)
	recvResult(t, s2cCh)
}

// Peeking with an explicit id returns just that one chunk.
func TestWatchPeek_ById(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true})
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	c2sCh := interceptAsync(ti, info, []byte("c2s-data"))
	s2cInfo := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: info.DstEndpoint, DstEndpoint: info.SrcEndpoint}
	s2cCh := interceptAsync(ti, s2cInfo, []byte("s2c-data"))
	waitForPendingCount(t, ti, 1, 2)

	ti.mu.Lock()
	var c2sID int64
	for id, pc := range ti.streams[1].pending {
		if pc.direction == directionC2S {
			c2sID = id
		}
	}
	ti.mu.Unlock()

	watch := dialWatch(t, wsURL, 1)
	writeJSON(t, watch, watchInboundMsg{Type: "peek", ID: &c2sID})
	replies, datas, errReply := collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 || replies[0].ID != c2sID || string(datas[0]) != "c2s-data" {
		t.Fatalf("unexpected peek-by-id result: replies=%+v datas=%q", replies, datas)
	}

	control := dialControl(t, ti, wsURL)
	writeJSON(t, control, inboundMsg{Type: "list-streams"})
	var list streamListMsg
	readJSON(t, control, &list)
	for _, p := range findStreamInfo(&list, 1).Pending {
		sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(p.ID), Action: "forward"})
	}
	recvResult(t, c2sCh)
	recvResult(t, s2cCh)
}

// Peeking with id + offset/length returns only that slice, echoing back the actual
// offset/length served alongside the full chunk's total_length.
func TestWatchPeek_OffsetLength(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true})
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	resCh := interceptAsync(ti, info, []byte("0123456789"))
	waitForPendingCount(t, ti, 1, 1)

	ti.mu.Lock()
	var id int64
	for chunkID := range ti.streams[1].pending {
		id = chunkID
	}
	ti.mu.Unlock()

	watch := dialWatch(t, wsURL, 1)

	writeJSON(t, watch, watchInboundMsg{Type: "peek", ID: &id, Offset: 3, Length: 4})
	replies, datas, errReply := collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 {
		t.Fatalf("expected 1 reply, got %d", len(replies))
	}
	if r := replies[0]; r.Offset != 3 || r.Length != 4 || r.TotalLength != 10 || string(datas[0]) != "3456" {
		t.Fatalf("unexpected sliced peek result: %+v data=%q", r, datas[0])
	}

	// Length omitted (0) means "to the end of the chunk".
	writeJSON(t, watch, watchInboundMsg{Type: "peek", ID: &id, Offset: 8})
	replies, datas, errReply = collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 || replies[0].Length != 2 || string(datas[0]) != "89" {
		t.Fatalf("unexpected to-the-end peek result: replies=%+v data=%q", replies, datas[0])
	}

	control := dialControl(t, ti, wsURL)
	sendCommandOK(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(id), Action: "forward"})
	recvResult(t, resCh)
}

// Peeking a specific id that isn't currently pending returns an error reply instead of
// silently returning nothing.
func TestWatchPeek_UnknownId(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	watch := dialWatch(t, wsURL, 1)
	unknown := int64(999999)
	writeJSON(t, watch, watchInboundMsg{Type: "peek", ID: &unknown})
	replies, _, errReply := collectPeekReplies(t, watch)
	if errReply == nil {
		t.Fatalf("expected an error reply, got replies=%+v", replies)
	}
}

// With HoldUntilConnected, a chunk is held even though no control client has ever
// connected, and remains bounded by hold-timeout-ms.
func TestHoldUntilConnected_TimeoutWithoutControl(t *testing.T) {
	ti := NewTamperInterceptor(&TamperConfig{HoldTimeoutMs: 50, HoldUntilConnected: true}, nil)
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	resCh := interceptAsync(ti, info, []byte("original"))
	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "original" {
		t.Fatalf("expected original bytes after timeout, got %q", r.data)
	}
}

// A chunk held before any control client connected is discoverable (via stream-list)
// and resolvable once one finally does.
func TestHoldUntilConnected_VisibleAndResolvableOnceConnected(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true}) // infinite timeout
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	resCh := interceptAsync(ti, info, []byte("original"))
	waitForPendingCount(t, ti, 1, 1)

	select {
	case r := <-resCh:
		t.Fatalf("Intercept returned before any control client connected: %+v", r)
	case <-time.After(50 * time.Millisecond):
	}

	control := dialControl(t, ti, wsURL)
	writeJSON(t, control, inboundMsg{Type: "list-streams"})
	var list streamListMsg
	readJSON(t, control, &list)
	stream := findStreamInfo(&list, 1)
	if stream == nil || len(stream.Pending) != 1 {
		t.Fatalf("expected the pre-held chunk to be visible after connecting, got %+v", stream)
	}

	writeJSON(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(stream.Pending[0].ID), Action: "forward", Edited: boolPtr(true)})
	if err := control.WriteMessage(websocket.BinaryMessage, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	requireOK(t, readAck(t, control))

	r := recvResult(t, resCh)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if string(r.data) != "edited" {
		t.Fatalf("expected edited bytes, got %q", r.data)
	}
}

// set-mode against an unknown stream returns an error instead of silently no-op'ing.
func TestSetMode_UnknownStream_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	control := dialControl(t, ti, wsURL)

	writeJSON(t, control, inboundMsg{Type: "set-mode", Conn: u32Ptr(999), Intercepting: boolPtr(true)})
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an unknown stream, got %+v", r)
	}
}

// resolve against an unknown/already-resolved chunk id returns an error instead of
// silently no-op'ing.
func TestResolve_UnknownChunk_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)

	writeJSON(t, control, inboundMsg{Type: "resolve", Conn: u32Ptr(1), ID: i64Ptr(999), Action: "forward"})
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an unknown chunk id, got %+v", r)
	}
}
