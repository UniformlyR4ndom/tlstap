package tamper

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"tlstap/logging"
	"tlstap/proxy"
)

func newTestServer(t *testing.T, holdTimeoutMs int) (*TamperInterceptor, string) {
	t.Helper()
	return newTestServerWithConfig(t, TamperConfig{HoldTimeoutMs: holdTimeoutMs})
}

func newTestServerWithConfig(t *testing.T, config TamperConfig) (*TamperInterceptor, string) {
	t.Helper()
	ti, err := NewTamperInterceptor(&config, nil)
	if err != nil {
		t.Fatal(err)
	}
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

func boolPtr(b bool) *bool                { return &b }
func u32Ptr(u uint32) *uint32             { return &u }
func directionPtr(d direction) *direction { return &d }

// replyMsg is a superset of okMsg/errorMsg's fields, decoded generically since which
// one arrived is read from Type.
type replyMsg struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Message string `json:"message"`
}

// readAck reads one control-channel reply and requires it to be an "ok" or "error"
// acknowledgment — every set-mode/release/drop-connection/set-auto-intercept command
// sends exactly one.
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

// sendCommandOK writes msg to control and asserts the reply acknowledges success. Only
// for commands that carry no trailing binary frame; a command that does (an edited
// release) must write the binary frame itself and call readAck directly instead.
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

// waitForHeldChunks polls internal state until a stream direction's held-buffer chunk
// count reaches want, avoiding a race between registering a hold and observing it.
func waitForHeldChunks(t *testing.T, ti *TamperInterceptor, connID uint32, dir direction, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ti.mu.Lock()
		st := ti.streams[connID]
		ti.mu.Unlock()
		if st != nil && st.held[dir].numChunks() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("stream %d direction %d never reached %d held chunk(s)", connID, dir, want)
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
	Direction   int    `json:"direction"`
	Time        int64  `json:"time"`
	Offset      int64  `json:"offset"`
	Length      int    `json:"length"`
	TotalLength int    `json:"total_length"`
	Bounds      []int  `json:"bounds"`
	Message     string `json:"message"`
}

// collectPeekReplies reads "pending" (+ its binary frame) messages until "peek-done" or
// "error", returning whichever terminated the sequence. A "peek" always produces at
// most one "pending" entry today, but this stays generic over that count.
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

// recvRelease reads exactly one value off a heldBuffer's release channel, as exposed via
// ReleaseChannel.
func recvRelease(t *testing.T, ch <-chan proxy.ReleasedData) proxy.ReleasedData {
	t.Helper()
	select {
	case rd := <-ch:
		return rd
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a release")
		return proxy.ReleasedData{}
	}
}

// No control client connected at all: traffic must pass straight through, and
// Intercept must never block waiting for anything.
func TestNoControl_PassThrough(t *testing.T) {
	ti, err := NewTamperInterceptor(&TamperConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	if created.Type != msgStreamCreated {
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

// A held chunk released with "forward" + edited bytes releases the edited bytes.
func TestHold_ReleaseForwardEdited(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)

	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)
	if held.Type != msgHeld || held.Direction != directionC2S || held.Length != len("original") || held.Offset != 0 {
		t.Fatalf("unexpected held message: %+v", held)
	}

	writeJSON(t, control, inboundMsg{
		Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S),
		Edited: boolPtr(true), PrefixLength: len("original"), Bounds: []int{0}, ReleaseChunks: 1, Action: actionForward,
	})
	if err := control.WriteMessage(websocket.BinaryMessage, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	requireOK(t, readAck(t, control))

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "edited" {
		t.Fatalf("expected edited bytes, got %q", rd.Data)
	}
}

// A held chunk released with "forward" and no edit releases the original bytes.
func TestHold_ReleaseForwardUnedited(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "original" {
		t.Fatalf("expected original bytes, got %q", rd.Data)
	}
}

// A held chunk released with "drop" forwards nothing and does not error.
func TestHold_ReleaseDrop(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionDrop, ReleaseChunks: 1})

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if len(rd.Data) != 0 {
		t.Fatalf("expected no data forwarded on drop, got %q", rd.Data)
	}
}

// "drop-connection" aborts the connection outright, independent of "release".
func TestHold_DropConnection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: cmdDropConnection, Conn: u32Ptr(1), Direction: directionPtr(directionC2S)})

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != proxy.ErrAbort {
		t.Fatalf("expected proxy.ErrAbort, got %v", rd.Err)
	}
}

// If nobody releases a held chunk before the configured timeout, it is auto-forwarded
// unmodified.
func TestHold_Timeout(t *testing.T) {
	ti, wsURL := newTestServer(t, 50)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)
	// Deliberately never release.

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "original" {
		t.Fatalf("expected original bytes on timeout, got %q", rd.Data)
	}
}

// Disconnecting the control client immediately releases everything currently held,
// forwarding the original bytes, rather than waiting for individual timeouts.
func TestHold_ControlDisconnectReleases(t *testing.T) {
	ti, wsURL := newTestServer(t, 0) // infinite timeout: only disconnect can release this
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)

	control.Close()

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "original" {
		t.Fatalf("expected original bytes on control disconnect, got %q", rd.Data)
	}
}

// Switching a stream back to watch mode force-releases anything currently held for it,
// rather than leaving it to time out.
func TestSetMode_ForceReleasesPending(t *testing.T) {
	ti, wsURL := newTestServer(t, 0) // infinite timeout: only the mode switch can release this
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)

	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(false)})

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "original" {
		t.Fatalf("expected original bytes forced-released, got %q", rd.Data)
	}
}

// Direction is derived from comparing SrcEndpoint against the client endpoint recorded
// on the first ConnectionEstablished call.
func TestDirectionDetection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	up := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: "client:1000", DstEndpoint: "server:443"}
	down := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: "server:443", DstEndpoint: "client:1000"}

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(up) // first call: src=client -> records client endpoint
	var created streamCreatedMsg
	readJSON(t, control, &created)
	ti.ConnectionEstablished(down) // second call for the same ConnID: no-op, no event

	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(up, []byte("c2s"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	var c2sHeld heldMsg
	readJSON(t, control, &c2sHeld)
	if c2sHeld.Direction != directionC2S {
		t.Fatalf("expected c2s direction for up info, got %d", c2sHeld.Direction)
	}
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(up))

	out, err = ti.Intercept(down, []byte("s2c"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	var s2cHeld heldMsg
	readJSON(t, control, &s2cHeld)
	if s2cHeld.Direction != directionS2C {
		t.Fatalf("expected s2c direction for down info, got %d", s2cHeld.Direction)
	}
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionS2C), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(down))
}

// stream-list reports each direction's held buffer inline as a chunks/length summary, so
// reconnecting to control at any time (not just being connected at the moment a chunk
// was held) is enough to discover and act on everything outstanding.
func TestStreamList_PendingInfo(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("pending-data"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	var held heldMsg
	readJSON(t, control, &held)

	writeJSON(t, control, inboundMsg{Type: cmdListStreams})
	var list streamListMsg
	readJSON(t, control, &list)

	stream := findStreamInfo(&list, 1)
	if stream == nil {
		t.Fatal("stream 1 not found in stream-list")
	}
	if len(stream.Pending) != 1 {
		t.Fatalf("expected exactly 1 pending direction, got %d", len(stream.Pending))
	}
	p := stream.Pending[0]
	if p.Direction != directionC2S || p.Chunks != 1 || p.Length != len("pending-data") {
		t.Fatalf("unexpected pending info: %+v", p)
	}

	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(info))
}

// A direction's held buffer can hold more than one chunk at once. Releasing both chunks
// together forwards them as one contiguous blob, and peek's bounds reflect both original
// chunk boundaries.
func TestHold_MultipleChunksSameDirection(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true})
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	out, err := ti.Intercept(info, []byte("abc"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	out, err = ti.Intercept(info, []byte("de"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	waitForHeldChunks(t, ti, 1, directionC2S, 2)

	watch := dialWatch(t, wsURL, 1)
	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(directionC2S)})
	replies, datas, errReply := collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 {
		t.Fatalf("expected 1 pending reply, got %d", len(replies))
	}
	r := replies[0]
	if string(datas[0]) != "abcde" || r.TotalLength != 5 {
		t.Fatalf("expected merged buffer %q, got %+v data=%q", "abcde", r, datas[0])
	}
	if len(r.Bounds) != 2 || r.Bounds[0] != 0 || r.Bounds[1] != 3 {
		t.Fatalf("expected bounds [0 3], got %v", r.Bounds)
	}

	control := dialControl(t, ti, wsURL)
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 2})
	rd := recvRelease(t, ti.ReleaseChannel(info))
	if string(rd.Data) != "abcde" {
		t.Fatalf("expected both chunks forwarded together, got %q", rd.Data)
	}
}

// peek returns both currently-held directions' buffers independently.
func TestWatchPeek_Direction(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true})
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	out, err := ti.Intercept(info, []byte("c2s-data"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	s2cInfo := &proxy.ConnInfo{ConnID: 1, SrcEndpoint: info.DstEndpoint, DstEndpoint: info.SrcEndpoint}
	out, err = ti.Intercept(s2cInfo, []byte("s2c-data"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	watch := dialWatch(t, wsURL, 1)

	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(directionC2S)})
	replies, datas, errReply := collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 || replies[0].Offset != 0 || replies[0].Length != replies[0].TotalLength || string(datas[0]) != "c2s-data" {
		t.Fatalf("unexpected c2s peek result: replies=%+v datas=%q", replies, datas)
	}

	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(directionS2C)})
	replies, datas, errReply = collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 || string(datas[0]) != "s2c-data" {
		t.Fatalf("unexpected s2c peek result: replies=%+v datas=%q", replies, datas)
	}

	control := dialControl(t, ti, wsURL)
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(info))
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionS2C), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(s2cInfo))
}

// Peeking with offset/length returns only that slice, echoing back the actual
// offset/length served alongside the full buffer's total_length.
func TestWatchPeek_OffsetLength(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true})
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	out, err := ti.Intercept(info, []byte("0123456789"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	waitForHeldChunks(t, ti, 1, directionC2S, 1)

	watch := dialWatch(t, wsURL, 1)

	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(directionC2S), Offset: 3, Length: 4})
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

	// Length omitted (0) means "to the end of the buffer".
	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(directionC2S), Offset: 8})
	replies, datas, errReply = collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 || replies[0].Length != 2 || string(datas[0]) != "89" {
		t.Fatalf("unexpected to-the-end peek result: replies=%+v data=%q", replies, datas[0])
	}

	control := dialControl(t, ti, wsURL)
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(info))
}

// Peeking an invalid direction value returns an error reply.
func TestWatchPeek_InvalidDirection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	watch := dialWatch(t, wsURL, 1)
	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(99)})
	replies, _, errReply := collectPeekReplies(t, watch)
	if errReply == nil {
		t.Fatalf("expected an error reply, got replies=%+v", replies)
	}
}

// Peeking with the "direction" field omitted entirely returns an error rather than
// silently defaulting to directionC2S.
func TestWatchPeek_MissingDirection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	watch := dialWatch(t, wsURL, 1)
	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek})
	replies, _, errReply := collectPeekReplies(t, watch)
	if errReply == nil {
		t.Fatalf("expected an error reply, got replies=%+v", replies)
	}
}

// Peeking a valid direction with nothing currently held returns a zero-length reply, not
// an error: an empty direction is a perfectly normal state (e.g. a watch-mode stream).
func TestWatchPeek_EmptyDirection(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	watch := dialWatch(t, wsURL, 1)
	writeJSON(t, watch, watchInboundMsg{Type: cmdPeek, Direction: directionPtr(directionC2S)})
	replies, datas, errReply := collectPeekReplies(t, watch)
	if errReply != nil {
		t.Fatalf("unexpected error reply: %+v", errReply)
	}
	if len(replies) != 1 || replies[0].TotalLength != 0 || len(datas[0]) != 0 {
		t.Fatalf("expected a single zero-length reply, got replies=%+v datas=%q", replies, datas)
	}
}

// With HoldUntilConnected, a chunk is held even though no control client has ever
// connected, and remains bounded by hold-timeout-ms.
func TestHoldUntilConnected_TimeoutWithoutControl(t *testing.T) {
	ti, err := NewTamperInterceptor(&TamperConfig{HoldTimeoutMs: 50, HoldUntilConnected: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}

	rd := recvRelease(t, ti.ReleaseChannel(info))
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "original" {
		t.Fatalf("expected original bytes after timeout, got %q", rd.Data)
	}
}

// A chunk held before any control client connected is discoverable (via stream-list)
// and releasable once one finally does.
func TestHoldUntilConnected_VisibleAndResolvableOnceConnected(t *testing.T) {
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{HoldUntilConnected: true}) // infinite timeout
	info := fakeConnInfo(1)
	ti.ConnectionEstablished(info)

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	waitForHeldChunks(t, ti, 1, directionC2S, 1)

	relCh := ti.ReleaseChannel(info)
	select {
	case rd := <-relCh:
		t.Fatalf("released before any control client connected: %+v", rd)
	case <-time.After(50 * time.Millisecond):
	}

	control := dialControl(t, ti, wsURL)
	writeJSON(t, control, inboundMsg{Type: cmdListStreams})
	var list streamListMsg
	readJSON(t, control, &list)
	stream := findStreamInfo(&list, 1)
	if stream == nil || len(stream.Pending) != 1 {
		t.Fatalf("expected the pre-held chunk to be visible after connecting, got %+v", stream)
	}

	writeJSON(t, control, inboundMsg{
		Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S),
		Edited: boolPtr(true), PrefixLength: len("original"), Bounds: []int{0}, ReleaseChunks: 1, Action: actionForward,
	})
	if err := control.WriteMessage(websocket.BinaryMessage, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	requireOK(t, readAck(t, control))

	rd := recvRelease(t, relCh)
	if rd.Err != nil {
		t.Fatal(rd.Err)
	}
	if string(rd.Data) != "edited" {
		t.Fatalf("expected edited bytes, got %q", rd.Data)
	}
}

// set-mode against an unknown stream returns an error instead of silently no-op'ing.
func TestSetMode_UnknownStream_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	control := dialControl(t, ti, wsURL)

	writeJSON(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(999), Intercepting: boolPtr(true)})
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an unknown stream, got %+v", r)
	}
}

// release against an unknown stream returns an error instead of silently no-op'ing.
func TestRelease_UnknownStream_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	control := dialControl(t, ti, wsURL)

	writeJSON(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(999), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an unknown stream, got %+v", r)
	}
}

// release asking for more chunks than are currently held returns an error instead of
// silently no-op'ing.
func TestRelease_TooManyChunks_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)

	writeJSON(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply when releasing more than is held, got %+v", r)
	}
}

// A "release" with prefix_length exceeding the buffer's current length (e.g. a
// hold-timeout already flushed it in the meantime) is rejected rather than silently
// corrupting or misapplying the edit — the concurrency-safety mechanism performAction
// relies on in place of a synthetic version counter.
func TestRelease_StalePrefixLength_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("abc"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	var held heldMsg
	readJSON(t, control, &held)

	writeJSON(t, control, inboundMsg{
		Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S),
		Edited: boolPtr(true), PrefixLength: 100, Bounds: []int{0}, ReleaseChunks: 1, Action: actionForward,
	})
	if err := control.WriteMessage(websocket.BinaryMessage, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an out-of-range prefix_length, got %+v", r)
	}

	// The rejected release must leave the buffer untouched.
	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	rd := recvRelease(t, ti.ReleaseChannel(info))
	if string(rd.Data) != "abc" {
		t.Fatalf("expected untouched original data after the rejected edit, got %q", rd.Data)
	}
}

// A "release" with edited:true but an invalid action must still consume the promised
// binary frame and reply with a clean error, rather than leaving the frame unread and
// desyncing (and silently killing) the control connection.
func TestRelease_InvalidActionWithEditedFrame_DoesNotDesyncControl(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	out, err := ti.Intercept(info, []byte("original"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	var held heldMsg
	readJSON(t, control, &held)

	writeJSON(t, control, inboundMsg{
		Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S),
		Edited: boolPtr(true), PrefixLength: len("original"), Bounds: []int{0}, ReleaseChunks: 1, Action: "not-a-real-action",
	})
	if err := control.WriteMessage(websocket.BinaryMessage, []byte("edited")); err != nil {
		t.Fatal(err)
	}
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an invalid action, got %+v", r)
	}

	// The control connection must still be usable after the malformed command.
	writeJSON(t, control, inboundMsg{Type: cmdListStreams})
	var list streamListMsg
	readJSON(t, control, &list)
	if findStreamInfo(&list, 1) == nil {
		t.Fatal("control connection appears desynced: list-streams failed after the invalid release")
	}
}

// drop-connection against an unknown stream returns an error instead of silently
// no-op'ing.
func TestDropConnection_UnknownStream_ReturnsError(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	control := dialControl(t, ti, wsURL)

	writeJSON(t, control, inboundMsg{Type: cmdDropConnection, Conn: u32Ptr(999), Direction: directionPtr(directionC2S)})
	if r := readAck(t, control); r.Type != "error" {
		t.Fatalf("expected an error reply for an unknown stream, got %+v", r)
	}
}

// HasPending/ReleaseChannel (the proxy.BufferingInterceptor methods) reflect a
// direction's held state directly, independent of the control-channel protocol built on
// top of them.
func TestHasPending(t *testing.T) {
	ti, wsURL := newTestServer(t, 0)
	info := fakeConnInfo(1)

	control := dialControl(t, ti, wsURL)
	ti.ConnectionEstablished(info)
	var created streamCreatedMsg
	readJSON(t, control, &created)
	sendCommandOK(t, control, inboundMsg{Type: cmdSetMode, Conn: u32Ptr(1), Intercepting: boolPtr(true)})

	if ti.HasPending(info) {
		t.Fatal("expected HasPending false before any hold")
	}

	out, err := ti.Intercept(info, []byte("x"))
	if err != nil || out != nil {
		t.Fatalf("expected held (nil, nil), got (%q, %v)", out, err)
	}
	var held heldMsg
	readJSON(t, control, &held)
	if !ti.HasPending(info) {
		t.Fatal("expected HasPending true after a hold")
	}

	sendCommandOK(t, control, inboundMsg{Type: cmdRelease, Conn: u32Ptr(1), Direction: directionPtr(directionC2S), Action: actionForward, ReleaseChunks: 1})
	recvRelease(t, ti.ReleaseChannel(info))
	if ti.HasPending(info) {
		t.Fatal("expected HasPending false after release")
	}
}

// Init assigns i.logFile concurrently with handleLogFileInfo reading it — both must go
// through logFileMu, or this is a data race under -race.
func TestLogFile_InitRaceWithHandleLogFileInfo(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "tamper.log")
	ti, wsURL := newTestServerWithConfig(t, TamperConfig{LogFile: logPath})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/log-file"

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := ti.Init(net.TCPAddr{}); err != nil {
			t.Error(err)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			resp := httpDo(t, http.MethodGet, base, nil)
			resp.Body.Close()
		}
	}()
	wg.Wait()
	t.Cleanup(func() { ti.Finalize(net.TCPAddr{}) })
}

// Finalize closes i.logFile concurrently with writeScriptLog writing to it — both must
// go through logFileMu, or this is a data race (and a use-after-close) under -race.
func TestLogFile_FinalizeRaceWithWriteScriptLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "tamper.log")
	logger := logging.NewLogger(io.Discard, &slog.HandlerOptions{}, false)
	ti, err := NewTamperInterceptor(&TamperConfig{LogFile: logPath}, &logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := ti.Init(net.TCPAddr{}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			ti.writeScriptLog("log", "line")
		}
	}()
	go func() {
		defer wg.Done()
		ti.Finalize(net.TCPAddr{})
	}()
	wg.Wait()
}
