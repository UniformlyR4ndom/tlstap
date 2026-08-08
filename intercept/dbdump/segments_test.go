package dbdump

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func i64Ptr(v int64) *int64 { return &v }

// newTestSegmentsServer starts a real HTTP server backed by a fresh interceptor and
// returns it (for seeding chunks via insertChunk) alongside a dialed /segments
// connection, both cleaned up automatically.
func newTestSegmentsServer(t *testing.T) (*DbDumpInterceptor, *websocket.Conn) {
	t.Helper()
	d := newTestInterceptor(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/i/dbdump/segments"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial /segments: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return d, conn
}

type segmentsReq struct {
	Session     int64  `json:"session"`
	Stream      int64  `json:"stream"`
	AfterStid   *int64 `json:"afterStid,omitempty"`
	BeforeStid  *int64 `json:"beforeStid,omitempty"`
	MaxSegments int    `json:"maxSegments"`
	MaxBytes    int64  `json:"maxBytes"`
}

// doSegments sends one request and reads back the response — either the metadata+binary
// pair (segments, reachedEnd, concatenated bytes, "" error) or a lone error frame
// (nil, false, nil, message).
func doSegments(t *testing.T, conn *websocket.Conn, req segmentsReq) ([]segmentMeta, bool, []byte, string) {
	t.Helper()
	if err := conn.WriteJSON(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read metadata frame: %v", err)
	}
	var frame struct {
		Segments   []segmentMeta `json:"segments"`
		ReachedEnd bool          `json:"reachedEnd"`
		Error      string        `json:"error"`
	}
	if err := json.Unmarshal(msg, &frame); err != nil {
		t.Fatalf("unmarshal metadata frame: %v", err)
	}
	if frame.Error != "" {
		return nil, false, nil, frame.Error
	}
	_, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read binary frame: %v", err)
	}
	return frame.Segments, frame.ReachedEnd, data, ""
}

func wantSegmentStids(t *testing.T, segments []segmentMeta, want []int64) {
	t.Helper()
	if len(segments) != len(want) {
		t.Fatalf("expected stids %v, got %+v", want, segments)
	}
	for j, w := range want {
		if segments[j].Stid != w {
			t.Errorf("segment %d: expected stid %d, got %+v", j, w, segments[j])
		}
	}
}

func TestSegments_Forward_Basic(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("aaaa"))
	insertChunk(t, d.db, 1, 1, 1, 0, 0, 11, []byte("bb"))
	insertChunk(t, d.db, 1, 1, 0, 1, 4, 12, []byte("ccc"))

	segments, reachedEnd, data, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 50, MaxBytes: 1 << 20,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10, 11, 12})
	if !reachedEnd {
		t.Error("expected reachedEnd=true (nothing left after the last chunk)")
	}
	if string(data) != "aaaabbccc" {
		t.Errorf("expected concatenated data %q, got %q", "aaaabbccc", data)
	}
	if segments[0].SegmentID != 0 || segments[0].Direction != 0 || segments[0].Offset != 0 || segments[0].Length != 4 {
		t.Errorf("unexpected segment 0 metadata: %+v", segments[0])
	}
	if segments[1].SegmentID != 0 || segments[1].Direction != 1 || segments[1].Offset != 0 || segments[1].Length != 2 {
		t.Errorf("unexpected segment 1 metadata: %+v", segments[1])
	}
}

func TestSegments_Forward_MaxSegmentsCap(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 5; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*4, 10+j, []byte("aaaa"))
	}

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 2, MaxBytes: 1 << 20,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10, 11})
	if reachedEnd {
		t.Error("expected reachedEnd=false — 3 more chunks exist")
	}
}

func TestSegments_Forward_MaxBytesCap(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 4; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*10, 10+j, []byte("0123456789"))
	}

	// 10 bytes/chunk, cap at 15: first chunk alone doesn't cross it, second does.
	segments, reachedEnd, data, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 50, MaxBytes: 15,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10, 11})
	if reachedEnd {
		t.Error("expected reachedEnd=false — chunks remain past the byte cap")
	}
	if len(data) != 20 {
		t.Errorf("expected 20 bytes (2 whole chunks, no truncation), got %d", len(data))
	}
}

// TestSegments_SingleChunkExceedsMaxBytes confirms a single oversized chunk is never
// truncated — the byte cap only ever stops the walk *between* whole chunks, so it can
// overshoot maxBytes by up to one chunk's own size.
func TestSegments_SingleChunkExceedsMaxBytes(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	big := make([]byte, 100)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, big)
	insertChunk(t, d.db, 1, 1, 0, 1, 100, 11, []byte("x"))

	segments, reachedEnd, data, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 50, MaxBytes: 10,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10})
	if len(data) != 100 {
		t.Errorf("expected the full 100-byte chunk, not truncated, got %d bytes", len(data))
	}
	if reachedEnd {
		t.Error("expected reachedEnd=false — one more chunk exists")
	}
}

// TestSegments_ByteCapTriggersAtSegmentCapBoundary is the tight edge case for the +1
// lookahead: the byte cap fires on exactly the last segment maxSegments would have
// allowed anyway. The lookahead row must still be reachable to report reachedEnd
// correctly.
func TestSegments_ByteCapTriggersAtSegmentCapBoundary(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 4; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*10, 10+j, []byte("0123456789"))
	}

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 3, MaxBytes: 25,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10, 11, 12})
	if reachedEnd {
		t.Error("expected reachedEnd=false — a 4th chunk exists beyond both caps")
	}
}

func TestSegments_Forward_NaturalExhaustion(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("aa"))
	insertChunk(t, d.db, 1, 1, 0, 1, 2, 11, []byte("bb"))

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 50, MaxBytes: 1000,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10, 11})
	if !reachedEnd {
		t.Error("expected reachedEnd=true — neither cap was hit, rows just ran out")
	}
}

func TestSegments_Backward_Basic(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 5; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*4, 10+j, []byte("aaaa"))
	}

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, BeforeStid: i64Ptr(13), MaxSegments: 50, MaxBytes: 1 << 20,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	// stid 13 excluded (exclusive boundary); 10,11,12 remain, returned ascending. That's
	// also the entire available range below 13 (nothing exists before stid 10), so this
	// is a natural-exhaustion case, not a cap-triggered one.
	wantSegmentStids(t, segments, []int64{10, 11, 12})
	if !reachedEnd {
		t.Error("expected reachedEnd=true — 10,11,12 is the whole range below stid 13")
	}
}

func TestSegments_Backward_ReachedStart(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 3; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*4, 10+j, []byte("aaaa"))
	}

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, BeforeStid: i64Ptr(100), MaxSegments: 50, MaxBytes: 1 << 20,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	wantSegmentStids(t, segments, []int64{10, 11, 12})
	if !reachedEnd {
		t.Error("expected reachedEnd=true — these are the very first chunks of the stream")
	}
}

func TestSegments_Backward_MaxSegmentsCap(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 5; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*4, 10+j, []byte("aaaa"))
	}

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, BeforeStid: i64Ptr(100), MaxSegments: 2, MaxBytes: 1 << 20,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	// Nearest 2 to the boundary, still returned ascending.
	wantSegmentStids(t, segments, []int64{13, 14})
	if reachedEnd {
		t.Error("expected reachedEnd=false — stids 10-12 remain further back")
	}
}

func TestSegments_EmptyResult_NoError(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("aa"))

	segments, reachedEnd, data, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(100), MaxSegments: 50, MaxBytes: 1 << 20,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	if len(segments) != 0 {
		t.Errorf("expected no segments, got %+v", segments)
	}
	if len(data) != 0 {
		t.Errorf("expected an empty binary frame, got %d bytes", len(data))
	}
	if !reachedEnd {
		t.Error("expected reachedEnd=true")
	}
}

func TestSegments_MalformedRequest_BothBoundaries(t *testing.T) {
	_, conn := newTestSegmentsServer(t)
	_, _, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(0), BeforeStid: i64Ptr(0), MaxSegments: 50, MaxBytes: 1 << 20,
	})
	if errMsg == "" {
		t.Fatal("expected an error when both afterStid and beforeStid are given")
	}
}

func TestSegments_MalformedRequest_NeitherBoundary(t *testing.T) {
	_, conn := newTestSegmentsServer(t)
	_, _, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, MaxSegments: 50, MaxBytes: 1 << 20,
	})
	if errMsg == "" {
		t.Fatal("expected an error when neither afterStid nor beforeStid is given")
	}
}

func TestSegments_UnlimitedCaps(t *testing.T) {
	d, conn := newTestSegmentsServer(t)
	for j := int64(0); j < 10; j++ {
		insertChunk(t, d.db, 1, 1, 0, j, j*4, 10+j, []byte("aaaa"))
	}

	segments, reachedEnd, _, errMsg := doSegments(t, conn, segmentsReq{
		Session: 1, Stream: 1, AfterStid: i64Ptr(-1), MaxSegments: 0, MaxBytes: 0,
	})
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	if len(segments) != 10 {
		t.Fatalf("expected all 10 segments with both caps unlimited, got %d", len(segments))
	}
	if !reachedEnd {
		t.Error("expected reachedEnd=true")
	}
}
