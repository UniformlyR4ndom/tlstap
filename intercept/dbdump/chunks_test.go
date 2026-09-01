package dbdump

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func chunkStids(records []chunkTimelineRecord) []int64 {
	out := make([]int64, len(records))
	for j, r := range records {
		out[j] = r.Stid
	}
	return out
}

func TestListChunksTimeline_Forward_MergesBothDirections(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("aaaa"))
	insertChunk(t, d.db, 1, 1, directionS2C, 0, 0, 11, []byte("bb"))
	insertChunk(t, d.db, 1, 1, directionC2S, 1, 4, 12, []byte("ccc"))

	records, err := d.listChunksTimeline(1, 1, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := chunkStids(records); !equalInt64s(got, []int64{10, 11, 12}) {
		t.Errorf("expected stids [10 11 12], got %v", got)
	}
	if records[0].Length != 4 || records[1].Length != 2 || records[2].Length != 3 {
		t.Errorf("unexpected lengths: %+v", records)
	}
}

func TestListChunksTimeline_Forward_NLimit(t *testing.T) {
	d := newTestInterceptor(t)
	for j := int64(0); j < 5; j++ {
		insertChunk(t, d.db, 1, 1, directionC2S, j, j*4, 10+j, []byte("aaaa"))
	}
	records, err := d.listChunksTimeline(1, 1, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := chunkStids(records); !equalInt64s(got, []int64{10, 11}) {
		t.Errorf("expected stids [10 11], got %v", got)
	}
}

func TestListChunksTimelineBackward_ReturnsAscending(t *testing.T) {
	d := newTestInterceptor(t)
	for j := int64(0); j < 5; j++ {
		insertChunk(t, d.db, 1, 1, directionC2S, j, j*4, 10+j, []byte("aaaa"))
	}
	records, err := d.listChunksTimelineBackward(1, 1, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	// Nearest 2 to the boundary (largest stids below 100), still returned ascending.
	if got := chunkStids(records); !equalInt64s(got, []int64{13, 14}) {
		t.Errorf("expected stids [13 14], got %v", got)
	}
}

func TestListChunksTimelineBackward_ExclusiveBoundary(t *testing.T) {
	d := newTestInterceptor(t)
	for j := int64(0); j < 3; j++ {
		insertChunk(t, d.db, 1, 1, directionC2S, j, j*4, 10+j, []byte("aaaa"))
	}
	records, err := d.listChunksTimelineBackward(1, 1, 12, 0)
	if err != nil {
		t.Fatal(err)
	}
	// stid 12 excluded (exclusive boundary); 10, 11 remain.
	if got := chunkStids(records); !equalInt64s(got, []int64{10, 11}) {
		t.Errorf("expected stids [10 11], got %v", got)
	}
}

func TestListChunksTimeline_NoTieBreakNeeded(t *testing.T) {
	// Unlike frames.stid, chunks.stid is never tied — confirm a plain LIMIT lands exactly
	// where n says it should, with no group-boundary logic involved.
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("a"))
	insertChunk(t, d.db, 1, 1, directionS2C, 0, 0, 11, []byte("b"))
	insertChunk(t, d.db, 1, 1, directionC2S, 1, 1, 12, []byte("c"))

	records, err := d.listChunksTimeline(1, 1, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := chunkStids(records); !equalInt64s(got, []int64{10, 11}) {
		t.Errorf("expected the page to end exactly at n=2 with no boundary group logic, got %v", got)
	}
}

func equalInt64s(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for j := range a {
		if a[j] != b[j] {
			return false
		}
	}
	return true
}

// ── handleChunksTimeline (HTTP-level) ───────────────────────────────────────────────

func newTestChunksTimelineServer(t *testing.T) (*DbDumpInterceptor, *httptest.Server) {
	t.Helper()
	d := newTestInterceptor(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return d, server
}

func doChunksTimeline(t *testing.T, server *httptest.Server, body string) (int, []chunkTimelineResponse, string) {
	t.Helper()
	resp, err := http.Post(server.URL+"/api/i/dbdump/chunks/timeline", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return resp.StatusCode, nil, errResp.Error
	}
	var records []chunkTimelineResponse
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, records, ""
}

func TestHandleChunksTimeline_Forward(t *testing.T) {
	d, server := newTestChunksTimelineServer(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("aaaa"))
	insertChunk(t, d.db, 1, 1, directionS2C, 0, 0, 11, []byte("bb"))

	status, records, errMsg := doChunksTimeline(t, server, `{"session":1,"stream":1,"start":0,"n":0}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, errMsg)
	}
	if len(records) != 2 || records[0].Stid != 10 || records[1].Stid != 11 {
		t.Errorf("unexpected records: %+v", records)
	}
	if records[0].Direction != directionC2S || records[1].Direction != directionS2C {
		t.Errorf("unexpected directions: %+v", records)
	}
}

func TestHandleChunksTimeline_Backward(t *testing.T) {
	d, server := newTestChunksTimelineServer(t)
	for j := int64(0); j < 3; j++ {
		insertChunk(t, d.db, 1, 1, directionC2S, j, j*4, 10+j, []byte("aaaa"))
	}

	status, records, errMsg := doChunksTimeline(t, server, `{"session":1,"stream":1,"beforeStid":100,"n":0}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, errMsg)
	}
	if got := (func() []int64 {
		out := make([]int64, len(records))
		for j, r := range records {
			out[j] = r.Stid
		}
		return out
	})(); !equalInt64s(got, []int64{10, 11, 12}) {
		t.Errorf("expected stids [10 11 12], got %v", got)
	}
}

func TestHandleChunksTimeline_BothBoundaries_400(t *testing.T) {
	_, server := newTestChunksTimelineServer(t)
	status, _, errMsg := doChunksTimeline(t, server, `{"session":1,"stream":1,"start":0,"beforeStid":0,"n":0}`)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
	if errMsg == "" {
		t.Error("expected a non-empty error message")
	}
}

func TestHandleChunksTimeline_NeitherBoundary_400(t *testing.T) {
	_, server := newTestChunksTimelineServer(t)
	status, _, _ := doChunksTimeline(t, server, `{"session":1,"stream":1,"n":0}`)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", status)
	}
}

func TestHandleChunksTimeline_EmptyResult(t *testing.T) {
	d, server := newTestChunksTimelineServer(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("a"))

	status, records, errMsg := doChunksTimeline(t, server, `{"session":1,"stream":1,"start":100,"n":0}`)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, errMsg)
	}
	if len(records) != 0 {
		t.Errorf("expected no records, got %+v", records)
	}
}
