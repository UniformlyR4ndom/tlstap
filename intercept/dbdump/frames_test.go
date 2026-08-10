package dbdump

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postJSON POSTs v as a JSON body to url and decodes the response into resp (if
// non-nil), returning the status code.
func postJSON(t *testing.T, url string, v, resp any) int {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if resp != nil {
		if err := json.NewDecoder(r.Body).Decode(resp); err != nil {
			t.Fatal(err)
		}
	}
	return r.StatusCode
}

func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func strPtr(s string) *string { return &s }

func TestFrameProgress_NotStarted(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}

	offset, state, _, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 || state != nil {
		t.Fatalf("expected (0, nil) for a key with no data, got (%d, %v)", offset, state)
	}
}

func TestAppendFrames_InitialAndIncremental(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}

	err := d.appendFrames(key, 0, []frameInput{
		{Offset: 0, Length: 10, Meta: strPtr("a"), Time: 1000},
		{Offset: 10, Length: 5, Meta: nil, Time: 1005},
	}, 15, []byte("state1"), false)
	if err != nil {
		t.Fatal(err)
	}

	offset, state, _, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 15 || string(state) != "state1" {
		t.Fatalf("unexpected progress: offset=%d state=%q", offset, state)
	}

	frames, err := d.listFrames(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[0].ID != 0 || frames[0].Offset != 0 || frames[0].Length != 10 || frames[0].Meta == nil || *frames[0].Meta != "a" || frames[0].Time != 1000 {
		t.Errorf("unexpected frame 0: %+v", frames[0])
	}
	if frames[1].ID != 1 || frames[1].Offset != 10 || frames[1].Length != 5 || frames[1].Meta != nil || frames[1].Time != 1005 {
		t.Errorf("unexpected frame 1: %+v", frames[1])
	}

	// A second batch continues ids from where the first left off and advances progress.
	if err := d.appendFrames(key, 15, []frameInput{{Offset: 15, Length: 20}}, 35, []byte("state2"), false); err != nil {
		t.Fatal(err)
	}
	offset, state, _, err = d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 35 || string(state) != "state2" {
		t.Fatalf("unexpected progress after extension: offset=%d state=%q", offset, state)
	}
	frames, err = d.listFrames(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 || frames[2].ID != 2 || frames[2].Offset != 15 {
		t.Fatalf("expected 3 frames with a continuing id, got %+v", frames)
	}
}

// TestFrameProgress_ClosedFlag confirms the connection-close bit persists independently
// of processed_offset/state: it starts false, an appendFrames call with closed=true sets
// it without disturbing the other fields, and a subsequent ordinary (closed=false) call
// for a *different* key is unaffected.
func TestFrameProgress_ClosedFlag(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	other := frameKey{Session: 1, Stream: 1, Direction: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, 0, []frameInput{{Offset: 0, Length: 10}}, 10, []byte("state1"), false); err != nil {
		t.Fatal(err)
	}
	if _, _, closed, err := d.getFrameProgress(key); err != nil || closed {
		t.Fatalf("expected closed=false before the closing call, got closed=%v err=%v", closed, err)
	}

	// The dedicated closing call: no new frames, processed_offset unchanged, closed=true.
	if err := d.appendFrames(key, 10, nil, 10, []byte("state1"), true); err != nil {
		t.Fatal(err)
	}
	offset, state, closed, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if !closed || offset != 10 || string(state) != "state1" {
		t.Fatalf("expected (10, %q, true), got (%d, %q, %v)", "state1", offset, state, closed)
	}

	if err := d.appendFrames(other, 0, []frameInput{{Offset: 0, Length: 5}}, 5, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, closed, err := d.getFrameProgress(other); err != nil || closed {
		t.Fatalf("expected the other key's closed flag untouched, got closed=%v err=%v", closed, err)
	}
}

func TestAppendFrames_ConflictOnStaleOffset(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, 0, []frameInput{{Offset: 0, Length: 10}}, 10, nil, false); err != nil {
		t.Fatal(err)
	}

	// expectedProcessedOffset still claims 0, but the stored value is now 10.
	err := d.appendFrames(key, 0, []frameInput{{Offset: 10, Length: 5}}, 15, nil, false)
	if err != errFrameProgressConflict {
		t.Fatalf("expected errFrameProgressConflict, got %v", err)
	}

	// The rejected call must not have written anything.
	offset, _, _, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 10 {
		t.Fatalf("expected progress to still be 10 after the rejected append, got %d", offset)
	}
	frames, err := d.listFrames(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame after the rejected append, got %d", len(frames))
	}
}

func TestListFrames_Paging(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}

	inputs := make([]frameInput, 5)
	for j := range inputs {
		inputs[j] = frameInput{Offset: int64(j * 10), Length: 10}
	}
	if err := d.appendFrames(key, 0, inputs, 50, nil, false); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFrames(key, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || frames[0].ID != 2 || frames[1].ID != 3 {
		t.Fatalf("expected ids [2,3], got %+v", frames)
	}
}

func TestPurgeOtherFrameVersions(t *testing.T) {
	d := newTestInterceptor(t)
	keyV1 := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	keyV2 := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v2"}
	keyOtherScript := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "bar", ScriptVersion: "v1"}

	for _, k := range []frameKey{keyV1, keyV2, keyOtherScript} {
		if err := d.appendFrames(k, 0, []frameInput{{Offset: 0, Length: 10}}, 10, nil, false); err != nil {
			t.Fatal(err)
		}
	}

	if err := d.purgeOtherFrameVersions("foo", "v2"); err != nil {
		t.Fatal(err)
	}

	if frames, err := d.listFrames(keyV1, 0, 0); err != nil || len(frames) != 0 {
		t.Fatalf("expected v1 purged, got frames=%+v err=%v", frames, err)
	}
	if offset, _, _, err := d.getFrameProgress(keyV1); err != nil || offset != 0 {
		t.Fatalf("expected v1 progress purged, got offset=%d err=%v", offset, err)
	}
	if frames, err := d.listFrames(keyV2, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected v2 kept, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(keyOtherScript, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected other script untouched, got frames=%+v err=%v", frames, err)
	}
}

func TestPurgeAllFrameVersions(t *testing.T) {
	d := newTestInterceptor(t)
	keyV1 := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	keyV2 := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v2"}
	keyOtherScript := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "bar", ScriptVersion: "v1"}

	for _, k := range []frameKey{keyV1, keyV2, keyOtherScript} {
		if err := d.appendFrames(k, 0, []frameInput{{Offset: 0, Length: 10}}, 10, nil, false); err != nil {
			t.Fatal(err)
		}
	}

	if err := d.purgeAllFrameVersions("foo"); err != nil {
		t.Fatal(err)
	}

	for _, k := range []frameKey{keyV1, keyV2} {
		if frames, err := d.listFrames(k, 0, 0); err != nil || len(frames) != 0 {
			t.Fatalf("expected %+v purged, got frames=%+v err=%v", k, frames, err)
		}
	}
	if frames, err := d.listFrames(keyOtherScript, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected other script untouched, got frames=%+v err=%v", frames, err)
	}
}

func TestClearStreamFrames(t *testing.T) {
	d := newTestInterceptor(t)
	keep := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v2"}
	staleVersion := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	otherScript := frameKey{Session: 1, Stream: 1, Direction: 1, Script: "bar", ScriptVersion: "v1"}
	otherStream := frameKey{Session: 1, Stream: 2, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	otherSession := frameKey{Session: 2, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}

	for _, k := range []frameKey{keep, staleVersion, otherScript, otherStream, otherSession} {
		if err := d.appendFrames(k, 0, []frameInput{{Offset: 0, Length: 10}}, 10, nil, false); err != nil {
			t.Fatal(err)
		}
	}

	keepTimeline := frameTimelineKey{Session: keep.Session, Stream: keep.Stream, Script: keep.Script, ScriptVersion: keep.ScriptVersion}
	if err := d.clearStreamFrames(keepTimeline); err != nil {
		t.Fatal(err)
	}

	if frames, err := d.listFrames(keep, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected keep kept, got frames=%+v err=%v", frames, err)
	}
	for _, k := range []frameKey{staleVersion, otherScript} {
		if frames, err := d.listFrames(k, 0, 0); err != nil || len(frames) != 0 {
			t.Fatalf("expected %+v purged (same stream, different script/version), got frames=%+v err=%v", k, frames, err)
		}
		if offset, _, _, err := d.getFrameProgress(k); err != nil || offset != 0 {
			t.Fatalf("expected %+v progress purged, got offset=%d err=%v", k, offset, err)
		}
	}
	for _, k := range []frameKey{otherStream, otherSession} {
		if frames, err := d.listFrames(k, 0, 0); err != nil || len(frames) != 1 {
			t.Fatalf("expected %+v untouched (different stream/session), got frames=%+v err=%v", k, frames, err)
		}
	}
}

// TestClearStreamFrames_KeepSameVersionIsNoop confirms rerunning the same (script,
// script_version) already active for a stream leaves its frame_progress intact —
// TrafficView.js's handleRunFramer relies on this to resume rather than reprocess an
// unchanged rerun.
func TestClearStreamFrames_KeepSameVersionIsNoop(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	if err := d.appendFrames(key, 0, []frameInput{{Offset: 0, Length: 10}}, 10, nil, false); err != nil {
		t.Fatal(err)
	}

	keepTimeline := frameTimelineKey{Session: key.Session, Stream: key.Stream, Script: key.Script, ScriptVersion: key.ScriptVersion}
	if err := d.clearStreamFrames(keepTimeline); err != nil {
		t.Fatal(err)
	}

	if frames, err := d.listFrames(key, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected frame data kept, got frames=%+v err=%v", frames, err)
	}
	if offset, _, _, err := d.getFrameProgress(key); err != nil || offset != 10 {
		t.Fatalf("expected progress kept at 10, got offset=%d err=%v", offset, err)
	}
}

// TestFramesClearAPI_HTTP is the HTTP-level counterpart to TestClearStreamFrames,
// exercising the real POST /frames/clear route.
func TestFramesClearAPI_HTTP(t *testing.T) {
	d := newTestInterceptor(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	keep := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v2"}
	stale := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	for _, k := range []frameKey{keep, stale} {
		if err := d.appendFrames(k, 0, []frameInput{{Offset: 0, Length: 10}}, 10, nil, false); err != nil {
			t.Fatal(err)
		}
	}

	status := postJSON(t, server.URL+"/api/i/dbdump/frames/clear", map[string]any{
		"session": keep.Session, "stream": keep.Stream, "script": keep.Script, "script_version": keep.ScriptVersion,
	}, nil)
	if status != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", status)
	}

	if frames, err := d.listFrames(keep, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected keep kept, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(stale, 0, 0); err != nil || len(frames) != 0 {
		t.Fatalf("expected stale purged, got frames=%+v err=%v", frames, err)
	}
}

// TestFramerScriptsAPI_PutPurgesStaleVersions is an end-to-end test that PUTting a
// framer script (via the scriptstore-backed REST endpoints RegisterRoutes wires)
// triggers onFramerScriptPut, purging every other persisted frame-index version for
// that script name while leaving the version matching the new content (and other
// scripts) untouched.
func TestFramerScriptsAPI_PutPurgesStaleVersions(t *testing.T) {
	dir := t.TempDir()
	d := newTestInterceptorWithScripts(t, dir)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	newContent := "function frame(state, chunk) {}"
	staleKey := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "myframer", ScriptVersion: "stale"}
	freshKey := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "myframer", ScriptVersion: sha256Hex(newContent)}
	otherKey := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "other", ScriptVersion: "stale"}

	for _, k := range []frameKey{staleKey, freshKey, otherKey} {
		if err := d.appendFrames(k, 0, []frameInput{{Offset: 0, Length: 1}}, 1, nil, false); err != nil {
			t.Fatal(err)
		}
	}

	req, err := http.NewRequest(http.MethodPut, server.URL+"/api/i/dbdump/scripts/myframer", strings.NewReader(newContent))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT script: expected 204, got %d", resp.StatusCode)
	}

	if frames, err := d.listFrames(staleKey, 0, 0); err != nil || len(frames) != 0 {
		t.Fatalf("expected stale version purged, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(freshKey, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected version matching new content to be kept, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(otherKey, 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected other script untouched, got frames=%+v err=%v", frames, err)
	}
}

// TestFramerScriptsAPI_DeletePurgesAllVersions is the DELETE counterpart: every
// persisted version for the deleted script name is purged.
func TestFramerScriptsAPI_DeletePurgesAllVersions(t *testing.T) {
	dir := t.TempDir()
	d := newTestInterceptorWithScripts(t, dir)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// A script must exist before it can be deleted.
	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/api/i/dbdump/scripts/myframer", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	putResp.Body.Close()

	keyV1 := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "myframer", ScriptVersion: "v1"}
	keyV2 := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "myframer", ScriptVersion: "v2"}
	if err := d.appendFrames(keyV1, 0, []frameInput{{Offset: 0, Length: 1}}, 1, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := d.appendFrames(keyV2, 0, []frameInput{{Offset: 0, Length: 1}}, 1, nil, false); err != nil {
		t.Fatal(err)
	}

	delReq, err := http.NewRequest(http.MethodDelete, server.URL+"/api/i/dbdump/scripts/myframer", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE script: expected 204, got %d", resp.StatusCode)
	}

	for _, k := range []frameKey{keyV1, keyV2} {
		if frames, err := d.listFrames(k, 0, 0); err != nil || len(frames) != 0 {
			t.Fatalf("expected %+v purged after delete, got frames=%+v err=%v", k, frames, err)
		}
	}
}

func newTestFramesServer(t *testing.T) string {
	t.Helper()
	d := newTestInterceptor(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server.URL + "/api/i/dbdump"
}

func TestHandleFrameProgress_NotStarted(t *testing.T) {
	base := newTestFramesServer(t)

	var resp struct {
		ProcessedOffset int64  `json:"processed_offset"`
		State           []byte `json:"state"`
		Closed          bool   `json:"closed"`
	}
	req := map[string]any{"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1"}
	if status := postJSON(t, base+"/frame-progress", req, &resp); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if resp.ProcessedOffset != 0 || resp.State != nil || resp.Closed {
		t.Fatalf("expected (0, nil, false), got (%d, %v, %v)", resp.ProcessedOffset, resp.State, resp.Closed)
	}
}

// TestHandleFramesAppend_Closed is the HTTP-level counterpart to
// TestFrameProgress_ClosedFlag: POSTing /frames/append with "closed": true is reflected
// back by /frame-progress.
func TestHandleFramesAppend_Closed(t *testing.T) {
	base := newTestFramesServer(t)
	key := map[string]any{"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1"}

	closeReq := map[string]any{
		"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames":                []map[string]any{},
		"new_processed_offset":      0,
		"closed":                    true,
	}
	if status := postJSON(t, base+"/frames/append", closeReq, nil); status != http.StatusNoContent {
		t.Fatalf("append: expected 204, got %d", status)
	}

	var resp struct {
		Closed bool `json:"closed"`
	}
	if status := postJSON(t, base+"/frame-progress", key, &resp); status != http.StatusOK {
		t.Fatalf("frame-progress: expected 200, got %d", status)
	}
	if !resp.Closed {
		t.Fatalf("expected closed=true, got %v", resp.Closed)
	}
}

func TestHandleFramesAppendAndList(t *testing.T) {
	base := newTestFramesServer(t)
	key := map[string]any{"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1"}

	appendReq := map[string]any{
		"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames": []map[string]any{
			{"offset": 0, "length": 10, "meta": "a", "time": 1000},
			{"offset": 10, "length": 5, "time": 1005},
		},
		"new_processed_offset": 15,
	}
	if status := postJSON(t, base+"/frames/append", appendReq, nil); status != http.StatusNoContent {
		t.Fatalf("append: expected 204, got %d", status)
	}

	var progress struct {
		ProcessedOffset int64  `json:"processed_offset"`
		State           []byte `json:"state"`
	}
	if status := postJSON(t, base+"/frame-progress", key, &progress); status != http.StatusOK {
		t.Fatalf("frame-progress: expected 200, got %d", status)
	}
	if progress.ProcessedOffset != 15 {
		t.Fatalf("expected processed_offset 15, got %d", progress.ProcessedOffset)
	}

	var frames []struct {
		ID     int64   `json:"id"`
		Offset int64   `json:"offset"`
		Length int64   `json:"length"`
		Meta   *string `json:"meta"`
		Time   int64   `json:"time"`
	}
	listReq := map[string]any{"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1", "start": 0, "n": 0}
	if status := postJSON(t, base+"/frames", listReq, &frames); status != http.StatusOK {
		t.Fatalf("frames: expected 200, got %d", status)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[0].ID != 0 || frames[0].Offset != 0 || frames[0].Length != 10 || frames[0].Meta == nil || *frames[0].Meta != "a" || frames[0].Time != 1000 {
		t.Errorf("unexpected frame 0: %+v", frames[0])
	}
	if frames[1].ID != 1 || frames[1].Offset != 10 || frames[1].Length != 5 || frames[1].Meta != nil || frames[1].Time != 1005 {
		t.Errorf("unexpected frame 1: %+v", frames[1])
	}
}

func TestHandleFramesAppend_ConflictOnStaleOffset(t *testing.T) {
	base := newTestFramesServer(t)

	first := map[string]any{
		"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames":                []map[string]any{{"offset": 0, "length": 10}},
		"new_processed_offset":      10,
	}
	if status := postJSON(t, base+"/frames/append", first, nil); status != http.StatusNoContent {
		t.Fatalf("first append: expected 204, got %d", status)
	}

	// Stale expected_processed_offset (still claims 0).
	second := map[string]any{
		"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames":                []map[string]any{{"offset": 10, "length": 5}},
		"new_processed_offset":      15,
	}
	if status := postJSON(t, base+"/frames/append", second, nil); status != http.StatusConflict {
		t.Fatalf("expected 409, got %d", status)
	}
}

func TestHandleFramesAppend_BadJSON(t *testing.T) {
	base := newTestFramesServer(t)
	resp, err := http.Post(base+"/frames/append", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// TestListFramesTimeline_OrderingAndTieBreak is the core correctness test for the
// cross-direction merge: stid ties (routine — one raw chunk producing several frames
// at once) must break by id, and a page must never split a tied group, or the "+1 from
// last stid" pagination cursor useChunkBuffer relies on would silently skip frames.
func TestListFramesTimeline_OrderingAndTieBreak(t *testing.T) {
	d := newTestInterceptor(t)
	keyC2S := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	keyS2C := frameKey{Session: 1, Stream: 1, Direction: 1, Script: "foo", ScriptVersion: "v1"}

	// Direction 0: ids 0..3, with ids 1 and 2 tied on stid=12 (both completed on the
	// same underlying chunk).
	if err := d.appendFrames(keyC2S, 0, []frameInput{
		{Offset: 0, Length: 10, Stid: 10},
		{Offset: 10, Length: 5, Stid: 12},
		{Offset: 15, Length: 5, Stid: 12},
		{Offset: 20, Length: 5, Stid: 15},
	}, 25, nil, false); err != nil {
		t.Fatal(err)
	}
	// Direction 1: ids 0..1, interleaved with direction 0's stids but never tied with
	// them (different chunks, so different stids, by construction).
	if err := d.appendFrames(keyS2C, 0, []frameInput{
		{Offset: 0, Length: 8, Stid: 11},
		{Offset: 8, Length: 8, Stid: 13},
	}, 16, nil, false); err != nil {
		t.Fatal(err)
	}

	tKey := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	all, err := d.listFramesTimeline(tKey, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantStids := []int64{10, 11, 12, 12, 13, 15}
	if len(all) != len(wantStids) {
		t.Fatalf("expected %d frames, got %d: %+v", len(wantStids), len(all), all)
	}
	for j, want := range wantStids {
		if all[j].Stid != want {
			t.Errorf("frame %d: expected stid %d, got %d", j, want, all[j].Stid)
		}
	}
	// The stid=12 tie must resolve in id order: dir0/id1 before dir0/id2.
	if all[2].Direction != 0 || all[2].ID != 1 || all[3].Direction != 0 || all[3].ID != 2 {
		t.Errorf("expected the stid=12 tie ordered (dir0/id1, dir0/id2), got %+v, %+v", all[2], all[3])
	}

	// n=3 would naively cut off after the first of the two stid=12 frames — the page
	// must extend to 4 rows instead of splitting that tie.
	page, err := d.listFramesTimeline(tKey, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 4 {
		t.Fatalf("expected the page to extend to 4 rows to avoid splitting the stid=12 tie, got %d: %+v", len(page), page)
	}
	for j, want := range []int64{10, 11, 12, 12} {
		if page[j].Stid != want {
			t.Errorf("page frame %d: expected stid %d, got %d", j, want, page[j].Stid)
		}
	}

	// Resuming from the page's last stid+1 must continue with nothing skipped or
	// duplicated — the actual concern the group-boundary handling exists for.
	next, err := d.listFramesTimeline(tKey, page[len(page)-1].Stid+1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 2 || next[0].Stid != 13 || next[1].Stid != 15 {
		t.Fatalf("expected [13, 15] after resuming past the tie, got %+v", next)
	}

	// A page that doesn't reach any tie should cut cleanly at exactly n.
	clean, err := d.listFramesTimeline(tKey, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != 1 || clean[0].Stid != 10 {
		t.Fatalf("expected a clean 1-row page, got %+v", clean)
	}
}

// TestListFramesTimelineBackward_OrderingAndTieBreak mirrors
// TestListFramesTimeline_OrderingAndTieBreak exactly (same fixture), walking backward
// instead — the tie-group-boundary-safety guarantee must hold symmetrically.
func TestListFramesTimelineBackward_OrderingAndTieBreak(t *testing.T) {
	d := newTestInterceptor(t)
	keyC2S := frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}
	keyS2C := frameKey{Session: 1, Stream: 1, Direction: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(keyC2S, 0, []frameInput{
		{Offset: 0, Length: 10, Stid: 10},
		{Offset: 10, Length: 5, Stid: 12},
		{Offset: 15, Length: 5, Stid: 12},
		{Offset: 20, Length: 5, Stid: 15},
	}, 25, nil, false); err != nil {
		t.Fatal(err)
	}
	if err := d.appendFrames(keyS2C, 0, []frameInput{
		{Offset: 0, Length: 8, Stid: 11},
		{Offset: 8, Length: 8, Stid: 13},
	}, 16, nil, false); err != nil {
		t.Fatal(err)
	}

	tKey := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	all, err := d.listFramesTimelineBackward(tKey, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantStids := []int64{10, 11, 12, 12, 13, 15}
	if len(all) != len(wantStids) {
		t.Fatalf("expected %d frames, got %d: %+v", len(wantStids), len(all), all)
	}
	for j, want := range wantStids {
		if all[j].Stid != want {
			t.Errorf("frame %d: expected stid %d, got %d", j, want, all[j].Stid)
		}
	}
	if all[2].Direction != 0 || all[2].ID != 1 || all[3].Direction != 0 || all[3].ID != 2 {
		t.Errorf("expected the stid=12 tie ordered (dir0/id1, dir0/id2), got %+v, %+v", all[2], all[3])
	}

	// n=3 nearest-to-100 would naively be [15,13,12] — cutting off the first of the two
	// stid=12 frames. The page must extend to 4 rows instead of splitting that tie.
	page, err := d.listFramesTimelineBackward(tKey, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 4 {
		t.Fatalf("expected the page to extend to 4 rows to avoid splitting the stid=12 tie, got %d: %+v", len(page), page)
	}
	for j, want := range []int64{12, 12, 13, 15} {
		if page[j].Stid != want {
			t.Errorf("page frame %d: expected stid %d, got %d", j, want, page[j].Stid)
		}
	}
	if page[0].ID != 1 || page[1].ID != 2 {
		t.Errorf("expected the stid=12 tie ordered (id1, id2) even walking backward, got %+v, %+v", page[0], page[1])
	}

	// Resuming further back from this page's own smallest stid must continue with
	// nothing skipped or duplicated.
	next, err := d.listFramesTimelineBackward(tKey, page[0].Stid, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 2 || next[0].Stid != 10 || next[1].Stid != 11 {
		t.Fatalf("expected [10, 11] after resuming past the tie, got %+v", next)
	}

	// A page that doesn't reach any tie should cut cleanly at exactly n.
	clean, err := d.listFramesTimelineBackward(tKey, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != 1 || clean[0].Stid != 15 {
		t.Fatalf("expected a clean 1-row page (nearest to the boundary), got %+v", clean)
	}
}

func TestHandleFramesTimeline(t *testing.T) {
	base := newTestFramesServer(t)

	appendC2S := map[string]any{
		"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames": []map[string]any{
			{"offset": 0, "length": 10, "stid": 10},
			{"offset": 10, "length": 5, "stid": 12},
		},
		"new_processed_offset": 15,
	}
	if status := postJSON(t, base+"/frames/append", appendC2S, nil); status != http.StatusNoContent {
		t.Fatalf("append c2s: expected 204, got %d", status)
	}
	appendS2C := map[string]any{
		"session": 1, "stream": 1, "direction": 1, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames": []map[string]any{
			{"offset": 0, "length": 8, "stid": 11},
		},
		"new_processed_offset": 8,
	}
	if status := postJSON(t, base+"/frames/append", appendS2C, nil); status != http.StatusNoContent {
		t.Fatalf("append s2c: expected 204, got %d", status)
	}

	var timeline []struct {
		ID        int64   `json:"id"`
		Offset    int64   `json:"offset"`
		Length    int64   `json:"length"`
		Meta      *string `json:"meta"`
		Direction int     `json:"direction"`
		Stid      int64   `json:"stid"`
	}
	req := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "start": 0, "n": 0}
	if status := postJSON(t, base+"/frames/timeline", req, &timeline); status != http.StatusOK {
		t.Fatalf("timeline: expected 200, got %d", status)
	}
	if len(timeline) != 3 {
		t.Fatalf("expected 3 frames, got %d: %+v", len(timeline), timeline)
	}
	wantStids := []int64{10, 11, 12}
	for j, want := range wantStids {
		if timeline[j].Stid != want {
			t.Errorf("frame %d: expected stid %d, got %d", j, want, timeline[j].Stid)
		}
	}
	if timeline[1].Direction != 1 {
		t.Errorf("expected the stid=11 frame to be direction 1, got %+v", timeline[1])
	}
}

// TestHandleFramesTimeline_Backward confirms the REST layer's beforeStid wiring —
// listFramesTimelineBackward itself is exercised in full by
// TestListFramesTimelineBackward_OrderingAndTieBreak above.
func TestHandleFramesTimeline_Backward(t *testing.T) {
	base := newTestFramesServer(t)

	appendC2S := map[string]any{
		"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1",
		"expected_processed_offset": 0,
		"new_frames": []map[string]any{
			{"offset": 0, "length": 10, "stid": 10},
			{"offset": 10, "length": 5, "stid": 12},
		},
		"new_processed_offset": 15,
	}
	if status := postJSON(t, base+"/frames/append", appendC2S, nil); status != http.StatusNoContent {
		t.Fatalf("append c2s: expected 204, got %d", status)
	}

	var timeline []struct {
		ID   int64 `json:"id"`
		Stid int64 `json:"stid"`
	}
	req := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "beforeStid": 100, "n": 0}
	if status := postJSON(t, base+"/frames/timeline", req, &timeline); status != http.StatusOK {
		t.Fatalf("timeline: expected 200, got %d", status)
	}
	if len(timeline) != 2 || timeline[0].Stid != 10 || timeline[1].Stid != 12 {
		t.Fatalf("expected [10, 12] ascending, got %+v", timeline)
	}
}

func TestHandleFramesTimeline_BadRequest_BothOrNeitherBoundary(t *testing.T) {
	base := newTestFramesServer(t)

	both := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "start": 0, "beforeStid": 10, "n": 0}
	if status := postJSON(t, base+"/frames/timeline", both, nil); status != http.StatusBadRequest {
		t.Fatalf("both start and beforeStid: expected 400, got %d", status)
	}

	neither := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "n": 0}
	if status := postJSON(t, base+"/frames/timeline", neither, nil); status != http.StatusBadRequest {
		t.Fatalf("neither start nor beforeStid: expected 400, got %d", status)
	}
}
