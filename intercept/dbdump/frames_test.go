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
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	p, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProcessedOffsetC2S != 0 || p.ProcessedOffsetS2C != 0 || p.State != nil || p.ClosedC2S || p.ClosedS2C {
		t.Fatalf("expected a zero-value progress for a key with no data, got %+v", p)
	}
}

func TestAppendFrames_InitialAndIncremental(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Ranges: []frameRange{{Offset: 0, Length: 10}}, Meta: strPtr("a"), Time: 1000},
		{Ranges: []frameRange{{Offset: 10, Length: 5}}, Meta: nil, Time: 1005},
	}, frameProgress{ProcessedOffsetC2S: 15, State: []byte("state1")})
	if err != nil {
		t.Fatal(err)
	}

	p, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProcessedOffsetC2S != 15 || string(p.State) != "state1" {
		t.Fatalf("unexpected progress: %+v state=%q", p, p.State)
	}

	frames, err := d.listFrames(frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[0].ID != 0 || len(frames[0].Ranges) != 1 || frames[0].Ranges[0].Offset != 0 || frames[0].Ranges[0].Length != 10 || frames[0].Meta == nil || *frames[0].Meta != "a" || frames[0].Time != 1000 || frames[0].Seq != 0 {
		t.Errorf("unexpected frame 0: %+v", frames[0])
	}
	if frames[1].ID != 1 || len(frames[1].Ranges) != 1 || frames[1].Ranges[0].Offset != 10 || frames[1].Ranges[0].Length != 5 || frames[1].Meta != nil || frames[1].Time != 1005 || frames[1].Seq != 1 {
		t.Errorf("unexpected frame 1: %+v", frames[1])
	}

	// A second batch continues ids/seq from where the first left off and advances progress.
	if err := d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 15}, []frameInput{{Ranges: []frameRange{{Offset: 15, Length: 20}}}}, frameProgress{ProcessedOffsetC2S: 35, State: []byte("state2")}); err != nil {
		t.Fatal(err)
	}
	p, err = d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProcessedOffsetC2S != 35 || string(p.State) != "state2" {
		t.Fatalf("unexpected progress after extension: %+v state=%q", p, p.State)
	}
	frames, err = d.listFrames(frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 || frames[2].ID != 2 || frames[2].Ranges[0].Offset != 15 || frames[2].Seq != 2 {
		t.Fatalf("expected 3 frames with a continuing id/seq, got %+v", frames)
	}
}

// TestFrameProgress_ClosedFlags confirms closed_c2s/closed_s2c persist independently of
// each other and of processed_offset/state on the same key (both start false; setting
// one via a dedicated closing call doesn't disturb the other or the offsets/state), and
// that a different key entirely is unaffected.
func TestFrameProgress_ClosedFlags(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	other := frameTimelineKey{Session: 1, Stream: 2, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{{Ranges: []frameRange{{Offset: 0, Length: 10}}}}, frameProgress{ProcessedOffsetC2S: 10, State: []byte("state1")}); err != nil {
		t.Fatal(err)
	}
	if p, err := d.getFrameProgress(key); err != nil || p.ClosedC2S || p.ClosedS2C {
		t.Fatalf("expected both closed flags false before the closing call, got %+v err=%v", p, err)
	}

	// The dedicated closing call for c2s only: no new frames, offsets/state unchanged,
	// closed_c2s=true, closed_s2c left false.
	if err := d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 10}, nil, frameProgress{ProcessedOffsetC2S: 10, State: []byte("state1"), ClosedC2S: true}); err != nil {
		t.Fatal(err)
	}
	p, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if !p.ClosedC2S || p.ClosedS2C || p.ProcessedOffsetC2S != 10 || string(p.State) != "state1" {
		t.Fatalf("expected closedC2S=true, closedS2C=false, offset 10, state1 kept, got %+v state=%q", p, p.State)
	}

	if err := d.appendFrames(other, frameProgress{}, []frameInput{{Ranges: []frameRange{{Offset: 0, Length: 5}}}}, frameProgress{ProcessedOffsetC2S: 5}); err != nil {
		t.Fatal(err)
	}
	if p, err := d.getFrameProgress(other); err != nil || p.ClosedC2S || p.ClosedS2C {
		t.Fatalf("expected the other key's closed flags untouched, got %+v err=%v", p, err)
	}
}

func TestAppendFrames_ConflictOnStaleOffset(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{{Ranges: []frameRange{{Offset: 0, Length: 10}}}}, frameProgress{ProcessedOffsetC2S: 10}); err != nil {
		t.Fatal(err)
	}

	// expected still claims 0, but the stored value is now 10.
	err := d.appendFrames(key, frameProgress{}, []frameInput{{Ranges: []frameRange{{Offset: 10, Length: 5}}}}, frameProgress{ProcessedOffsetC2S: 15})
	if err != errFrameProgressConflict {
		t.Fatalf("expected errFrameProgressConflict, got %v", err)
	}

	// The rejected call must not have written anything.
	p, err := d.getFrameProgress(key)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProcessedOffsetC2S != 10 {
		t.Fatalf("expected progress to still be 10 after the rejected append, got %+v", p)
	}
	frames, err := d.listFrames(frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame after the rejected append, got %d", len(frames))
	}

	// A mismatch on just the *other* direction's offset must also be rejected, even
	// though C2S alone matches.
	err = d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 10, ProcessedOffsetS2C: 5}, nil, frameProgress{ProcessedOffsetC2S: 10, ProcessedOffsetS2C: 5})
	if err != errFrameProgressConflict {
		t.Fatalf("expected errFrameProgressConflict on a stale S2C offset, got %v", err)
	}
}

func TestListFrames_Paging(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	inputs := make([]frameInput, 5)
	for j := range inputs {
		inputs[j] = frameInput{Ranges: []frameRange{{Offset: int64(j * 10), Length: 10}}}
	}
	if err := d.appendFrames(key, frameProgress{}, inputs, frameProgress{ProcessedOffsetC2S: 50}); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFrames(frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || frames[0].ID != 2 || frames[1].ID != 3 {
		t.Fatalf("expected ids [2,3], got %+v", frames)
	}
}

// appendSimple is a small test helper covering the common "one batch, one direction,
// starting fresh" append shape most of the tests below want — expectedOffset/
// newOffset apply to whichever single direction dir names; the other direction's
// offset is always 0 throughout, so passing 0/0 for it is always a correct CAS match.
func appendSimple(t *testing.T, d *DbDumpInterceptor, key frameTimelineKey, dir int, offset, length int64) {
	t.Helper()
	if err := d.appendFrames(key, frameProgress{}, []frameInput{{Direction: dir, Ranges: []frameRange{{Offset: offset, Length: length}}}}, frameProgress{ProcessedOffsetC2S: offset + length}); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeOtherFrameVersions(t *testing.T) {
	d := newTestInterceptor(t)
	keyV1 := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	keyV2 := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v2"}
	keyOtherScript := frameTimelineKey{Session: 1, Stream: 1, Script: "bar", ScriptVersion: "v1"}

	for _, k := range []frameTimelineKey{keyV1, keyV2, keyOtherScript} {
		appendSimple(t, d, k, 0, 0, 10)
	}

	if err := d.purgeOtherFrameVersions("foo", "v2"); err != nil {
		t.Fatal(err)
	}

	frameKeyOf := func(k frameTimelineKey) frameKey {
		return frameKey{Session: k.Session, Stream: k.Stream, Direction: 0, Script: k.Script, ScriptVersion: k.ScriptVersion}
	}

	if frames, err := d.listFrames(frameKeyOf(keyV1), 0, 0); err != nil || len(frames) != 0 {
		t.Fatalf("expected v1 purged, got frames=%+v err=%v", frames, err)
	}
	if p, err := d.getFrameProgress(keyV1); err != nil || p.ProcessedOffsetC2S != 0 {
		t.Fatalf("expected v1 progress purged, got %+v err=%v", p, err)
	}
	if frames, err := d.listFrames(frameKeyOf(keyV2), 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected v2 kept, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(frameKeyOf(keyOtherScript), 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected other script untouched, got frames=%+v err=%v", frames, err)
	}
}

func TestPurgeAllFrameVersions(t *testing.T) {
	d := newTestInterceptor(t)
	keyV1 := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	keyV2 := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v2"}
	keyOtherScript := frameTimelineKey{Session: 1, Stream: 1, Script: "bar", ScriptVersion: "v1"}

	for _, k := range []frameTimelineKey{keyV1, keyV2, keyOtherScript} {
		appendSimple(t, d, k, 0, 0, 10)
	}

	if err := d.purgeAllFrameVersions("foo"); err != nil {
		t.Fatal(err)
	}

	frameKeyOf := func(k frameTimelineKey) frameKey {
		return frameKey{Session: k.Session, Stream: k.Stream, Direction: 0, Script: k.Script, ScriptVersion: k.ScriptVersion}
	}

	for _, k := range []frameTimelineKey{keyV1, keyV2} {
		if frames, err := d.listFrames(frameKeyOf(k), 0, 0); err != nil || len(frames) != 0 {
			t.Fatalf("expected %+v purged, got frames=%+v err=%v", k, frames, err)
		}
	}
	if frames, err := d.listFrames(frameKeyOf(keyOtherScript), 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected other script untouched, got frames=%+v err=%v", frames, err)
	}
}

func TestClearStreamFrames(t *testing.T) {
	d := newTestInterceptor(t)
	keep := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v2"}
	staleVersion := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	otherScript := frameTimelineKey{Session: 1, Stream: 1, Script: "bar", ScriptVersion: "v1"}
	otherStream := frameTimelineKey{Session: 1, Stream: 2, Script: "foo", ScriptVersion: "v1"}
	otherSession := frameTimelineKey{Session: 2, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	for _, k := range []frameTimelineKey{keep, staleVersion, otherScript, otherStream, otherSession} {
		appendSimple(t, d, k, 0, 0, 10)
	}

	if err := d.clearStreamFrames(keep); err != nil {
		t.Fatal(err)
	}

	frameKeyOf := func(k frameTimelineKey) frameKey {
		return frameKey{Session: k.Session, Stream: k.Stream, Direction: 0, Script: k.Script, ScriptVersion: k.ScriptVersion}
	}

	if frames, err := d.listFrames(frameKeyOf(keep), 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected keep kept, got frames=%+v err=%v", frames, err)
	}
	for _, k := range []frameTimelineKey{staleVersion, otherScript} {
		if frames, err := d.listFrames(frameKeyOf(k), 0, 0); err != nil || len(frames) != 0 {
			t.Fatalf("expected %+v purged (same stream, different script/version), got frames=%+v err=%v", k, frames, err)
		}
		if p, err := d.getFrameProgress(k); err != nil || p.ProcessedOffsetC2S != 0 {
			t.Fatalf("expected %+v progress purged, got %+v err=%v", k, p, err)
		}
	}
	for _, k := range []frameTimelineKey{otherStream, otherSession} {
		if frames, err := d.listFrames(frameKeyOf(k), 0, 0); err != nil || len(frames) != 1 {
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
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	appendSimple(t, d, key, 0, 0, 10)

	if err := d.clearStreamFrames(key); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFrames(frameKey{Session: 1, Stream: 1, Direction: 0, Script: "foo", ScriptVersion: "v1"}, 0, 0)
	if err != nil || len(frames) != 1 {
		t.Fatalf("expected frame data kept, got frames=%+v err=%v", frames, err)
	}
	if p, err := d.getFrameProgress(key); err != nil || p.ProcessedOffsetC2S != 10 {
		t.Fatalf("expected progress kept at 10, got %+v err=%v", p, err)
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

	keep := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v2"}
	stale := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	for _, k := range []frameTimelineKey{keep, stale} {
		appendSimple(t, d, k, 0, 0, 10)
	}

	status := postJSON(t, server.URL+"/api/i/dbdump/frames/clear", map[string]any{
		"session": keep.Session, "stream": keep.Stream, "script": keep.Script, "script_version": keep.ScriptVersion,
	}, nil)
	if status != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", status)
	}

	frameKeyOf := func(k frameTimelineKey) frameKey {
		return frameKey{Session: k.Session, Stream: k.Stream, Direction: 0, Script: k.Script, ScriptVersion: k.ScriptVersion}
	}
	if frames, err := d.listFrames(frameKeyOf(keep), 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected keep kept, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(frameKeyOf(stale), 0, 0); err != nil || len(frames) != 0 {
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
	staleKey := frameTimelineKey{Session: 1, Stream: 1, Script: "myframer", ScriptVersion: "stale"}
	freshKey := frameTimelineKey{Session: 1, Stream: 1, Script: "myframer", ScriptVersion: sha256Hex(newContent)}
	otherKey := frameTimelineKey{Session: 1, Stream: 1, Script: "other", ScriptVersion: "stale"}

	for _, k := range []frameTimelineKey{staleKey, freshKey, otherKey} {
		appendSimple(t, d, k, 0, 0, 1)
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

	frameKeyOf := func(k frameTimelineKey) frameKey {
		return frameKey{Session: k.Session, Stream: k.Stream, Direction: 0, Script: k.Script, ScriptVersion: k.ScriptVersion}
	}
	if frames, err := d.listFrames(frameKeyOf(staleKey), 0, 0); err != nil || len(frames) != 0 {
		t.Fatalf("expected stale version purged, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(frameKeyOf(freshKey), 0, 0); err != nil || len(frames) != 1 {
		t.Fatalf("expected version matching new content to be kept, got frames=%+v err=%v", frames, err)
	}
	if frames, err := d.listFrames(frameKeyOf(otherKey), 0, 0); err != nil || len(frames) != 1 {
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

	keyV1 := frameTimelineKey{Session: 1, Stream: 1, Script: "myframer", ScriptVersion: "v1"}
	keyV2 := frameTimelineKey{Session: 1, Stream: 1, Script: "myframer", ScriptVersion: "v2"}
	appendSimple(t, d, keyV1, 0, 0, 1)
	appendSimple(t, d, keyV2, 0, 0, 1)

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

	frameKeyOf := func(k frameTimelineKey) frameKey {
		return frameKey{Session: k.Session, Stream: k.Stream, Direction: 0, Script: k.Script, ScriptVersion: k.ScriptVersion}
	}
	for _, k := range []frameTimelineKey{keyV1, keyV2} {
		if frames, err := d.listFrames(frameKeyOf(k), 0, 0); err != nil || len(frames) != 0 {
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
		ProcessedOffsetC2S int64  `json:"processed_offset_c2s"`
		ProcessedOffsetS2C int64  `json:"processed_offset_s2c"`
		State              []byte `json:"state"`
		ClosedC2S          bool   `json:"closed_c2s"`
		ClosedS2C          bool   `json:"closed_s2c"`
	}
	req := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1"}
	if status := postJSON(t, base+"/frame-progress", req, &resp); status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if resp.ProcessedOffsetC2S != 0 || resp.ProcessedOffsetS2C != 0 || resp.State != nil || resp.ClosedC2S || resp.ClosedS2C {
		t.Fatalf("expected an all-zero-value response, got %+v", resp)
	}
}

// TestHandleFramesAppend_Closed is the HTTP-level counterpart to
// TestFrameProgress_ClosedFlags: POSTing /frames/append with "closed_c2s": true is
// reflected back by /frame-progress, without disturbing closed_s2c.
func TestHandleFramesAppend_Closed(t *testing.T) {
	base := newTestFramesServer(t)
	key := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1"}

	closeReq := map[string]any{
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames": []map[string]any{},
		"closed_c2s": true,
	}
	if status := postJSON(t, base+"/frames/append", closeReq, nil); status != http.StatusNoContent {
		t.Fatalf("append: expected 204, got %d", status)
	}

	var resp struct {
		ClosedC2S bool `json:"closed_c2s"`
		ClosedS2C bool `json:"closed_s2c"`
	}
	if status := postJSON(t, base+"/frame-progress", key, &resp); status != http.StatusOK {
		t.Fatalf("frame-progress: expected 200, got %d", status)
	}
	if !resp.ClosedC2S || resp.ClosedS2C {
		t.Fatalf("expected closed_c2s=true, closed_s2c=false, got %+v", resp)
	}
}

func TestHandleFramesAppendAndList(t *testing.T) {
	base := newTestFramesServer(t)
	key := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1"}

	appendReq := map[string]any{
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames": []map[string]any{
			{"direction": 0, "ranges": []map[string]any{{"offset": 0, "length": 10}}, "meta": "a", "time": 1000},
			{"direction": 0, "ranges": []map[string]any{{"offset": 10, "length": 5}}, "time": 1005},
		},
		"new_processed_offset_c2s": 15,
	}
	if status := postJSON(t, base+"/frames/append", appendReq, nil); status != http.StatusNoContent {
		t.Fatalf("append: expected 204, got %d", status)
	}

	var progress struct {
		ProcessedOffsetC2S int64  `json:"processed_offset_c2s"`
		State              []byte `json:"state"`
	}
	if status := postJSON(t, base+"/frame-progress", key, &progress); status != http.StatusOK {
		t.Fatalf("frame-progress: expected 200, got %d", status)
	}
	if progress.ProcessedOffsetC2S != 15 {
		t.Fatalf("expected processed_offset_c2s 15, got %d", progress.ProcessedOffsetC2S)
	}

	var frames []struct {
		ID            int64        `json:"id"`
		Ranges        []frameRange `json:"ranges"`
		Meta          *string      `json:"meta"`
		Time          int64        `json:"time"`
		Seq           int64        `json:"seq"`
		VirtualOffset int64        `json:"virtual_offset"`
	}
	listReq := map[string]any{"session": 1, "stream": 1, "direction": 0, "script": "foo", "script_version": "v1", "start": 0, "n": 0}
	if status := postJSON(t, base+"/frames", listReq, &frames); status != http.StatusOK {
		t.Fatalf("frames: expected 200, got %d", status)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if frames[0].ID != 0 || len(frames[0].Ranges) != 1 || frames[0].Ranges[0].Offset != 0 || frames[0].Ranges[0].Length != 10 || frames[0].Meta == nil || *frames[0].Meta != "a" || frames[0].Time != 1000 || frames[0].Seq != 0 || frames[0].VirtualOffset != 0 {
		t.Errorf("unexpected frame 0: %+v", frames[0])
	}
	if frames[1].ID != 1 || len(frames[1].Ranges) != 1 || frames[1].Ranges[0].Offset != 10 || frames[1].Ranges[0].Length != 5 || frames[1].Meta != nil || frames[1].Time != 1005 || frames[1].Seq != 1 || frames[1].VirtualOffset != 10 {
		t.Errorf("unexpected frame 1: %+v", frames[1])
	}
}

func TestHandleFramesAppend_ConflictOnStaleOffset(t *testing.T) {
	base := newTestFramesServer(t)

	first := map[string]any{
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames":               []map[string]any{{"ranges": []map[string]any{{"offset": 0, "length": 10}}}},
		"new_processed_offset_c2s": 10,
	}
	if status := postJSON(t, base+"/frames/append", first, nil); status != http.StatusNoContent {
		t.Fatalf("first append: expected 204, got %d", status)
	}

	// Stale expected_processed_offset_c2s (still claims 0).
	second := map[string]any{
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames":               []map[string]any{{"ranges": []map[string]any{{"offset": 10, "length": 5}}}},
		"new_processed_offset_c2s": 15,
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

// seedTimelineFixture appends the shared c2s/s2c fixture used by both
// TestListFramesTimeline_OrderingAndTieBreak and its backward counterpart: one
// appendFrames call per direction against the same frameTimelineKey, coordinating the
// shared frame_progress row's CAS between them (c2s's own call must report the S2C
// offset it found unchanged, and vice versa for s2c's).
func seedTimelineFixture(t *testing.T, d *DbDumpInterceptor, key frameTimelineKey) {
	t.Helper()
	// Direction 0: ids 0..3, with ids 1 and 2 tied on stid=12 (both completed on the
	// same underlying chunk).
	if err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 10}}, Stid: 10},
		{Direction: 0, Ranges: []frameRange{{Offset: 10, Length: 5}}, Stid: 12},
		{Direction: 0, Ranges: []frameRange{{Offset: 15, Length: 5}}, Stid: 12},
		{Direction: 0, Ranges: []frameRange{{Offset: 20, Length: 5}}, Stid: 15},
	}, frameProgress{ProcessedOffsetC2S: 25}); err != nil {
		t.Fatal(err)
	}
	// Direction 1: ids 0..1, interleaved with direction 0's stids but never tied with
	// them (different chunks, so different stids, by construction).
	if err := d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 25}, []frameInput{
		{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 8}}, Stid: 11},
		{Direction: 1, Ranges: []frameRange{{Offset: 8, Length: 8}}, Stid: 13},
	}, frameProgress{ProcessedOffsetC2S: 25, ProcessedOffsetS2C: 16}); err != nil {
		t.Fatal(err)
	}
}

// TestListFramesTimeline_OrderingAndTieBreak is the core correctness test for the
// cross-direction merge: stid ties (routine — one raw chunk producing several frames
// at once) must break by id, and a page must never split a tied group, or the "+1 from
// last stid" pagination cursor useChunkBuffer relies on would silently skip frames.
func TestListFramesTimeline_OrderingAndTieBreak(t *testing.T) {
	d := newTestInterceptor(t)
	tKey := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	seedTimelineFixture(t, d, tKey)

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
	tKey := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}
	seedTimelineFixture(t, d, tKey)

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
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames": []map[string]any{
			{"direction": 0, "ranges": []map[string]any{{"offset": 0, "length": 10}}, "stid": 10},
			{"direction": 0, "ranges": []map[string]any{{"offset": 10, "length": 5}}, "stid": 12},
		},
		"new_processed_offset_c2s": 15,
	}
	if status := postJSON(t, base+"/frames/append", appendC2S, nil); status != http.StatusNoContent {
		t.Fatalf("append c2s: expected 204, got %d", status)
	}
	appendS2C := map[string]any{
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"expected_processed_offset_c2s": 15,
		"new_frames": []map[string]any{
			{"direction": 1, "ranges": []map[string]any{{"offset": 0, "length": 8}}, "stid": 11},
		},
		"new_processed_offset_c2s": 15,
		"new_processed_offset_s2c": 8,
	}
	if status := postJSON(t, base+"/frames/append", appendS2C, nil); status != http.StatusNoContent {
		t.Fatalf("append s2c: expected 204, got %d", status)
	}

	var timeline []struct {
		ID        int64        `json:"id"`
		Ranges    []frameRange `json:"ranges"`
		Meta      *string      `json:"meta"`
		Direction int          `json:"direction"`
		Stid      int64        `json:"stid"`
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
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames": []map[string]any{
			{"direction": 0, "ranges": []map[string]any{{"offset": 0, "length": 10}}, "stid": 10},
			{"direction": 0, "ranges": []map[string]any{{"offset": 10, "length": 5}}, "stid": 12},
		},
		"new_processed_offset_c2s": 15,
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

// TestAppendFrames_SeqAssignment confirms seq is a single counter spanning both
// directions, assigned in newFrames' own array order regardless of each frame's
// direction — distinct from id, which stays a separate 0-based counter per direction.
func TestAppendFrames_SeqAssignment(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 5}}},
		{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 5}}},
		{Direction: 0, Ranges: []frameRange{{Offset: 5, Length: 5}}},
	}, frameProgress{ProcessedOffsetC2S: 10, ProcessedOffsetS2C: 5}); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFramesBySeq(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %+v", frames)
	}
	wantSeq := []int64{0, 1, 2}
	wantDir := []int{0, 1, 0}
	wantID := []int64{0, 0, 1} // per-direction: dir0's second frame continues its own id sequence
	for j := range frames {
		if frames[j].Seq != wantSeq[j] || frames[j].Direction != wantDir[j] || frames[j].ID != wantID[j] {
			t.Errorf("frame %d: expected seq=%d direction=%d id=%d, got %+v", j, wantSeq[j], wantDir[j], wantID[j], frames[j])
		}
	}
}

// TestAppendFrames_SeqContinuesAcrossCalls confirms seq keeps advancing across separate
// appendFrames calls for the same key, the same way id already does per direction.
func TestAppendFrames_SeqContinuesAcrossCalls(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 5}}}}, frameProgress{ProcessedOffsetC2S: 5}); err != nil {
		t.Fatal(err)
	}
	if err := d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 5}, []frameInput{{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 5}}}}, frameProgress{ProcessedOffsetC2S: 5, ProcessedOffsetS2C: 5}); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFramesBySeq(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || frames[0].Seq != 0 || frames[1].Seq != 1 {
		t.Fatalf("expected seq [0, 1] across the two calls, got %+v", frames)
	}
}

// TestAppendFrames_VirtualOffsetAssignment confirms virtual_offset is a running total
// scoped independently per direction: it starts at 0 for each direction's first frame and
// advances by that frame's own byte length (sum of its ranges), regardless of how the two
// directions' frames are interleaved in the batch.
func TestAppendFrames_VirtualOffsetAssignment(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 5}}},
		{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 7}}},
		{Direction: 0, Ranges: []frameRange{{Offset: 5, Length: 3}}},
		{Direction: 1, Ranges: []frameRange{{Offset: 7, Length: 2}}},
	}, frameProgress{ProcessedOffsetC2S: 8, ProcessedOffsetS2C: 9}); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFramesBySeq(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 {
		t.Fatalf("expected 4 frames, got %+v", frames)
	}
	wantVirtualOffset := []int64{0, 0, 5, 7} // dir0: 0, 5; dir1: 0, 7 — independent counters
	for j := range frames {
		if frames[j].VirtualOffset != wantVirtualOffset[j] {
			t.Errorf("frame %d (direction=%d): expected virtual_offset=%d, got %d", j, frames[j].Direction, wantVirtualOffset[j], frames[j].VirtualOffset)
		}
	}
}

// TestAppendFrames_VirtualOffsetContinuesAcrossCalls confirms each direction's running
// total keeps advancing across separate appendFrames calls, the same way id already does.
func TestAppendFrames_VirtualOffsetContinuesAcrossCalls(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 5}}}}, frameProgress{ProcessedOffsetC2S: 5}); err != nil {
		t.Fatal(err)
	}
	if err := d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 5}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 5, Length: 4}}},
		{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 3}}},
	}, frameProgress{ProcessedOffsetC2S: 9, ProcessedOffsetS2C: 3}); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFramesBySeq(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 frames, got %+v", frames)
	}
	// dir0's second frame (across the two calls) continues from 5; dir1's first frame,
	// appended in the same second call, starts fresh at 0 — unaffected by dir0's total.
	wantVirtualOffset := []int64{0, 5, 0}
	for j := range frames {
		if frames[j].VirtualOffset != wantVirtualOffset[j] {
			t.Errorf("frame %d (direction=%d): expected virtual_offset=%d, got %d", j, frames[j].Direction, wantVirtualOffset[j], frames[j].VirtualOffset)
		}
	}
}

// TestAppendFrames_VirtualOffsetSumsMultipleRanges confirms a frame's contribution to the
// running total is the plain sum of its own ranges' lengths, not the length of their
// merged/deduplicated span — matching /byte-ranges' and selectByBudget's own no-dedup
// treatment of overlapping ranges elsewhere in this codebase. Uses two overlapping ranges
// (the second starts before the first ends) specifically to rule out a union-based
// computation, which would produce a smaller total than a plain sum here.
func TestAppendFrames_VirtualOffsetSumsMultipleRanges(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 4}, {Offset: 2, Length: 6}}}, // sum=10, union would be 8
		{Direction: 0, Ranges: []frameRange{{Offset: 8, Length: 1}}},
	}, frameProgress{ProcessedOffsetC2S: 9}); err != nil {
		t.Fatal(err)
	}

	frames, err := d.listFramesBySeq(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %+v", frames)
	}
	if frames[0].VirtualOffset != 0 {
		t.Errorf("expected first frame's virtual_offset=0, got %d", frames[0].VirtualOffset)
	}
	if frames[1].VirtualOffset != 10 {
		t.Errorf("expected second frame's virtual_offset=10 (sum of the first frame's ranges, not their 8-byte union), got %d", frames[1].VirtualOffset)
	}
}

// TestListFramesBySeq_OrderCanDifferFromStid is the concrete scenario seq exists for:
// a script that holds a fully-parsed frame in its own state and returns it later,
// alongside a correlated frame from the other direction — e.g. an HTTP/1 request held
// until its matching response completes. The two frames' stids reflect true wire-arrival
// order (request first), but their seqs reflect the order the script actually chose to
// emit them (both together, once the response was ready) — listFramesTimeline and
// listFramesBySeq must each reflect their own ordering, independently.
func TestListFramesBySeq_OrderCanDifferFromStid(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	// A first, unrelated frame gets seq=0. Then the "held" request frame (stid=5) and
	// its response (stid=20) are returned together, in response-then-request order —
	// deliberately the reverse of their stid order, to make sure seq isn't secretly
	// derived from stid.
	if err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 5}}, Stid: 1},
	}, frameProgress{ProcessedOffsetC2S: 5}); err != nil {
		t.Fatal(err)
	}
	if err := d.appendFrames(key, frameProgress{ProcessedOffsetC2S: 5}, []frameInput{
		{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 5}}, Stid: 20}, // the response, emitted first
		{Direction: 0, Ranges: []frameRange{{Offset: 5, Length: 5}}, Stid: 5},  // the held-back request, emitted second
	}, frameProgress{ProcessedOffsetC2S: 10, ProcessedOffsetS2C: 5}); err != nil {
		t.Fatal(err)
	}

	byStid, err := d.listFramesTimeline(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(byStid) != 3 || byStid[0].Stid != 1 || byStid[1].Stid != 5 || byStid[2].Stid != 20 {
		t.Fatalf("expected stid order [1, 5, 20] (true wire order), got %+v", byStid)
	}

	bySeq, err := d.listFramesBySeq(key, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(bySeq) != 3 || bySeq[0].Stid != 1 || bySeq[1].Stid != 20 || bySeq[2].Stid != 5 {
		t.Fatalf("expected seq order [stid 1, stid 20, stid 5] (emission order), got %+v", bySeq)
	}
}

func TestListFramesBySeqBackward(t *testing.T) {
	d := newTestInterceptor(t)
	key := frameTimelineKey{Session: 1, Stream: 1, Script: "foo", ScriptVersion: "v1"}

	if err := d.appendFrames(key, frameProgress{}, []frameInput{
		{Direction: 0, Ranges: []frameRange{{Offset: 0, Length: 5}}},
		{Direction: 1, Ranges: []frameRange{{Offset: 0, Length: 5}}},
		{Direction: 0, Ranges: []frameRange{{Offset: 5, Length: 5}}},
	}, frameProgress{ProcessedOffsetC2S: 10, ProcessedOffsetS2C: 5}); err != nil {
		t.Fatal(err)
	}

	all, err := d.listFramesBySeqBackward(key, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Seq != 0 || all[1].Seq != 1 || all[2].Seq != 2 {
		t.Fatalf("expected ascending seq [0,1,2], got %+v", all)
	}

	page, err := d.listFramesBySeqBackward(key, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 || page[0].Seq != 1 || page[1].Seq != 2 {
		t.Fatalf("expected the 2 nearest-to-100 (still ascending), got %+v", page)
	}

	rest, err := d.listFramesBySeqBackward(key, page[0].Seq, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 1 || rest[0].Seq != 0 {
		t.Fatalf("expected resuming before seq=1 to yield [0], got %+v", rest)
	}
}

func TestHandleFramesBySeq_HTTP(t *testing.T) {
	base := newTestFramesServer(t)

	appendReq := map[string]any{
		"session": 1, "stream": 1, "script": "foo", "script_version": "v1",
		"new_frames": []map[string]any{
			{"direction": 0, "ranges": []map[string]any{{"offset": 0, "length": 5}}},
			{"direction": 1, "ranges": []map[string]any{{"offset": 0, "length": 5}}},
		},
		"new_processed_offset_c2s": 5,
		"new_processed_offset_s2c": 5,
	}
	if status := postJSON(t, base+"/frames/append", appendReq, nil); status != http.StatusNoContent {
		t.Fatalf("append: expected 204, got %d", status)
	}

	var bySeq []struct {
		Seq       int64 `json:"seq"`
		Direction int   `json:"direction"`
	}
	req := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "start": 0, "n": 0}
	if status := postJSON(t, base+"/frames/by-seq", req, &bySeq); status != http.StatusOK {
		t.Fatalf("by-seq: expected 200, got %d", status)
	}
	if len(bySeq) != 2 || bySeq[0].Seq != 0 || bySeq[0].Direction != 0 || bySeq[1].Seq != 1 || bySeq[1].Direction != 1 {
		t.Fatalf("expected [{seq:0,dir:0},{seq:1,dir:1}], got %+v", bySeq)
	}

	var backward []struct {
		Seq int64 `json:"seq"`
	}
	backReq := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "beforeSeq": 100, "n": 0}
	if status := postJSON(t, base+"/frames/by-seq", backReq, &backward); status != http.StatusOK {
		t.Fatalf("by-seq backward: expected 200, got %d", status)
	}
	if len(backward) != 2 || backward[0].Seq != 0 || backward[1].Seq != 1 {
		t.Fatalf("expected ascending [0, 1], got %+v", backward)
	}

	both := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "start": 0, "beforeSeq": 10, "n": 0}
	if status := postJSON(t, base+"/frames/by-seq", both, nil); status != http.StatusBadRequest {
		t.Fatalf("both start and beforeSeq: expected 400, got %d", status)
	}
	neither := map[string]any{"session": 1, "stream": 1, "script": "foo", "script_version": "v1", "n": 0}
	if status := postJSON(t, base+"/frames/by-seq", neither, nil); status != http.StatusBadRequest {
		t.Fatalf("neither start nor beforeSeq: expected 400, got %d", status)
	}
}
