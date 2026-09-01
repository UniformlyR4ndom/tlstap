package dbdump

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// insertStream adds one minimal stream row — handleByteRanges is the only handler in
// this package that actually checks stream existence (every other endpoint here is
// content to operate on chunks rows directly, real stream or not), so it's the only test
// file that needs this.
func insertStream(t *testing.T, db *sql.DB, session, id int64) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO stream (id, session, src, dst, start) VALUES (?, ?, '', '', 0)`,
		id, session,
	)
	if err != nil {
		t.Fatal(err)
	}
}

// encodeRangesForTest builds a /byte-ranges request body from (offset, signedLength)
// pairs, mirroring web/byteRangesCore.js's encodeByteRangesRequest.
func encodeRangesForTest(pairs ...[2]int64) []byte {
	body := make([]byte, 0, len(pairs)*16)
	for _, p := range pairs {
		var buf [16]byte
		binary.BigEndian.PutUint64(buf[0:8], uint64(p[0]))
		binary.BigEndian.PutUint64(buf[8:16], uint64(p[1]))
		body = append(body, buf[:]...)
	}
	return body
}

func TestEncodeDecodeSignedLength_RoundTrip(t *testing.T) {
	cases := []struct {
		direction int
		magnitude int64
	}{
		{directionC2S, 1},
		{directionS2C, 1},
		{directionC2S, maxRangeBytes},
		{directionS2C, maxRangeBytes},
	}
	for _, c := range cases {
		signedLength := encodeSignedLength(c.direction, c.magnitude)
		gotDir, gotMag := decodeSignedLength(signedLength)
		if gotDir != c.direction || gotMag != c.magnitude {
			t.Errorf("encodeSignedLength(%d, %d) -> decodeSignedLength -> (%d, %d), want (%d, %d)",
				c.direction, c.magnitude, gotDir, gotMag, c.direction, c.magnitude)
		}
	}
}

func TestDecodeSignedLength_MinInt64(t *testing.T) {
	// -math.MinInt64 overflows back to math.MinInt64 itself in two's complement — the
	// only signedLength value whose magnitude comes back still negative. This is what
	// parseByteRangesRequest's overflow check relies on.
	_, magnitude := decodeSignedLength(math.MinInt64)
	if magnitude >= 0 {
		t.Fatalf("expected decodeSignedLength(MinInt64) to yield a still-negative magnitude, got %d", magnitude)
	}
}

func TestParseByteRangesRequest_Valid(t *testing.T) {
	body := encodeRangesForTest([2]int64{10, encodeSignedLength(directionC2S, 5)}, [2]int64{0, encodeSignedLength(directionS2C, 20)})
	entries, err := parseByteRangesRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byteRangeEntry{
		{Offset: 10, Direction: directionC2S, Magnitude: 5},
		{Offset: 0, Direction: directionS2C, Magnitude: 20},
	}
	if len(entries) != len(want) {
		t.Fatalf("expected %d entries, got %d", len(want), len(entries))
	}
	for j := range want {
		if entries[j] != want[j] {
			t.Errorf("entry %d: got %+v, want %+v", j, entries[j], want[j])
		}
	}
}

func TestParseByteRangesRequest_EmptyBodyIsValid(t *testing.T) {
	entries, err := parseByteRangesRequest(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no entries, got %+v", entries)
	}
}

func TestParseByteRangesRequest_BodyLengthNotMultipleOf16(t *testing.T) {
	if _, err := parseByteRangesRequest(make([]byte, 17)); err == nil {
		t.Fatal("expected an error for a body length that isn't a multiple of 16")
	}
}

func TestParseByteRangesRequest_NegativeOffset(t *testing.T) {
	body := encodeRangesForTest([2]int64{-1, encodeSignedLength(directionC2S, 5)})
	if _, err := parseByteRangesRequest(body); err == nil {
		t.Fatal("expected an error for a negative offset")
	}
}

func TestParseByteRangesRequest_ZeroLength(t *testing.T) {
	body := encodeRangesForTest([2]int64{0, 0})
	if _, err := parseByteRangesRequest(body); err == nil {
		t.Fatal("expected an error for a zero-length entry")
	}
}

func TestParseByteRangesRequest_MinInt64Overflow(t *testing.T) {
	body := encodeRangesForTest([2]int64{0, math.MinInt64})
	if _, err := parseByteRangesRequest(body); err == nil {
		t.Fatal("expected an error for a MinInt64 length (overflow on negation)")
	}
}

func TestParseByteRangesRequest_SingleRangeBound(t *testing.T) {
	okBody := encodeRangesForTest([2]int64{0, encodeSignedLength(directionC2S, maxRangeBytes)})
	if _, err := parseByteRangesRequest(okBody); err != nil {
		t.Errorf("expected magnitude == maxRangeBytes to be accepted, got error: %v", err)
	}

	tooBigBody := encodeRangesForTest([2]int64{0, encodeSignedLength(directionC2S, maxRangeBytes+1)})
	if _, err := parseByteRangesRequest(tooBigBody); err == nil {
		t.Error("expected magnitude == maxRangeBytes+1 to be rejected")
	}
}

func TestParseByteRangesRequest_EntryCountBound(t *testing.T) {
	pairs := make([][2]int64, maxRangeEntries)
	for j := range pairs {
		pairs[j] = [2]int64{int64(j), encodeSignedLength(directionC2S, 1)}
	}
	if _, err := parseByteRangesRequest(encodeRangesForTest(pairs...)); err != nil {
		t.Errorf("expected exactly maxRangeEntries entries to be accepted, got error: %v", err)
	}

	pairs = append(pairs, [2]int64{int64(len(pairs)), encodeSignedLength(directionC2S, 1)})
	if _, err := parseByteRangesRequest(encodeRangesForTest(pairs...)); err == nil {
		t.Error("expected maxRangeEntries+1 entries to be rejected")
	}
}

func TestParseByteRangesRequest_TotalBytesBound(t *testing.T) {
	// Two entries, each individually under the per-entry cap, whose sum exceeds the
	// total cap — must still be rejected even though neither alone would be.
	half := maxTotalRangeBytes/2 + 1
	body := encodeRangesForTest(
		[2]int64{0, encodeSignedLength(directionC2S, half)},
		[2]int64{0, encodeSignedLength(directionS2C, half)},
	)
	if _, err := parseByteRangesRequest(body); err == nil {
		t.Error("expected the sum-of-magnitudes bound to reject this request")
	}
}

// ── resolveByteRange ────────────────────────────────────────────────────────────────

func TestResolveByteRange_WithinOneChunk(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("0123456789"))

	got, err := d.resolveByteRange(1, 1, directionC2S, 2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "23456" {
		t.Errorf("got %q, want %q", got, "23456")
	}
}

func TestResolveByteRange_SpansMultipleChunks(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("aaa"))
	insertChunk(t, d.db, 1, 1, directionC2S, 1, 3, 11, []byte("bbb"))
	insertChunk(t, d.db, 1, 1, directionC2S, 2, 6, 12, []byte("ccc"))

	got, err := d.resolveByteRange(1, 1, directionC2S, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "aabbbcc" {
		t.Errorf("got %q, want %q", got, "aabbbcc")
	}
}

func TestResolveByteRange_PartialAtBothEdges(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("0123456789"))

	// Fully inside, starting and ending mid-chunk.
	got, err := d.resolveByteRange(1, 1, directionC2S, 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "456" {
		t.Errorf("got %q, want %q", got, "456")
	}
}

func TestResolveByteRange_ExtendsPastAvailableData_ShortReadNoError(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("01234"))

	got, err := d.resolveByteRange(1, 1, directionC2S, 3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "34" {
		t.Errorf("got %q, want a short read of %q", got, "34")
	}
}

func TestResolveByteRange_EntirelyPastAvailableData_ZeroLengthNoError(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("01234"))

	got, err := d.resolveByteRange(1, 1, directionC2S, 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("expected a zero-length result, got %q", got)
	}
}

func TestResolveByteRange_OverlappingCallsAreIndependent(t *testing.T) {
	d := newTestInterceptor(t)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("0123456789"))

	a, err := d.resolveByteRange(1, 1, directionC2S, 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	b, err := d.resolveByteRange(1, 1, directionC2S, 3, 6)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != "012345" || string(b) != "345678" {
		t.Errorf("overlapping ranges resolved incorrectly: a=%q b=%q", a, b)
	}
}

// ── handleByteRanges (HTTP-level) ───────────────────────────────────────────────────

func newTestByteRangesServer(t *testing.T) (*DbDumpInterceptor, *httptest.Server) {
	t.Helper()
	d := newTestInterceptor(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return d, server
}

func doByteRanges(t *testing.T, server *httptest.Server, session, stream int64, body []byte) (int, []byte) {
	t.Helper()
	url := server.URL + "/api/i/dbdump/byte-ranges?session=" +
		strconv.FormatInt(session, 10) + "&stream=" + strconv.FormatInt(stream, 10)
	resp, err := http.Post(url, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /byte-ranges: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, respBody
}

// parseByteRangesResponse walks count length-prefixed entries out of a successful
// /byte-ranges response body, mirroring web/byteRangesCore.js's decodeByteRangesResponse.
func parseByteRangesResponse(t *testing.T, body []byte, count int) [][]byte {
	t.Helper()
	out := make([][]byte, 0, count)
	pos := 0
	for j := 0; j < count; j++ {
		if pos+8 > len(body) {
			t.Fatalf("response truncated before entry %d's length prefix", j)
		}
		length := int64(binary.BigEndian.Uint64(body[pos:]))
		pos += 8
		if pos+int(length) > len(body) {
			t.Fatalf("response truncated within entry %d's data (length %d)", j, length)
		}
		out = append(out, body[pos:pos+int(length)])
		pos += int(length)
	}
	return out
}

func TestHandleByteRanges_Success_MixedDirectionsAndOrder(t *testing.T) {
	d, server := newTestByteRangesServer(t)
	insertStream(t, d.db, 1, 1)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("c2s-data"))
	insertChunk(t, d.db, 1, 1, directionS2C, 0, 0, 11, []byte("s2c-data"))

	body := encodeRangesForTest(
		[2]int64{2, encodeSignedLength(directionC2S, 4)},
		[2]int64{0, encodeSignedLength(directionS2C, 3)},
	)
	status, respBody := doByteRanges(t, server, 1, 1, body)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", status, respBody)
	}
	entries := parseByteRangesResponse(t, respBody, 2)
	if string(entries[0]) != "s-da" {
		t.Errorf("entry 0: got %q, want %q", entries[0], "s-da")
	}
	if string(entries[1]) != "s2c" {
		t.Errorf("entry 1: got %q, want %q", entries[1], "s2c")
	}
}

func TestHandleByteRanges_EmptyRequest_Empty200(t *testing.T) {
	d, server := newTestByteRangesServer(t)
	insertStream(t, d.db, 1, 1)
	status, respBody := doByteRanges(t, server, 1, 1, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(respBody) != 0 {
		t.Errorf("expected an empty response body, got %d bytes", len(respBody))
	}
}

func TestHandleByteRanges_MalformedBody_400(t *testing.T) {
	_, server := newTestByteRangesServer(t)
	status, _ := doByteRanges(t, server, 1, 1, make([]byte, 17))
	if status != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", status)
	}
}

func TestHandleByteRanges_InvalidRange_400(t *testing.T) {
	_, server := newTestByteRangesServer(t)
	body := encodeRangesForTest([2]int64{-1, encodeSignedLength(directionC2S, 5)})
	status, _ := doByteRanges(t, server, 1, 1, body)
	if status != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", status)
	}
}

func TestHandleByteRanges_BoundViolation_400(t *testing.T) {
	_, server := newTestByteRangesServer(t)
	body := encodeRangesForTest([2]int64{0, encodeSignedLength(directionC2S, maxRangeBytes+1)})
	status, _ := doByteRanges(t, server, 1, 1, body)
	if status != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", status)
	}
}

func TestHandleByteRanges_UnknownStream_404(t *testing.T) {
	_, server := newTestByteRangesServer(t)
	body := encodeRangesForTest([2]int64{0, encodeSignedLength(directionC2S, 5)})
	status, _ := doByteRanges(t, server, 1, 999, body)
	if status != http.StatusNotFound {
		t.Errorf("expected 404, got %d", status)
	}
}

func TestHandleByteRanges_MissingQueryParams_400(t *testing.T) {
	_, server := newTestByteRangesServer(t)
	resp, err := http.Post(server.URL+"/api/i/dbdump/byte-ranges", "application/octet-stream", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandleByteRanges_ShortReadPastAvailableData(t *testing.T) {
	d, server := newTestByteRangesServer(t)
	insertStream(t, d.db, 1, 1)
	insertChunk(t, d.db, 1, 1, directionC2S, 0, 0, 10, []byte("hi"))

	body := encodeRangesForTest([2]int64{0, encodeSignedLength(directionC2S, 100)})
	status, respBody := doByteRanges(t, server, 1, 1, body)
	if status != http.StatusOK {
		t.Fatalf("expected 200 (a short read is not an error), got %d", status)
	}
	entries := parseByteRangesResponse(t, respBody, 1)
	if string(entries[0]) != "hi" {
		t.Errorf("got %q, want a short read of %q", entries[0], "hi")
	}
}
