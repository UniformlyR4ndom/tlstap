package dbdump

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doSearch posts a raw JSON body to handleSearchText and returns the decoded matches.
func doSearch(t *testing.T, d *DbDumpInterceptor, body string) []searchMatch {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/search-text", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSearchText(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
	}
	var ms []searchMatch
	if err := json.Unmarshal(w.Body.Bytes(), &ms); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, w.Body.String())
	}
	return ms
}

func b64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// searchBodyBase64 builds a /search-text JSON request body using base64 encoding.
func searchBodyBase64(session, stream, direction int, pattern []byte) string {
	return fmt.Sprintf(
		`{"session":%d,"stream":%d,"direction":%d,"pattern":%q,"pattern_encoding":"base64"}`,
		session, stream, direction, b64Encode(pattern),
	)
}

// ── encoding=base64 with plain ASCII bytes ────────────────────────────────────

func TestEncoding_Base64ASCII(t *testing.T) {
	d := setupDB(t)
	// "GET /index HTTP/1.1\r\n": "HTTP" starts at byte offset 11
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("GET /index HTTP/1.1\r\n"))

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, []byte("HTTP")))
	if len(ms) != 1 || ms[0].Offset != 11 {
		t.Fatalf("expected match at 11, got %v", matchOffsets(ms))
	}
}

// ── arbitrary binary bytes (e.g. from hex input) ─────────────────────────────

func TestEncoding_Base64ArbitraryBytes(t *testing.T) {
	d := setupDB(t)
	data := []byte{0x00, 0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11}
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, data)

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, []byte{0xDE, 0xAD, 0xBE, 0xEF}))
	if len(ms) != 1 || ms[0].Offset != 2 {
		t.Fatalf("expected match at 2, got %v", matchOffsets(ms))
	}
}

// Null bytes must be preserved through the base64 round-trip.
func TestEncoding_Base64NullBytes(t *testing.T) {
	d := setupDB(t)
	data := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x01}
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, data)

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, []byte{0x00, 0x01}))
	if len(ms) != 3 {
		t.Fatalf("expected 3 matches (at 0, 2, 4), got %v", matchOffsets(ms))
	}
}

// ── UTF-16 LE / BE ────────────────────────────────────────────────────────────

// utf16le encodes a BMP string as UTF-16 LE (no BOM).
func utf16le(s string) []byte {
	b := make([]byte, len([]rune(s))*2)
	for i, r := range []rune(s) {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

// utf16be encodes a BMP string as UTF-16 BE (no BOM).
func utf16be(s string) []byte {
	b := make([]byte, len([]rune(s))*2)
	for i, r := range []rune(s) {
		binary.BigEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

func TestEncoding_UTF16LE(t *testing.T) {
	d := setupDB(t)
	prefix := []byte{0xAA, 0xBB, 0xCC}
	data := append(prefix, utf16le("Hello")...)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, data)

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, utf16le("Hello")))
	if len(ms) != 1 || ms[0].Offset != int64(len(prefix)) {
		t.Fatalf("expected match at %d, got %v", len(prefix), matchOffsets(ms))
	}
}

func TestEncoding_UTF16LE_NotFoundAsBE(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, utf16le("Hello"))

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, utf16be("Hello")))
	if len(ms) != 0 {
		t.Fatalf("expected no matches, got %v", matchOffsets(ms))
	}
}

func TestEncoding_UTF16BE(t *testing.T) {
	d := setupDB(t)
	prefix := []byte{0x00, 0x00}
	data := append(prefix, utf16be("World")...)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, data)

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, utf16be("World")))
	if len(ms) != 1 || ms[0].Offset != int64(len(prefix)) {
		t.Fatalf("expected match at %d, got %v", len(prefix), matchOffsets(ms))
	}
}

// "Ärger": Ä = U+00C4 → LE bytes [C4 00], BE bytes [00 C4]
func TestEncoding_UTF16LE_NonASCII(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, utf16le("Ärger"))

	ms := doSearch(t, d, searchBodyBase64(1, 1, 0, utf16le("Ärger")))
	if len(ms) != 1 || ms[0].Offset != 0 {
		t.Fatalf("expected match at 0, got %v", matchOffsets(ms))
	}
}

// ── regex ─────────────────────────────────────────────────────────────────────

func searchBodyRegex(session, stream, direction int, pattern string) string {
	p, _ := json.Marshal(pattern)
	return fmt.Sprintf(
		`{"session":%d,"stream":%d,"direction":%d,"pattern":%s,"pattern_encoding":"regex"}`,
		session, stream, direction, p,
	)
}

func TestEncoding_RegexBasic(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("GET /index HTTP/1.1\r\n"))

	// "GET /\S+" should match "GET /index"
	ms := doSearch(t, d, searchBodyRegex(1, 1, 0, `GET /\S+`))
	if len(ms) != 1 || ms[0].Offset != 0 {
		t.Fatalf("expected match at 0, got %v", matchOffsets(ms))
	}
}

func TestEncoding_RegexCaseInsensitive(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("HTTP/1.1 200 OK\r\n"))

	ms := doSearch(t, d, searchBodyRegex(1, 1, 0, `(?i)http`))
	if len(ms) != 1 || ms[0].Offset != 0 {
		t.Fatalf("expected match at 0, got %v", matchOffsets(ms))
	}
}

func TestEncoding_RegexMultipleMatches(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("aabbaa"))

	// "a+" matches "aa" at 0 and "aa" at 4
	ms := doSearch(t, d, searchBodyRegex(1, 1, 0, `a+`))
	if len(ms) != 2 {
		t.Fatalf("expected 2 matches, got %v", matchOffsets(ms))
	}
	if ms[0].Offset != 0 || ms[1].Offset != 4 {
		t.Fatalf("expected offsets [0, 4], got %v", matchOffsets(ms))
	}
}

func TestEncoding_RegexNewline(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("line1\r\nline2\r\n"))

	// Match each CRLF-terminated line
	ms := doSearch(t, d, searchBodyRegex(1, 1, 0, `(?s)\w+\r\n`))
	if len(ms) != 2 {
		t.Fatalf("expected 2 matches, got %v", matchOffsets(ms))
	}
	if ms[0].Offset != 0 || ms[1].Offset != 7 {
		t.Fatalf("expected offsets [0, 7], got %v", matchOffsets(ms))
	}
}

func TestEncoding_RegexInvalid(t *testing.T) {
	d := setupDB(t)
	body := `{"session":1,"stream":1,"direction":0,"pattern":"[invalid","pattern_encoding":"regex"}`
	req := httptest.NewRequest(http.MethodPost, "/search-text", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSearchText(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEncoding_TextPatternTooLong(t *testing.T) {
	d := setupDB(t)
	pattern := strings.Repeat("x", maxPatternLen+1)
	body := fmt.Sprintf(`{"session":1,"stream":1,"direction":0,"pattern":%q,"pattern_encoding":"text"}`, pattern)
	req := httptest.NewRequest(http.MethodPost, "/search-text", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSearchText(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEncoding_Base64PatternTooLong(t *testing.T) {
	d := setupDB(t)
	body := searchBodyBase64(1, 1, 0, make([]byte, maxPatternLen+1))
	req := httptest.NewRequest(http.MethodPost, "/search-text", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSearchText(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEncoding_TextPatternAtMaxLen(t *testing.T) {
	d := setupDB(t)
	pattern := strings.Repeat("x", maxPatternLen)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte(pattern))
	body := fmt.Sprintf(`{"session":1,"stream":1,"direction":0,"pattern":%q,"pattern_encoding":"text"}`, pattern)
	ms := doSearch(t, d, body)
	if len(ms) != 1 || ms[0].Offset != 0 {
		t.Fatalf("expected 1 match at offset 0, got %v", matchOffsets(ms))
	}
}

// ── error cases ───────────────────────────────────────────────────────────────

func TestEncoding_InvalidBase64(t *testing.T) {
	d := setupDB(t)
	body := `{"session":1,"stream":1,"direction":0,"pattern":"!!!not-valid-base64!!!","pattern_encoding":"base64"}`
	req := httptest.NewRequest(http.MethodPost, "/search-text", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSearchText(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEncoding_UnknownEncoding(t *testing.T) {
	d := setupDB(t)
	body := `{"session":1,"stream":1,"direction":0,"pattern":"foo","pattern_encoding":"binary"}`
	req := httptest.NewRequest(http.MethodPost, "/search-text", strings.NewReader(body))
	w := httptest.NewRecorder()
	d.handleSearchText(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

// pattern_encoding="" must fall back to raw text mode.
func TestEncoding_EmptyFallsBackToText(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("hello world"))

	body := `{"session":1,"stream":1,"direction":0,"pattern":"world","pattern_encoding":""}`
	ms := doSearch(t, d, body)
	if len(ms) != 1 || ms[0].Offset != 6 {
		t.Fatalf("expected match at 6, got %v", matchOffsets(ms))
	}
}
