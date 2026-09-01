package fs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T, dir string) *httptest.Server {
	t.Helper()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux, "/api/core/fs")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func httpDo(t *testing.T, method, url string, body *strings.Reader) *http.Response {
	t.Helper()
	var reqBody *strings.Reader
	if body != nil {
		reqBody = body
	} else {
		reqBody = strings.NewReader("")
	}
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// TestAPI_EndToEnd exercises the REST handlers over real HTTP. Traversal attempts
// aren't tested here beyond a normal one: net/http's ServeMux itself cleans/redirects
// literal ".." segments in the URL path before they ever reach our handler, so that
// guard is only reachable (and only meaningfully tested) at the Store.resolve level in
// fs_test.go.
func TestAPI_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	server := newTestServer(t, dir)
	base := server.URL + "/api/core/fs"

	resp := httpDo(t, http.MethodGet, base+"/list", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /list: expected 200, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodPut, base+"/file/sub/foo.bin", strings.NewReader("hello"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /file/sub/foo.bin: expected 204, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodGet, base+"/file/sub/foo.bin", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /file/sub/foo.bin: expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %q", ct)
	}

	resp = httpDo(t, http.MethodGet, base+"/list/sub", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /list/sub: expected 200, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodGet, base+"/file/nope.bin", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET missing file: expected 404, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodGet, base+"/list/nope", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET missing dir listing: expected 404, got %d", resp.StatusCode)
	}

	// POST appends rather than overwriting, and creates the file if it doesn't exist.
	resp = httpDo(t, http.MethodPost, base+"/file/sub/log.txt", strings.NewReader("line 1\n"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /file/sub/log.txt (create): expected 204, got %d", resp.StatusCode)
	}
	resp = httpDo(t, http.MethodPost, base+"/file/sub/log.txt", strings.NewReader("line 2\n"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /file/sub/log.txt (append): expected 204, got %d", resp.StatusCode)
	}
}
