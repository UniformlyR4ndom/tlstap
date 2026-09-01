package kv

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "kv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux, "/api/core/kv")
	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.Close()
		s.Close()
	})
	return server
}

func post(t *testing.T, urlStr string, body []byte) *http.Response {
	t.Helper()
	resp, err := http.Post(urlStr, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestAPI_WriteReadDelete_RoundTrip(t *testing.T) {
	server := newTestServer(t)

	if resp := post(t, server.URL+"/api/core/kv/write?key=mykey", []byte("hello")); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("write: got %d, want 204", resp.StatusCode)
	}

	resp := post(t, server.URL+"/api/core/kv/read?key=mykey", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("got Content-Type %q, want application/octet-stream", ct)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}

	if resp := post(t, server.URL+"/api/core/kv/delete?key=mykey", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204", resp.StatusCode)
	}

	if resp := post(t, server.URL+"/api/core/kv/read?key=mykey", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("read after delete: got %d, want 404", resp.StatusCode)
	}
}

func TestAPI_MissingKeyParam(t *testing.T) {
	server := newTestServer(t)
	for _, path := range []string{"/api/core/kv/read", "/api/core/kv/write", "/api/core/kv/delete"} {
		if resp := post(t, server.URL+path, []byte("v")); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: got %d, want 400", path, resp.StatusCode)
		}
	}
}

func TestAPI_Delete_Idempotent(t *testing.T) {
	server := newTestServer(t)
	if resp := post(t, server.URL+"/api/core/kv/delete?key=never-existed", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got %d, want 204", resp.StatusCode)
	}
}

func TestAPI_Write_ValueTooLarge(t *testing.T) {
	server := newTestServer(t)
	resp := post(t, server.URL+"/api/core/kv/write?key=k", make([]byte, maxValueBytes+1))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
	// A value of exactly the limit must still be accepted over HTTP, not just at the
	// Store level (guards against an off-by-one in the handler's +1 LimitReader cap).
	if resp := post(t, server.URL+"/api/core/kv/write?key=k", make([]byte, maxValueBytes)); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("got %d, want 204", resp.StatusCode)
	}
}

func TestAPI_Write_KeyTooLong(t *testing.T) {
	server := newTestServer(t)
	longKey := strings.Repeat("k", maxKeyBytes+1)
	resp := post(t, server.URL+"/api/core/kv/write?key="+url.QueryEscape(longKey), []byte("v"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
}

func TestAPI_Write_Overwrite(t *testing.T) {
	server := newTestServer(t)
	post(t, server.URL+"/api/core/kv/write?key=k", []byte("v1"))
	post(t, server.URL+"/api/core/kv/write?key=k", []byte("v2"))

	resp := post(t, server.URL+"/api/core/kv/read?key=k", nil)
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "v2" {
		t.Fatalf("got %q, want %q", got, "v2")
	}
}

func TestAPI_List(t *testing.T) {
	server := newTestServer(t)
	for _, k := range []string{"a.1", "a.2", "b.1"} {
		post(t, server.URL+"/api/core/kv/write?key="+url.QueryEscape(k), []byte("v"))
	}

	resp := post(t, server.URL+"/api/core/kv/list?prefix="+url.QueryEscape("a."), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	var result struct {
		Keys []string `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !equalUnordered(result.Keys, []string{"a.1", "a.2"}) {
		t.Fatalf("got %v, want [a.1 a.2]", result.Keys)
	}
}

func TestAPI_List_EmptyStoreReturnsEmptyArrayNotNull(t *testing.T) {
	server := newTestServer(t)
	resp := post(t, server.URL+"/api/core/kv/list", nil)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(body)); got != `{"keys":[]}` {
		t.Fatalf(`got %q, want {"keys":[]}`, got)
	}
}
