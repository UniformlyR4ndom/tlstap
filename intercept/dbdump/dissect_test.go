package dbdump

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDissectScriptsAPI_CRUDAndNamespaceIsolation exercises the dissector script store's
// REST CRUD (same shape as the framer's, just nested under "/dissect") and confirms it's
// a genuinely separate namespace from the framer's own "/scripts" — same name, same
// interceptor, no collision.
func TestDissectScriptsAPI_CRUDAndNamespaceIsolation(t *testing.T) {
	d := newTestInterceptorWithScriptDirs(t, t.TempDir(), t.TempDir())
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	dissectContent := "function dissect(bytes, frame) { return [] }"
	framerContent := "function frame(state, chunk) {}"

	putReq, err := http.NewRequest(http.MethodPut, server.URL+"/api/i/dbdump/dissect/scripts/shared-name", strings.NewReader(dissectContent))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT dissect script: expected 204, got %d", resp.StatusCode)
	}

	putReq, err = http.NewRequest(http.MethodPut, server.URL+"/api/i/dbdump/scripts/shared-name", strings.NewReader(framerContent))
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(putReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT framer script: expected 204, got %d", resp.StatusCode)
	}

	resp, err = http.Get(server.URL + "/api/i/dbdump/dissect/scripts/shared-name")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(got) != dissectContent {
		t.Fatalf("GET dissect script: expected 200 %q, got %d %q", dissectContent, resp.StatusCode, got)
	}

	resp, err = http.Get(server.URL + "/api/i/dbdump/scripts/shared-name")
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(got) != framerContent {
		t.Fatalf("GET framer script: expected 200 %q, got %d %q", framerContent, resp.StatusCode, got)
	}

	delReq, err := http.NewRequest(http.MethodDelete, server.URL+"/api/i/dbdump/dissect/scripts/shared-name", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE dissect script: expected 204, got %d", resp.StatusCode)
	}

	resp, err = http.Get(server.URL + "/api/i/dbdump/dissect/scripts/shared-name")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET deleted dissect script: expected 404, got %d", resp.StatusCode)
	}

	resp, err = http.Get(server.URL + "/api/i/dbdump/scripts/shared-name")
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(got) != framerContent {
		t.Fatalf("framer script should survive dissect script's deletion: expected 200 %q, got %d %q", framerContent, resp.StatusCode, got)
	}
}

// TestDissectScriptsAPI_UnconfiguredRejects mirrors the framer store's own
// unconfigured-directory convention: with DissectScriptsDir empty, the routes exist but
// reject every request with 501 rather than silently defaulting to an implicit directory.
func TestDissectScriptsAPI_UnconfiguredRejects(t *testing.T) {
	d := newTestInterceptor(t) // no scripts-dir, no dissect-scripts-dir
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, "/api/i/dbdump")
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/api/i/dbdump/dissect/scripts")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", resp.StatusCode)
	}
}
