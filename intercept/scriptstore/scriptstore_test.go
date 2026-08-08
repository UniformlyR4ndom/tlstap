package scriptstore

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	valid := []string{"foo", "foo.js", "my.lib", "my utils", "a-b_c.2", "123"}
	for _, name := range valid {
		if err := validateName(name); err != nil {
			t.Errorf("validateName(%q): expected valid, got error: %v", name, err)
		}
	}

	invalid := []string{
		"", ".", "..", ".foo", "foo.", " foo", "foo ", "foo/bar", "../foo", "foo\\bar",
		"foo\x00bar", "foo\tbar",
	}
	for _, name := range invalid {
		if err := validateName(name); err == nil {
			t.Errorf("validateName(%q): expected error, got nil", name)
		}
	}
}

func TestStore_PutGetDelete(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put("foo", []byte("console.log('hi')")); err != nil {
		t.Fatal(err)
	}
	content, err := s.Get("foo")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "console.log('hi')" {
		t.Fatalf("unexpected content: %q", content)
	}

	// Overwrite.
	if err := s.Put("foo", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	content, err = s.Get("foo")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "v2" {
		t.Fatalf("expected overwritten content, got %q", content)
	}

	if err := s.Delete("foo"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("foo"); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error after delete, got %v", err)
	}
	if err := s.Delete("foo"); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error deleting again, got %v", err)
	}
}

func TestStore_InvalidNameRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put("..", []byte("x")); err == nil {
		t.Fatal("expected error putting a script named \"..\"")
	}
	if _, err := s.Get(".."); err == nil {
		t.Fatal("expected error getting a script named \"..\"")
	}
	if err := s.Delete(".."); err == nil {
		t.Fatal("expected error deleting a script named \"..\"")
	}

	// The directory itself (and its parent) must survive an attempted ".."/"." write.
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("scripts dir should still exist: %v", err)
	}
}

func TestStore_List(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put("b", []byte("22")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	// A non-.js file in the directory must not show up in the listing.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o644); err != nil {
		t.Fatal(err)
	}

	infos, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 scripts, got %d: %+v", len(infos), infos)
	}
	if infos[0].Name != "a" || infos[0].Size != 1 {
		t.Errorf("unexpected first entry: %+v", infos[0])
	}
	if infos[1].Name != "b" || infos[1].Size != 2 {
		t.Errorf("unexpected second entry: %+v", infos[1])
	}
}

func TestStore_CreatesDirIfMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "scripts")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("precondition: dir should not exist yet, got %v", err)
	}

	if _, err := New(dir); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatalf("expected %s to be a directory", dir)
	}
}

func TestStore_Put_AtomicNoPartialOnFailure(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	// No temp files (".tmp-*") should be left behind after a successful Put.
	if err := s.Put("foo", []byte("data")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "foo.js" {
		t.Fatalf("expected exactly one file foo.js, got %+v", entries)
	}
}

// TestRegisterRoutesEndToEnd exercises the REST handlers over real HTTP, including the
// onPut/onDelete callbacks. Path-traversal names ("..") aren't tested here: net/http's
// ServeMux cleans/redirects such paths before they ever reach the handler, so that guard
// is only reachable (and only meaningfully tested) at the Store/validateName level above.
func TestRegisterRoutesEndToEnd(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}

	var puts, deletes []string
	mux := http.NewServeMux()
	RegisterRoutes(mux, "/api/i/test", store,
		func(name string) { puts = append(puts, name) },
		func(name string) { deletes = append(deletes, name) })
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	base := server.URL + "/api/i/test/scripts"

	resp := httpDo(t, http.MethodGet, base, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /scripts: expected 200, got %d", resp.StatusCode)
	}
	if body := strings.TrimSpace(string(readBody(t, resp))); body != "[]" {
		t.Fatalf("expected empty list, got %s", body)
	}

	resp = httpDo(t, http.MethodPut, base+"/foo", strings.NewReader("console.log(1)"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /scripts/foo: expected 204, got %d", resp.StatusCode)
	}
	if len(puts) != 1 || puts[0] != "foo" {
		t.Fatalf("expected onPut(\"foo\") to have fired once, got %+v", puts)
	}

	resp = httpDo(t, http.MethodGet, base+"/foo", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /scripts/foo: expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("expected Content-Type application/javascript, got %q", ct)
	}
	if body := string(readBody(t, resp)); body != "console.log(1)" {
		t.Fatalf("unexpected content: %s", body)
	}

	resp = httpDo(t, http.MethodGet, base, nil)
	if body := string(readBody(t, resp)); !strings.Contains(body, `"foo"`) {
		t.Fatalf("expected listing to contain foo, got %s", body)
	}

	resp = httpDo(t, http.MethodDelete, base+"/foo", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /scripts/foo: expected 204, got %d", resp.StatusCode)
	}
	if len(deletes) != 1 || deletes[0] != "foo" {
		t.Fatalf("expected onDelete(\"foo\") to have fired once, got %+v", deletes)
	}

	resp = httpDo(t, http.MethodGet, base+"/foo", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after delete: expected 404, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodDelete, base+"/foo", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("DELETE unknown script: expected 404, got %d", resp.StatusCode)
	}

	// A name violating the charset (but not path-special, so it isn't cleaned/redirected
	// away by net/http before reaching our handler) is rejected with 400.
	resp = httpDo(t, http.MethodPut, base+"/foo!bar", strings.NewReader("x"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT invalid name: expected 400, got %d", resp.StatusCode)
	}
}

func TestRegisterRoutesDisabledWithoutStore(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, "/api/i/test", nil, nil, nil)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	resp := httpDo(t, http.MethodGet, server.URL+"/api/i/test/scripts", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when store is nil, got %d", resp.StatusCode)
	}
}

func httpDo(t *testing.T, method, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
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

func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
