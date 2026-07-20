package tamper

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFsStore_Resolve(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Clean(root)

	cases := []struct {
		in   string
		want string
	}{
		{"", root},
		{"foo.txt", filepath.Join(root, "foo.txt")},
		{"sub/dir/file.bin", filepath.Join(root, "sub/dir/file.bin")},
		{"../../etc/passwd", filepath.Join(root, "etc/passwd")},
		{"../..", root},
		{"a/../b", filepath.Join(root, "b")},
	}
	for _, c := range cases {
		got, err := s.resolve(c.in)
		if err != nil {
			t.Errorf("resolve(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("resolve(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFsStore_ResolveNeverEscapesRoot(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	root = filepath.Clean(root)

	// However deep the traversal, the cleaned result must stay under (or equal to) root —
	// path.Clean("/"+relPath) eats leading ".." against the synthetic "/" prefix before
	// it's ever joined onto root, so there is structurally no relPath that escapes.
	attempts := []string{
		"..", "../", "../../../../../../etc/passwd", "....//....//etc/passwd",
	}
	for _, a := range attempts {
		got, err := s.resolve(a)
		if err != nil {
			t.Errorf("resolve(%q): unexpected error: %v", a, err)
			continue
		}
		if got != root && !strings.HasPrefix(got, root+string(filepath.Separator)) {
			t.Errorf("resolve(%q) = %q escaped root %q", a, got, root)
		}
	}
}

func TestFsStore_NewRequiresExistingDir(t *testing.T) {
	if _, err := newFsStore(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for a non-existent fs-root")
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newFsStore(file); err == nil {
		t.Fatal("expected error when fs-root points at a file, not a directory")
	}
}

func TestFsStore_PutGetList(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put("foo.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	content, err := s.Get("foo.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %q", content)
	}

	// Overwrite.
	if err := s.Put("foo.txt", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	content, err = s.Get("foo.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "v2" {
		t.Fatalf("expected overwritten content, got %q", content)
	}

	// Nested path: parent directories auto-created.
	if err := s.Put("a/b/c.bin", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	content, err = s.Get("a/b/c.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 3 {
		t.Fatalf("unexpected content: %v", content)
	}

	// Root listing sees foo.txt and the "a" subdirectory.
	infos, err := s.List("")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 root entries, got %d: %+v", len(infos), infos)
	}
	if infos[0].Name != "a" || !infos[0].Dir {
		t.Errorf("unexpected first entry: %+v", infos[0])
	}
	if infos[1].Name != "foo.txt" || infos[1].Dir || infos[1].Size != 2 {
		t.Errorf("unexpected second entry: %+v", infos[1])
	}

	// Subdirectory listing.
	infos, err = s.List("a/b")
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].Name != "c.bin" || infos[0].Size != 3 {
		t.Fatalf("unexpected listing of a/b: %+v", infos)
	}
}

func TestFsStore_GetMissing(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("nope.txt"); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
	if _, err := s.List("nope"); !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestFsStore_Put_AtomicNoTempFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put("sub/foo.bin", []byte("data")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "foo.bin" {
		t.Fatalf("expected exactly one file foo.bin, got %+v", entries)
	}
}

func TestFsStore_Append(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Appending to a file that doesn't exist yet creates it, including missing parent
	// directories.
	if err := s.Append("sub/log.txt", []byte("line 1\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("sub/log.txt", []byte("line 2\n")); err != nil {
		t.Fatal(err)
	}
	content, err := s.Get("sub/log.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "line 1\nline 2\n" {
		t.Fatalf("unexpected content: %q", content)
	}

	// Put followed by Append: append starts from Put's content, not from scratch.
	if err := s.Put("foo.txt", []byte("start\n")); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("foo.txt", []byte("more\n")); err != nil {
		t.Fatal(err)
	}
	content, err = s.Get("foo.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "start\nmore\n" {
		t.Fatalf("unexpected content: %q", content)
	}
}

// TestFsStore_Append_ConcurrentSafe exercises the actual reason Append opens the file
// with O_APPEND instead of being implemented as a client-side Get+concatenate+Put: many
// concurrent appends (as would happen from different connections' independent script
// handlers — see CLAUDE.md's "Per-connection event serialization" note) must not lose
// or interleave-corrupt any writer's data.
func TestFsStore_Append_ConcurrentSafe(t *testing.T) {
	dir := t.TempDir()
	s, err := newFsStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	const writers = 20
	const linesPerWriter = 50
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for l := 0; l < linesPerWriter; l++ {
				line := fmt.Sprintf("writer-%d-line-%d\n", w, l)
				if err := s.Append("concurrent.log", []byte(line)); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	content, err := s.Get("concurrent.log")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	if len(lines) != writers*linesPerWriter {
		t.Fatalf("expected %d lines, got %d", writers*linesPerWriter, len(lines))
	}
	seen := make(map[string]bool, len(lines))
	for _, line := range lines {
		if seen[line] {
			t.Fatalf("duplicate line (torn/repeated write?): %q", line)
		}
		seen[line] = true
	}
}

// TestFsAPI_EndToEnd exercises the REST handlers over real HTTP. Traversal attempts
// aren't tested here beyond a normal one: net/http's ServeMux itself cleans/redirects
// literal ".." segments in the URL path before they ever reach our handler, so that
// guard is only reachable (and only meaningfully tested) at the fsStore.resolve level
// above.
func TestFsAPI_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	_, wsURL := newTestServerWithConfig(t, TamperConfig{FsRoot: dir})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/fs"

	resp := httpDo(t, http.MethodGet, base+"/list", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /fs/list: expected 200, got %d", resp.StatusCode)
	}
	if body := strings.TrimSpace(string(readBody(t, resp))); body != "[]" {
		t.Fatalf("expected empty list, got %s", body)
	}

	resp = httpDo(t, http.MethodPut, base+"/file/sub/foo.bin", strings.NewReader("hello"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT /fs/file/sub/foo.bin: expected 204, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodGet, base+"/file/sub/foo.bin", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /fs/file/sub/foo.bin: expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("expected Content-Type application/octet-stream, got %q", ct)
	}
	if body := string(readBody(t, resp)); body != "hello" {
		t.Fatalf("unexpected content: %s", body)
	}

	resp = httpDo(t, http.MethodGet, base+"/list/sub", nil)
	if body := string(readBody(t, resp)); !strings.Contains(body, `"foo.bin"`) {
		t.Fatalf("expected listing of sub to contain foo.bin, got %s", body)
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
		t.Fatalf("POST /fs/file/sub/log.txt (create): expected 204, got %d", resp.StatusCode)
	}
	resp = httpDo(t, http.MethodPost, base+"/file/sub/log.txt", strings.NewReader("line 2\n"))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("POST /fs/file/sub/log.txt (append): expected 204, got %d", resp.StatusCode)
	}
	resp = httpDo(t, http.MethodGet, base+"/file/sub/log.txt", nil)
	if body := string(readBody(t, resp)); body != "line 1\nline 2\n" {
		t.Fatalf("unexpected appended content: %q", body)
	}
}

func TestFsAPI_DisabledWithoutFsRoot(t *testing.T) {
	_, wsURL := newTestServerWithConfig(t, TamperConfig{})
	base := "http" + strings.TrimPrefix(wsURL, "ws") + "/api/i/tamper/fs"

	resp := httpDo(t, http.MethodGet, base+"/list", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when fs-root isn't configured, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodGet, base+"/file/foo", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when fs-root isn't configured, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodPut, base+"/file/foo", strings.NewReader("x"))
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when fs-root isn't configured, got %d", resp.StatusCode)
	}

	resp = httpDo(t, http.MethodPost, base+"/file/foo", strings.NewReader("x"))
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("expected 501 when fs-root isn't configured, got %d", resp.StatusCode)
	}
}
