package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStore_Resolve(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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

func TestStore_ResolveNeverEscapesRoot(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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

func TestStore_NewRequiresExistingDir(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for a non-existent root")
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(file); err == nil {
		t.Fatal("expected error when root points at a file, not a directory")
	}
}

func TestStore_PutGetList(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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

func TestStore_GetMissing(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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

func TestStore_Put_AtomicNoTempFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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

func TestStore_Append(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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

// TestStore_Append_ConcurrentSafe exercises the actual reason Append opens the file with
// O_APPEND instead of being implemented as a client-side Get+concatenate+Put: many
// concurrent appends must not lose or interleave-corrupt any writer's data.
func TestStore_Append_ConcurrentSafe(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
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
