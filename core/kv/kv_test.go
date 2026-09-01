package kv

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "kv.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestReadWriteDelete_RoundTrip(t *testing.T) {
	s := newTestStore(t)

	if _, found, err := s.Read("missing"); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("expected found=false for a key that was never written")
	}

	if err := s.Write("k", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if value, found, err := s.Read("k"); err != nil {
		t.Fatal(err)
	} else if !found || string(value) != "v1" {
		t.Fatalf("got (%q, %v), want (\"v1\", true)", value, found)
	}

	// Write is a plain upsert — a second write to the same key overwrites, no separate
	// "update" operation.
	if err := s.Write("k", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if value, found, err := s.Read("k"); err != nil {
		t.Fatal(err)
	} else if !found || string(value) != "v2" {
		t.Fatalf("got (%q, %v), want (\"v2\", true)", value, found)
	}

	if err := s.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Read("k"); err != nil {
		t.Fatal(err)
	} else if found {
		t.Fatal("expected found=false after Delete")
	}

	// Delete is idempotent — deleting an already-absent (or never-existing) key is not
	// an error.
	if err := s.Delete("k"); err != nil {
		t.Fatalf("Delete on an absent key should not error, got: %v", err)
	}
	if err := s.Delete("never-existed"); err != nil {
		t.Fatalf("Delete on a never-existing key should not error, got: %v", err)
	}
}

func TestWrite_EmptyValue(t *testing.T) {
	s := newTestStore(t)
	if err := s.Write("k", []byte{}); err != nil {
		t.Fatal(err)
	}
	if value, found, err := s.Read("k"); err != nil {
		t.Fatal(err)
	} else if !found || len(value) != 0 {
		t.Fatalf("got (%q, %v), want (\"\", true)", value, found)
	}
}

func TestWrite_KeyTooLong(t *testing.T) {
	s := newTestStore(t)
	key := make([]byte, maxKeyBytes+1)
	if err := s.Write(string(key), []byte("v")); !errors.Is(err, ErrKeyTooLong) {
		t.Fatalf("got %v, want ErrKeyTooLong", err)
	}
	// The boundary itself must be accepted.
	if err := s.Write(string(key[:maxKeyBytes]), []byte("v")); err != nil {
		t.Fatalf("a key of exactly maxKeyBytes should be accepted, got: %v", err)
	}
}

func TestWrite_ValueTooLarge(t *testing.T) {
	s := newTestStore(t)
	value := make([]byte, maxValueBytes+1)
	if err := s.Write("k", value); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("got %v, want ErrValueTooLarge", err)
	}
	if err := s.Write("k", value[:maxValueBytes]); err != nil {
		t.Fatalf("a value of exactly maxValueBytes should be accepted, got: %v", err)
	}
}

func TestList(t *testing.T) {
	s := newTestStore(t)

	keys := []string{
		"myproto.cryptkey",
		"myproto.other",
		"myproto.",
		"myproto.a",
		"myproto.z",
		"myprotoX",
		"myprot",
		"myproto/subkey",
		"café.true",
		"café",
		"cafés",
		"cafe",
		"ab\xffsomething",
		"ab\xff",
		"ab\xfe",
		"ac",
		"ad",
		"\xff\xffmore",
		"\xff\xff",
		"zzz",
	}
	for _, k := range keys {
		if err := s.Write(k, nil); err != nil {
			t.Fatalf("writing %q: %v", k, err)
		}
	}

	tests := []struct {
		name   string
		prefix string
		want   []string
	}{
		{
			name:   "empty prefix returns every key",
			prefix: "",
			want:   keys,
		},
		{
			name:   "plain ASCII prefix",
			prefix: "myproto.",
			want:   []string{"myproto.", "myproto.a", "myproto.cryptkey", "myproto.other", "myproto.z"},
		},
		{
			name:   "multi-byte UTF-8 prefix",
			prefix: "café",
			want:   []string{"café", "café.true", "cafés"},
		},
		{
			name:   "prefix ending in 0xFF carries into the preceding byte",
			prefix: "ab\xff",
			want:   []string{"ab\xff", "ab\xffsomething"},
		},
		{
			name:   "all-0xFF prefix has no finite upper bound",
			prefix: "\xff\xff",
			want:   []string{"\xff\xff", "\xff\xffmore"},
		},
		{
			name:   "prefix matching nothing",
			prefix: "nonexistent",
			want:   []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.List(tt.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if !equalUnordered(got, tt.want) {
				t.Fatalf("List(%q) = %q, want %q", tt.prefix, got, tt.want)
			}
		})
	}
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, s := range a {
		count[s]++
	}
	for _, s := range b {
		count[s]--
	}
	for _, c := range count {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestNew_ReopeningExistingFileIsIdempotentAndPreservesData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kv.sqlite")

	s1, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.Write("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := New(path)
	if err != nil {
		t.Fatalf("reopening an existing store's file should succeed, got: %v", err)
	}
	defer s2.Close()
	if value, found, err := s2.Read("k"); err != nil {
		t.Fatal(err)
	} else if !found || string(value) != "v" {
		t.Fatalf("data written before close should survive reopen, got (%q, %v)", value, found)
	}
}

func TestNew_CoexistsWithPreExistingUnrelatedTables(t *testing.T) {
	// Simulates enabling core.kv against a file some other database (e.g. dbdump's own)
	// has already been using — New must not disturb pre-existing tables, and its own
	// core_kv table must work normally alongside them.
	path := filepath.Join(t.TempDir(), "shared.sqlite")

	seed, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Exec(`CREATE TABLE sessions (id INTEGER PRIMARY KEY, start INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Exec(`INSERT INTO sessions (id, start) VALUES (1, 12345)`); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(path)
	if err != nil {
		t.Fatalf("New should tolerate a file with pre-existing unrelated tables, got: %v", err)
	}
	defer s.Close()

	if err := s.Write("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if value, found, err := s.Read("k"); err != nil {
		t.Fatal(err)
	} else if !found || string(value) != "v" {
		t.Fatalf("got (%q, %v), want (\"v\", true)", value, found)
	}

	// The pre-existing table and its data must be untouched.
	verify, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer verify.Close()
	var start int
	if err := verify.QueryRow(`SELECT start FROM sessions WHERE id = 1`).Scan(&start); err != nil {
		t.Fatalf("pre-existing table should be untouched: %v", err)
	}
	if start != 12345 {
		t.Fatalf("got start=%d, want 12345", start)
	}
}
