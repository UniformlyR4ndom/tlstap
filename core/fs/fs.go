// Package fs implements core/fs's storage layer: scoped read/write/list access to one
// host directory, independent of any interceptor. See core/CLAUDE.md for the full
// design/rationale and intercept/tamper/CLAUDE.md for how tamper's ctx.fs.* script API
// sits on top of this from the frontend side only (no Go-level connection between the
// two packages).
//
// Named fs, like the standard library's io/fs — callers must import this aliased (e.g.
// corefs "tlstap/core/fs") wherever both are needed in the same file.
package fs

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// errOutsideRoot is returned by Store.resolve when a path, once cleaned, would land
// outside the configured root.
var errOutsideRoot = errors.New("path escapes root")

// entry is one entry of a List reply. Size is meaningless for directories (the raw
// value os.FileInfo happens to report); callers should key off Dir instead.
type entry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
}

// Store exposes read/write/list access to one host directory. Names are arbitrary
// slash-separated paths (files can live in subdirectories), so containment is enforced
// structurally rather than by restricting the charset of a single path segment.
// Deliberately does not resolve symlinks: a symlink planted inside the root escaping it
// is a host filesystem concern, not this store's problem to solve.
type Store struct {
	root string // absolute, cleaned
}

// New requires dir to already exist and be a directory: this exposes a directory the
// operator chose, so a typo'd path should fail construction loudly rather than silently
// creating one.
func New(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("core.fs directory %q is not a directory", dir)
	}
	return &Store{root: abs}, nil
}

// Finalize implements cli.CoreService. Nothing to release — a Store holds no open
// resource beyond a directory path.
func (s *Store) Finalize() {}

// resolve maps a request path (always slash-separated, as it arrives from a URL
// wildcard) to an absolute host path under root. path.Clean("/"+relPath) is the key
// step: prefixing with "/" before cleaning means any leading ".." components are eaten
// against that synthetic root rather than able to walk above it, so the result can never
// climb outside relPath's own tree — no symlink resolution needed to make this safe. The
// suffix check after Join is a second, independent guard against the same class of
// escape (not a bare strings.HasPrefix, which would wrongly accept a sibling like
// "<root>-evil").
func (s *Store) resolve(relPath string) (string, error) {
	clean := path.Clean("/" + relPath)
	full := filepath.Join(s.root, filepath.FromSlash(clean))
	if full != s.root && !strings.HasPrefix(full, s.root+string(filepath.Separator)) {
		return "", errOutsideRoot
	}
	return full, nil
}

// List returns one directory level (not recursive) of relPath, "" meaning root itself.
func (s *Store) List(relPath string) ([]entry, error) {
	full, err := s.resolve(relPath)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}

	infos := make([]entry, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue // e.g. removed between ReadDir and Info; just skip it
		}
		infos = append(infos, entry{Name: e.Name(), Dir: e.IsDir(), Size: fi.Size()})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

func (s *Store) Get(relPath string) ([]byte, error) {
	full, err := s.resolve(relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(full)
}

// Put atomically creates or overwrites a file via write-to-temp-file + rename. The temp
// file lives alongside the target (which may be in a subdirectory of root, not root
// itself), and missing parent directories are created first, since a script writing to
// a new subdirectory shouldn't have to create it via a separate call this store doesn't
// offer.
func (s *Store) Put(relPath string, content []byte) error {
	full, err := s.resolve(relPath)
	if err != nil {
		return err
	}

	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	return atomicWriteFile(dir, full, content)
}

// Append adds content to the end of a file, creating it (and any missing parent
// directories) if it doesn't exist yet. Deliberately not implemented as a client-side
// Get+concatenate+Put: two callers appending to the same file around the same time
// would otherwise race, silently losing one side's data. Opening with O_APPEND instead
// delegates the seek-to-end-and-write to the kernel, which performs it atomically per
// Write call, so concurrent appends to the same file are safe without any locking of
// our own.
func (s *Store) Append(relPath string, content []byte) error {
	full, err := s.resolve(relPath)
	if err != nil {
		return err
	}

	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(full, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(content)
	return err
}

// atomicWriteFile creates or overwrites target with content via write-to-temp-file (in
// tmpDir) + rename, so a concurrent reader can never observe a partial write. tmpDir
// must already exist.
func atomicWriteFile(tmpDir, target string, content []byte) error {
	tmp, err := os.CreateTemp(tmpDir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
