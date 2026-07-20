package tamper

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// errOutsidefsRoot is returned by fsStore.resolve when a path, once cleaned, would land
// outside the configured root.
var errOutsideFsRoot = errors.New("path escapes fs-root")

// fsEntry is one entry of an /fs/list reply. Size is meaningless for directories (the
// raw value os.FileInfo happens to report); callers should key off Dir instead.
type fsEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
}

// fsStore exposes read/write/list access to one host directory (fs-root), scoped to
// scripts. Unlike scriptStore, names are arbitrary slash-separated paths (files can live
// in subdirectories), so containment is enforced structurally — see resolve — rather
// than by restricting the charset of a single path segment. Deliberately does not
// resolve symlinks: a symlink planted inside fs-root escaping it is a host filesystem
// concern, not this store's problem to solve.
type fsStore struct {
	root string // absolute, cleaned
}

// newFsStore requires dir to already exist and be a directory — unlike scriptStore, this
// exposes a directory the operator chose, so a typo'd path should fail interceptor
// construction loudly rather than silently creating one.
func newFsStore(dir string) (*fsStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	abs = filepath.Clean(abs)

	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("fs-root %q is not a directory", dir)
	}
	return &fsStore{root: abs}, nil
}

// resolve maps a request path (always slash-separated, as it arrives from a URL
// wildcard) to an absolute host path under root. path.Clean("/"+relPath) is the key
// step: prefixing with "/" before cleaning means any leading ".." components are eaten
// against that synthetic root rather than able to walk above it, so the result can never
// climb outside relPath's own tree — no symlink resolution needed to make this safe. The
// suffix check after Join is a second, independent belt-and-suspenders guard against the
// same class of escape, matching the boundary-aware form used elsewhere in this codebase
// (not a bare strings.HasPrefix, which would wrongly accept a sibling like
// "<root>-evil").
func (s *fsStore) resolve(relPath string) (string, error) {
	clean := path.Clean("/" + relPath)
	full := filepath.Join(s.root, filepath.FromSlash(clean))
	if full != s.root && !strings.HasPrefix(full, s.root+string(filepath.Separator)) {
		return "", errOutsideFsRoot
	}
	return full, nil
}

// List returns one directory level (not recursive) of relPath, "" meaning root itself.
func (s *fsStore) List(relPath string) ([]fsEntry, error) {
	full, err := s.resolve(relPath)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}

	infos := make([]fsEntry, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue // e.g. removed between ReadDir and Info; just skip it
		}
		infos = append(infos, fsEntry{Name: e.Name(), Dir: e.IsDir(), Size: fi.Size()})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

func (s *fsStore) Get(relPath string) ([]byte, error) {
	full, err := s.resolve(relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(full)
}

// Put atomically creates or overwrites a file via write-to-temp-file + rename, mirroring
// scriptStore.Put — except the temp file lives alongside the target (which may be in a
// subdirectory of root, not root itself), and missing parent directories are created
// first, since a script writing to a new subdirectory shouldn't have to create it first
// via a separate call this store doesn't offer.
func (s *fsStore) Put(relPath string, content []byte) error {
	full, err := s.resolve(relPath)
	if err != nil {
		return err
	}

	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
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
	if err := os.Rename(tmpName, full); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// Append adds content to the end of a file, creating it (and any missing parent
// directories) if it doesn't exist yet. Deliberately not implemented as a client-side
// Get+concatenate+Put: two scripts appending to the same file around the same time run
// on independent per-connection goroutines (see CLAUDE.md's "Per-connection event
// serialization" note), so a read-modify-write from the caller's side would be racy —
// one append could silently clobber the other. Opening with O_APPEND instead delegates
// the seek-to-end-and-write to the kernel, which performs it atomically per Write call
// (the same mechanism the interceptor's own log-file already relies on — see
// writeScriptLog/Init in tamper.go), so concurrent appends to the same file are safe
// without any locking of our own.
func (s *fsStore) Append(relPath string, content []byte) error {
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

// ── REST handlers ───────────────────────────────────────────────────────────────────
// Registered by RegisterRoutes (api.go). File content is transferred as a raw body
// (application/octet-stream), unlike scripts' raw-text convention, since fs-root content
// is arbitrary binary, not always UTF-8 JS.

func (i *TamperInterceptor) handleFsList(w http.ResponseWriter, r *http.Request) {
	if i.fsRoot == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "fs-root not configured")
		return
	}

	infos, err := i.fsRoot.List(r.PathValue("path"))
	if err != nil {
		if os.IsNotExist(err) {
			writeErrorResponse(w, http.StatusNotFound, "unknown directory")
			return
		}
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSONResponse(w, infos)
}

func (i *TamperInterceptor) handleFsGet(w http.ResponseWriter, r *http.Request) {
	if i.fsRoot == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "fs-root not configured")
		return
	}

	content, err := i.fsRoot.Get(r.PathValue("path"))
	if err != nil {
		if os.IsNotExist(err) {
			writeErrorResponse(w, http.StatusNotFound, "unknown file")
			return
		}
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(content)
}

func (i *TamperInterceptor) handleFsPut(w http.ResponseWriter, r *http.Request) {
	if i.fsRoot == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "fs-root not configured")
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if err := i.fsRoot.Put(r.PathValue("path"), content); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleFsAppend is POST, not PUT: PUT is expected to be idempotent (repeat = same
// result), which an append explicitly isn't (repeat = content appended twice) — POST is
// the generic "process this at the target resource, non-idempotent" verb, so it's the
// better fit here despite every other fs-root endpoint being GET/PUT.
func (i *TamperInterceptor) handleFsAppend(w http.ResponseWriter, r *http.Request) {
	if i.fsRoot == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "fs-root not configured")
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if err := i.fsRoot.Append(r.PathValue("path"), content); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
