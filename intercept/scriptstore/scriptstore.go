// Package scriptstore is a flat name -> content store for user-editable *.js scripts,
// plus the REST handlers to serve one over HTTP. Shared by any interceptor that lets a
// client author/store scripts (tamper's control scripts, dbdump's framer scripts) —
// storage and HTTP mechanics are identical across callers; what differs (e.g. whether a
// write pushes a live notification) is expressed via the onPut/onDelete callbacks passed
// to RegisterRoutes, not by this package.
package scriptstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const scriptExt = ".js"

// nameRe restricts a script name to a single safe path segment: letters, digits, '_',
// '-', '.', and spaces. Path separators are excluded outright, so "." and ".." are the
// only remaining values that resolve outside the store's directory when joined with it —
// rejected explicitly below, along with leading/trailing '.'/' ' to avoid confusingly-named
// near-duplicates (e.g. "foo" vs "foo ").
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_\-. ]+$`)

func validateName(name string) error {
	if name == "" {
		return errors.New("script name must not be empty")
	}
	if !nameRe.MatchString(name) {
		return errors.New("script name may only contain letters, digits, '_', '-', '.', and spaces")
	}
	if name == "." || name == ".." {
		return errors.New("invalid script name")
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") ||
		strings.HasPrefix(name, " ") || strings.HasSuffix(name, " ") {
		return errors.New("script name must not start or end with '.' or ' '")
	}
	return nil
}

// ScriptInfo is one entry of a script listing.
type ScriptInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// Store is a flat name -> content store backed by one *.js file per script in dir. It
// has no opinion about which script is "main" or which are "libraries" — that's a
// runtime-level concern, resolved later by whatever explicitly loads scripts by name.
type Store struct {
	dir string
}

// New creates dir (including any missing parents) if it doesn't already exist, and
// returns a Store backed by it.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, name+scriptExt)
}

func (s *Store) List() ([]ScriptInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	infos := make([]ScriptInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), scriptExt) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue // e.g. removed between ReadDir and Info; just skip it
		}
		infos = append(infos, ScriptInfo{Name: strings.TrimSuffix(e.Name(), scriptExt), Size: fi.Size()})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

func (s *Store) Get(name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	return os.ReadFile(s.path(name))
}

// Put atomically creates or overwrites a script via write-to-temp-file + rename, so a
// concurrent Get can never observe a partially-written file.
func (s *Store) Put(name string, content []byte) error {
	if err := validateName(name); err != nil {
		return err
	}
	return atomicWriteFile(s.dir, s.path(name), content)
}

func (s *Store) Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return os.Remove(s.path(name))
}

// ── REST handlers ───────────────────────────────────────────────────────────────────
// Content is transferred as a raw body, not JSON/base64-wrapped, since it's always
// UTF-8 JS text.

// RegisterRoutes wires GET {basePath}/scripts and GET/PUT/DELETE {basePath}/scripts/{name}
// against store. store may be nil (feature disabled for this interceptor instance) —
// every route then responds 501 rather than silently defaulting to some implicit
// directory. onPut/onDelete (either may be nil) are called with the script's name after
// a successful PUT/DELETE respectively, letting a caller react — e.g. push a live change
// notification, or invalidate data derived from a now-stale script — without this package
// needing to know anything about what that reaction is.
func RegisterRoutes(mux *http.ServeMux, basePath string, store *Store, onPut, onDelete func(name string)) {
	mux.HandleFunc("GET "+basePath+"/scripts", func(w http.ResponseWriter, r *http.Request) {
		if !requireStore(w, store) {
			return
		}
		infos, err := store.List()
		if err != nil {
			writeErrorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResponse(w, infos)
	})

	mux.HandleFunc("GET "+basePath+"/scripts/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !requireStore(w, store) {
			return
		}
		content, err := store.Get(r.PathValue("name"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeErrorResponse(w, http.StatusNotFound, "unknown script")
				return
			}
			writeErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		// ?hash=1 returns the script's sha256 hex digest instead of its content — the
		// same "version" a framer/dissector run computes over this same content
		// client-side (framerRun.js's sha256Hex) and dbdump persists as
		// frames.script_version/frame_progress.script_version — so a caller that already
		// knows a script's name can learn its current version directly, rather than
		// fetching the content just to hash it itself.
		if r.URL.Query().Has("hash") {
			sum := sha256.Sum256(content)
			writeJSONResponse(w, struct {
				Sha256 string `json:"sha256"`
			}{hex.EncodeToString(sum[:])})
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(content)
	})

	mux.HandleFunc("PUT "+basePath+"/scripts/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !requireStore(w, store) {
			return
		}
		content, err := io.ReadAll(r.Body)
		if err != nil {
			writeErrorResponse(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		name := r.PathValue("name")
		if err := store.Put(name, content); err != nil {
			writeErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		if onPut != nil {
			onPut(name)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("DELETE "+basePath+"/scripts/{name}", func(w http.ResponseWriter, r *http.Request) {
		if !requireStore(w, store) {
			return
		}
		name := r.PathValue("name")
		if err := store.Delete(name); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeErrorResponse(w, http.StatusNotFound, "unknown script")
				return
			}
			writeErrorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		if onDelete != nil {
			onDelete(name)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// requireStore reports whether store is non-nil, writing the standard 501 otherwise.
// Callers should return immediately on false.
func requireStore(w http.ResponseWriter, store *Store) bool {
	if store != nil {
		return true
	}
	writeErrorResponse(w, http.StatusNotImplemented, "scripts-dir not configured")
	return false
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

func writeJSONResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErrorResponse(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
