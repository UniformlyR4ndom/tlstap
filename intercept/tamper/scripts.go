package tamper

import (
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

// scriptNameRe restricts a script name to a single safe path segment: letters, digits,
// '_', '-', '.', and spaces. Path separators are excluded outright, so "." and ".." are
// the only remaining values that resolve outside the scripts directory when joined with
// it — rejected explicitly below, along with leading/trailing '.'/' ' to avoid
// confusingly-named near-duplicates (e.g. "foo" vs "foo ").
var scriptNameRe = regexp.MustCompile(`^[A-Za-z0-9_\-. ]+$`)

func validateScriptName(name string) error {
	if name == "" {
		return errors.New("script name must not be empty")
	}
	if !scriptNameRe.MatchString(name) {
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

// scriptInfo is one entry of the /scripts listing.
type scriptInfo struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// scriptStore is a flat name -> content store backed by one *.js file per script in dir.
// It has no opinion about which script is "main" or which are "libraries" — that's a
// runtime-level concern, resolved later by whatever explicitly loads scripts by name.
type scriptStore struct {
	dir string
}

func newScriptStore(dir string) (*scriptStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &scriptStore{dir: dir}, nil
}

func (s *scriptStore) path(name string) string {
	return filepath.Join(s.dir, name+scriptExt)
}

func (s *scriptStore) List() ([]scriptInfo, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	infos := make([]scriptInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), scriptExt) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue // e.g. removed between ReadDir and Info; just skip it
		}
		infos = append(infos, scriptInfo{Name: strings.TrimSuffix(e.Name(), scriptExt), Size: fi.Size()})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos, nil
}

func (s *scriptStore) Get(name string) ([]byte, error) {
	if err := validateScriptName(name); err != nil {
		return nil, err
	}
	return os.ReadFile(s.path(name))
}

// Put atomically creates or overwrites a script via write-to-temp-file + rename, so a
// concurrent Get can never observe a partially-written file.
func (s *scriptStore) Put(name string, content []byte) error {
	if err := validateScriptName(name); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
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
	if err := os.Rename(tmpName, s.path(name)); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func (s *scriptStore) Delete(name string) error {
	if err := validateScriptName(name); err != nil {
		return err
	}
	return os.Remove(s.path(name))
}

// ── REST handlers ───────────────────────────────────────────────────────────────────
// Registered by RegisterRoutes (api.go). Content is transferred as a raw body, not
// JSON/base64-wrapped, since it's always UTF-8 JS text.

func (i *TamperInterceptor) handleScriptsList(w http.ResponseWriter, r *http.Request) {
	if i.scripts == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "scripts-dir not configured")
		return
	}

	infos, err := i.scripts.List()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResponse(w, infos)
}

func (i *TamperInterceptor) handleScriptGet(w http.ResponseWriter, r *http.Request) {
	if i.scripts == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "scripts-dir not configured")
		return
	}

	content, err := i.scripts.Get(r.PathValue("name"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeErrorResponse(w, http.StatusNotFound, "unknown script")
			return
		}
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/javascript")
	w.Write(content)
}

func (i *TamperInterceptor) handleScriptPut(w http.ResponseWriter, r *http.Request) {
	if i.scripts == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "scripts-dir not configured")
		return
	}

	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if err := i.scripts.Put(r.PathValue("name"), content); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	i.sendEvent(scriptUpdatedMsg{Type: msgScriptUpdated, Name: r.PathValue("name")})
	w.WriteHeader(http.StatusNoContent)
}

func (i *TamperInterceptor) handleScriptDelete(w http.ResponseWriter, r *http.Request) {
	if i.scripts == nil {
		writeErrorResponse(w, http.StatusNotImplemented, "scripts-dir not configured")
		return
	}

	if err := i.scripts.Delete(r.PathValue("name")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeErrorResponse(w, http.StatusNotFound, "unknown script")
			return
		}
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	i.sendEvent(scriptUpdatedMsg{Type: msgScriptUpdated, Name: r.PathValue("name")})
	w.WriteHeader(http.StatusNoContent)
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
