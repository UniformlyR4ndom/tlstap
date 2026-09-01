package fs

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
)

// RegisterRoutes implements proxy.ApiProvider and cli.CoreService.
//
// Two patterns are registered for list (with and without the trailing wildcard) because
// Go's {path...} wildcard doesn't match an empty trailing segment, so root and
// subdirectory listing need separate routes to the same handler.
func (s *Store) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc("GET "+basePath+"/list", s.handleList)
	mux.HandleFunc("GET "+basePath+"/list/{path...}", s.handleList)
	mux.HandleFunc("GET "+basePath+"/file/{path...}", s.handleGet)
	mux.HandleFunc("PUT "+basePath+"/file/{path...}", s.handlePut)
	mux.HandleFunc("POST "+basePath+"/file/{path...}", s.handleAppend)
}

func (s *Store) handleList(w http.ResponseWriter, r *http.Request) {
	infos, err := s.List(r.PathValue("path"))
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "unknown directory")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, infos)
}

func (s *Store) handleGet(w http.ResponseWriter, r *http.Request) {
	content, err := s.Get(r.PathValue("path"))
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "unknown file")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(content)
}

func (s *Store) handlePut(w http.ResponseWriter, r *http.Request) {
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if err := s.Put(r.PathValue("path"), content); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAppend is POST, not PUT: PUT is expected to be idempotent (repeat = same
// result), which an append explicitly isn't (repeat = content appended twice) — POST is
// the generic "process this at the target resource, non-idempotent" verb, so it's the
// better fit here despite every other endpoint here being GET/PUT.
func (s *Store) handleAppend(w http.ResponseWriter, r *http.Request) {
	content, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	if err := s.Append(r.PathValue("path"), content); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
