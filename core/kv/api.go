package kv

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// RegisterRoutes implements proxy.ApiProvider and cli.CoreService.
//
// Unlike this codebase's usual all-JSON-body convention, key/prefix travel in the query
// string on every endpoint here, keeping the request/response body reserved purely for
// value bytes (write's request, read's response) — see doc/design/core-kv-store.md's
// "REST API" section for why.
func (s *Store) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc("POST "+basePath+"/list", s.handleList)
	mux.HandleFunc("POST "+basePath+"/read", s.handleRead)
	mux.HandleFunc("POST "+basePath+"/write", s.handleWrite)
	mux.HandleFunc("POST "+basePath+"/delete", s.handleDelete)
}

// Finalize implements cli.CoreService.
func (s *Store) Finalize() {
	_ = s.Close()
}

func (s *Store) handleList(w http.ResponseWriter, r *http.Request) {
	keys, err := s.List(r.URL.Query().Get("prefix"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string][]string{"keys": keys})
}

func (s *Store) handleRead(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}

	value, found, err := s.Read(key)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(value)
}

func (s *Store) handleWrite(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}

	// Capped one byte past the real limit — enough for Write's own size check below to
	// correctly reject an oversized value, without buffering an unbounded body into
	// memory just to find out it's too large.
	value, err := io.ReadAll(io.LimitReader(r.Body, maxValueBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body: "+err.Error())
		return
	}

	if err := s.Write(key, value); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrKeyTooLong) || errors.Is(err, ErrValueTooLarge) {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Store) handleDelete(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "key is required")
		return
	}

	if err := s.Delete(key); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
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
