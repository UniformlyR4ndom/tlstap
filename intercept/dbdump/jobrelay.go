package dbdump

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/websocket"
)

// jobRelay is the shared single-connected-client request/response mechanism behind both
// /framer-jobs (framerjobs.go) and /dissector-jobs (dissectorjobs.go): a browser tab
// opts in by opening the WebSocket register handles; the corresponding POST .../run
// pushes one job to it and blocks for a matching result. The relay itself is
// payload-agnostic — it only needs each job to carry a caller-chosen job_id and each
// result frame to echo it back; every other field in the job/result JSON is each
// caller's own concern to build/decode. Extracted here because the connection-tracking/
// dispatch/timeout mechanics are identical between the two relays — a fix to one would
// need to apply identically to the other.
//
// Only one connection is tracked at a time — a new one replaces (and closes) whichever
// was previously registered, since there's normally exactly one operator's tab doing
// this; nothing here tries to pick among several.
type jobRelay struct {
	mu      sync.Mutex
	conn    *websocket.Conn
	pending map[string]chan []byte // raw result-frame bytes, keyed by job_id
	nextID  int64
}

func newJobRelay() *jobRelay {
	return &jobRelay{pending: make(map[string]chan []byte)}
}

// errNoBrowserConnected is submit's error when nothing is currently registered — the
// caller maps this to a 503, same "unconfigured/unavailable feature" clarity every other
// gated endpoint in this codebase gives, even though this isn't config-gated so much as
// connection-gated.
var errNoBrowserConnected = errors.New("no browser connected")

// newJobID returns a fresh, unique-per-relay job id.
func (r *jobRelay) newJobID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	return strconv.FormatInt(r.nextID, 10)
}

// register upgrades req to a WebSocket and becomes the tracked connection (last-connect-
// wins, closing whichever connection was previously registered), then reads result
// frames until the connection closes. Each incoming frame must be a JSON object with at
// least a "job_id" string field — everything else is opaque here, delivered verbatim (as
// raw bytes) to whichever submit() call is waiting on that id, if any; a frame with an
// unmatched or missing job_id (already answered, or malformed) is silently dropped.
func (r *jobRelay) register(w http.ResponseWriter, req *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}

	r.mu.Lock()
	old := r.conn
	r.conn = conn
	r.mu.Unlock()
	if old != nil {
		old.Close()
	}

	defer func() {
		r.mu.Lock()
		if r.conn == conn {
			r.conn = nil
		}
		// Fail every job still waiting on this connection immediately, rather than
		// leaving submit to discover the loss only via its own timeout — each channel
		// is buffered (cap 1), so this never blocks even if a submit call has already
		// moved on (timed out, or its own caller disconnected).
		for jobID, ch := range r.pending {
			ch <- []byte(`{"ok":false,"error":"browser disconnected"}`)
			delete(r.pending, jobID)
		}
		r.mu.Unlock()
		conn.Close()
	}()

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var envelope struct {
			JobID string `json:"job_id"`
		}
		if json.Unmarshal(data, &envelope) != nil || envelope.JobID == "" {
			continue
		}
		r.mu.Lock()
		ch, exists := r.pending[envelope.JobID]
		if exists {
			delete(r.pending, envelope.JobID)
		}
		r.mu.Unlock()
		if exists {
			ch <- data
		}
	}
}

// submit marshals job (which must include jobID under whatever field name the caller's
// own wire shape uses — this function never inspects it) and sends it to the currently
// connected client, then blocks until either a matching result frame arrives (returned as
// raw bytes for the caller to decode into its own result shape), ctx is done (a deadline
// the caller derives from its own timeout constant, or the original HTTP request's own
// context), or nothing is connected at all (errNoBrowserConnected, returned immediately
// without blocking).
func (r *jobRelay) submit(ctx context.Context, jobID string, job any) ([]byte, error) {
	r.mu.Lock()
	conn := r.conn
	if conn == nil {
		r.mu.Unlock()
		return nil, errNoBrowserConnected
	}
	resultCh := make(chan []byte, 1)
	r.pending[jobID] = resultCh
	data, err := json.Marshal(job)
	if err == nil {
		err = conn.WriteMessage(websocket.TextMessage, data)
	}
	if err != nil {
		delete(r.pending, jobID)
	}
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case result := <-resultCh:
		return result, nil
	case <-ctx.Done():
		r.mu.Lock()
		delete(r.pending, jobID)
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}
