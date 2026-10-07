package dbdump

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// remoteJobTimeout bounds how long a POST .../run call (framer or dissector jobs) waits
// for a connected browser to report a result before giving up — a script hung or a
// browser tab that quietly died mid-run shouldn't leave the HTTP caller blocked forever.
const remoteJobTimeout = 2 * time.Minute

// handleFramerJobsSocket is the browser-tab side of the relay: a persistent connection,
// opened only while the user has explicitly opted in (a UI toggle — see web/CLAUDE.md's
// "Remote framer job listener" section), that receives pushed job messages and reports
// results back. The server never runs a script itself — this only brokers between
// tapctl's REST call below and whichever browser tab is currently connected, dispatching
// to the *real* catchUpFramer already running in that page. See jobrelay.go for the
// shared connection-tracking/dispatch mechanics.
func (i *DbDumpInterceptor) handleFramerJobsSocket(w http.ResponseWriter, r *http.Request) {
	i.framerJobs.register(w, r)
}

// handleFramerJobsRun is tapctl's side: a plain REST call (POST, not WebSocket — tapctl
// stays a one-shot "connect, act, exit" client like every other command) that blocks
// until the connected browser reports a result, or remoteJobTimeout/an unresponsive
// write/the caller disconnecting cuts it short. 503 immediately, nothing dispatched, if
// no browser is currently connected.
func (i *DbDumpInterceptor) handleFramerJobsRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session int64  `json:"session"`
		Stream  int64  `json:"stream"`
		Script  string `json:"script"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	jobID := i.framerJobs.newJobID()
	ctx, cancel := context.WithTimeout(r.Context(), remoteJobTimeout)
	defer cancel()
	data, err := i.framerJobs.submit(ctx, jobID, struct {
		Kind    string `json:"kind"`
		JobID   string `json:"job_id"`
		Session int64  `json:"session"`
		Stream  int64  `json:"stream"`
		Script  string `json:"script"`
	}{"job", jobID, req.Session, req.Stream, req.Script})
	if err != nil {
		writeRemoteJobError(w, err, "framer")
		return
	}

	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		writeError(w, http.StatusInternalServerError, "malformed result from browser: "+err.Error())
		return
	}
	if result.OK {
		writeJSON(w, map[string]string{"status": "ok"})
	} else {
		writeError(w, http.StatusUnprocessableEntity, result.Error)
	}
}

// writeRemoteJobError maps a jobRelay.submit error to the right HTTP status — shared by
// handleFramerJobsRun and handleDissectorJobsRun (dissectorjobs.go). kind names the
// relay in the "no browser connected" message ("framer"/"dissector"). A canceled
// context (the HTTP caller disconnected before a result arrived) writes nothing — same
// as the original per-relay handlers before this was shared, since nothing is left to
// read the response anyway.
func writeRemoteJobError(w http.ResponseWriter, err error, kind string) {
	switch {
	case errors.Is(err, errNoBrowserConnected):
		writeError(w, http.StatusServiceUnavailable, "no browser connected for "+kind+" jobs")
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, kind+" job timed out waiting for browser")
	case errors.Is(err, context.Canceled):
		// Caller disconnected; nothing to write to.
	default:
		writeError(w, http.StatusServiceUnavailable, "browser connection lost: "+err.Error())
	}
}
