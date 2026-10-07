package dbdump

import (
	"context"
	"encoding/json"
	"net/http"
)

// handleDissectorJobsSocket is the browser-tab side of the relay — see
// handleFramerJobsSocket's doc comment (framerjobs.go) for the shared shape; this one
// dispatches to dissectRuntime.js's runDissector instead of catchUpFramer. See
// web/CLAUDE.md's "Remote dissector job listener" section for what actually runs on
// receipt of a job.
func (i *DbDumpInterceptor) handleDissectorJobsSocket(w http.ResponseWriter, r *http.Request) {
	i.dissectorJobs.register(w, r)
}

// handleDissectorJobsRun is tapctl's side. Unlike a framer job, dissection output is
// never persisted anywhere (see "Dissector scripts" above) — there is nothing to go
// inspect afterward via some other endpoint the way frames-timeline works for framer
// jobs — so a successful result carries the dissector's own FieldNode[] tree directly,
// passed through opaque (this package never parses or validates it, same as
// frames.meta's own treatment). The job identifies one already-persisted frame by
// (session, stream, direction, framer_script, framer_script_version, frame_id) — the
// same five-part key frames.go's frameKey uses, since a frame's id is only unique within
// that key — plus which dissector script to run.
func (i *DbDumpInterceptor) handleDissectorJobsRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session             int64  `json:"session"`
		Stream              int64  `json:"stream"`
		Direction           int    `json:"direction"`
		FramerScript        string `json:"framer_script"`
		FramerScriptVersion string `json:"framer_script_version"`
		FrameID             int64  `json:"frame_id"`
		DissectScript       string `json:"dissect_script"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	jobID := i.dissectorJobs.newJobID()
	ctx, cancel := context.WithTimeout(r.Context(), remoteJobTimeout)
	defer cancel()
	data, err := i.dissectorJobs.submit(ctx, jobID, struct {
		Kind                string `json:"kind"`
		JobID               string `json:"job_id"`
		Session             int64  `json:"session"`
		Stream              int64  `json:"stream"`
		Direction           int    `json:"direction"`
		FramerScript        string `json:"framer_script"`
		FramerScriptVersion string `json:"framer_script_version"`
		FrameID             int64  `json:"frame_id"`
		DissectScript       string `json:"dissect_script"`
	}{
		"job", jobID, req.Session, req.Stream, req.Direction,
		req.FramerScript, req.FramerScriptVersion, req.FrameID, req.DissectScript,
	})
	if err != nil {
		writeRemoteJobError(w, err, "dissector")
		return
	}

	var result struct {
		OK    bool            `json:"ok"`
		Error string          `json:"error"`
		Nodes json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		writeError(w, http.StatusInternalServerError, "malformed result from browser: "+err.Error())
		return
	}
	if !result.OK {
		writeError(w, http.StatusUnprocessableEntity, result.Error)
		return
	}
	if len(result.Nodes) == 0 {
		writeError(w, http.StatusInternalServerError, "browser reported success with no nodes")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result.Nodes)
}
