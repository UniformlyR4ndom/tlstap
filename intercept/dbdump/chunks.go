package dbdump

import (
	"database/sql"
	"net/http"
)

// chunkTimelineRecord is one raw chunk as returned by listChunksTimeline/
// listChunksTimelineBackward — metadata only, no bytes (see /byte-ranges for those).
type chunkTimelineRecord struct {
	ID        int64
	Direction int
	Stid      int64
	Time      int64
	Offset    int64
	Length    int64
}

func scanChunkTimelineRows(rows *sql.Rows) ([]chunkTimelineRecord, error) {
	defer rows.Close()
	out := []chunkTimelineRecord{}
	for rows.Next() {
		var c chunkTimelineRecord
		if err := rows.Scan(&c.ID, &c.Direction, &c.Stid, &c.Time, &c.Offset, &c.Length); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// listChunksTimeline returns up to n raw chunks for (session, stream) across both
// directions, ordered by stid, with stid >= start. n <= 0 means unlimited. Unlike
// listFramesTimeline (frames.go), chunks.stid is unique per row — never tied, since two
// different chunks (from either direction) never share a stid — so no n+1-lookahead/
// tied-group-boundary logic is needed here: a plain LIMIT is always a safe page boundary.
// Selects LENGTH(data) rather than data itself — this is a metadata-only listing; see
// /byte-ranges for fetching the actual bytes.
func (i *DbDumpInterceptor) listChunksTimeline(session, stream, start int64, n int) ([]chunkTimelineRecord, error) {
	query := `SELECT id, direction, stid, time, offset, LENGTH(data) FROM chunks
	          WHERE session = ? AND stream = ? AND stid >= ? ORDER BY stid`
	args := []any{session, stream, start}
	if n > 0 {
		query += ` LIMIT ?`
		args = append(args, n)
	}
	rows, err := i.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	return scanChunkTimelineRows(rows)
}

// listChunksTimelineBackward is the backward counterpart: chunks with stid < beforeStid,
// walked nearest-first (stid DESC) then re-sorted ascending before returning — same
// convention as listFramesTimelineBackward, minus its tied-group lookahead (doesn't apply
// here, see listChunksTimeline's doc comment). n <= 0 means unlimited.
func (i *DbDumpInterceptor) listChunksTimelineBackward(session, stream, beforeStid int64, n int) ([]chunkTimelineRecord, error) {
	query := `SELECT id, direction, stid, time, offset, LENGTH(data) FROM chunks
	          WHERE session = ? AND stream = ? AND stid < ? ORDER BY stid DESC`
	args := []any{session, stream, beforeStid}
	if n > 0 {
		query += ` LIMIT ?`
		args = append(args, n)
	}
	rows, err := i.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	records, err := scanChunkTimelineRows(rows)
	if err != nil {
		return nil, err
	}
	for l, r := 0, len(records)-1; l < r; l, r = l+1, r-1 {
		records[l], records[r] = records[r], records[l]
	}
	return records, nil
}

// ── REST handler ─────────────────────────────────────────────────────────────────────

type chunkTimelineResponse struct {
	ID        int64 `json:"id"`
	Direction int   `json:"direction"`
	Stid      int64 `json:"stid"`
	Time      int64 `json:"time"`
	Offset    int64 `json:"offset"`
	Length    int64 `json:"length"`
}

func buildChunkTimelineResponse(records []chunkTimelineRecord) []chunkTimelineResponse {
	resp := make([]chunkTimelineResponse, len(records))
	for j, c := range records {
		resp[j] = chunkTimelineResponse{ID: c.ID, Direction: c.Direction, Stid: c.Stid, Time: c.Time, Offset: c.Offset, Length: c.Length}
	}
	return resp
}

// handleChunksTimeline mirrors handleFramesTimeline (frames.go), minus any script key —
// chunks have no such key, just session/stream. Exactly one of start (forward, inclusive)
// or beforeStid (backward, exclusive) must be given, same convention as
// handleFramesTimeline's start/beforeStid. No server-side budget selection — this is a
// plain candidate listing; the frontend applies its own budget (web/frameSegmentsCore.js's
// selectByBudget), same as it already does for frames.
func (i *DbDumpInterceptor) handleChunksTimeline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session    int64  `json:"session"`
		Stream     int64  `json:"stream"`
		Start      *int64 `json:"start"`
		BeforeStid *int64 `json:"beforeStid"`
		N          int    `json:"n"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if (req.Start == nil) == (req.BeforeStid == nil) {
		writeError(w, http.StatusBadRequest, "exactly one of start/beforeStid must be given")
		return
	}

	var records []chunkTimelineRecord
	var err error
	if req.Start != nil {
		records, err = i.listChunksTimeline(req.Session, req.Stream, *req.Start, req.N)
	} else {
		records, err = i.listChunksTimelineBackward(req.Session, req.Stream, *req.BeforeStid, req.N)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, buildChunkTimelineResponse(records))
}
