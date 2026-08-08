package dbdump

import (
	"database/sql"
	"errors"
	"net/http"
)

// frameKey identifies one script's persisted frame index for one (session, stream,
// direction) — the frames/frame_progress tables' shared key prefix.
type frameKey struct {
	Session       int64
	Stream        int64
	Direction     int
	Script        string
	ScriptVersion string
}

// frameTimelineKey identifies one script's persisted frame index for a stream *across
// both directions* — listFramesTimeline's key, deliberately without Direction (every
// other frames/frame_progress access is scoped to one direction; the merged
// cross-direction listing is the one exception).
type frameTimelineKey struct {
	Session       int64
	Stream        int64
	Script        string
	ScriptVersion string
}

// frameRecord is one persisted frame, as returned by listFrames/listFramesTimeline.
// Direction is redundant for listFrames (already fixed by its request's frameKey) but
// shared here anyway rather than a second near-identical type, since it's harmless and
// keeps one scan implementation for both.
type frameRecord struct {
	ID        int64
	Offset    int64
	Length    int64
	Meta      *string // nil if the framer attached no metadata for this frame
	Direction int
	Stid      int64 // inherited from whichever raw chunk this frame completes on
	Time      int64 // ditto — that same completing chunk's own timestamp
}

// frameInput is one newly-computed frame, as submitted to appendFrames — no ID, since
// that's assigned sequentially, continuing from whatever's already stored for key.
type frameInput struct {
	Offset int64
	Length int64
	Meta   *string
	Stid   int64
	Time   int64
}

// errFrameProgressConflict is returned by appendFrames when the caller's
// expectedProcessedOffset no longer matches what's stored — see its doc comment.
var errFrameProgressConflict = errors.New("frame progress has advanced past the expected offset")

// getFrameProgress reports how far framing has progressed for key: the processed
// offset (0 if framing hasn't started for key yet) and the framer's own opaque
// persisted state (nil if none). "Not started" is a normal, common state, not an error.
func (i *DbDumpInterceptor) getFrameProgress(key frameKey) (processedOffset int64, state []byte, err error) {
	row := i.db.QueryRow(
		`SELECT processed_offset, state FROM frame_progress
		 WHERE session = ? AND stream = ? AND direction = ? AND script = ? AND script_version = ?`,
		key.Session, key.Stream, key.Direction, key.Script, key.ScriptVersion,
	)
	err = row.Scan(&processedOffset, &state)
	if err == sql.ErrNoRows {
		return 0, nil, nil
	}
	return processedOffset, state, err
}

// scanFrameRows reads every row of rows into a frameRecord slice, closing rows itself.
// Shared by listFrames and listFramesTimeline, whose SELECTs return the same seven
// columns in the same order.
func scanFrameRows(rows *sql.Rows) ([]frameRecord, error) {
	defer rows.Close()
	frames := []frameRecord{}
	for rows.Next() {
		var f frameRecord
		if err := rows.Scan(&f.ID, &f.Offset, &f.Length, &f.Meta, &f.Direction, &f.Stid, &f.Time); err != nil {
			return nil, err
		}
		frames = append(frames, f)
	}
	return frames, rows.Err()
}

// listFrames returns up to n frames for key with id >= start, ordered by id. n <= 0
// means unlimited.
func (i *DbDumpInterceptor) listFrames(key frameKey, start int64, n int) ([]frameRecord, error) {
	query := `SELECT id, offset, length, meta, direction, stid, time FROM frames
	          WHERE session = ? AND stream = ? AND direction = ? AND script = ? AND script_version = ? AND id >= ?
	          ORDER BY id`
	args := []any{key.Session, key.Stream, key.Direction, key.Script, key.ScriptVersion, start}
	if n > 0 {
		query += ` LIMIT ?`
		args = append(args, n)
	}

	rows, err := i.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	return scanFrameRows(rows)
}

// listFramesTimeline returns frames for key across *both* directions, ordered by
// (stid, id) — id is the tie-break for multiple frames completing on the same
// underlying chunk, which is routine (e.g. one raw read containing several small
// application-layer records at once), not an edge case: cross-direction ties are
// impossible (two different chunks, from either direction, never share a stid), so any
// tie is necessarily same-direction, making the frame's own id a correct and sufficient
// secondary key.
//
// n <= 0 means unlimited. For n > 0, this guarantees the returned page never splits a
// tied-stid group: a caller paginating via "start = last returned row's stid + 1" must
// never have a group straddle two pages, or it would silently skip the rest of that
// group on the next call (an actual loss of frames from view, not just a display
// glitch) — see intercept/dbdump/CLAUDE.md's "Framer scripts" section, "Known
// limitation" note, for the full rationale.
func (i *DbDumpInterceptor) listFramesTimeline(key frameTimelineKey, start int64, n int) ([]frameRecord, error) {
	query := `SELECT id, offset, length, meta, direction, stid, time FROM frames
	          WHERE session = ? AND stream = ? AND script = ? AND script_version = ? AND stid >= ?
	          ORDER BY stid, id`
	args := []any{key.Session, key.Stream, key.Script, key.ScriptVersion, start}
	if n > 0 {
		// Fetch one extra row beyond what was asked, purely to detect whether the
		// requested cut point (row n-1) falls inside a tied-stid group that continues
		// past it.
		query += ` LIMIT ?`
		args = append(args, n+1)
	}

	rows, err := i.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	frames, err := scanFrameRows(rows)
	if err != nil {
		return nil, err
	}

	if n <= 0 || len(frames) <= n {
		return frames, nil
	}

	// len(frames) == n+1: the lookahead row is real. If its stid differs from the
	// cutoff row's, the page already ends cleanly at a group boundary.
	boundaryStid := frames[n-1].Stid
	if frames[n].Stid != boundaryStid {
		return frames[:n], nil
	}

	// The boundary group extends beyond what was fetched. Keep everything strictly
	// before it (already complete, since ordering is stid-then-id), and fetch the
	// *whole* boundary group fresh rather than trying to figure out how much of it
	// frames[:n+1] already covers.
	before := make([]frameRecord, 0, n)
	for _, f := range frames {
		if f.Stid < boundaryStid {
			before = append(before, f)
		}
	}
	groupRows, err := i.db.Query(
		`SELECT id, offset, length, meta, direction, stid, time FROM frames
		 WHERE session = ? AND stream = ? AND script = ? AND script_version = ? AND stid = ?
		 ORDER BY id`,
		key.Session, key.Stream, key.Script, key.ScriptVersion, boundaryStid,
	)
	if err != nil {
		return nil, err
	}
	group, err := scanFrameRows(groupRows)
	if err != nil {
		return nil, err
	}
	return append(before, group...), nil
}

// listFramesTimelineBackward is listFramesTimeline's backward counterpart, mirroring
// /segments' beforeStid semantics (see doc/design/hexview-segment-buffer.md and
// intercept/dbdump/CLAUDE.md's "WebSocket /segments protocol"): frames with
// stid < beforeStid (exclusive), walked nearest-first (stid DESC, id DESC — the reverse
// of listFramesTimeline's tie-break, so a tied group's raw query order is still a
// contiguous run), always returned in the same ascending (stid, id) order
// listFramesTimeline uses, so a caller never special-cases direction when consuming the
// result. Same tie-group-boundary-safety guarantee as the forward version, mirrored for
// the reverse walk: never returns a page that splits a tied-stid group. n <= 0 means
// unlimited.
func (i *DbDumpInterceptor) listFramesTimelineBackward(key frameTimelineKey, beforeStid int64, n int) ([]frameRecord, error) {
	query := `SELECT id, offset, length, meta, direction, stid, time FROM frames
	          WHERE session = ? AND stream = ? AND script = ? AND script_version = ? AND stid < ?
	          ORDER BY stid DESC, id DESC`
	args := []any{key.Session, key.Stream, key.Script, key.ScriptVersion, beforeStid}
	if n > 0 {
		query += ` LIMIT ?`
		args = append(args, n+1)
	}

	rows, err := i.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	frames, err := scanFrameRows(rows)
	if err != nil {
		return nil, err
	}

	if n > 0 && len(frames) > n {
		// len(frames) == n+1: the lookahead row is real.
		boundaryStid := frames[n-1].Stid
		if frames[n].Stid == boundaryStid {
			// The boundary group extends beyond what was fetched. before holds
			// everything strictly closer to beforeStid (larger stid, already complete,
			// still in the query's own stid-DESC/id-DESC order) — reversed in place to
			// ascending below. The group itself is re-fetched ascending by id directly,
			// same as the forward version, rather than trying to figure out how much of
			// it frames[n-1:] already covers.
			before := make([]frameRecord, 0, n)
			for _, f := range frames {
				if f.Stid > boundaryStid {
					before = append(before, f)
				}
			}
			for l, r := 0, len(before)-1; l < r; l, r = l+1, r-1 {
				before[l], before[r] = before[r], before[l]
			}
			groupRows, err := i.db.Query(
				`SELECT id, offset, length, meta, direction, stid, time FROM frames
				 WHERE session = ? AND stream = ? AND script = ? AND script_version = ? AND stid = ?
				 ORDER BY id`,
				key.Session, key.Stream, key.Script, key.ScriptVersion, boundaryStid,
			)
			if err != nil {
				return nil, err
			}
			group, err := scanFrameRows(groupRows)
			if err != nil {
				return nil, err
			}
			// group has the smallest stid of everything returned, so it leads.
			return append(group, before...), nil
		}
		frames = frames[:n]
	}

	// No boundary tie (or n <= 0, or fewer rows than requested exist at all): frames is
	// uniformly in stid-DESC/id-DESC order throughout, so a single full reversal alone
	// gives the desired ascending (stid, id) order.
	for l, r := 0, len(frames)-1; l < r; l, r = l+1, r-1 {
		frames[l], frames[r] = frames[r], frames[l]
	}
	return frames, nil
}

// appendFrames extends key's persisted frame index by one batch, computed by a
// browser-run framer script: newFrames are inserted with sequential ids continuing from
// whatever's already stored, and processed_offset/state are advanced to
// newProcessedOffset/newState — all in one transaction. expectedProcessedOffset must
// match the currently-stored processed_offset (0 if framing hasn't started for key yet);
// a mismatch returns errFrameProgressConflict without writing anything. There is
// deliberately no retry/CAS-defense beyond that single check: the UI enforces one writer
// per key, so a mismatch here always indicates a client bug, not a real race to resolve
// gracefully.
func (i *DbDumpInterceptor) appendFrames(key frameKey, expectedProcessedOffset int64, newFrames []frameInput, newProcessedOffset int64, newState []byte) error {
	tx, err := i.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once Commit succeeds

	var current int64
	err = tx.QueryRow(
		`SELECT processed_offset FROM frame_progress
		 WHERE session = ? AND stream = ? AND direction = ? AND script = ? AND script_version = ?`,
		key.Session, key.Stream, key.Direction, key.Script, key.ScriptVersion,
	).Scan(&current)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if current != expectedProcessedOffset {
		return errFrameProgressConflict
	}

	var nextID int64
	if err := tx.QueryRow(
		`SELECT COALESCE(MAX(id) + 1, 0) FROM frames
		 WHERE session = ? AND stream = ? AND direction = ? AND script = ? AND script_version = ?`,
		key.Session, key.Stream, key.Direction, key.Script, key.ScriptVersion,
	).Scan(&nextID); err != nil {
		return err
	}

	stmt, err := tx.Prepare(
		`INSERT INTO frames (session, stream, direction, script, script_version, id, offset, length, meta, stid, time)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range newFrames {
		if _, err := stmt.Exec(key.Session, key.Stream, key.Direction, key.Script, key.ScriptVersion, nextID, f.Offset, f.Length, f.Meta, f.Stid, f.Time); err != nil {
			return err
		}
		nextID++
	}

	if _, err := tx.Exec(
		`INSERT INTO frame_progress (session, stream, direction, script, script_version, processed_offset, state)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (session, stream, direction, script, script_version)
		 DO UPDATE SET processed_offset = excluded.processed_offset, state = excluded.state`,
		key.Session, key.Stream, key.Direction, key.Script, key.ScriptVersion, newProcessedOffset, newState,
	); err != nil {
		return err
	}

	return tx.Commit()
}

// purgeOtherFrameVersions deletes every persisted frame/progress row for script whose
// script_version isn't keepVersion, across every session/stream/direction — called when
// a script's content changes, since its previous version's persisted frame data can
// never be reached again (script_version is keyed by a hash of the content, computed
// client-side).
func (i *DbDumpInterceptor) purgeOtherFrameVersions(script, keepVersion string) error {
	tx, err := i.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM frames WHERE script = ? AND script_version <> ?`, script, keepVersion); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM frame_progress WHERE script = ? AND script_version <> ?`, script, keepVersion); err != nil {
		return err
	}
	return tx.Commit()
}

// purgeAllFrameVersions deletes every persisted frame/progress row for script,
// regardless of version — called when the script itself is deleted.
func (i *DbDumpInterceptor) purgeAllFrameVersions(script string) error {
	tx, err := i.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM frames WHERE script = ?`, script); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM frame_progress WHERE script = ?`, script); err != nil {
		return err
	}
	return tx.Commit()
}

// ── REST handlers ───────────────────────────────────────────────────────────────────

// frameKeyRequest is the JSON shape every frames/frame-progress request shares as its
// key prefix; handlers needing extra fields embed it (encoding/json promotes an
// embedded struct's fields into the same JSON object).
type frameKeyRequest struct {
	Session       int64  `json:"session"`
	Stream        int64  `json:"stream"`
	Direction     int    `json:"direction"`
	Script        string `json:"script"`
	ScriptVersion string `json:"script_version"`
}

func (r frameKeyRequest) key() frameKey {
	return frameKey{
		Session: r.Session, Stream: r.Stream, Direction: r.Direction,
		Script: r.Script, ScriptVersion: r.ScriptVersion,
	}
}

// frameTimelineKeyRequest is frameKeyRequest without Direction — listFramesTimeline's
// request shape, since a merged cross-direction listing has no single direction to key
// on.
type frameTimelineKeyRequest struct {
	Session       int64  `json:"session"`
	Stream        int64  `json:"stream"`
	Script        string `json:"script"`
	ScriptVersion string `json:"script_version"`
}

func (r frameTimelineKeyRequest) key() frameTimelineKey {
	return frameTimelineKey{Session: r.Session, Stream: r.Stream, Script: r.Script, ScriptVersion: r.ScriptVersion}
}

// frameResponse is the wire shape of one frame, shared by /frames and /frames/timeline
// (identical fields; /frames' direction is technically redundant with its own request,
// but including it uniformly is harmless and keeps one response builder for both).
type frameResponse struct {
	ID        int64   `json:"id"`
	Offset    int64   `json:"offset"`
	Length    int64   `json:"length"`
	Meta      *string `json:"meta"`
	Direction int     `json:"direction"`
	Stid      int64   `json:"stid"`
	Time      int64   `json:"time"`
}

func buildFrameResponse(frames []frameRecord) []frameResponse {
	resp := make([]frameResponse, len(frames))
	for j, f := range frames {
		resp[j] = frameResponse{ID: f.ID, Offset: f.Offset, Length: f.Length, Meta: f.Meta, Direction: f.Direction, Stid: f.Stid, Time: f.Time}
	}
	return resp
}

func (i *DbDumpInterceptor) handleFrameProgress(w http.ResponseWriter, r *http.Request) {
	var req frameKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	offset, state, err := i.getFrameProgress(req.key())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, struct {
		ProcessedOffset int64  `json:"processed_offset"`
		State           []byte `json:"state"`
	}{ProcessedOffset: offset, State: state})
}

func (i *DbDumpInterceptor) handleFramesList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		frameKeyRequest
		Start int64 `json:"start"`
		N     int   `json:"n"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	frames, err := i.listFrames(req.key(), req.Start, req.N)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, buildFrameResponse(frames))
}

// handleFramesTimeline is /frames' cross-direction counterpart: same paged-listing
// shape, but keyed without a direction and ordered by (stid, id) instead of id — see
// listFramesTimeline's doc comment for why both matter. Exactly one of start (forward,
// inclusive — the original, unchanged shape) or beforeStid (backward, exclusive —
// mirrors /segments' own beforeStid) must be given; Start is a pointer purely so its
// absence is distinguishable from an explicit 0, which is backward-compatible on the
// wire since every existing caller already sends start explicitly.
func (i *DbDumpInterceptor) handleFramesTimeline(w http.ResponseWriter, r *http.Request) {
	var req struct {
		frameTimelineKeyRequest
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

	var frames []frameRecord
	var err error
	if req.Start != nil {
		frames, err = i.listFramesTimeline(req.key(), *req.Start, req.N)
	} else {
		frames, err = i.listFramesTimelineBackward(req.key(), *req.BeforeStid, req.N)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, buildFrameResponse(frames))
}

func (i *DbDumpInterceptor) handleFramesAppend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		frameKeyRequest
		ExpectedProcessedOffset int64 `json:"expected_processed_offset"`
		NewFrames               []struct {
			Offset int64   `json:"offset"`
			Length int64   `json:"length"`
			Meta   *string `json:"meta"`
			Stid   int64   `json:"stid"`
			Time   int64   `json:"time"`
		} `json:"new_frames"`
		NewProcessedOffset int64  `json:"new_processed_offset"`
		NewState           []byte `json:"new_state"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	inputs := make([]frameInput, len(req.NewFrames))
	for j, f := range req.NewFrames {
		inputs[j] = frameInput{Offset: f.Offset, Length: f.Length, Meta: f.Meta, Stid: f.Stid, Time: f.Time}
	}

	err := i.appendFrames(req.key(), req.ExpectedProcessedOffset, inputs, req.NewProcessedOffset, req.NewState)
	if err == errFrameProgressConflict {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
