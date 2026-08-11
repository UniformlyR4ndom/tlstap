package dbdump

import (
	"database/sql"
	"errors"
	"net/http"
)

// frameKey identifies one script's persisted frame index for one (session, stream,
// direction) — the frames table's per-direction access key (listFrames, and the
// per-direction Direction carried on each frameInput appendFrames writes).
type frameKey struct {
	Session       int64
	Stream        int64
	Direction     int
	Script        string
	ScriptVersion string
}

// frameTimelineKey identifies one script's persisted frame index for a stream *across
// both directions* — listFramesTimeline/listFramesBySeq's key, and frame_progress's own
// key (see doc/design/framer-cross-direction-correlation.md: a combined-mode script run
// tracks both directions' progress/state/closed at once, so frame_progress has no
// Direction of its own to begin with).
type frameTimelineKey struct {
	Session       int64
	Stream        int64
	Script        string
	ScriptVersion string
}

// frameRecord is one persisted frame, as returned by listFrames/listFramesTimeline/
// listFramesBySeq. Direction is redundant for listFrames (already fixed by its request's
// frameKey) but shared here anyway rather than a second near-identical type, since it's
// harmless and keeps one scan implementation for all three.
type frameRecord struct {
	ID        int64
	Offset    int64
	Length    int64
	Meta      *string // nil if the framer attached no metadata for this frame
	Direction int
	Stid      int64 // inherited from whichever raw chunk this frame completes on
	Time      int64 // ditto — that same completing chunk's own timestamp
	Seq       int64 // emission order across both directions — see listFramesBySeq
}

// frameInput is one newly-computed frame, as submitted to appendFrames — no ID or Seq,
// since both are assigned sequentially server-side (ID continuing per-direction,
// Seq per-key across both directions) from whatever's already stored. Direction is
// carried per-frame (rather than fixed by the request's key, the way frameKey's used to
// fix it) since one combined-mode batch can mix frames from either direction.
type frameInput struct {
	Direction int
	Offset    int64
	Length    int64
	Meta      *string
	Stid      int64
	Time      int64
}

// frameProgress is frame_progress's row shape for one key: both directions' processed
// offset and connection-close flag, plus the one shared framer state. Used both to
// report current progress (getFrameProgress) and, in appendFrames, as both the
// expected-current-value CAS check (State is ignored there — only the offsets are
// compared) and the new value to write.
type frameProgress struct {
	ProcessedOffsetC2S int64
	ProcessedOffsetS2C int64
	State              []byte
	ClosedC2S          bool
	ClosedS2C          bool
}

// errFrameProgressConflict is returned by appendFrames when the caller's expected
// offsets no longer match what's stored — see its doc comment.
var errFrameProgressConflict = errors.New("frame progress has advanced past the expected offset")

// getFrameProgress reports how far a combined-mode framer run has progressed for key:
// both directions' processed offset (0 if framing hasn't started for key yet), the
// framer's own opaque persisted state (nil if none), and whether each direction's
// connection-close signal has already been delivered to (and persisted by) the script —
// see catchUpFramer in web/framerRun.js. "Not started" is a normal, common state, not an
// error.
func (i *DbDumpInterceptor) getFrameProgress(key frameTimelineKey) (frameProgress, error) {
	row := i.db.QueryRow(
		`SELECT processed_offset_c2s, processed_offset_s2c, state, closed_c2s, closed_s2c FROM frame_progress
		 WHERE session = ? AND stream = ? AND script = ? AND script_version = ?`,
		key.Session, key.Stream, key.Script, key.ScriptVersion,
	)
	var p frameProgress
	err := row.Scan(&p.ProcessedOffsetC2S, &p.ProcessedOffsetS2C, &p.State, &p.ClosedC2S, &p.ClosedS2C)
	if err == sql.ErrNoRows {
		return frameProgress{}, nil
	}
	return p, err
}

// scanFrameRows reads every row of rows into a frameRecord slice, closing rows itself.
// Shared by listFrames/listFramesTimeline/listFramesBySeq (and their backward
// counterparts), whose SELECTs all return the same eight columns in the same order.
func scanFrameRows(rows *sql.Rows) ([]frameRecord, error) {
	defer rows.Close()
	frames := []frameRecord{}
	for rows.Next() {
		var f frameRecord
		if err := rows.Scan(&f.ID, &f.Offset, &f.Length, &f.Meta, &f.Direction, &f.Stid, &f.Time, &f.Seq); err != nil {
			return nil, err
		}
		frames = append(frames, f)
	}
	return frames, rows.Err()
}

// listFrames returns up to n frames for key with id >= start, ordered by id. n <= 0
// means unlimited.
func (i *DbDumpInterceptor) listFrames(key frameKey, start int64, n int) ([]frameRecord, error) {
	query := `SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
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
	query := `SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
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
		`SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
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
	query := `SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
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
				`SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
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

// listFramesBySeq returns frames for key across both directions, ordered by seq — the
// server-assigned emission order (see appendFrames), reflecting whatever order a
// combined-mode script actually returned each frame in, which need not match stid order
// (a script may hold a fully-parsed frame in its own state and return it later, once
// e.g. a correlated frame from the other direction is also ready — see
// doc/design/framer-cross-direction-correlation.md). Unlike listFramesTimeline, seq is
// unique per key by construction (a bare per-key counter, never shared across two
// frames), so no tied-group pagination safety net is needed here: a plain LIMIT is
// always a safe page boundary. n <= 0 means unlimited. Not yet surfaced in any UI.
func (i *DbDumpInterceptor) listFramesBySeq(key frameTimelineKey, start int64, n int) ([]frameRecord, error) {
	query := `SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
	          WHERE session = ? AND stream = ? AND script = ? AND script_version = ? AND seq >= ?
	          ORDER BY seq`
	args := []any{key.Session, key.Stream, key.Script, key.ScriptVersion, start}
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

// listFramesBySeqBackward is listFramesBySeq's backward counterpart: frames with
// seq < beforeSeq (exclusive), always returned in ascending seq order like the forward
// version. n <= 0 means unlimited.
func (i *DbDumpInterceptor) listFramesBySeqBackward(key frameTimelineKey, beforeSeq int64, n int) ([]frameRecord, error) {
	query := `SELECT id, offset, length, meta, direction, stid, time, seq FROM frames
	          WHERE session = ? AND stream = ? AND script = ? AND script_version = ? AND seq < ?
	          ORDER BY seq DESC`
	args := []any{key.Session, key.Stream, key.Script, key.ScriptVersion, beforeSeq}
	if n > 0 {
		query += ` LIMIT ?`
		args = append(args, n)
	}

	rows, err := i.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	frames, err := scanFrameRows(rows)
	if err != nil {
		return nil, err
	}
	for l, r := 0, len(frames)-1; l < r; l, r = l+1, r-1 {
		frames[l], frames[r] = frames[r], frames[l]
	}
	return frames, nil
}

// appendFrames extends key's persisted frame index by one batch, computed by a
// browser-run combined-mode framer script: newFrames (each carrying its own Direction)
// are inserted with sequential per-direction ids continuing from whatever's already
// stored for that direction, and a sequential per-key seq continuing from whatever's
// already stored for key — assigned in newFrames' own array order, i.e. the order the
// script actually returned them in, spanning both directions (see listFramesBySeq).
// frame_progress is then advanced from expected to newProgress — all in one transaction.
// expected's ProcessedOffsetC2S/S2C must match what's currently stored (0 if framing
// hasn't started for key yet); a mismatch returns errFrameProgressConflict without
// writing anything. There is deliberately no retry/CAS-defense beyond that check: the UI
// enforces one writer per key, so a mismatch here always indicates a client bug, not a
// real race to resolve gracefully.
//
// newProgress.ClosedC2S/S2C are normally false — ordinary batches processing real
// backlog never set them. catchUpFramer (web/framerRun.js) passes true in exactly one
// dedicated trailing call, once every direction's synthetic connection-close chunk has
// itself already been persisted via a prior (closed=false) call to this same function.
func (i *DbDumpInterceptor) appendFrames(key frameTimelineKey, expected frameProgress, newFrames []frameInput, newProgress frameProgress) error {
	tx, err := i.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once Commit succeeds

	var currentC2S, currentS2C int64
	err = tx.QueryRow(
		`SELECT processed_offset_c2s, processed_offset_s2c FROM frame_progress
		 WHERE session = ? AND stream = ? AND script = ? AND script_version = ?`,
		key.Session, key.Stream, key.Script, key.ScriptVersion,
	).Scan(&currentC2S, &currentS2C)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if currentC2S != expected.ProcessedOffsetC2S || currentS2C != expected.ProcessedOffsetS2C {
		return errFrameProgressConflict
	}

	var nextSeq int64
	if err := tx.QueryRow(
		`SELECT COALESCE(MAX(seq) + 1, 0) FROM frames
		 WHERE session = ? AND stream = ? AND script = ? AND script_version = ?`,
		key.Session, key.Stream, key.Script, key.ScriptVersion,
	).Scan(&nextSeq); err != nil {
		return err
	}

	// nextID is computed lazily, per direction, the first time that direction actually
	// appears in newFrames — most batches only ever touch one direction.
	nextID := map[int]int64{}

	stmt, err := tx.Prepare(
		`INSERT INTO frames (session, stream, direction, script, script_version, id, offset, length, meta, stid, time, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, f := range newFrames {
		id, ok := nextID[f.Direction]
		if !ok {
			if err := tx.QueryRow(
				`SELECT COALESCE(MAX(id) + 1, 0) FROM frames
				 WHERE session = ? AND stream = ? AND direction = ? AND script = ? AND script_version = ?`,
				key.Session, key.Stream, f.Direction, key.Script, key.ScriptVersion,
			).Scan(&id); err != nil {
				return err
			}
		}
		if _, err := stmt.Exec(key.Session, key.Stream, f.Direction, key.Script, key.ScriptVersion, id, f.Offset, f.Length, f.Meta, f.Stid, f.Time, nextSeq); err != nil {
			return err
		}
		nextID[f.Direction] = id + 1
		nextSeq++
	}

	if _, err := tx.Exec(
		`INSERT INTO frame_progress (session, stream, script, script_version, processed_offset_c2s, processed_offset_s2c, state, closed_c2s, closed_s2c)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (session, stream, script, script_version)
		 DO UPDATE SET processed_offset_c2s = excluded.processed_offset_c2s, processed_offset_s2c = excluded.processed_offset_s2c,
		               state = excluded.state, closed_c2s = excluded.closed_c2s, closed_s2c = excluded.closed_s2c`,
		key.Session, key.Stream, key.Script, key.ScriptVersion,
		newProgress.ProcessedOffsetC2S, newProgress.ProcessedOffsetS2C, newProgress.State, newProgress.ClosedC2S, newProgress.ClosedS2C,
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

// clearStreamFrames enforces "at most one framing view per stream": deletes every
// persisted frame/progress row for keep's (session, stream) whose (script,
// script_version) isn't keep's own, across every direction. Unlike
// purgeOtherFrameVersions/purgeAllFrameVersions above (which purge one script by name,
// globally, only reachable from a script PUT/DELETE — so never triggered by a script
// edited directly on disk under scripts-dir, bypassing the REST API), this is meant to
// be called on every framing run, keyed by whatever's about to run — a rerun of the same
// (script, script_version) already active for this stream is then a no-op (its
// frame_progress survives, so catchUpFramer resumes instead of reprocessing); switching
// to any other script or a new version purges the old one first.
func (i *DbDumpInterceptor) clearStreamFrames(keep frameTimelineKey) error {
	tx, err := i.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`DELETE FROM frames WHERE session = ? AND stream = ? AND NOT (script = ? AND script_version = ?)`,
		keep.Session, keep.Stream, keep.Script, keep.ScriptVersion,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`DELETE FROM frame_progress WHERE session = ? AND stream = ? AND NOT (script = ? AND script_version = ?)`,
		keep.Session, keep.Stream, keep.Script, keep.ScriptVersion,
	); err != nil {
		return err
	}
	return tx.Commit()
}

// ── REST handlers ───────────────────────────────────────────────────────────────────

// frameKeyRequest is /frames' request shape — the one remaining per-direction access
// pattern, since the frames table itself (unlike frame_progress) is still scoped to one
// direction per row.
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

// frameTimelineKeyRequest is frameKeyRequest without Direction — shared by every
// cross-direction request shape: /frame-progress, /frames/timeline, /frames/by-seq,
// /frames/append, /frames/clear.
type frameTimelineKeyRequest struct {
	Session       int64  `json:"session"`
	Stream        int64  `json:"stream"`
	Script        string `json:"script"`
	ScriptVersion string `json:"script_version"`
}

func (r frameTimelineKeyRequest) key() frameTimelineKey {
	return frameTimelineKey{Session: r.Session, Stream: r.Stream, Script: r.Script, ScriptVersion: r.ScriptVersion}
}

// frameResponse is the wire shape of one frame, shared by /frames, /frames/timeline, and
// /frames/by-seq (identical fields; /frames' direction is technically redundant with its
// own request, but including it uniformly is harmless and keeps one response builder for
// all three).
type frameResponse struct {
	ID        int64   `json:"id"`
	Offset    int64   `json:"offset"`
	Length    int64   `json:"length"`
	Meta      *string `json:"meta"`
	Direction int     `json:"direction"`
	Stid      int64   `json:"stid"`
	Time      int64   `json:"time"`
	Seq       int64   `json:"seq"`
}

func buildFrameResponse(frames []frameRecord) []frameResponse {
	resp := make([]frameResponse, len(frames))
	for j, f := range frames {
		resp[j] = frameResponse{ID: f.ID, Offset: f.Offset, Length: f.Length, Meta: f.Meta, Direction: f.Direction, Stid: f.Stid, Time: f.Time, Seq: f.Seq}
	}
	return resp
}

func (i *DbDumpInterceptor) handleFrameProgress(w http.ResponseWriter, r *http.Request) {
	var req frameTimelineKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	p, err := i.getFrameProgress(req.key())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, struct {
		ProcessedOffsetC2S int64  `json:"processed_offset_c2s"`
		ProcessedOffsetS2C int64  `json:"processed_offset_s2c"`
		State              []byte `json:"state"`
		ClosedC2S          bool   `json:"closed_c2s"`
		ClosedS2C          bool   `json:"closed_s2c"`
	}{
		ProcessedOffsetC2S: p.ProcessedOffsetC2S, ProcessedOffsetS2C: p.ProcessedOffsetS2C,
		State: p.State, ClosedC2S: p.ClosedC2S, ClosedS2C: p.ClosedS2C,
	})
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

// handleFramesBySeq is /frames/timeline's seq-ordered sibling — see listFramesBySeq.
// Exactly one of start (forward, inclusive) or beforeSeq (backward, exclusive) must be
// given, same convention as handleFramesTimeline's start/beforeStid.
func (i *DbDumpInterceptor) handleFramesBySeq(w http.ResponseWriter, r *http.Request) {
	var req struct {
		frameTimelineKeyRequest
		Start     *int64 `json:"start"`
		BeforeSeq *int64 `json:"beforeSeq"`
		N         int    `json:"n"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if (req.Start == nil) == (req.BeforeSeq == nil) {
		writeError(w, http.StatusBadRequest, "exactly one of start/beforeSeq must be given")
		return
	}

	var frames []frameRecord
	var err error
	if req.Start != nil {
		frames, err = i.listFramesBySeq(req.key(), *req.Start, req.N)
	} else {
		frames, err = i.listFramesBySeqBackward(req.key(), *req.BeforeSeq, req.N)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, buildFrameResponse(frames))
}

func (i *DbDumpInterceptor) handleFramesAppend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		frameTimelineKeyRequest
		ExpectedProcessedOffsetC2S int64 `json:"expected_processed_offset_c2s"`
		ExpectedProcessedOffsetS2C int64 `json:"expected_processed_offset_s2c"`
		NewFrames                  []struct {
			Direction int     `json:"direction"`
			Offset    int64   `json:"offset"`
			Length    int64   `json:"length"`
			Meta      *string `json:"meta"`
			Stid      int64   `json:"stid"`
			Time      int64   `json:"time"`
		} `json:"new_frames"`
		NewProcessedOffsetC2S int64  `json:"new_processed_offset_c2s"`
		NewProcessedOffsetS2C int64  `json:"new_processed_offset_s2c"`
		NewState              []byte `json:"new_state"`
		ClosedC2S             bool   `json:"closed_c2s"`
		ClosedS2C             bool   `json:"closed_s2c"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	inputs := make([]frameInput, len(req.NewFrames))
	for j, f := range req.NewFrames {
		inputs[j] = frameInput{Direction: f.Direction, Offset: f.Offset, Length: f.Length, Meta: f.Meta, Stid: f.Stid, Time: f.Time}
	}

	err := i.appendFrames(req.key(),
		frameProgress{ProcessedOffsetC2S: req.ExpectedProcessedOffsetC2S, ProcessedOffsetS2C: req.ExpectedProcessedOffsetS2C},
		inputs,
		frameProgress{
			ProcessedOffsetC2S: req.NewProcessedOffsetC2S, ProcessedOffsetS2C: req.NewProcessedOffsetS2C,
			State: req.NewState, ClosedC2S: req.ClosedC2S, ClosedS2C: req.ClosedS2C,
		},
	)
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

func (i *DbDumpInterceptor) handleFramesClear(w http.ResponseWriter, r *http.Request) {
	var req frameTimelineKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := i.clearStreamFrames(req.key()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
