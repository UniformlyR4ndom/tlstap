// TODO: remove this whole file (and segments_test.go, and the /segments route in
// api.go) — superseded by /byte-ranges (byteranges.go) + /chunks/timeline (chunks.go).
// Nothing in web/ calls this anymore (openSegmentsStream/splitSegments in api.js are
// likewise dead). Left in place pending manual end-to-end browser verification of the
// replacement; see doc/design/hexview-segment-buffer.md's "Migration plan" step 6.

package dbdump

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/websocket"
)

// segmentMeta is the wire shape of one segment in a /segments response — always a raw
// chunk (this endpoint has no frame-awareness at all; frame bytes are derived from these
// by the frontend, see doc/design/hexview-segment-buffer.md).
type segmentMeta struct {
	Stid      int64 `json:"stid"`
	SegmentID int64 `json:"segmentId"`
	Direction int   `json:"direction"`
	Time      int64 `json:"time"`
	Offset    int64 `json:"offset"`
	Length    int64 `json:"length"`
}

func (i *DbDumpInterceptor) handleSegments(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		var req struct {
			Session     int64  `json:"session"`
			Stream      int64  `json:"stream"`
			AfterStid   *int64 `json:"afterStid"`
			BeforeStid  *int64 `json:"beforeStid"`
			MaxSegments int    `json:"maxSegments"`
			MaxBytes    int64  `json:"maxBytes"`
		}
		if err := conn.ReadJSON(&req); err != nil {
			return
		}
		if err := i.streamSegments(conn, req.Session, req.Stream, req.AfterStid, req.BeforeStid, req.MaxSegments, req.MaxBytes); err != nil {
			return
		}
	}
}

// streamSegments answers one /segments request with exactly one text+binary frame pair
// (metadata array, then every included segment's bytes concatenated in the same order) —
// see doc/design/hexview-segment-buffer.md's "Wire protocol: /segments" section for the
// full rationale.
//
// Exactly one of afterStid/beforeStid must be given, selecting scan direction: forward
// walks stid ascending from afterStid (exclusive), backward walks stid descending from
// beforeStid (exclusive) and re-sorts the result ascending before responding, so callers
// never need to special-case direction when consuming the response.
//
// maxSegments/maxBytes are both checked only *between* whole chunks — a single maximal
// chunk can push totalBytes past maxBytes, which is fine (bounded overshoot, same as
// fetchDirectionChunks already accepts for toOffset today) since a chunk's size is
// capped; this endpoint never truncates one. maxSegments <= 0 / maxBytes <= 0 each mean
// unlimited, same convention as listFrames' n.
//
// reachedEnd means "no more segments in the requested direction" — no more after
// afterStid (forward) or none before beforeStid (backward).
func (i *DbDumpInterceptor) streamSegments(conn *websocket.Conn, session, stream int64, afterStid, beforeStid *int64, maxSegments int, maxBytes int64) error {
	if (afterStid == nil) == (beforeStid == nil) {
		return writeSegmentsError(conn, "exactly one of afterStid/beforeStid must be given")
	}

	forward := afterStid != nil
	var (
		query    string
		boundary int64
	)
	if forward {
		boundary = *afterStid
		query = `SELECT stid, id, direction, time, offset, data FROM chunks
		          WHERE session = ? AND stream = ? AND stid > ? ORDER BY stid ASC`
	} else {
		boundary = *beforeStid
		query = `SELECT stid, id, direction, time, offset, data FROM chunks
		          WHERE session = ? AND stream = ? AND stid < ? ORDER BY stid DESC`
	}

	args := []any{session, stream, boundary}
	// +1 lookahead row, purely to detect reachedEnd cheaply below. Always safely covers
	// the byte-cap-triggered peek too: that peek only ever needs the single row
	// immediately after wherever within [1, maxSegments] the byte cap fired.
	if maxSegments > 0 {
		query += ` LIMIT ?`
		args = append(args, maxSegments+1)
	}

	rows, err := i.db.Query(query, args...)
	if err != nil {
		return writeSegmentsError(conn, err.Error())
	}
	defer rows.Close()

	type rawSegment struct {
		meta segmentMeta
		data []byte
	}
	var segments []rawSegment
	var totalBytes int64
	reachedEnd := true

	for rows.Next() {
		if maxSegments > 0 && len(segments) >= maxSegments {
			// Lookahead row beyond what we're allowed to return — its existence alone is
			// the signal; never scanned.
			reachedEnd = false
			break
		}

		var s rawSegment
		if err := rows.Scan(&s.meta.Stid, &s.meta.SegmentID, &s.meta.Direction, &s.meta.Time, &s.meta.Offset, &s.data); err != nil {
			// No frame written yet at this point in the response, but mirrors
			// streamRows' convention of returning a scan error without an error frame —
			// kept consistent rather than special-cased here.
			return err
		}
		s.meta.Length = int64(len(s.data))
		segments = append(segments, s)
		totalBytes += s.meta.Length

		if maxBytes > 0 && totalBytes >= maxBytes {
			if rows.Next() {
				reachedEnd = false
			}
			break
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !forward {
		for l, r := 0, len(segments)-1; l < r; l, r = l+1, r-1 {
			segments[l], segments[r] = segments[r], segments[l]
		}
	}

	metas := make([]segmentMeta, len(segments))
	combined := make([]byte, 0, totalBytes)
	for j, s := range segments {
		metas[j] = s.meta
		combined = append(combined, s.data...)
	}

	resp, _ := json.Marshal(struct {
		Segments   []segmentMeta `json:"segments"`
		ReachedEnd bool          `json:"reachedEnd"`
	}{metas, reachedEnd})
	if err := conn.WriteMessage(websocket.TextMessage, resp); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.BinaryMessage, combined)
}

func writeSegmentsError(conn *websocket.Conn, msg string) error {
	data, _ := json.Marshal(map[string]string{"error": msg})
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return err
	}
	return errors.New(msg)
}
