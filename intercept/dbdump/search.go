package dbdump

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"regexp"
)

const searchBatchSize = 1 << 20 // 1 MB

type searchTextRequest struct {
	Session         int64  `json:"session"`
	Stream          *int64 `json:"stream"`
	Start           *int64 `json:"start"`
	End             *int64 `json:"end"`
	Pattern         string `json:"pattern"`
	PatternEncoding string `json:"pattern_encoding"` // "" | "text" = raw UTF-8; "base64" = base64-encoded bytes; "regex" = Go regex
	Direction       *int   `json:"direction"`
	Contiguous      bool   `json:"contiguous"`
}

type searchMatch struct {
	Stream    int64 `json:"stream"`
	Direction int   `json:"direction"`
	Offset    int64 `json:"offset"`
	Stid      int64 `json:"stid"`
}

// matchFinder finds all matches in data and returns their [start, end) byte ranges.
// For literal search consecutive overlapping matches are returned; for regex the
// standard non-overlapping semantics of FindAllIndex apply.
type matchFinder func(data []byte) [][]int

func literalFinder(pattern []byte) matchFinder {
	return func(data []byte) [][]int {
		var out [][]int
		pos := 0
		for {
			idx := bytes.Index(data[pos:], pattern)
			if idx < 0 {
				break
			}
			abs := pos + idx
			out = append(out, []int{abs, abs + len(pattern)})
			pos = abs + 1
		}
		return out
	}
}

func regexFinder(re *regexp.Regexp) matchFinder {
	return func(data []byte) [][]int { return re.FindAllIndex(data, -1) }
}

// chunkPos records where a chunk's data starts within the batch buffer.
type chunkPos struct {
	bufStart int
	stid     int64
}

// findStidForPos returns the stid of the chunk that owns batchPos (an offset
// within batchBuf, not counting any prepended overlap). The posns slice must be
// sorted by bufStart ascending.
func findStidForPos(posns []chunkPos, batchPos int) int64 {
	for j := len(posns) - 1; j >= 0; j-- {
		if posns[j].bufStart <= batchPos {
			return posns[j].stid
		}
	}
	return posns[0].stid
}

func (i *DbDumpInterceptor) handleSearchText(w http.ResponseWriter, r *http.Request) {
	var req searchTextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Pattern == "" {
		writeError(w, http.StatusBadRequest, "pattern is required")
		return
	}

	start := int64(0)
	if req.Start != nil {
		start = *req.Start
	}
	end := int64(math.MaxInt64)
	if req.End != nil {
		if *req.End <= start {
			writeError(w, http.StatusBadRequest, "end must be greater than start")
			return
		}
		end = *req.End
	}

	var streamIDs []int64
	if req.Stream != nil {
		streamIDs = []int64{*req.Stream}
	} else {
		rows, err := i.db.Query(`SELECT id FROM stream WHERE session = ? ORDER BY id`, req.Session)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			streamIDs = append(streamIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	var dirs []int
	if req.Direction != nil {
		dirs = []int{*req.Direction}
	} else {
		dirs = []int{0, 1}
	}

	var (
		find   matchFinder
		ovlLen int // overlap bytes between batches in contiguous mode
	)
	switch req.PatternEncoding {
	case "", "text":
		p := []byte(req.Pattern)
		find = literalFinder(p)
		ovlLen = len(p) - 1
	case "base64":
		p, err := base64.StdEncoding.DecodeString(req.Pattern)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid base64 pattern: "+err.Error())
			return
		}
		find = literalFinder(p)
		ovlLen = len(p) - 1
	case "regex":
		re, err := regexp.Compile(req.Pattern)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid regex: "+err.Error())
			return
		}
		find = regexFinder(re)
		ovlLen = 0 // minimum match length is unknown; no cross-batch overlap
	default:
		writeError(w, http.StatusBadRequest, "unknown pattern_encoding: "+req.PatternEncoding)
		return
	}

	matches := []searchMatch{}
	for _, sid := range streamIDs {
		for _, dir := range dirs {
			ms, err := i.searchTextInDirection(req.Session, sid, dir, find, ovlLen, start, end, req.Contiguous)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			matches = append(matches, ms...)
		}
	}
	writeJSON(w, matches)
}

func (i *DbDumpInterceptor) searchTextInDirection(session, stream int64, direction int, find matchFinder, ovlLen int, start, end int64, contiguous bool) ([]searchMatch, error) {
	if contiguous {
		return i.searchContiguous(session, stream, direction, find, ovlLen, start, end)
	}
	return i.searchNonContiguous(session, stream, direction, find, start, end)
}

// searchNonContiguous searches each chunk independently. Cross-chunk patterns
// are never matched.
func (i *DbDumpInterceptor) searchNonContiguous(session, stream int64, direction int, find matchFinder, start, end int64) ([]searchMatch, error) {
	q := `SELECT stid, offset, data FROM chunks
	      WHERE session = ? AND stream = ? AND direction = ?
	        AND offset + length(data) > ?`
	args := []any{session, stream, direction, start}
	if end < math.MaxInt64 {
		q += ` AND offset < ?`
		args = append(args, end)
	}
	q += ` ORDER BY id`

	rows, err := i.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var matches []searchMatch
	for rows.Next() {
		var stid, chunkOff int64
		var data []byte
		if err := rows.Scan(&stid, &chunkOff, &data); err != nil {
			return nil, err
		}

		// Clip the search window to [start, end) within this chunk.
		lo := int64(0)
		if start > chunkOff {
			lo = start - chunkOff
		}
		hi := int64(len(data))
		if end < math.MaxInt64 {
			if e := end - chunkOff; e < hi {
				hi = e
			}
		}
		if lo >= hi {
			continue
		}

		for _, m := range find(data[lo:hi]) {
			matches = append(matches, searchMatch{
				Stream:    stream,
				Direction: direction,
				Offset:    chunkOff + lo + int64(m[0]),
				Stid:      stid,
			})
		}
	}
	return matches, rows.Err()
}

// searchContiguous accumulates chunks into a 1 MB batch buffer so that the
// matcher operates on a large contiguous slice, and patterns split across chunk
// boundaries are still found. An overlap of ovlLen bytes is carried from the
// end of each batch into the next to catch cross-batch splits. For regex,
// ovlLen is 0 (minimum match length is unknown) so patterns spanning a 1 MB
// batch boundary will not be found.
func (i *DbDumpInterceptor) searchContiguous(session, stream int64, direction int, find matchFinder, ovlLen int, start, end int64) ([]searchMatch, error) {
	// Extend the left SQL bound so we can load the chunk that contributes the
	// overlap bytes preceding 'start'.
	leftBound := start
	if int64(ovlLen) <= leftBound {
		leftBound -= int64(ovlLen)
	} else {
		leftBound = 0
	}

	q := `SELECT stid, offset, data FROM chunks
	      WHERE session = ? AND stream = ? AND direction = ?
	        AND offset + length(data) > ?`
	args := []any{session, stream, direction, leftBound}
	if end < math.MaxInt64 {
		q += ` AND offset < ?`
		args = append(args, end)
	}
	q += ` ORDER BY id`

	rows, err := i.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		matches      []searchMatch
		batchBuf     = make([]byte, 0, searchBatchSize)
		combined     = make([]byte, 0, searchBatchSize+ovlLen) // reused across flushes
		posns        []chunkPos
		batchBase    int64
		batchBaseSet bool
		overlap      []byte // copied tail of the previous batch
		overlapBase  int64  // global byte offset of overlap[0]
		prevLastStid int64  // stid of the chunk that contributed the overlap bytes
	)

	flush := func() {
		if len(batchBuf) == 0 {
			return
		}

		var combinedBase int64
		if len(overlap) > 0 {
			combinedBase = overlapBase
		} else {
			combinedBase = batchBase
		}

		combined = combined[:0]
		combined = append(combined, overlap...)
		combined = append(combined, batchBuf...)

		// Clip search window to [start, end) expressed as indices into combined.
		lo := 0
		if start > combinedBase {
			l := int(start - combinedBase)
			if l > len(combined) {
				l = len(combined)
			}
			lo = l
		}
		hi := len(combined)
		if end < math.MaxInt64 {
			if e := int(end - combinedBase); e < hi {
				if e < 0 {
					e = 0
				}
				hi = e
			}
		}

		if lo < hi {
			for _, m := range find(combined[lo:hi]) {
				absIdx := lo + m[0]
				globalOff := combinedBase + int64(absIdx)

				var stid int64
				if absIdx < len(overlap) {
					// Match starts inside the overlap region — attribute to the
					// last chunk of the previous batch.
					stid = prevLastStid
				} else {
					stid = findStidForPos(posns, absIdx-len(overlap))
				}
				// Guard against matches that fall before start due to the
				// extended left SQL bound.
				if globalOff >= start {
					matches = append(matches, searchMatch{
						Stream:    stream,
						Direction: direction,
						Offset:    globalOff,
						Stid:      stid,
					})
				}
			}
		}

		// Copy the tail of batchBuf as the overlap for the next batch.
		o := ovlLen
		if o > len(batchBuf) {
			o = len(batchBuf)
		}
		if o > 0 {
			newOverlap := make([]byte, o)
			copy(newOverlap, batchBuf[len(batchBuf)-o:])
			overlap = newOverlap
			overlapBase = batchBase + int64(len(batchBuf)) - int64(o)
			prevLastStid = posns[len(posns)-1].stid
		} else {
			overlap = nil
		}
	}

	for rows.Next() {
		var stid, chunkOff int64
		var data []byte
		if err := rows.Scan(&stid, &chunkOff, &data); err != nil {
			return nil, err
		}
		if len(data) == 0 {
			continue
		}
		if !batchBaseSet {
			batchBase = chunkOff
			batchBaseSet = true
		}
		posns = append(posns, chunkPos{len(batchBuf), stid})
		batchBuf = append(batchBuf, data...)

		if len(batchBuf) >= searchBatchSize {
			flush()
			batchBuf = batchBuf[:0]
			posns = posns[:0]
			batchBaseSet = false
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	flush()
	return matches, nil
}
