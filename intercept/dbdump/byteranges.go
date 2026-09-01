package dbdump

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

const (
	maxRangeBytes      int64 = 128 * 1024 * 1024 // per-entry magnitude bound
	maxRangeEntries          = 1024               // entries per request
	maxTotalRangeBytes int64 = 128 * 1024 * 1024  // sum-of-magnitudes bound
)

// decodeSignedLength/encodeSignedLength turn a /byte-ranges wire entry's single signed
// length field into (direction, magnitude) and back — the sign encodes direction (see
// intercept/dbdump/CLAUDE.md's "POST /byte-ranges" section for the full rationale: a
// valid range's length is always non-zero, while offset can legitimately be 0, so length
// is the only field that can safely carry it). Mirrors web/direction.js's identically
// named helpers exactly.
func decodeSignedLength(signedLength int64) (direction int, magnitude int64) {
	if signedLength < 0 {
		// -signedLength overflows back to signedLength itself (still negative) only when
		// signedLength == math.MinInt64 — the sole two's-complement value with no positive
		// counterpart. Not special-cased here: parseByteRangesRequest below detects it by
		// checking whether magnitude is still negative afterward.
		return directionC2S, -signedLength
	}
	return directionS2C, signedLength
}

func encodeSignedLength(direction int, magnitude int64) int64 {
	if direction == directionC2S {
		return -magnitude
	}
	return magnitude
}

type byteRangeEntry struct {
	Offset    int64
	Direction int
	Magnitude int64
}

// parseByteRangesRequest validates and decodes the whole binary request body per
// intercept/dbdump/CLAUDE.md's "POST /byte-ranges" bounds. Any failure rejects the
// entire request — nothing is fetched, matching writeError's {"error":"..."} convention
// at the call site.
func parseByteRangesRequest(body []byte) ([]byteRangeEntry, error) {
	if len(body)%16 != 0 {
		return nil, fmt.Errorf("body length %d is not a multiple of 16", len(body))
	}
	n := len(body) / 16
	if n > maxRangeEntries {
		return nil, fmt.Errorf("%d entries exceeds max %d", n, maxRangeEntries)
	}

	entries := make([]byteRangeEntry, n)
	var total int64
	for j := 0; j < n; j++ {
		offset := int64(binary.BigEndian.Uint64(body[j*16:]))
		signedLength := int64(binary.BigEndian.Uint64(body[j*16+8:]))

		if offset < 0 {
			return nil, fmt.Errorf("entry %d: negative offset", j)
		}
		if signedLength == 0 {
			return nil, fmt.Errorf("entry %d: zero length", j)
		}

		direction, magnitude := decodeSignedLength(signedLength)
		// magnitude < 0 here means its sign bit is still set after negation — the only
		// way -math.MinInt64's two's-complement overflow (which wraps back to MinInt64
		// itself) can be detected. Checked directly via the sign bit, not by naming the
		// constant, and before the size-bound comparison below.
		if magnitude < 0 {
			return nil, fmt.Errorf("entry %d: length magnitude overflow", j)
		}
		if magnitude > maxRangeBytes {
			return nil, fmt.Errorf("entry %d: length %d exceeds max %d", j, magnitude, maxRangeBytes)
		}
		total += magnitude
		if total > maxTotalRangeBytes {
			return nil, fmt.Errorf("total requested bytes exceeds max %d", maxTotalRangeBytes)
		}

		entries[j] = byteRangeEntry{Offset: offset, Direction: direction, Magnitude: magnitude}
	}
	return entries, nil
}

// resolveByteRange returns up to magnitude bytes starting at offset for
// (session, stream, direction) — possibly fewer, even zero, when the requested range
// reaches past what's currently captured (a still-live stream not yet flushed that far,
// or the genuine end of a closed one); that's not an error, see intercept/dbdump/
// CLAUDE.md's "POST /byte-ranges" section. Finds every chunks row overlapping
// [offset, offset+magnitude) and slices exactly the requested sub-range out of them — a
// range may legitimately span more than one chunk. Relies on chunk offsets being
// contiguous per (session, stream, direction), true by construction (see dbdump.go's
// Intercept) — a genuine gap isn't defended against, per the "optimize for the common
// case, not adversarial worst cases" guidance this endpoint was scoped under.
func (i *DbDumpInterceptor) resolveByteRange(session, stream int64, direction int, offset, magnitude int64) ([]byte, error) {
	rangeEnd := offset + magnitude
	rows, err := i.db.Query(
		`SELECT offset, data FROM chunks
		 WHERE session = ? AND stream = ? AND direction = ? AND offset < ? AND offset + LENGTH(data) > ?
		 ORDER BY offset`,
		session, stream, direction, rangeEnd, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]byte, 0, magnitude)
	want := offset
	for rows.Next() {
		var chunkOffset int64
		var data []byte
		if err := rows.Scan(&chunkOffset, &data); err != nil {
			return nil, err
		}
		lo := want - chunkOffset
		if lo < 0 {
			lo = 0
		}
		hi := rangeEnd - chunkOffset
		if hi > int64(len(data)) {
			hi = int64(len(data))
		}
		if lo >= hi {
			continue
		}
		out = append(out, data[lo:hi]...)
		want = chunkOffset + hi
	}
	return out, rows.Err()
}

// handleByteRanges answers a whole-request-validated batch of byte-range fetches for one
// (session, stream) — session/stream come from the URL query string, a new convention for
// this package: every other handler takes a JSON body, but /byte-ranges' body must be
// pure binary, so there's nowhere else to put them. Streams the response directly (no
// buffering) rather than building it in memory first.
func (i *DbDumpInterceptor) handleByteRanges(w http.ResponseWriter, r *http.Request) {
	session, errS := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
	stream, errT := strconv.ParseInt(r.URL.Query().Get("stream"), 10, 64)
	if errS != nil || errT != nil {
		writeError(w, http.StatusBadRequest, "session/stream query parameters must be integers")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := parseByteRangesRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var exists int
	err = i.db.QueryRow(`SELECT 1 FROM stream WHERE session = ? AND id = ?`, session, stream).Scan(&exists)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "stream not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	var lenBuf [8]byte
	for _, e := range entries {
		data, err := i.resolveByteRange(session, stream, e.Direction, e.Offset, e.Magnitude)
		if err != nil {
			// The response may already be mid-write (a prior entry's length-prefix+bytes
			// already sent, headers already flushed) — same "no error frame once writing
			// has started" convention streamRows/streamSegments already use.
			i.logger.Error("dbdump: /byte-ranges resolve session=%d stream=%d: %v", session, stream, err)
			return
		}
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(data)))
		w.Write(lenBuf[:])
		w.Write(data)
	}
}
