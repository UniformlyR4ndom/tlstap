package dbdump

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"

	"tlstap/intercept/scriptstore"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
	Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
		writeError(w, status, reason.Error())
	},
}

func (i *DbDumpInterceptor) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc("GET "+basePath+"/status", i.handleStatus)
	mux.HandleFunc("GET "+basePath+"/sessions", i.handleSessions)
	mux.HandleFunc("POST "+basePath+"/streams", i.handleStreams)
	mux.HandleFunc("POST "+basePath+"/chunk", i.handleChunk)
	mux.HandleFunc("POST "+basePath+"/chunklist", i.handleChunkList)
	mux.HandleFunc("POST "+basePath+"/latest", i.handleLatest)
	mux.HandleFunc("POST "+basePath+"/chunk-stid", i.handleChunkStid)
	mux.HandleFunc("POST "+basePath+"/byte-stid", i.handleByteStid)
	mux.HandleFunc("GET "+basePath+"/stid-stream", i.handleStidStream)
	mux.HandleFunc("GET "+basePath+"/sgid-stream", i.handleSgidStream)
	mux.HandleFunc("GET "+basePath+"/segments", i.handleSegments)
	mux.HandleFunc("POST "+basePath+"/search-text", i.handleSearchText)
	mux.HandleFunc("POST "+basePath+"/frame-progress", i.handleFrameProgress)
	mux.HandleFunc("POST "+basePath+"/frames", i.handleFramesList)
	mux.HandleFunc("POST "+basePath+"/frames/timeline", i.handleFramesTimeline)
	mux.HandleFunc("POST "+basePath+"/frames/by-seq", i.handleFramesBySeq)
	mux.HandleFunc("POST "+basePath+"/frames/append", i.handleFramesAppend)
	mux.HandleFunc("POST "+basePath+"/frames/clear", i.handleFramesClear)

	scriptstore.RegisterRoutes(mux, basePath, i.scripts, i.onFramerScriptPut, i.onFramerScriptDelete)

	// Nested under its own "/dissect" segment so this second Store's routes don't collide
	// with the framer's own basePath+"/scripts" above — RegisterRoutes always registers at
	// <basePath>/scripts, so a distinct basePath is what keeps the two independent. No
	// onPut/onDelete: dissection output is never persisted (see
	// doc/design/packet-dissector.md's "Laziness" section), so there's nothing to purge on
	// a script write/delete the way onFramerScriptPut/onFramerScriptDelete purge frame data.
	scriptstore.RegisterRoutes(mux, basePath+"/dissect", i.dissectScripts, nil, nil)
}

// onFramerScriptPut purges any other persisted frame-index version for name, keeping
// only the one matching its just-written content — a script's previous version can
// never be reached again once overwritten (script_version has no history, just the
// current content's hash), so keeping its data around would only grow the DB for
// nothing. Re-reads the content just written (rather than the callback carrying it)
// since scriptstore.RegisterRoutes' callback contract is deliberately just a name.
func (i *DbDumpInterceptor) onFramerScriptPut(name string) {
	content, err := i.scripts.Get(name)
	if err != nil {
		i.logger.Error("dbdump: re-reading script %q after write: %v", name, err)
		return
	}
	sum := sha256.Sum256(content)
	if err := i.purgeOtherFrameVersions(name, hex.EncodeToString(sum[:])); err != nil {
		i.logger.Error("dbdump: purge stale frame data for script %q: %v", name, err)
	}
}

// onFramerScriptDelete purges every persisted frame-index version for name — none of
// them can ever be reached again once the script itself is gone.
func (i *DbDumpInterceptor) onFramerScriptDelete(name string) {
	if err := i.purgeAllFrameVersions(name); err != nil {
		i.logger.Error("dbdump: purge frame data for deleted script %q: %v", name, err)
	}
}

func (i *DbDumpInterceptor) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (i *DbDumpInterceptor) handleSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := i.db.Query(`SELECT id, start, config FROM sessions ORDER BY id`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type sessionResponse struct {
		ID     int64           `json:"id"`
		Start  int64           `json:"start"`
		Config json.RawMessage `json:"config"`
	}

	sessions := []sessionResponse{}
	for rows.Next() {
		var s sessionResponse
		var config string
		if err := rows.Scan(&s.ID, &s.Start, &config); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.Config = json.RawMessage(config)
		sessions = append(sessions, s)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, sessions)
}

func (i *DbDumpInterceptor) handleStreams(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID int64 `json:"session"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	rows, err := i.db.Query(
		`SELECT s.id, s.session, s.src, s.dst, s.start, COALESCE(s.end, 0),
		        COALESCE(MAX(CASE WHEN c.direction = 0 THEN c.offset + length(c.data) END), -1),
		        COALESCE(MAX(CASE WHEN c.direction = 1 THEN c.offset + length(c.data) END), -1),
		        s.sni, s.alpn, s.tls_version, s.cipher_suite
		 FROM stream s LEFT JOIN chunks c ON c.stream = s.id AND c.session = s.session
		 WHERE s.session = ? GROUP BY s.id ORDER BY s.id`,
		req.SessionID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type streamResponse struct {
		ID          int64   `json:"id"`
		Session     int64   `json:"session"`
		Src         string  `json:"src"`
		Dst         string  `json:"dst"`
		Start       int64   `json:"start"`
		End         int64   `json:"end"`
		Length0     int64   `json:"length0"`
		Length1     int64   `json:"length1"`
		SNI         *string `json:"sni"`
		ALPN        *string `json:"alpn"`
		TLSVersion  *int64  `json:"tls_version"`
		CipherSuite *int64  `json:"cipher_suite"`
	}

	streams := []streamResponse{}
	for rows.Next() {
		var s streamResponse
		if err := rows.Scan(&s.ID, &s.Session, &s.Src, &s.Dst, &s.Start, &s.End, &s.Length0, &s.Length1,
			&s.SNI, &s.ALPN, &s.TLSVersion, &s.CipherSuite); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		streams = append(streams, s)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, streams)
}

func (i *DbDumpInterceptor) handleChunk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session   int64   `json:"session"`
		Stream    int64   `json:"stream"`
		Direction int     `json:"direction"`
		Chunks    []int64 `json:"chunks"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if len(req.Chunks) == 0 {
		mw := multipart.NewWriter(w)
		w.Header().Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())
		mw.Close()
		return
	}

	// Build the IN clause dynamically; args: session, stream, direction, chunk IDs…
	placeholders := make([]string, len(req.Chunks))
	args := make([]any, 0, 3+len(req.Chunks))
	args = append(args, req.Session, req.Stream, req.Direction)
	for j, id := range req.Chunks {
		placeholders[j] = "?"
		args = append(args, id)
	}

	rows, err := i.db.Query(
		fmt.Sprintf(
			`SELECT id, offset, time, data
			 FROM chunks
			 WHERE session = ? AND stream = ? AND direction = ? AND id IN (%s)
			 ORDER BY id`,
			strings.Join(placeholders, ", "),
		),
		args...,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	// Set Content-Type before the first write; multipart.NewWriter does not write on creation.
	mw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", "multipart/form-data; boundary="+mw.Boundary())

	for rows.Next() {
		var id, offset, ts int64
		var data []byte
		if err := rows.Scan(&id, &offset, &ts, &data); err != nil {
			mw.Close()
			return
		}

		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%d"`, id))
		h.Set("Content-Type", "application/octet-stream")
		h.Set("X-Chunk-Offset", strconv.FormatInt(offset, 10))
		h.Set("X-Chunk-Time", strconv.FormatInt(ts, 10))

		pw, err := mw.CreatePart(h)
		if err != nil {
			mw.Close()
			return
		}
		pw.Write(data)
	}
	mw.Close()
}

func (i *DbDumpInterceptor) handleChunkList(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session int64 `json:"session"`
		Stream  int64 `json:"stream"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	rows, err := i.db.Query(
		`SELECT c.direction, c.id, c.offset + length(c.data)
		 FROM chunks c
		 JOIN (SELECT direction, MAX(id) AS max_id FROM chunks WHERE session = ? AND stream = ? GROUP BY direction) m
		   ON c.direction = m.direction AND c.id = m.max_id
		 WHERE c.session = ? AND c.stream = ?`,
		req.Session, req.Stream, req.Session, req.Stream,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type chunkListResponse struct {
		Latest0 int64 `json:"latest0"`
		Latest1 int64 `json:"latest1"`
		Length0 int64 `json:"length0"`
		Length1 int64 `json:"length1"`
	}
	resp := chunkListResponse{Latest0: -1, Latest1: -1, Length0: -1, Length1: -1}
	for rows.Next() {
		var dir int
		var latest, length int64
		if err := rows.Scan(&dir, &latest, &length); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		switch dir {
		case 0:
			resp.Latest0 = latest
			resp.Length0 = length
		case 1:
			resp.Latest1 = latest
			resp.Length1 = length
		}
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, resp)
}

// handleLatest is a single consolidated cheap-check endpoint, folding together a
// session's latest_sgid/streams_version, a stream's latest_stid, and a global latest
// session id — the one thing a live-poll client calls per tick, carrying whichever of
// session/stream it currently has selected. session and stream are both optional and
// independent: omitting session yields only latest_session_id; supplying session
// without stream omits latest_stid.
func (i *DbDumpInterceptor) handleLatest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session *int64 `json:"session"`
		Stream  *int64 `json:"stream"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	resp := struct {
		LatestSessionID int64 `json:"latest_session_id"`
		LatestSgid      int64 `json:"latest_sgid"`
		StreamsVersion  int64 `json:"streams_version"`
		LatestStid      int64 `json:"latest_stid"`
	}{LatestSessionID: -1, LatestSgid: -1, StreamsVersion: -1, LatestStid: -1}

	var latestSessionID sql.NullInt64
	if err := i.db.QueryRow(`SELECT MAX(id) FROM sessions`).Scan(&latestSessionID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if latestSessionID.Valid {
		resp.LatestSessionID = latestSessionID.Int64
	}

	if req.Session == nil {
		writeJSON(w, resp)
		return
	}

	var latestSgid sql.NullInt64
	if err := i.db.QueryRow(
		`SELECT MAX(sgid) FROM chunks WHERE session = ?`,
		*req.Session,
	).Scan(&latestSgid); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if latestSgid.Valid {
		resp.LatestSgid = latestSgid.Int64
	}

	// streamsVersion is in-memory and only meaningful for the one session this
	// interceptor instance is actively writing to — see handleSessionLatest above.
	i.mu.RLock()
	if i.sessionCreated && i.sessionID == *req.Session {
		resp.StreamsVersion = i.streamsVersion
	}
	i.mu.RUnlock()

	if req.Stream == nil {
		writeJSON(w, resp)
		return
	}

	var latestStid sql.NullInt64
	if err := i.db.QueryRow(
		`SELECT MAX(stid) FROM chunks WHERE session = ? AND stream = ?`,
		*req.Session, *req.Stream,
	).Scan(&latestStid); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if latestStid.Valid {
		resp.LatestStid = latestStid.Int64
	}

	writeJSON(w, resp)
}

func (i *DbDumpInterceptor) handleChunkStid(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session   int64 `json:"session"`
		Stream    int64 `json:"stream"`
		Direction int   `json:"direction"`
		ID        int64 `json:"id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	var stid int64
	err := i.db.QueryRow(
		`SELECT stid FROM chunks WHERE session = ? AND stream = ? AND direction = ? AND id = ?`,
		req.Session, req.Stream, req.Direction, req.ID,
	).Scan(&stid)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "chunk not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int64{"stid": stid})
}

func (i *DbDumpInterceptor) handleByteStid(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session   int64 `json:"session"`
		Stream    int64 `json:"stream"`
		Direction int   `json:"direction"`
		Offset    int64 `json:"offset"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	var stid int64
	err := i.db.QueryRow(
		`SELECT stid FROM chunks WHERE session = ? AND stream = ? AND direction = ? AND offset <= ? ORDER BY offset DESC LIMIT 1`,
		req.Session, req.Stream, req.Direction, req.Offset,
	).Scan(&stid)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "no chunk found at or before that offset")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]int64{"stid": stid})
}

func (i *DbDumpInterceptor) handleStidStream(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		var req struct {
			Session int64 `json:"session"`
			Stream  int64 `json:"stream"`
			Start   int64 `json:"start"`
			N       int   `json:"n"`
		}
		if err := conn.ReadJSON(&req); err != nil {
			return
		}
		if err := i.streamChunksByStid(conn, req.Session, req.Stream, req.Start, req.N); err != nil {
			return
		}
	}
}

func (i *DbDumpInterceptor) streamChunksByStid(conn *websocket.Conn, session, stream, start int64, n int) error {
	q := `SELECT stid, id, direction, offset, time, data
	      FROM chunks WHERE session = ? AND stream = ? AND stid >= ? ORDER BY stid`
	args := []any{session, stream, start}
	if n > 0 {
		q += ` LIMIT ?`
		args = append(args, n)
	}
	return i.streamRows(conn, q, args, func(rows *sql.Rows) error {
		var stid, chunkID, offset, ts int64
		var direction int
		var data []byte
		if err := rows.Scan(&stid, &chunkID, &direction, &offset, &ts, &data); err != nil {
			return err
		}
		meta, _ := json.Marshal(struct {
			Stid      int64 `json:"stid"`
			ChunkID   int64 `json:"chunk-id"`
			Direction int   `json:"direction"`
			Time      int64 `json:"time"`
			Offset    int64 `json:"offset"`
		}{stid, chunkID, direction, ts, offset})
		if err := conn.WriteMessage(websocket.TextMessage, meta); err != nil {
			return err
		}
		return conn.WriteMessage(websocket.BinaryMessage, data)
	})
}

func (i *DbDumpInterceptor) handleSgidStream(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		var req struct {
			Session int64 `json:"session"`
			Start   int64 `json:"start"`
			N       int   `json:"n"`
		}
		if err := conn.ReadJSON(&req); err != nil {
			return
		}
		if err := i.streamChunksBySgid(conn, req.Session, req.Start, req.N); err != nil {
			return
		}
	}
}

func (i *DbDumpInterceptor) streamChunksBySgid(conn *websocket.Conn, session, start int64, n int) error {
	q := `SELECT sgid, stream, direction, id, offset, time, data
	      FROM chunks WHERE session = ? AND sgid >= ? ORDER BY sgid`
	args := []any{session, start}
	if n > 0 {
		q += ` LIMIT ?`
		args = append(args, n)
	}
	return i.streamRows(conn, q, args, func(rows *sql.Rows) error {
		var sgid, stream, chunkID, offset, ts int64
		var direction int
		var data []byte
		if err := rows.Scan(&sgid, &stream, &direction, &chunkID, &offset, &ts, &data); err != nil {
			return err
		}
		meta, _ := json.Marshal(struct {
			SGID      int64 `json:"sgid"`
			Stream    int64 `json:"stream"`
			ChunkID   int64 `json:"chunk-id"`
			Direction int   `json:"direction"`
			Time      int64 `json:"time"`
			Offset    int64 `json:"offset"`
		}{sgid, stream, chunkID, direction, ts, offset})
		if err := conn.WriteMessage(websocket.TextMessage, meta); err != nil {
			return err
		}
		return conn.WriteMessage(websocket.BinaryMessage, data)
	})
}

// streamRows writes an error frame only for a query failure; an emit error
// (scan/write) is returned without one, since a frame may already be mid-write.
func (i *DbDumpInterceptor) streamRows(conn *websocket.Conn, query string, args []any, emit func(*sql.Rows) error) error {
	rows, err := i.db.Query(query, args...)
	if err != nil {
		msg, _ := json.Marshal(map[string]string{"error": err.Error()})
		conn.WriteMessage(websocket.TextMessage, msg)
		return err
	}
	defer rows.Close()

	for rows.Next() {
		if err := emit(rows); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	done, _ := json.Marshal(struct {
		Done bool `json:"done"`
	}{true})
	return conn.WriteMessage(websocket.TextMessage, done)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
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
