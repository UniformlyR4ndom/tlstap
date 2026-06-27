package dbdump

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func (i *DbDumpInterceptor) RegisterRoutes(mux *http.ServeMux, basePath string) {
	mux.HandleFunc(basePath+"/status", i.handleStatus)
	mux.HandleFunc(basePath+"/sessions", i.handleSessions)
	mux.HandleFunc(basePath+"/streams", i.handleStreams)
	mux.HandleFunc(basePath+"/chunk", i.handleChunk)
	mux.HandleFunc(basePath+"/chunklist", i.handleChunkList)
	mux.HandleFunc(basePath+"/chunk-stid", i.handleChunkStid)
	mux.HandleFunc(basePath+"/byte-stid", i.handleByteStid)
	mux.HandleFunc(basePath+"/stid-stream", i.handleStidStream)
	mux.HandleFunc(basePath+"/sgid-stream", i.handleSgidStream)
	mux.HandleFunc(basePath+"/search-text", i.handleSearchText)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rows, err := i.db.Query(
		`SELECT s.id, s.session, s.src, s.dst, s.start, COALESCE(s.end, 0),
		        COALESCE(MAX(CASE WHEN c.direction = 0 THEN c.offset + length(c.data) END), -1),
		        COALESCE(MAX(CASE WHEN c.direction = 1 THEN c.offset + length(c.data) END), -1)
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
		ID      int64  `json:"id"`
		Session int64  `json:"session"`
		Src     string `json:"src"`
		Dst     string `json:"dst"`
		Start   int64  `json:"start"`
		End     int64  `json:"end"`
		Length0 int64  `json:"length0"`
		Length1 int64  `json:"length1"`
	}

	streams := []streamResponse{}
	for rows.Next() {
		var s streamResponse
		if err := rows.Scan(&s.ID, &s.Session, &s.Src, &s.Dst, &s.Start, &s.End, &s.Length0, &s.Length1); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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

func (i *DbDumpInterceptor) handleChunkStid(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Session   int64 `json:"session"`
		Stream    int64 `json:"stream"`
		Direction int   `json:"direction"`
		ID        int64 `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
	rows, err := i.db.Query(q, args...)
	if err != nil {
		msg, _ := json.Marshal(map[string]string{"error": err.Error()})
		conn.WriteMessage(websocket.TextMessage, msg)
		return err
	}
	defer rows.Close()

	for rows.Next() {
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
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	done, _ := json.Marshal(struct{ Done bool `json:"done"` }{true})
	return conn.WriteMessage(websocket.TextMessage, done)
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
	rows, err := i.db.Query(q, args...)
	if err != nil {
		msg, _ := json.Marshal(map[string]string{"error": err.Error()})
		conn.WriteMessage(websocket.TextMessage, msg)
		return err
	}
	defer rows.Close()

	for rows.Next() {
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
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
