package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func dbdumpMain(args []string) {
	if len(args) < 1 {
		dbdumpUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "status":
		cmdDbdumpStatus(args[1:])
	case "sessions":
		cmdDbdumpSessions(args[1:])
	case "streams":
		cmdDbdumpStreams(args[1:])
	case "chunklist":
		cmdDbdumpChunkList(args[1:])
	case "latest":
		cmdDbdumpLatest(args[1:])
	case "chunk":
		cmdDbdumpChunk(args[1:])
	case "chunk-stid":
		cmdDbdumpChunkStid(args[1:])
	case "byte-stid":
		cmdDbdumpByteStid(args[1:])
	case "search":
		cmdDbdumpSearch(args[1:])
	case "stid-stream":
		cmdDbdumpStidStream(args[1:])
	case "sgid-stream":
		cmdDbdumpSgidStream(args[1:])
	case "frame-progress":
		cmdDbdumpFrameProgress(args[1:])
	case "frames-timeline":
		cmdDbdumpFramesTimeline(args[1:])
	case "script-list":
		cmdDbdumpScriptList(args[1:])
	case "script-get":
		cmdDbdumpScriptGet(args[1:])
	case "script-put":
		cmdDbdumpScriptPut(args[1:])
	case "script-delete":
		cmdDbdumpScriptDelete(args[1:])
	case "dissect-script-list":
		cmdDbdumpDissectScriptList(args[1:])
	case "dissect-script-get":
		cmdDbdumpDissectScriptGet(args[1:])
	case "dissect-script-put":
		cmdDbdumpDissectScriptPut(args[1:])
	case "dissect-script-delete":
		cmdDbdumpDissectScriptDelete(args[1:])
	case "-h", "--help", "help":
		dbdumpUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown dbdump command: %s\n\n", args[0])
		dbdumpUsage()
		os.Exit(2)
	}
}

func dbdumpUsage() {
	fmt.Fprint(os.Stderr, `tapctl dbdump - drive the dbdump interceptor's REST/WebSocket API

Usage:
  tapctl dbdump status [--api URL]
  tapctl dbdump sessions [--api URL]
  tapctl dbdump streams --session N [--api URL]
  tapctl dbdump chunklist --session N --stream N [--api URL]
  tapctl dbdump latest [--session N] [--stream N] [--api URL]
  tapctl dbdump chunk --session N --stream N --direction N --chunks 0,1,2 [--api URL]
  tapctl dbdump chunk-stid --session N --stream N --direction N --id N [--api URL]
  tapctl dbdump byte-stid --session N --stream N --direction N --offset N [--api URL]
  tapctl dbdump search --session N --pattern STR [--stream N] [--start N] [--end N]
                        [--pattern-encoding text|base64|regex] [--direction N] [--contiguous] [--api URL]
  tapctl dbdump stid-stream --session N --stream N [--start N] [--n 50] [--api URL]
  tapctl dbdump sgid-stream --session N [--start N] [--n 50] [--api URL]
  tapctl dbdump frame-progress --session N --stream N --script NAME --script-version HASH [--api URL]
  tapctl dbdump frames-timeline --session N --stream N --script NAME --script-version HASH
                                 [--start N | --before-stid N] [--n 50] [--api URL]
  tapctl dbdump script-list [--api URL]
  tapctl dbdump script-get --name NAME [--hash] [--api URL]
  tapctl dbdump script-put --name NAME (--file PATH | --file -) [--api URL]
  tapctl dbdump script-delete --name NAME [--api URL]
  tapctl dbdump dissect-script-list [--api URL]
  tapctl dbdump dissect-script-get --name NAME [--hash] [--api URL]
  tapctl dbdump dissect-script-put --name NAME (--file PATH | --file -) [--api URL]
  tapctl dbdump dissect-script-delete --name NAME [--api URL]

stid-stream/sgid-stream default --n to 50 (not the protocol's 0/unlimited), since the
whole reply is buffered into one JSON blob before printing; pass --n 0 explicitly for
unlimited.

frame-progress/frames-timeline both key on (session, stream, script, script_version) —
the exact version a framer run was persisted under, learnable via "dbdump script-get
--hash" without fetching and hashing the script's content yourself. frame-progress
reports bookkeeping only (each direction's processed byte offset, the framer's opaque
state, and whether each direction's close signal was delivered) — not frame content;
useful for checking whether a stream has actually been framed with this exact
script/version yet, and how far, before/instead of pulling frames-timeline's real data.
frames-timeline is the one with the actual payoff: persisted frames (byte ranges,
script-attached meta, direction, stid, time) merged across both directions in
chronological order — see CLAUDE.md's "Framer scripts" section for the full schema.
Defaults to forward pagination from --start (0 unless given); pass --before-stid instead
for backward pagination — exactly one of the two, matching the server's own
"exactly one of start/beforeStid" rule (enforced client-side here too, for a clearer
error than the server's own 400 would give). --n defaults to 50 like stid-stream/
sgid-stream above, for the same reason (buffered into one JSON blob before printing);
pass --n 0 for unlimited.

script-list/-get/-put/-delete are plain REST CRUD wrappers over dbdump's framer-script
store (scripts-dir; frame(state, chunk) scripts run in the browser to reassemble a
stream's raw chunks into frames — see CLAUDE.md's "Framer scripts" section), the same
four-verb shape as "tapctl tamper script-*". script-get prints the raw script source to
stdout (not JSON-wrapped) so it's directly pipeable — or, with --hash, prints
{"sha256":"..."} instead: the same "version" a framer run computes over this same
content (framerRun.js's sha256Hex) and persists as frames.script_version/
frame_progress.script_version, so a caller that already knows a script's name can learn
its current version directly rather than fetching the content just to hash it. script-put
reads from --file (a path, or - for stdin).

dissect-script-list/-get/-put/-delete are the same four commands (including -get's
--hash) against dbdump's separate dissect-scripts-dir store (dissect(bytes, frame)
scripts, producing a field-tree breakdown of one frame — see CLAUDE.md's "Dissector
scripts" section) — a distinct store/namespace from scripts-dir above.
`)
}

// --- request/response wire types (mirror intercept/dbdump/api.go's JSON shapes) ---

type sessionScopedRequest struct {
	Session int64 `json:"session"`
}

type streamScopedRequest struct {
	Session int64 `json:"session"`
	Stream  int64 `json:"stream"`
}

type latestRequest struct {
	Session *int64 `json:"session,omitempty"`
	Stream  *int64 `json:"stream,omitempty"`
}

type directionScopedRequest struct {
	Session   int64 `json:"session"`
	Stream    int64 `json:"stream"`
	Direction int   `json:"direction"`
}

type chunkRequest struct {
	Session   int64   `json:"session"`
	Stream    int64   `json:"stream"`
	Direction int     `json:"direction"`
	Chunks    []int64 `json:"chunks"`
}

type chunkStidRequest struct {
	Session   int64 `json:"session"`
	Stream    int64 `json:"stream"`
	Direction int   `json:"direction"`
	ID        int64 `json:"id"`
}

type byteStidRequest struct {
	Session   int64 `json:"session"`
	Stream    int64 `json:"stream"`
	Direction int   `json:"direction"`
	Offset    int64 `json:"offset"`
}

type searchRequest struct {
	Session         int64  `json:"session"`
	Stream          *int64 `json:"stream,omitempty"`
	Start           *int64 `json:"start,omitempty"`
	End             *int64 `json:"end,omitempty"`
	Pattern         string `json:"pattern"`
	PatternEncoding string `json:"pattern_encoding,omitempty"`
	Direction       *int   `json:"direction,omitempty"`
	Contiguous      bool   `json:"contiguous,omitempty"`
}

type stidStreamRequest struct {
	Session int64 `json:"session"`
	Stream  int64 `json:"stream"`
	Start   int64 `json:"start"`
	N       int   `json:"n"`
}

type sgidStreamRequest struct {
	Session int64 `json:"session"`
	Start   int64 `json:"start"`
	N       int   `json:"n"`
}

// frameTimelineKeyRequest mirrors intercept/dbdump/frames.go's own type of the same
// name — identifies one persisted framer run (a stream, script, and exact script
// version; see "dbdump script-get --hash" for learning that version without fetching
// and hashing the script's content yourself). Shared by frame-progress and
// frames-timeline below, exactly as it is server-side.
type frameTimelineKeyRequest struct {
	Session       int64  `json:"session"`
	Stream        int64  `json:"stream"`
	Script        string `json:"script"`
	ScriptVersion string `json:"script_version"`
}

// framesTimelineRequest mirrors handleFramesTimeline's anonymous request struct.
// BeforeStid's json tag is "beforeStid" (camelCase), unlike every snake_case field
// around it — a real inconsistency in the wire protocol itself, not a typo here.
type framesTimelineRequest struct {
	frameTimelineKeyRequest
	Start      *int64 `json:"start,omitempty"`
	BeforeStid *int64 `json:"beforeStid,omitempty"`
	N          int    `json:"n"`
}

// streamFrame covers every field either stid-stream's or sgid-stream's per-chunk
// metadata frame, or their shared "done"/"error" terminator frames, can carry — which
// one arrived is read from Done/Error, so unused fields for a given command are simply
// left at their zero value and ignored.
type streamFrame struct {
	Done  bool   `json:"done,omitempty"`
	Error string `json:"error,omitempty"`

	Stid      int64 `json:"stid"`
	SGID      int64 `json:"sgid"`
	Stream    int64 `json:"stream"`
	ChunkID   int64 `json:"chunk-id"`
	Direction int   `json:"direction"`
	Time      int64 `json:"time"`
	Offset    int64 `json:"offset"`
}

// --- simple passthrough subcommands ---

func cmdDbdumpStatus(args []string) {
	fs := flag.NewFlagSet("dbdump status", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/dbdump/status")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpSessions(args []string) {
	fs := flag.NewFlagSet("dbdump sessions", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/dbdump/sessions")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpStreams(args []string) {
	fs := flag.NewFlagSet("dbdump streams", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	fs.Parse(args)

	if !flagWasSet(fs, "session") {
		fail("--session is required")
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/streams", sessionScopedRequest{Session: *session})
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpChunkList(args []string) {
	fs := flag.NewFlagSet("dbdump chunklist", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	fs.Parse(args)

	if !flagWasSet(fs, "session") {
		fail("--session is required")
	}
	if !flagWasSet(fs, "stream") {
		fail("--stream is required")
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/chunklist", streamScopedRequest{Session: *session, Stream: *stream})
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpLatest(args []string) {
	fs := flag.NewFlagSet("dbdump latest", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "restrict to one session (omit for latest_session_id only)")
	stream := fs.Int64("stream", 0, "restrict to one stream within --session (omit for no latest_stid)")
	fs.Parse(args)

	var req latestRequest
	if flagWasSet(fs, "session") {
		req.Session = session
	}
	if flagWasSet(fs, "stream") {
		req.Stream = stream
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/latest", req)
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpChunkStid(args []string) {
	fs := flag.NewFlagSet("dbdump chunk-stid", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	direction := fs.Int("direction", 0, "0 = client->server, 1 = server->client (required)")
	id := fs.Int64("id", 0, "per-direction chunk id (required)")
	fs.Parse(args)

	for _, name := range []string{"session", "stream", "direction", "id"} {
		if !flagWasSet(fs, name) {
			fail("--%s is required", name)
		}
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/chunk-stid", chunkStidRequest{
		Session: *session, Stream: *stream, Direction: *direction, ID: *id,
	})
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpByteStid(args []string) {
	fs := flag.NewFlagSet("dbdump byte-stid", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	direction := fs.Int("direction", 0, "0 = client->server, 1 = server->client (required)")
	offset := fs.Int64("offset", 0, "byte offset (required)")
	fs.Parse(args)

	for _, name := range []string{"session", "stream", "direction", "offset"} {
		if !flagWasSet(fs, name) {
			fail("--%s is required", name)
		}
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/byte-stid", byteStidRequest{
		Session: *session, Stream: *stream, Direction: *direction, Offset: *offset,
	})
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpSearch(args []string) {
	fs := flag.NewFlagSet("dbdump search", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "restrict to one session id (omit to search every session)")
	pattern := fs.String("pattern", "", "search pattern (required)")
	patternEncoding := fs.String("pattern-encoding", "text", "text | base64 | regex")
	stream := fs.Int64("stream", 0, "restrict to one stream id — requires --session, since stream ids are only unique within a session")
	start := fs.Int64("start", 0, "lower bound byte offset (inclusive)")
	end := fs.Int64("end", 0, "upper bound byte offset (exclusive)")
	direction := fs.Int("direction", 0, "restrict to one direction (omit to search both)")
	contiguous := fs.Bool("contiguous", false, "concatenate chunks so cross-chunk matches are found")
	fs.Parse(args)

	if *pattern == "" {
		fail("--pattern is required")
	}
	if flagWasSet(fs, "stream") && !flagWasSet(fs, "session") {
		fail("--stream requires --session (stream ids are only unique within a session, so a bare --stream would apply to a different actual stream in each session searched)")
	}

	req := searchRequest{
		Pattern:         *pattern,
		PatternEncoding: *patternEncoding,
		Contiguous:      *contiguous,
	}
	if flagWasSet(fs, "stream") {
		req.Stream = stream
	}
	if flagWasSet(fs, "start") {
		req.Start = start
	}
	if flagWasSet(fs, "end") {
		req.End = end
	}
	if flagWasSet(fs, "direction") {
		req.Direction = direction
	}

	if flagWasSet(fs, "session") {
		req.Session = *session
		data, err := httpPostJSON(*api, "/api/i/dbdump/search-text", req)
		if err != nil {
			fail("%v", err)
		}
		printRawJSON(data)
		return
	}

	// No --session: fan out across every session (client-side only — /search-text itself
	// stays single-session, matching searchTextRequest's own non-optional Session field
	// server-side). Each session's own reply has no session field of its own (a match is
	// always implicit in the single-session request today), so it's tagged in here.
	sessData, err := httpGet(*api, "/api/i/dbdump/sessions")
	if err != nil {
		fail("list sessions: %v", err)
	}
	var sessions []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(sessData, &sessions); err != nil {
		fail("parse sessions: %v", err)
	}

	type taggedMatch struct {
		Session   int64 `json:"session"`
		Stream    int64 `json:"stream"`
		Direction int   `json:"direction"`
		Offset    int64 `json:"offset"`
		Stid      int64 `json:"stid"`
	}
	all := []taggedMatch{} // never printed as JSON null, even with zero sessions/matches
	for _, s := range sessions {
		req.Session = s.ID
		data, err := httpPostJSON(*api, "/api/i/dbdump/search-text", req)
		if err != nil {
			fail("search session %d: %v", s.ID, err)
		}
		var matches []struct {
			Stream    int64 `json:"stream"`
			Direction int   `json:"direction"`
			Offset    int64 `json:"offset"`
			Stid      int64 `json:"stid"`
		}
		if err := json.Unmarshal(data, &matches); err != nil {
			fail("parse search results for session %d: %v", s.ID, err)
		}
		for _, m := range matches {
			all = append(all, taggedMatch{Session: s.ID, Stream: m.Stream, Direction: m.Direction, Offset: m.Offset, Stid: m.Stid})
		}
	}
	printJSON(all)
}

// --- /chunk: multipart response, built into a JSON output shape ---

func cmdDbdumpChunk(args []string) {
	fs := flag.NewFlagSet("dbdump chunk", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	direction := fs.Int("direction", 0, "0 = client->server, 1 = server->client (required)")
	chunksFlag := fs.String("chunks", "", "comma-separated chunk ids to fetch, e.g. 0,1,2 (required)")
	fs.Parse(args)

	for _, name := range []string{"session", "stream", "direction"} {
		if !flagWasSet(fs, name) {
			fail("--%s is required", name)
		}
	}
	if *chunksFlag == "" {
		fail("--chunks is required")
	}

	var chunkIDs []int64
	for _, s := range strings.Split(*chunksFlag, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			fail("invalid --chunks value %q: %v", s, err)
		}
		chunkIDs = append(chunkIDs, id)
	}

	resp, err := httpPostRaw(*api, "/api/i/dbdump/chunk", chunkRequest{
		Session: *session, Stream: *stream, Direction: *direction, Chunks: chunkIDs,
	})
	if err != nil {
		fail("%v", err)
	}
	defer resp.Body.Close()

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		fail("unexpected response Content-Type: %q", resp.Header.Get("Content-Type"))
	}

	type outChunk struct {
		ID         int64  `json:"id"`
		Offset     int64  `json:"offset"`
		Time       int64  `json:"time"`
		DataBase64 string `json:"data_base64"`
	}

	var chunks []outChunk
	mr := multipart.NewReader(resp.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail("read multipart response: %v", err)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			fail("read chunk part: %v", err)
		}
		id, _ := strconv.ParseInt(part.FormName(), 10, 64)
		offset, _ := strconv.ParseInt(part.Header.Get("X-Chunk-Offset"), 10, 64)
		t, _ := strconv.ParseInt(part.Header.Get("X-Chunk-Time"), 10, 64)
		chunks = append(chunks, outChunk{
			ID: id, Offset: offset, Time: t,
			DataBase64: base64.StdEncoding.EncodeToString(data),
		})
	}

	printJSON(struct {
		Chunks []outChunk `json:"chunks"`
	}{chunks})
}

// --- stid-stream / sgid-stream: WebSocket, collected into a JSON output shape ---

func cmdDbdumpStidStream(args []string) {
	fs := flag.NewFlagSet("dbdump stid-stream", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	start := fs.Int64("start", 0, "first stid to fetch (inclusive)")
	n := fs.Int("n", 50, "max chunks to fetch; 0 = unlimited")
	fs.Parse(args)

	if !flagWasSet(fs, "session") {
		fail("--session is required")
	}
	if !flagWasSet(fs, "stream") {
		fail("--stream is required")
	}

	conn, err := dialWS(*api, "/api/i/dbdump/stid-stream")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(stidStreamRequest{Session: *session, Stream: *stream, Start: *start, N: *n}); err != nil {
		fail("send request: %v", err)
	}

	type outChunk struct {
		Stid       int64  `json:"stid"`
		ChunkID    int64  `json:"chunk-id"`
		Direction  int    `json:"direction"`
		Time       int64  `json:"time"`
		Offset     int64  `json:"offset"`
		DataBase64 string `json:"data_base64"`
	}

	var chunks []outChunk
	for {
		var f streamFrame
		if err := conn.ReadJSON(&f); err != nil {
			fail("read reply: %v", err)
		}
		if f.Error != "" {
			fail("%s", f.Error)
		}
		if f.Done {
			printJSON(struct {
				Chunks []outChunk `json:"chunks"`
			}{chunks})
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			fail("read chunk data: %v", err)
		}
		chunks = append(chunks, outChunk{
			Stid: f.Stid, ChunkID: f.ChunkID, Direction: f.Direction, Time: f.Time, Offset: f.Offset,
			DataBase64: base64.StdEncoding.EncodeToString(data),
		})
	}
}

func cmdDbdumpSgidStream(args []string) {
	fs := flag.NewFlagSet("dbdump sgid-stream", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	start := fs.Int64("start", 0, "first sgid to fetch (inclusive)")
	n := fs.Int("n", 50, "max chunks to fetch; 0 = unlimited")
	fs.Parse(args)

	if !flagWasSet(fs, "session") {
		fail("--session is required")
	}

	conn, err := dialWS(*api, "/api/i/dbdump/sgid-stream")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(sgidStreamRequest{Session: *session, Start: *start, N: *n}); err != nil {
		fail("send request: %v", err)
	}

	type outChunk struct {
		SGID       int64  `json:"sgid"`
		Stream     int64  `json:"stream"`
		ChunkID    int64  `json:"chunk-id"`
		Direction  int    `json:"direction"`
		Time       int64  `json:"time"`
		Offset     int64  `json:"offset"`
		DataBase64 string `json:"data_base64"`
	}

	var chunks []outChunk
	for {
		var f streamFrame
		if err := conn.ReadJSON(&f); err != nil {
			fail("read reply: %v", err)
		}
		if f.Error != "" {
			fail("%s", f.Error)
		}
		if f.Done {
			printJSON(struct {
				Chunks []outChunk `json:"chunks"`
			}{chunks})
			return
		}

		_, data, err := conn.ReadMessage()
		if err != nil {
			fail("read chunk data: %v", err)
		}
		chunks = append(chunks, outChunk{
			SGID: f.SGID, Stream: f.Stream, ChunkID: f.ChunkID, Direction: f.Direction, Time: f.Time, Offset: f.Offset,
			DataBase64: base64.StdEncoding.EncodeToString(data),
		})
	}
}

// --- scripts (framer scripts; REST CRUD, same shape as "tapctl tamper script-*" —
// see intercept/scriptstore/CLAUDE.md) ---

func cmdDbdumpScriptList(args []string) {
	fs := flag.NewFlagSet("dbdump script-list", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/dbdump/scripts")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpScriptGet(args []string) {
	fs := flag.NewFlagSet("dbdump script-get", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "script name, without .js (required)")
	hash := fs.Bool("hash", false, "print the script's sha256 hex digest instead of its content")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	path := "/api/i/dbdump/scripts/" + url.PathEscape(*name)
	if *hash {
		path += "?hash=1"
	}
	data, err := httpGet(*api, path)
	if err != nil {
		fail("%v", err)
	}
	if *hash {
		printRawJSON(data) // {"sha256": "..."} — JSON, unlike the raw-content path below
		return
	}
	// Raw script source, not JSON — printed verbatim (no trailing newline added) so
	// this is directly pipeable to a file, matching the REST endpoint's own raw-text
	// convention rather than tapctl's usual "print JSON to stdout".
	os.Stdout.Write(data)
}

func cmdDbdumpScriptPut(args []string) {
	fs := flag.NewFlagSet("dbdump script-put", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "script name, without .js (required)")
	file := fs.String("file", "", "path to script source, or - for stdin (required)")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}
	if *file == "" {
		fail("--file is required (path, or - for stdin)")
	}

	var content []byte
	var err error
	if *file == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*file)
	}
	if err != nil {
		fail("read --file: %v", err)
	}

	if _, err := httpPutRaw(*api, "/api/i/dbdump/scripts/"+url.PathEscape(*name), content, "application/javascript"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdDbdumpScriptDelete(args []string) {
	fs := flag.NewFlagSet("dbdump script-delete", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "script name, without .js (required)")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	if _, err := httpDelete(*api, "/api/i/dbdump/scripts/"+url.PathEscape(*name)); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

// --- dissect scripts (separate store/namespace from scripts above; see
// intercept/dbdump/CLAUDE.md's "Dissector scripts" section) ---

func cmdDbdumpDissectScriptList(args []string) {
	fs := flag.NewFlagSet("dbdump dissect-script-list", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/dbdump/dissect/scripts")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpDissectScriptGet(args []string) {
	fs := flag.NewFlagSet("dbdump dissect-script-get", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "dissect script name, without .js (required)")
	hash := fs.Bool("hash", false, "print the script's sha256 hex digest instead of its content")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	path := "/api/i/dbdump/dissect/scripts/" + url.PathEscape(*name)
	if *hash {
		path += "?hash=1"
	}
	data, err := httpGet(*api, path)
	if err != nil {
		fail("%v", err)
	}
	if *hash {
		printRawJSON(data) // {"sha256": "..."} — JSON, unlike the raw-content path below
		return
	}
	// Raw script source, not JSON — printed verbatim (no trailing newline added) so
	// this is directly pipeable to a file, matching the REST endpoint's own raw-text
	// convention rather than tapctl's usual "print JSON to stdout".
	os.Stdout.Write(data)
}

func cmdDbdumpDissectScriptPut(args []string) {
	fs := flag.NewFlagSet("dbdump dissect-script-put", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "dissect script name, without .js (required)")
	file := fs.String("file", "", "path to script source, or - for stdin (required)")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}
	if *file == "" {
		fail("--file is required (path, or - for stdin)")
	}

	var content []byte
	var err error
	if *file == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*file)
	}
	if err != nil {
		fail("read --file: %v", err)
	}

	if _, err := httpPutRaw(*api, "/api/i/dbdump/dissect/scripts/"+url.PathEscape(*name), content, "application/javascript"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdDbdumpDissectScriptDelete(args []string) {
	fs := flag.NewFlagSet("dbdump dissect-script-delete", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "dissect script name, without .js (required)")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	if _, err := httpDelete(*api, "/api/i/dbdump/dissect/scripts/"+url.PathEscape(*name)); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

// --- frame-progress / frames-timeline (persisted framer-script output; see
// intercept/dbdump/CLAUDE.md's "Framer scripts" section) ---

func cmdDbdumpFrameProgress(args []string) {
	fs := flag.NewFlagSet("dbdump frame-progress", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	script := fs.String("script", "", "framer script name (required)")
	scriptVersion := fs.String("script-version", "", "framer script's sha256 version, e.g. from \"dbdump script-get --hash\" (required)")
	fs.Parse(args)

	for _, name := range []string{"session", "stream", "script", "script-version"} {
		if !flagWasSet(fs, name) {
			fail("--%s is required", name)
		}
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/frame-progress", frameTimelineKeyRequest{
		Session: *session, Stream: *stream, Script: *script, ScriptVersion: *scriptVersion,
	})
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdDbdumpFramesTimeline(args []string) {
	fs := flag.NewFlagSet("dbdump frames-timeline", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	session := fs.Int64("session", 0, "session id (required)")
	stream := fs.Int64("stream", 0, "stream id (required)")
	script := fs.String("script", "", "framer script name (required)")
	scriptVersion := fs.String("script-version", "", "framer script's sha256 version, e.g. from \"dbdump script-get --hash\" (required)")
	start := fs.Int64("start", 0, "first stid to fetch (inclusive); default unless --before-stid is given")
	beforeStid := fs.Int64("before-stid", 0, "fetch backward instead, exclusive upper bound stid (mutually exclusive with --start)")
	n := fs.Int("n", 50, "max frames to fetch; 0 = unlimited")
	fs.Parse(args)

	for _, name := range []string{"session", "stream", "script", "script-version"} {
		if !flagWasSet(fs, name) {
			fail("--%s is required", name)
		}
	}
	if flagWasSet(fs, "start") && flagWasSet(fs, "before-stid") {
		fail("--start and --before-stid are mutually exclusive")
	}

	req := framesTimelineRequest{
		frameTimelineKeyRequest: frameTimelineKeyRequest{
			Session: *session, Stream: *stream, Script: *script, ScriptVersion: *scriptVersion,
		},
		N: *n,
	}
	if flagWasSet(fs, "before-stid") {
		req.BeforeStid = beforeStid
	} else {
		req.Start = start // defaults to 0 when neither flag is given
	}

	data, err := httpPostJSON(*api, "/api/i/dbdump/frames/timeline", req)
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}
