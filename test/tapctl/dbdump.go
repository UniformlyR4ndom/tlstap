package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
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
  tapctl dbdump chunk --session N --stream N --direction N --chunks 0,1,2 [--api URL]
  tapctl dbdump chunk-stid --session N --stream N --direction N --id N [--api URL]
  tapctl dbdump byte-stid --session N --stream N --direction N --offset N [--api URL]
  tapctl dbdump search --session N --pattern STR [--stream N] [--start N] [--end N]
                        [--pattern-encoding text|base64|regex] [--direction N] [--contiguous] [--api URL]
  tapctl dbdump stid-stream --session N --stream N [--start N] [--n 50] [--api URL]
  tapctl dbdump sgid-stream --session N [--start N] [--n 50] [--api URL]

stid-stream/sgid-stream default --n to 50 (not the protocol's 0/unlimited), since the
whole reply is buffered into one JSON blob before printing; pass --n 0 explicitly for
unlimited.
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
	session := fs.Int64("session", 0, "session id (required)")
	pattern := fs.String("pattern", "", "search pattern (required)")
	patternEncoding := fs.String("pattern-encoding", "text", "text | base64 | regex")
	stream := fs.Int64("stream", 0, "restrict to one stream id (omit to search the whole session)")
	start := fs.Int64("start", 0, "lower bound byte offset (inclusive)")
	end := fs.Int64("end", 0, "upper bound byte offset (exclusive)")
	direction := fs.Int("direction", 0, "restrict to one direction (omit to search both)")
	contiguous := fs.Bool("contiguous", false, "concatenate chunks so cross-chunk matches are found")
	fs.Parse(args)

	if !flagWasSet(fs, "session") {
		fail("--session is required")
	}
	if *pattern == "" {
		fail("--pattern is required")
	}

	req := searchRequest{
		Session:         *session,
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

	data, err := httpPostJSON(*api, "/api/i/dbdump/search-text", req)
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
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
