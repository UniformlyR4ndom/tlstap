package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gorilla/websocket"
)

func tamperMain(args []string) {
	if len(args) < 1 {
		tamperUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "streams":
		cmdTamperStreams(args[1:])
	case "peek":
		cmdTamperPeek(args[1:])
	case "release":
		cmdTamperRelease(args[1:])
	case "drop-connection":
		cmdTamperDropConnection(args[1:])
	case "set-mode":
		cmdTamperSetMode(args[1:])
	case "set-auto-intercept":
		cmdTamperSetAutoIntercept(args[1:])
	case "-h", "--help", "help":
		tamperUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown tamper command: %s\n\n", args[0])
		tamperUsage()
		os.Exit(2)
	}
}

func tamperUsage() {
	fmt.Fprint(os.Stderr, `tapctl tamper - drive the tamper interceptor's control/watch WebSocket API

Usage:
  tapctl tamper streams [--api URL]
  tapctl tamper peek --conn N --direction 0|1 [--offset N] [--length N] [--api URL]
  tapctl tamper release --conn N --direction 0|1 [--action forward|drop] [--release-chunks N]
                         [--edit PATH|- | --edit-base64 STRING] [--prefix-length N] [--bounds "0,10"]
                         [--api URL]
  tapctl tamper drop-connection --conn N --direction 0|1 [--api URL]
  tapctl tamper set-mode --conn N --intercepting=true|false [--api URL]
  tapctl tamper set-auto-intercept --enabled=true|false [--api URL]

release combines an optional edit with an optional release, mirroring the server's
performAction: --release-chunks defaults to 0 (edit only, nothing released); pass a
positive count to also release that many chunks of the post-edit buffer. --edit/
--edit-base64 replace the buffer's first --prefix-length bytes (as you last learned them
via peek) with the given data; --bounds defaults to "0" (the whole edit as one chunk).
`)
}

// --- wire types ---
//
// These mirror the JSON shapes documented in intercept/tamper/protocol.go and
// CLAUDE.md, kept local (rather than importing the tamper package) since tapctl only
// ever speaks the public wire protocol, exactly like any other client would.

// outboundMsg covers every control-channel command tapctl sends.
type outboundMsg struct {
	Type          string  `json:"type"`
	Enabled       *bool   `json:"enabled,omitempty"`
	Conn          *uint32 `json:"conn,omitempty"`
	Intercepting  *bool   `json:"intercepting,omitempty"`
	Direction     *int    `json:"direction,omitempty"`
	Edited        *bool   `json:"edited,omitempty"`
	PrefixLength  int     `json:"prefix_length,omitempty"`
	Bounds        []int   `json:"bounds,omitempty"`
	ReleaseChunks int     `json:"release_chunks,omitempty"`
	Action        string  `json:"action,omitempty"`
}

// watchRequest is the "peek" command sent on a /watch connection.
type watchRequest struct {
	Type      string `json:"type"`
	Direction int    `json:"direction"`
	Offset    int64  `json:"offset,omitempty"`
	Length    int64  `json:"length,omitempty"`
}

// ackReply is the {"type":"ok"|"error",...} shape every set-auto-intercept/set-mode/
// release/drop-connection command receives back.
type ackReply struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Message string `json:"message"`
}

// readAck reads one control-channel reply and fails the process with the server's
// error message if it wasn't "ok".
func readAck(conn *websocket.Conn) {
	var r ackReply
	if err := conn.ReadJSON(&r); err != nil {
		fail("read acknowledgment: %v", err)
	}
	if r.Type != "ok" {
		fail("%s", r.Message)
	}
}

// peekReply is a superset of the "pending"/"peek-done"/"error" reply shapes a "peek"
// command can produce, decoded generically since which one arrived is read from Type.
type peekReply struct {
	Type        string `json:"type"`
	Direction   int    `json:"direction"`
	Time        int64  `json:"time"`
	Offset      int64  `json:"offset"`
	Length      int    `json:"length"`
	TotalLength int    `json:"total_length"`
	Bounds      []int  `json:"bounds"`
	Message     string `json:"message"`
}

// --- subcommands ---

func cmdTamperStreams(args []string) {
	fs := flag.NewFlagSet("tamper streams", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(outboundMsg{Type: "list-streams"}); err != nil {
		fail("send list-streams: %v", err)
	}

	var reply any
	if err := conn.ReadJSON(&reply); err != nil {
		fail("read reply: %v", err)
	}
	printJSON(reply)
}

// parseDirection reads --direction, requiring it to be present and either 0 or 1.
func parseDirection(fs *flag.FlagSet, direction *int) int {
	if !flagWasSet(fs, "direction") {
		fail("--direction is required (0 = c->s, 1 = s->c)")
	}
	if *direction != 0 && *direction != 1 {
		fail("--direction must be 0 or 1")
	}
	return *direction
}

func cmdTamperPeek(args []string) {
	fs := flag.NewFlagSet("tamper peek", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	connFlag := fs.Uint64("conn", 0, "stream ConnID (required)")
	direction := fs.Int("direction", 0, "0 = c->s, 1 = s->c (required)")
	offset := fs.Int64("offset", 0, "byte offset within the buffer")
	length := fs.Int64("length", 0, "number of bytes to read from offset; 0 = to the end")
	fs.Parse(args)

	if !flagWasSet(fs, "conn") {
		fail("--conn is required")
	}
	dir := parseDirection(fs, direction)

	conn, err := dialWS(*api, fmt.Sprintf("/api/i/tamper/watch?conn=%d", uint32(*connFlag)))
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	req := watchRequest{Type: "peek", Direction: dir, Offset: *offset, Length: *length}
	if err := conn.WriteJSON(req); err != nil {
		fail("send peek: %v", err)
	}

	type outBuffer struct {
		Direction   int    `json:"direction"`
		Time        int64  `json:"time"`
		Offset      int64  `json:"offset"`
		Length      int    `json:"length"`
		TotalLength int    `json:"total_length"`
		Bounds      []int  `json:"bounds"`
		DataBase64  string `json:"data_base64"`
	}

	var buffers []outBuffer
	for {
		var r peekReply
		if err := conn.ReadJSON(&r); err != nil {
			fail("read reply: %v", err)
		}
		switch r.Type {
		case "pending":
			_, data, err := conn.ReadMessage()
			if err != nil {
				fail("read chunk data: %v", err)
			}
			buffers = append(buffers, outBuffer{
				Direction: r.Direction, Time: r.Time,
				Offset: r.Offset, Length: r.Length, TotalLength: r.TotalLength, Bounds: r.Bounds,
				DataBase64: base64.StdEncoding.EncodeToString(data),
			})
		case "peek-done":
			printJSON(struct {
				Chunks []outBuffer `json:"chunks"`
			}{buffers})
			return
		case "error":
			fail("%s", r.Message)
		default:
			fail("unexpected reply type: %s", r.Type)
		}
	}
}

// parseBounds parses a comma-separated list of ints, e.g. "0,10,20".
func parseBounds(s string) []int {
	parts := strings.Split(s, ",")
	bounds := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			fail("invalid --bounds entry %q: %v", p, err)
		}
		bounds = append(bounds, n)
	}
	return bounds
}

func cmdTamperRelease(args []string) {
	fs := flag.NewFlagSet("tamper release", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	connFlag := fs.Uint64("conn", 0, "stream ConnID (required)")
	direction := fs.Int("direction", 0, "0 = c->s, 1 = s->c (required)")
	action := fs.String("action", "forward", "forward | drop")
	releaseChunks := fs.Int("release-chunks", 0, "how many chunks of the post-edit buffer to release; 0 = edit only, release nothing")
	edit := fs.String("edit", "", "path to replacement bytes, or - for stdin (mutually exclusive with --edit-base64)")
	editBase64 := fs.String("edit-base64", "", "replacement bytes as base64 (mutually exclusive with --edit)")
	prefixLength := fs.Int("prefix-length", 0, "bytes of the current buffer (as you last learned them via peek) this edit replaces; required if editing")
	bounds := fs.String("bounds", "0", `comma-separated chunk-boundary offsets within the replacement data, e.g. "0,10"; defaults to a single chunk`)
	fs.Parse(args)

	if !flagWasSet(fs, "conn") {
		fail("--conn is required")
	}
	dir := parseDirection(fs, direction)
	switch *action {
	case "forward", "drop":
	default:
		fail("--action must be forward or drop (use 'tapctl tamper drop-connection' to abort the connection)")
	}
	if *releaseChunks < 0 {
		fail("--release-chunks must be >= 0")
	}

	if *edit != "" && *editBase64 != "" {
		fail("--edit and --edit-base64 are mutually exclusive")
	}

	var editedData []byte
	edited := false
	switch {
	case *editBase64 != "":
		var err error
		editedData, err = base64.StdEncoding.DecodeString(*editBase64)
		if err != nil {
			fail("decode --edit-base64: %v", err)
		}
		edited = true
	case *edit != "":
		var err error
		if *edit == "-" {
			editedData, err = io.ReadAll(os.Stdin)
		} else {
			editedData, err = os.ReadFile(*edit)
		}
		if err != nil {
			fail("read --edit data: %v", err)
		}
		edited = true
	}

	if !edited && *releaseChunks == 0 {
		fail("nothing to do: set --edit/--edit-base64 and/or --release-chunks > 0")
	}
	if edited && !flagWasSet(fs, "prefix-length") {
		fail("--prefix-length is required when editing")
	}

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	connID := uint32(*connFlag)
	msg := outboundMsg{
		Type: "release", Conn: &connID, Direction: &dir,
		ReleaseChunks: *releaseChunks, Action: *action,
	}
	if edited {
		msg.Edited = &edited
		msg.PrefixLength = *prefixLength
		msg.Bounds = parseBounds(*bounds)
	}
	if err := conn.WriteJSON(msg); err != nil {
		fail("send release: %v", err)
	}
	if edited {
		if err := conn.WriteMessage(websocket.BinaryMessage, editedData); err != nil {
			fail("send edited data: %v", err)
		}
	}

	readAck(conn)
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdTamperDropConnection(args []string) {
	fs := flag.NewFlagSet("tamper drop-connection", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	connFlag := fs.Uint64("conn", 0, "stream ConnID (required)")
	direction := fs.Int("direction", 0, "0 = c->s, 1 = s->c (required)")
	fs.Parse(args)

	if !flagWasSet(fs, "conn") {
		fail("--conn is required")
	}
	dir := parseDirection(fs, direction)

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	connID := uint32(*connFlag)
	if err := conn.WriteJSON(outboundMsg{Type: "drop-connection", Conn: &connID, Direction: &dir}); err != nil {
		fail("send drop-connection: %v", err)
	}

	readAck(conn)
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdTamperSetMode(args []string) {
	fs := flag.NewFlagSet("tamper set-mode", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	connFlag := fs.Uint64("conn", 0, "stream ConnID (required)")
	intercepting := fs.Bool("intercepting", false, "true = intercept (hold), false = watch (pass through)")
	fs.Parse(args)

	if !flagWasSet(fs, "conn") {
		fail("--conn is required")
	}

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	connID := uint32(*connFlag)
	if err := conn.WriteJSON(outboundMsg{Type: "set-mode", Conn: &connID, Intercepting: intercepting}); err != nil {
		fail("send set-mode: %v", err)
	}

	readAck(conn)
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdTamperSetAutoIntercept(args []string) {
	fs := flag.NewFlagSet("tamper set-auto-intercept", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	enabled := fs.Bool("enabled", false, "whether newly-established connections start in intercept mode")
	fs.Parse(args)

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(outboundMsg{Type: "set-auto-intercept", Enabled: enabled}); err != nil {
		fail("send set-auto-intercept: %v", err)
	}

	readAck(conn)
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}
