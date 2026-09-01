package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/url"
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
	case "script-log":
		cmdTamperScriptLog(args[1:])
	case "script-list":
		cmdTamperScriptList(args[1:])
	case "script-get":
		cmdTamperScriptGet(args[1:])
	case "script-put":
		cmdTamperScriptPut(args[1:])
	case "script-delete":
		cmdTamperScriptDelete(args[1:])
	case "framer-script-list":
		cmdTamperFramerScriptList(args[1:])
	case "framer-script-get":
		cmdTamperFramerScriptGet(args[1:])
	case "framer-script-put":
		cmdTamperFramerScriptPut(args[1:])
	case "framer-script-delete":
		cmdTamperFramerScriptDelete(args[1:])
	case "log-file":
		cmdTamperLogFile(args[1:])
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
  tapctl tamper script-log --level log|error --text TEXT [--api URL]
  tapctl tamper script-list [--api URL]
  tapctl tamper script-get --name NAME [--hash] [--api URL]
  tapctl tamper script-put --name NAME (--file PATH | --file -) [--api URL]
  tapctl tamper script-delete --name NAME [--api URL]
  tapctl tamper framer-script-list [--api URL]
  tapctl tamper framer-script-get --name NAME [--hash] [--api URL]
  tapctl tamper framer-script-put --name NAME (--file PATH | --file -) [--api URL]
  tapctl tamper framer-script-delete --name NAME [--api URL]
  tapctl tamper log-file [--api URL]

release combines an optional edit with an optional release, mirroring the server's
performAction: --release-chunks defaults to 0 (edit only, nothing released); pass a
positive count to also release that many chunks of the post-edit buffer. --edit/
--edit-base64 replace the buffer's first --prefix-length bytes (as you last learned them
via peek) with the given data; --bounds defaults to "0" (the whole edit as one chunk).

script-get prints the raw script source to stdout (not JSON-wrapped), so it's directly
pipeable, e.g. "tapctl tamper script-get --name foo > foo.js" — or, with --hash, prints
{"sha256":"..."} instead: the same "version" a framer/dissector run computes over this
same content (framerRun.js's sha256Hex; dbdump persists it as frames.script_version),
so a caller that already knows a script's name can learn its current version without a
separate hash step. script-put reads from --file (a path, or - for stdin), mirroring
release's --edit convention. Both act on the tamper interceptor's scripts-dir store; see
CLAUDE.md's "Script storage" section.

framer-script-list/-get/-put/-delete are the same four commands (including -get's --hash)
against tamper's separate framer-scripts-dir store (frame(state, chunk) scripts,
reassembling live traffic into frames for a selected interception script's onFrame hook)
— a distinct store/namespace from scripts-dir above, same name in both is not a collision.

script-log pushes one already-formatted log line for optional server-side persistence
(see the tamper interceptor's log-file config arg); it never gets a reply on success
(fire-and-forget, unlike every other control command), so tapctl doesn't wait for one —
it validates --level itself and exits immediately after sending.

log-file reports whether the interceptor was configured with log-file (see script-log
above) and the log's display filename; static for the server's whole run.
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
	Level         string  `json:"level,omitempty"`
	Text          string  `json:"text,omitempty"`
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

func cmdTamperScriptLog(args []string) {
	fs := flag.NewFlagSet("tamper script-log", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	level := fs.String("level", "log", "log | error")
	text := fs.String("text", "", "log line text (required)")
	fs.Parse(args)

	switch *level {
	case "log", "error":
	default:
		fail("--level must be log or error")
	}
	if *text == "" {
		fail("--text is required")
	}

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(outboundMsg{Type: "script-log", Level: *level, Text: *text}); err != nil {
		fail("send script-log: %v", err)
	}

	// Fire-and-forget: the server never replies on success (see
	// intercept/tamper/protocol.go's cmdScriptLog), so unlike every other control
	// command there's no readAck call here — the --level validation above already
	// rules out the one failure mode the server would otherwise report.
	printJSON(struct {
		Status string `json:"status"`
	}{"sent"})
}

// --- scripts (REST CRUD; see intercept/tamper/scripts.go) ---

func cmdTamperScriptList(args []string) {
	fs := flag.NewFlagSet("tamper script-list", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/tamper/scripts")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdTamperScriptGet(args []string) {
	fs := flag.NewFlagSet("tamper script-get", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "script name, without .js (required)")
	hash := fs.Bool("hash", false, "print the script's sha256 hex digest instead of its content")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	path := "/api/i/tamper/scripts/" + url.PathEscape(*name)
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

func cmdTamperScriptPut(args []string) {
	fs := flag.NewFlagSet("tamper script-put", flag.ExitOnError)
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

	if _, err := httpPutRaw(*api, "/api/i/tamper/scripts/"+url.PathEscape(*name), content, "application/javascript"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdTamperScriptDelete(args []string) {
	fs := flag.NewFlagSet("tamper script-delete", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "script name, without .js (required)")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	if _, err := httpDelete(*api, "/api/i/tamper/scripts/"+url.PathEscape(*name)); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

// --- framer scripts (REST CRUD; see intercept/tamper/api.go's second RegisterRoutes call) ---

func cmdTamperFramerScriptList(args []string) {
	fs := flag.NewFlagSet("tamper framer-script-list", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/tamper/framer/scripts")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}

func cmdTamperFramerScriptGet(args []string) {
	fs := flag.NewFlagSet("tamper framer-script-get", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "framer script name, without .js (required)")
	hash := fs.Bool("hash", false, "print the script's sha256 hex digest instead of its content")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	path := "/api/i/tamper/framer/scripts/" + url.PathEscape(*name)
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

func cmdTamperFramerScriptPut(args []string) {
	fs := flag.NewFlagSet("tamper framer-script-put", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "framer script name, without .js (required)")
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

	if _, err := httpPutRaw(*api, "/api/i/tamper/framer/scripts/"+url.PathEscape(*name), content, "application/javascript"); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

func cmdTamperFramerScriptDelete(args []string) {
	fs := flag.NewFlagSet("tamper framer-script-delete", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	name := fs.String("name", "", "framer script name, without .js (required)")
	fs.Parse(args)

	if *name == "" {
		fail("--name is required")
	}

	if _, err := httpDelete(*api, "/api/i/tamper/framer/scripts/"+url.PathEscape(*name)); err != nil {
		fail("%v", err)
	}
	printJSON(struct {
		Status string `json:"status"`
	}{"ok"})
}

// --- log-file (REST; see intercept/tamper/api.go's handleLogFileInfo) ---

func cmdTamperLogFile(args []string) {
	fs := flag.NewFlagSet("tamper log-file", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	fs.Parse(args)

	data, err := httpGet(*api, "/api/i/tamper/log-file")
	if err != nil {
		fail("%v", err)
	}
	printRawJSON(data)
}
