package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"

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
	case "resolve":
		cmdTamperResolve(args[1:])
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
  tapctl tamper peek --conn N [--id N] [--offset N] [--length N] [--api URL]
  tapctl tamper resolve --conn N --id N --action forward|drop|drop-connection [--edit PATH|-] [--api URL]
  tapctl tamper set-mode --conn N --intercepting=true|false [--api URL]
  tapctl tamper set-auto-intercept --enabled=true|false [--api URL]
`)
}

// --- wire types ---
//
// These mirror the JSON shapes documented in intercept/tamper/protocol.go and
// CLAUDE.md, kept local (rather than importing the tamper package) since tapctl only
// ever speaks the public wire protocol, exactly like any other client would.

// outboundMsg covers every control-channel command tapctl sends.
type outboundMsg struct {
	Type         string  `json:"type"`
	Enabled      *bool   `json:"enabled,omitempty"`
	Conn         *uint32 `json:"conn,omitempty"`
	Intercepting *bool   `json:"intercepting,omitempty"`
	ID           *int64  `json:"id,omitempty"`
	Action       string  `json:"action,omitempty"`
	Edited       *bool   `json:"edited,omitempty"`
}

// watchRequest is the "peek" command sent on a /watch connection.
type watchRequest struct {
	Type   string `json:"type"`
	ID     *int64 `json:"id,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Length int64  `json:"length,omitempty"`
}

// ackReply is the {"type":"ok"|"error",...} shape every set-auto-intercept/set-mode/
// resolve command receives back.
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
	ID          int64  `json:"id"`
	Direction   int    `json:"direction"`
	Time        int64  `json:"time"`
	Offset      int64  `json:"offset"`
	Length      int    `json:"length"`
	TotalLength int    `json:"total_length"`
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

func cmdTamperPeek(args []string) {
	fs := flag.NewFlagSet("tamper peek", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	connFlag := fs.Uint64("conn", 0, "stream ConnID (required)")
	idFlag := fs.Int64("id", 0, "specific chunk id (omit to peek every currently pending chunk)")
	offset := fs.Int64("offset", 0, "byte offset within the chunk (only applies with --id)")
	length := fs.Int64("length", 0, "number of bytes to read from offset; 0 = to the end (only applies with --id)")
	fs.Parse(args)

	idSet := flagWasSet(fs, "id")

	if !flagWasSet(fs, "conn") {
		fail("--conn is required")
	}

	conn, err := dialWS(*api, fmt.Sprintf("/api/i/tamper/watch?conn=%d", uint32(*connFlag)))
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	req := watchRequest{Type: "peek", Offset: *offset, Length: *length}
	if idSet {
		req.ID = idFlag
	}
	if err := conn.WriteJSON(req); err != nil {
		fail("send peek: %v", err)
	}

	type outChunk struct {
		ID          int64  `json:"id"`
		Direction   int    `json:"direction"`
		Time        int64  `json:"time"`
		Offset      int64  `json:"offset"`
		Length      int    `json:"length"`
		TotalLength int    `json:"total_length"`
		DataBase64  string `json:"data_base64"`
	}

	var chunks []outChunk
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
			chunks = append(chunks, outChunk{
				ID: r.ID, Direction: r.Direction, Time: r.Time,
				Offset: r.Offset, Length: r.Length, TotalLength: r.TotalLength,
				DataBase64: base64.StdEncoding.EncodeToString(data),
			})
		case "peek-done":
			printJSON(struct {
				Chunks []outChunk `json:"chunks"`
			}{chunks})
			return
		case "error":
			fail("%s", r.Message)
		default:
			fail("unexpected reply type: %s", r.Type)
		}
	}
}

func cmdTamperResolve(args []string) {
	fs := flag.NewFlagSet("tamper resolve", flag.ExitOnError)
	api := fs.String("api", defaultAPI, "API server root")
	connFlag := fs.Uint64("conn", 0, "stream ConnID (required)")
	idFlag := fs.Int64("id", 0, "held chunk id (required)")
	action := fs.String("action", "forward", "forward | drop | drop-connection")
	edit := fs.String("edit", "", "path to replacement bytes, or - for stdin (forward only)")
	fs.Parse(args)

	if !flagWasSet(fs, "conn") {
		fail("--conn is required")
	}
	if !flagWasSet(fs, "id") {
		fail("--id is required")
	}
	switch *action {
	case "forward", "drop", "drop-connection":
	default:
		fail("--action must be forward, drop, or drop-connection")
	}

	var editedData []byte
	edited := false
	if *edit != "" {
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

	conn, err := dialWS(*api, "/api/i/tamper/control")
	if err != nil {
		fail("connect: %v", err)
	}
	defer conn.Close()

	connID := uint32(*connFlag)
	msg := outboundMsg{Type: "resolve", Conn: &connID, ID: idFlag, Action: *action}
	if edited {
		msg.Edited = &edited
	}
	if err := conn.WriteJSON(msg); err != nil {
		fail("send resolve: %v", err)
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
