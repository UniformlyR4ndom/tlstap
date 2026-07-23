package tamper

// msgType is the "type" field of every message the proxy sends to a control or watch
// client (JSON discriminator).
type msgType string

const (
	msgStreamCreated    msgType = "stream-created"    // control, unsolicited: a new stream appeared
	msgStreamTerminated msgType = "stream-terminated" // control, unsolicited: a stream ended
	msgHeld             msgType = "held"              // control, unsolicited: one new chunk was appended to a held buffer
	msgStreamList       msgType = "stream-list"       // control, reply to "list-streams"
	msgScriptUpdated    msgType = "script-updated"    // control, unsolicited: a script was written or deleted via REST
	msgOk               msgType = "ok"                // control, reply acknowledging a command
	msgError            msgType = "error"             // control or watch, reply to any failed command
	msgPending          msgType = "pending"           // watch, reply to "peek"
	msgPeekDone         msgType = "peek-done"         // watch, terminates a "peek" reply
)

// cmdType is the "type" field of every message a client sends to the proxy (JSON
// discriminator).
type cmdType string

const (
	cmdSetAutoIntercept cmdType = "set-auto-intercept" // control
	cmdSetMode          cmdType = "set-mode"           // control
	cmdRelease          cmdType = "release"            // control
	cmdDropConnection   cmdType = "drop-connection"    // control
	cmdListStreams      cmdType = "list-streams"       // control
	cmdScriptLog        cmdType = "script-log"         // control; fire-and-forget, no ok/error reply on success
	cmdPeek             cmdType = "peek"               // watch
)

// ── Outbound: control channel ───────────────────────────────────────────────────────

type streamCreatedMsg struct {
	Type msgType `json:"type"`
	Conn uint32  `json:"conn"`
	Src  string  `json:"src"`
	Dst  string  `json:"dst"`
}

type streamTerminatedMsg struct {
	Type msgType `json:"type"`
	Conn uint32  `json:"conn"`
}

// heldMsg announces that one new chunk was appended to one direction's held buffer.
// Offset/Length describe just that new chunk (not the buffer as a whole), so a connected
// client can extend its own locally-tracked bounds incrementally instead of re-peeking on
// every arrival; Offset doubles as a consistency check the client can use to detect it
// missed an event and should fall back to "peek" to resync.
type heldMsg struct {
	Type      msgType   `json:"type"`
	Conn      uint32    `json:"conn"`
	Direction direction `json:"direction"`
	Offset    int       `json:"offset"`
	Length    int       `json:"length"`
	Time      int64     `json:"time"`
}

// pendingInfo summarizes one direction's currently-held buffer as a chunk count + byte
// length — chunk boundaries aren't reported here; embedded in streamInfo so
// "list-streams" alone is a full resync.
type pendingInfo struct {
	Direction direction `json:"direction"`
	Chunks    int       `json:"chunks"`
	Length    int       `json:"length"`
}

type streamInfo struct {
	Conn         uint32        `json:"conn"`
	Src          string        `json:"src"`
	Dst          string        `json:"dst"`
	Intercepting bool          `json:"intercepting"`
	Pending      []pendingInfo `json:"pending"` // 0-2 entries: only directions with something held
}

type streamListMsg struct {
	Type    msgType      `json:"type"`
	Streams []streamInfo `json:"streams"`
}

// scriptUpdatedMsg announces that a script was written (PUT) or removed (DELETE) via the
// REST API — Name alone is enough for a client to know what to re-pull or forget; whether
// it still exists is a plain GET/list away, so no separate "deleted" flag is carried.
type scriptUpdatedMsg struct {
	Type msgType `json:"type"`
	Name string  `json:"name"`
}

// okMsg acknowledges a successful command. Failures use errorMsg instead.
type okMsg struct {
	Type    msgType `json:"type"`
	Command cmdType `json:"command"`
}

// ── Shared: control + watch ─────────────────────────────────────────────────────────

type errorMsg struct {
	Type    msgType `json:"type"`
	Message string  `json:"message"`
}

// ── Inbound: control channel ────────────────────────────────────────────────────────

// inboundMsg is a flexible container for every control-channel command, discriminated by
// Type; only the fields relevant to that Type are populated.
//
// A "release" with Edited=true must be immediately followed by a binary frame carrying
// the replacement bytes for the buffer's first PrefixLength bytes; Edited=false releases
// ReleaseChunks chunks of the buffer exactly as it stands (PrefixLength/Bounds ignored).
// PrefixLength is checked against the buffer's actual current length, rejecting a stale
// edit (e.g. one a hold-timeout already flushed) rather than silently misapplying it.
//
// "drop-connection" is its own command rather than a Release Action value, since it
// isn't parameterized by buffer content the way forward/drop are.
type inboundMsg struct {
	Type cmdType `json:"type"`

	Enabled *bool `json:"enabled,omitempty"` // set-auto-intercept

	Conn *uint32 `json:"conn,omitempty"` // set-mode; release; drop-connection

	Intercepting *bool `json:"intercepting,omitempty"` // set-mode

	Direction *direction `json:"direction,omitempty"` // release; drop-connection

	// release
	Edited        *bool  `json:"edited,omitempty"`
	PrefixLength  int    `json:"prefix_length,omitempty"`
	Bounds        []int  `json:"bounds,omitempty"`
	ReleaseChunks int    `json:"release_chunks,omitempty"`
	Action        action `json:"action,omitempty"`

	// script-log: one already-formatted line, pushed here purely for optional
	// server-side persistence. Level is "log" or "error"; Text may itself span
	// multiple lines.
	Level string `json:"level,omitempty"`
	Text  string `json:"text,omitempty"`
}

// ── Outbound: watch channel ─────────────────────────────────────────────────────────

// watchFrameMsg precedes a binary frame with the mirrored chunk's bytes, sent for every
// chunk actually forwarded on the stream. No Type field: a /watch connection has
// exactly one unsolicited shape, so there's nothing to discriminate.
type watchFrameMsg struct {
	Direction direction `json:"direction"`
	Time      int64     `json:"time"`
	Length    int       `json:"length"`
}

// pendingChunkMsg precedes a binary frame with the (possibly sliced) requested bytes, in
// reply to a "peek". Offset/Length describe the *returned slice*; TotalLength and Bounds
// always describe the whole buffer regardless of what was sliced, since a resync always
// wants the complete picture and both are cheap to include in full.
type pendingChunkMsg struct {
	Type        msgType   `json:"type"`
	Direction   direction `json:"direction"`
	Time        int64     `json:"time"`
	Offset      int64     `json:"offset"`
	Length      int       `json:"length"`
	TotalLength int       `json:"total_length"`
	Bounds      []int     `json:"bounds"`
}

// peekDoneMsg terminates a "peek" reply (one pendingChunkMsg + binary pair, or a single errorMsg).
type peekDoneMsg struct {
	Type msgType `json:"type"`
}

// ── Inbound: watch channel ──────────────────────────────────────────────────────────

// watchInboundMsg is the one command a /watch client may send: read the bytes of one
// direction's currently-held buffer. Direction is a pointer so a request that omits it
// is rejected rather than silently defaulting to directionC2S.
type watchInboundMsg struct {
	Type      cmdType    `json:"type"`
	Direction *direction `json:"direction"`
	Offset    int64      `json:"offset,omitempty"`
	Length    int64      `json:"length,omitempty"` // 0 = to the end of the buffer
}
