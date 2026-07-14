package tamper

// Messages sent from the proxy to the control client (WebSocket text frames).
// "held" is metadata-only — no binary frame follows. A held chunk's actual bytes are
// only obtainable via the "peek" command on that stream's /watch connection (see
// below), so that reconnecting to control at any time (via "list-streams") is enough
// to discover and act on everything currently outstanding, without having had to be
// connected at the exact moment a chunk was held.

type streamCreatedMsg struct {
	Type string `json:"type"` // "stream-created"
	Conn uint32 `json:"conn"`
	Src  string `json:"src"`
	Dst  string `json:"dst"`
}

type streamTerminatedMsg struct {
	Type string `json:"type"` // "stream-terminated"
	Conn uint32 `json:"conn"`
}

type heldMsg struct {
	Type      string `json:"type"` // "held"
	Conn      uint32 `json:"conn"`
	ID        int64  `json:"id"`
	Direction int    `json:"direction"`
	Time      int64  `json:"time"`
	Length    int    `json:"length"`
}

// pendingInfo describes one currently-held chunk, reported inline in streamInfo so
// that "list-streams" alone is enough to resync after (re)connecting to control.
type pendingInfo struct {
	ID        int64 `json:"id"`
	Direction int   `json:"direction"`
	Time      int64 `json:"time"`
	Length    int   `json:"length"`
}

type streamInfo struct {
	Conn         uint32        `json:"conn"`
	Src          string        `json:"src"`
	Dst          string        `json:"dst"`
	Intercepting bool          `json:"intercepting"`
	Pending      []pendingInfo `json:"pending"`
}

type streamListMsg struct {
	Type    string       `json:"type"` // "stream-list"
	Streams []streamInfo `json:"streams"`
}

type errorMsg struct {
	Type    string `json:"type"` // "error"
	Message string `json:"message"`
}

// okMsg acknowledges a successful "set-auto-intercept", "set-mode", or "resolve"
// command. Failures use errorMsg instead (missing required fields, an unknown stream
// for "set-mode", or an unknown/already-resolved chunk for "resolve").
type okMsg struct {
	Type    string `json:"type"` // "ok"
	Command string `json:"command"`
}

// watchFrameMsg precedes a binary frame with the mirrored chunk's bytes, sent on a
// per-stream /watch connection for every chunk actually forwarded (live mirror; see
// watchInboundMsg for reading currently-held, not-yet-forwarded chunks instead).
type watchFrameMsg struct {
	Direction int   `json:"direction"`
	Time      int64 `json:"time"`
	Length    int   `json:"length"`
}

// watchInboundMsg is the one command a /watch client may send: a request to read the
// bytes of one or all currently-held chunks for that stream (this is the only way to
// read a held chunk's bytes at all — see the note on held above).
type watchInboundMsg struct {
	Type string `json:"type"` // "peek"

	// ID omitted => return every currently-pending chunk for the stream (at most one
	// per direction), in full, ignoring Offset/Length. ID set => return just that one
	// chunk, sliced by Offset/Length if given.
	ID     *int64 `json:"id,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Length int64  `json:"length,omitempty"` // 0 = to the end of the chunk
}

// pendingChunkMsg precedes a binary frame with the (possibly sliced) requested bytes,
// sent in reply to a "peek" command.
type pendingChunkMsg struct {
	Type        string `json:"type"` // "pending"
	ID          int64  `json:"id"`
	Direction   int    `json:"direction"`
	Time        int64  `json:"time"`
	Offset      int64  `json:"offset"`       // start of the returned slice within the chunk
	Length      int    `json:"length"`       // length of the returned slice
	TotalLength int    `json:"total_length"` // full chunk length
}

// peekDoneMsg terminates a "peek" reply (0 or more pendingChunkMsg + binary pairs).
type peekDoneMsg struct {
	Type string `json:"type"` // "peek-done"
}

// inboundMsg is a flexible container for every control-channel command, discriminated
// by Type. A "resolve" message with Edited=true must be immediately followed by a
// binary frame carrying the replacement bytes.
type inboundMsg struct {
	Type string `json:"type"`

	// set-auto-intercept
	Enabled *bool `json:"enabled,omitempty"`

	// set-mode (also uses Conn); resolve (also uses Conn)
	Conn         *uint32 `json:"conn,omitempty"`
	Intercepting *bool   `json:"intercepting,omitempty"`

	// resolve
	ID     *int64 `json:"id,omitempty"`
	Action string `json:"action,omitempty"`
	Edited *bool  `json:"edited,omitempty"`
}
