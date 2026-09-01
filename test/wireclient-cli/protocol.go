// wireclient-cli is a configurable raw protocol client/server for exercising tlstap's
// framer scripts against real wire traffic — full control over framing details (masking,
// fragmentation, RSV bits, deliberate mid-frame truncation) that a real browser client
// can't reach, since browsers only expose message content/size, never the underlying wire
// framing choices.
//
// Usage: wireclient-cli --role client|server --protocol websocket --addr host:port
// [--tls] [--cert ... --key ...] [--insecure-skip-verify] [--path /chat]
// [--require-upgrade=true] [--send <spec>]... [--timeout 10s]
//
// --require-upgrade (server role, default true) enforces RFC 6455 §4.2.1's Upgrade-request
// validation (GET, HTTP/1.1+, Upgrade/Connection token lists, Sec-WebSocket-Version: 13, a
// well-formed Sec-WebSocket-Key) before switching protocols, matching how a real WebSocket
// endpoint behaves — by far the most common real-world setup. Disabling it only skips that
// validation (a request still needs a Sec-WebSocket-Key to compute Sec-WebSocket-Accept at
// all); it's a deliberate escape hatch, not the default, since it doesn't reflect anything
// most real servers actually do.
//
// --send is repeatable and executed in order once the connection/handshake completes.
// WebSocket spec vocabulary:
//
//	text:<payload>                      unfragmented text frame
//	binary:hex=<hex>                    binary frame, exact content
//	binary:size=<N>                     binary frame, N deterministic bytes (A-Z repeating)
//	fragment:text|binary:<p1>,<p2>,...  one logical message as real multi-frame fragmentation
//	frame:0|1:<opcode>:<payload>        one raw frame, explicit fin/opcode — composes across
//	                                    separate --send calls to put a control frame (e.g.
//	                                    ping) in the middle of a fragmented message, unlike
//	                                    fragment: which always sends a whole message at once
//	ping:[payload]                      explicit ping
//	pong:[payload]                      explicit, unsolicited pong
//	close:<code>:<reason>               Close frame with a specific status code
//	rsv:1|2|3:text|binary:<payload>     a reserved bit set (deliberately unnegotiated)
//	raw:<hex>                           write arbitrary raw bytes verbatim
//	sleep:<ms>                          pacing control between sends
//	truncate:<opcode>:size=<N>          write half of a frame's bytes (any opcode — notably
//	                                    continuation:, for cutting short an accumulating
//	                                    fragmented message's final piece), then sever the raw
//	                                    connection — no close handshake, no TLS close_notify
package main

import (
	"crypto/tls"
	"errors"
	"net"
)

// ErrTruncated is returned by Send when a spec deliberately severed the connection
// mid-frame (WebSocket's "truncate") — expected, not a failure.
var ErrTruncated = errors.New("connection truncated by spec")

type Role int

const (
	RoleClient Role = iota
	RoleServer
)

func (r Role) String() string {
	if r == RoleServer {
		return "server"
	}
	return "client"
}

// Options carries protocol-specific connection parameters that don't fit the generic
// role/addr/tls flags — e.g. WebSocket's Upgrade request path.
type Options struct {
	Path string
}

// Frame is one logged wire-level unit, sent or received, independent of protocol.
type Frame struct {
	Direction string // "sent" | "recv"
	Summary   string
}

// Protocol is the seam a new --protocol value implements. Only "websocket" exists today;
// an "http2" implementation (RFC 9113 frames via a raw Framer, its own --send vocabulary —
// headers/settings/rststream/goaway/...) would plug in here without changing main.go's
// send-sequence execution or logging at all — though it may or may not need the same
// client/server asymmetry below, since HTTP/2 negotiates via ALPN during the TLS handshake
// itself rather than an in-band HTTP request/response cycle.
//
// The client and server halves are deliberately asymmetric, not just role parameters of
// one Handshake method: a client's handshake runs over a connection the caller already
// established (dial, then upgrade). A server's *can't* be split that way and still validate
// properly — a WebSocket upgrade is fundamentally one real HTTP request/response cycle
// followed by a protocol switch, so correctly validating it (method, Upgrade/Connection
// headers, version, key) needs an actual net/http.Server + Hijacker, not a bare net.Conn
// main.go could pre-accept and hand off.
type Protocol interface {
	// HandshakeClient performs the client-side handshake over an already-connected conn
	// (TCP or TLS). rawConn is the underlying TCP connection even when conn is
	// TLS-wrapped, kept for actions (like WebSocket's "truncate") that need it.
	HandshakeClient(conn net.Conn, rawConn net.Conn, opts Options, log func(string)) (Session, error)
	// ListenAndHandshakeServer owns the full listen-accept-validate-upgrade sequence
	// itself, for exactly the reason in the Protocol doc above. tlsConfig is nil for a
	// plain-TCP server.
	ListenAndHandshakeServer(addr string, tlsConfig *tls.Config, opts Options, requireUpgrade bool, log func(string)) (Session, error)
	// Send executes one --send spec against an established session. ErrTruncated signals
	// the spec deliberately severed the connection — expected, not a failure, but the
	// caller must stop running any further specs.
	Send(session Session, spec string, log func(Frame)) error
	// ReadLoop reads and logs incoming frames until the connection closes or errors.
	// Returns nil on a clean peer-initiated close.
	ReadLoop(session Session, log func(Frame)) error
}

type Session interface {
	Close() error
}
