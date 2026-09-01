# HTTP/1 Framer — design notes

**Status: implemented (2026-08-11/12); gap-fixing pass and WebSocket-upgrade support added
2026-08-24, verified only via throwaway Node smoke tests (not committed) — not yet
re-verified in a real browser against live traffic.** This documents
`examples/dbdump/framer/http1-framer.js` / `examples/dbdump/dissect/http1-dissector.js`
(closing out the last item in root `CLAUDE.md`'s TODO section) and the gap that surfaced
while planning it: correct HTTP/1 message-length framing needs information from the
*other* direction's stream, which the framer architecture had no way to provide before
combined mode. Was blocked on
[`doc/design/framer-cross-direction-correlation.md`](framer-cross-direction-correlation.md)
landing first — implemented as "combined mode" (one script instance per stream,
processing both directions' chunks merged into one chronological, `stid`-ordered
sequence, one shared `state`), which turns out to make *every* cross-direction case below
solvable, not just the one it was designed for — see its "Bonus this unlocks for HTTP/1"
section. Verified via a throwaway Node smoke test (39 checks: every message-length rule
below, pipelining, truncation, and error/desync paths — not committed, same convention as
every other example script's own verification) and **confirmed working end-to-end in a
real browser** against real HTTP/1.1 traffic — both a local origin (plain GET/HEAD/
chunked/truncated/large-body cases) and, through the TLS proxy against a real external
site (httpbin.org, SNI/Host-spoofed via `127.0.0.1`), a much wider variety: POST/PUT/
DELETE with request bodies, redirects (pipelined request/response pairs on one
connection), gzip content, multiple `Set-Cookie` headers, various status codes, Basic
auth, and an `Expect: 100-continue` exchange — the last of which surfaced a real bug (see
"Known limitations" below) that got fixed as a direct result of that traffic.

## What problem this solves

Same shape as the HTTP/2 pair (`examples/dbdump/framer/http2-framer.js`/
`examples/dbdump/dissect/http2-dissector.js`): split a stream into logical HTTP/1
messages and produce a Wireshark-style field tree for each one. Kept as a separate
script pair from HTTP/2, not a single ALPN-branching script — see root `CLAUDE.md`'s TODO
entry for that decision (already settled, unaffected by anything below).

## Message-length rules (RFC 9112 §6.3) and what they need

- **Self-contained per message** (only that message's own start-line/headers) —
  straightforward:
  - 1xx/204/304 responses → no body.
  - `Transfer-Encoding: chunked` as the final coding → read chunks to the terminator.
  - `Content-Length` → fixed length (reject mismatched duplicate values).
  - Neither present: request → no body; response → connection-close-delimited
    (the existing `chunk.closed` signal, built for exactly this case, is already usable
    here unmodified).
  - A 2xx response to `CONNECT` has no `Content-Length`/`Transfer-Encoding` either, but
    is specially classified (`body.kind: 'tunnel'`) rather than left to fall into the
    close-delimited case above — see "Tunnel/HTTP-0.9 fallback: raw per-chunk frames"
    below for what that classification actually triggers (added 2026-08-24; originally
    this bullet described it degrading into one oversized close-delimited frame with "no
    special-casing needed" — no longer true).
- **Needs the *other* direction's stream** — now solvable in full, via combined mode's
  single shared `state` (one script instance sees both directions' chunks in true
  chronological order, so a fact recorded while processing a `c2s` chunk is already
  available by the time a later, correlated `s2c` chunk arrives — see the mechanism doc):
  - **Any response to a `HEAD` request has no body**, even if it carries a
    `Content-Length` that looks otherwise definitive (RFC 9112 §6.3 rule 1, checked
    *before* Transfer-Encoding/Content-Length are even consulted). This is the pervasive
    case: it applies to *every* response, not just ambiguous ones, since a
    `Content-Length`-bearing response can still be a HEAD response with zero actual body
    bytes on the wire. Solved by keeping an ordered queue of request methods in `state`,
    pushed to on each request, shifted on each response — but **only a final (`>= 200`)
    response shifts**; a 1xx interim response (`100 Continue` in practice) is not the
    request's actual final response per RFC 9112 and must not consume the queue slot, or
    the real final response's own lookup (and every later response's, until the queue
    happens to re-align) shifts by one. Found via real `Expect: 100-continue` traffic
    during browser verification — see "Known limitations" below for the case this could
    have silently misclassified before the fix.
  - **Protocol upgrade** (`101 Switching Protocols`): the `s2c` branch sets
    `state.upgraded = true` on seeing it; the `c2s` branch checks that flag before
    attempting to parse further bytes as HTTP (post-upgrade client bytes always arrive
    later in the merged sequence than the 101 response, since the client waits for it) —
    stops cleanly instead of throwing on the first unparseable start-line.
  - **`CONNECT` tunnels**: the `c2s` branch records "request N was CONNECT" in
    `pendingMethods`; the `s2c` branch checks it when classifying the matching response,
    so the tunnel gets labeled correctly (`body.kind: 'tunnel'`) instead of merely
    falling into the close-delimited fallback by accident. What that labeling triggers —
    `state.tunneled` and raw per-chunk frames in both directions — is covered below.

## Tunnel/HTTP-0.9 fallback: raw per-chunk frames (added 2026-08-24)

Two situations leave this script with nothing left to parse as HTTP, but aren't a hard
error either — a `CONNECT` tunnel (both directions become opaque tunneled bytes, e.g. TLS
for an HTTPS-through-proxy connection) and an HTTP/0.9 response (no length signal at all,
raw bytes to connection close). Both fall back to the same mechanism: one
`{meta: {kind: 'raw', reason}}` frame per incoming chunk, covering exactly that chunk's
bytes with no further structure — visible in Frame view rather than silently vanishing,
without pretending to find structure that isn't there. `reason` is `'tunnel'` or
`'http09-response'`; the dissector renders a plain "Reason"/"Data" (hexdump) pair for
either.

- **`CONNECT` tunnel** — bilateral (`state.tunneled`, both directions gate on it at the
  top of `frame()`): once the 2xx response to `CONNECT` is classified, its own message
  frame is finished immediately (`body.kind: 'tunnel'`, zero-length — the tunnel-begins
  marker, not the tunnel payload itself), and any bytes already sitting past the response
  headers in that *same* chunk are emitted as one raw frame right there — they can't be
  left in a carry buffer, since `state.tunneled` short-circuits every future call for
  either direction before it would ever look at one again. This also fixes a real gap:
  the `c2s` side's own tunneled bytes (e.g. the client's actual TLS ClientHello, sent
  through the tunnel) previously got no frame at all — only the `s2c` side accumulated
  into one non-incremental frame at connection close. Both directions now stream raw
  frames incrementally instead.
- **HTTP/0.9 response** — unilateral (`state.s2cUnframable`, `s2c` only): see the HTTP/0.9
  section below for why only `s2c` gives up.

**Why not try to reconstruct message boundaries within the raw span** (e.g. splitting a
`CONNECT` tunnel's traffic back into "messages", or an HTTP/0.9 connection's — hypothetical,
since 0.9 forbids more than one exchange per connection anyway — multiple responses): the
underlying bytes carry no boundary information at all once the fallback triggers. Any split
would be an arbitrary heuristic presented as if it meant something, which is worse than no
split — one raw frame per chunk makes no claim beyond "the platform happened to hand this
many bytes to `frame()` at once," which is honest about what it is.

## HTTP/0.9 (added 2026-08-24)

An `HTTP/0.9` simple-request (`METHOD target\r\n` — no version, no headers) is detected in
the `c2s`, `phase === 'start-line'` branch when a request-line has exactly two
space-separated tokens instead of three (no HTTP-version) and the first token is a
plausible method (RFC 9110 §5.6.2 token charset) rather than throwing outright. It's framed
as one small `http-request` frame (`version: 'HTTP/0.9'` synthesized, empty headers,
`body.kind: 'none'`, tagged `meta.http09: true`), a `framer.log` warning is emitted, and
`state.s2cUnframable` is set.

**Why only `s2c` gives up, not `c2s`:** a genuine HTTP/0.9 exchange is inherently one-shot —
the original spec (there is no RFC for HTTP/0.9 itself; see the W3C "HTTP as implemented in
early 1991" page) is explicit that "the TCP-IP connection is broken by the server when the
whole document has been transferred," with no provision anywhere for a second request on
the same connection. So a compliant 0.9 client never sends anything more, and leaving `c2s`
running costs nothing in that case. What it buys: a hedge against *misdetecting* a
corrupted or capture-misaligned HTTP/1.x stream as 0.9 — if this 2-token line was a fluke
rather than real 0.9, later genuine requests on `c2s` get a chance to resync and frame
correctly instead of the whole connection going dark. (`state.s2cUnframable` has to be
carried forward explicitly each call — `!!state.s2cUnframable`, not a fresh `false` — unlike
the bilateral flags below, because `c2s` keeps running and rewriting `state` after it's set;
resetting to a fresh default each call would silently clear it on the very next `c2s` call.)

**Why `s2c` can't do anything better than raw per-chunk frames**: an HTTP/0.9 response has
no length signal of any kind. If the (non-compliant) connection somehow carries a second
response after the first, there is no byte-level way to tell where response 1 ends and
response 2 begins — not even by chunk arrival time, since ordinary network latency can
interleave a still-in-flight response 1 with a client that, for whatever reason, has already
started sending more `c2s` data. No split is attempted; see "Why not try to reconstruct
message boundaries" above.

## WebSocket upgrade (RFC 6455, added 2026-08-24)

`state.upgraded`'s old meaning — "the connection left HTTP, stay silent forever" — becomes
"switch both directions into WebSocket framing instead." No separate script pair: the
current one-framer-per-stream architecture has no way to hand a stream from one script to
another mid-connection, and this script is the only one that ever sees the Upgrade
handshake and knows exactly where the transition happens, so WebSocket support has to live
here rather than in a new file — a deliberate scope expansion of what this script *is*
(HTTP/1-then-WebSocket, not pure HTTP/1), decided rather than a side effect.

**Frame granularity: one wire frame = one tlstap frame, *except* a fragmented data
message, reassembled into one multi-range frame** (`advanceWebSocket`/`wsFrameMeta`/
`finalizeMessage`). A control frame (ping/pong/close) is independently self-delimited on
the wire and always gets its own single-range tlstap frame, `kind: 'websocket-frame'` —
unchanged since this section was first written, and unaffected by whether a data message
is mid-reassembly around it: a control frame can legally interleave between the fragments
of an in-progress message (RFC 6455 §5.4), and never touches the accumulator below. An
**unfragmented** Text/Binary message (`fin: true` on its own first frame — the
overwhelming common case) is likewise still emitted immediately as its own single-range
`kind: 'websocket-frame'`, byte-for-byte the same as before reassembly existed — this was
a deliberate design call (2026-08-31, see root `CLAUDE.md`'s "Overlapping/interleaved
frames" TODO entry) to keep the dissector's existing, already-verified code path for the
common case completely untouched, rather than unifying every data message under one meta
shape for architectural cleanliness alone.

A genuinely **fragmented** message (`fin: false` start, then one or more continuations)
is instead accumulated in `state.ws[dir].pendingMessage` — `{messageOpcode, ranges,
fragments}` — across as many `frame()` calls as it takes, and only finalized into one
tlstap frame, `kind: 'websocket-message'`, on the `fin: true` continuation that completes
it. `ranges` is each fragment's own full wire span (header + mask + payload), in
arrival order — the frame's own bytes, as `dissect()` receives them, are exactly this
concatenation, with no gap for whatever control frame may have physically interrupted the
sequence in between (its own bytes belong to its own, separately-emitted frame — never
double-fetched *or* dropped, since the two frames' `ranges` simply don't overlap).
`meta.fragments: [{payloadOffset, payloadLength, maskKey?}]` locates each fragment's own
payload within that concatenation (`payloadOffset` frame-relative, mirroring
`body.chunks`' own convention) for the dissector to unmask-then-concatenate into the
logical message body — see `http1-dissector.js`'s `websocketMessageNodes`. This needed no
new signal from the platform at all: `frame(state, chunk)`'s existing contract already
lets a script hold state across calls and defer returning a frame indefinitely, the same
mechanism `frames.seq` exists to support for an unrelated reason (a script revealing a
held frame once a correlated one is also ready). The platform-side prerequisite this
relied on — frame view actually being able to fetch/render a multi-range frame correctly
— is `frameSegmentsCore.js`'s/`frameSegments.js`'s virtual-addressing design (see
`web/CLAUDE.md`'s "Frame-mode adapter" bullet), done 2026-08-31, before this reassembly
was built.

**`meta.messageOpcode`**: still present on every data-message frame (Text/Binary), but no
longer needs to be threaded onto a continuation frame's own record the way it once did —
a continuation is never independently emitted any more, so `messageOpcode` now lives once
on the finalized frame (`kind: 'websocket-message'`) or on an unfragmented message's own
single frame (`kind: 'websocket-frame'`), never on a bare per-wire-frame basis. Absent for
a control frame either way.

**Scope cuts, both deliberate:**
- **No decompression** (`permessage-deflate`, RFC 7692), even though `rsv1` is captured.
  The framer has no good way to hand decompressed bytes to the dissector — the only
  channel is `meta`, and a decompressed payload has no byte-for-byte correspondence to the
  wire span it came from, unlike the RSV1 bit or the mask key, breaking the offset/length
  contract every other dissector node relies on for hex-view highlighting (same reason
  `http2-dissector.js` renders decoded HPACK headers as `content`-only nodes with no
  highlightable range — a reassembled block has no single wire span either). Decompression
  is a dissector-only concern if it happens at all, and it isn't attempted yet. When it is,
  it will hit the same wall HPACK decoding did on the dissector side: `permessage-deflate`
  with context takeover needs a persistent inflate dictionary across an entire session,
  which a stateless one-shot `dissect()` call can't hold — realistically restricting
  correct decompression to `no_context_takeover`-negotiated connections unless dissector
  scripts eventually gain cross-call state of their own. Left to a future dissector
  overhaul/expansion, not solved here.
- **No unmasking in the framer.** Unlike decompression, unmasking *is* a stateless,
  byte-for-byte transform (XOR against a 4-byte key, no cross-frame state) with the offset
  correspondence intact — byte *i* of the unmasked view is still exactly byte *i* of the
  wire payload — so it's cleanly a dissector-only concern instead, done for display only in
  `http1-dissector.js`'s `unmaskPayload`. The framer only captures `masked`/`maskKey` as
  structural meta — per fragment (`meta.fragments[].maskKey`) for a reassembled message,
  since RFC 6455 gives every wire frame, fragments included, its own independent key, never
  one shared per message.
- **Opcode names and close-code names** (RFC 6455 §5.2/§7.4.1) live in the dissector too,
  matching the precedent already set by `http2-dissector.js`'s RST_STREAM/GOAWAY error-code
  lookup — the framer captures only the raw numeric `opcode`/close status code.

**Leniency, matching this script's stance everywhere else**: nothing about a reserved
opcode, an RSV bit set with no extension negotiated, a control frame exceeding the
125-byte limit, or a mask bit not matching the expected per-direction convention (client
frames masked, server frames not) actually breaks this script's ability to correctly
delimit the frame — none of these throw, all are captured as raw fields for the dissector
to flag if it chooses to. Two things do throw, as misalignment signals: an implausible
declared payload length (`MAX_WS_PAYLOAD`, same sanity-cap role as `MAX_CHUNK_SIZE`), and
a continuation frame arriving with no message currently being accumulated (a genuine
protocol violation, not a leniency case — there's no coherent way to attribute it to any
message).

**Truncation at connection close** mirrors the `content-length` precedent for a
*non-accumulating* frame (a control frame, or an unfragmented message) exactly: cut short
mid-header (nothing coherent) is dropped silently; cut short mid-payload is still flushed
with `truncated: true` and the actual available length, not the declared one. A message
*mid-accumulation* when the connection closes is never silently dropped, though, unlike
before reassembly existed — whatever fragments already completed are flushed as one
`truncated: true` `websocket-message` frame, whether the close arrives with the final
fragment itself cut short mid-payload, or with no further fragment header ever arriving at
all (`abandonPendingOnClose` in `advanceWebSocket`) — the latter case has no precedent
elsewhere in this script, since every other truncation case here already has at least a
partial header to reason about.

**Leftover bytes bundled with the 101 response** (same concern the CONNECT tunnel case
already has, and the same fix): if the 101 response and the first WebSocket frame(s)
arrive in the same read, they're parsed inline within the same call rather than left in a
carry buffer nothing will read again — `state.ws[dir]`'s carry has to be threaded through
this path explicitly rather than via the shared write-back at the bottom of `frame()`,
since `upgraded`/`tunneled`/`s2cUnframable` reset to a fresh `false`/`carried-forward`
value every call but `state.ws` must not be clobbered on ordinary (non-transitioning)
calls.

## Proposed design (pending the mechanism doc)

**Frame granularity:** one frame = one complete HTTP message (start-line + headers +
body), like `tls-framer.js`'s one-frame-per-record — not split into separate
headers-frame/body-frame(s) the way `http2-framer.js` splits HEADERS/DATA. HTTP/2 splits
because the wire format itself is small independent frames; HTTP/1 has no equivalent
seam, and Wireshark treats a whole HTTP/1 message as one PDU too. Body chunk breakdown
(for `Transfer-Encoding: chunked`) is still visible via the dissector's per-chunk
sub-nodes, not via separate top-level frames.

**`meta` shape** (attached to the one frame per message, all offsets relative to the
frame — mirrors how `http2-framer.js` attaches fully-parsed `meta.headers` rather than
making the dissector reparse HPACK):

```js
{
  kind: 'http-request' | 'http-response',
  method, target, version,           // request
  statusCode, reasonPhrase, version, // response
  startLine: { offset, length },
  headers: [{ name, value, offset, length }], // one entry per header line
  body: {
    kind: 'none' | 'content-length' | 'chunked' | 'close-delimited' | 'tunnel',
    offset, length,                  // raw wire span (chunk framing included)
    chunks: [{ sizeOffset, sizeLength, dataOffset, dataLength }], // kind==='chunked' only
    trailers: [{ name, value, offset, length }],                  // kind==='chunked' only
  },
}
```
`'none'` covers 1xx/204/304 *and* HEAD responses (both are unconditionally zero-length,
just for different reasons); `'tunnel'` is the `CONNECT`-response case, zero-length — a
"tunnel begins here" marker on the response's own frame, not the tunnel payload itself
(see "Tunnel/HTTP-0.9 fallback" above for where that payload actually goes). A request
frame may also carry `http09: true` (HTTP/0.9 simple-request, `version` synthesized as
`'HTTP/0.9'` since it's not actually on the wire).

A second, unrelated `meta` shape — `{ kind: 'raw', reason: 'tunnel' | 'http09-response' }`
— covers the raw per-chunk fallback frames themselves; see "Tunnel/HTTP-0.9 fallback"
above.

Chunked-encoding parsing happens **only in the framer** (it already has to, to find the
message's total length) — the dissector consumes the pre-computed `chunks`/`trailers`
layout rather than re-parsing, same division of labor HTTP/2's HPACK-in-the-framer
already established.

**State machine**: under combined mode (see the mechanism doc), `state` carries *two*
independent sub-state-machines — `state.c2s`/`state.s2c`, each its own `carry` buffer and
parse position, the same per-direction shape every other example framer's `state` already
has — plus the shared correlation data (pending request methods, `upgraded` flag) neither
sub-machine owns alone. `frame(state, chunk)` dispatches on `chunk.direction` to advance
the right sub-machine: `awaiting-start-line → awaiting-headers → { fixed-length body |
chunked body (chunk-size → chunk-data → … → trailers) | close-delimited (consumes until
chunk.closed) | tunnel (consumes until chunk.closed, same as close-delimited but labeled
per the CONNECT-tracking above) } → emit frame, repeat`. A `while` loop over each
direction's own buffer like `http2-framer.js`'s, since multiple messages
(pipelining/keep-alive) can land in one chunk.

Because chunks arrive in true merged chronological order, the `awaiting-headers → decide
body kind` step for a response always has whatever it needs from `state` already —
there's no "not enough peer data yet" case to handle; the ordering guarantee (a
response's bytes never precede its request's) makes one pass always sufficient.

**Error handling**, matching existing precedent: a genuine desync with no way to recover
(bad start-line, conflicting `Content-Length` values, request `Transfer-Encoding` with a
non-final `chunked`) → throw, same as HTTP/2's `CONTINUATION`-without-`HEADERS` case. A
recoverable oddity (response `Transfer-Encoding` present but not chunked-final) →
`framer.log` a warning and fall back to close-delimited, same spirit as the HPACK-failure
latch.

**Dissector**: start-line fields, one clickable node per header (via `meta.headers`'
offsets), and a body node — content-length/close-delimited body as one clickable raw
span, chunked body as a parent node with one child per `meta.body.chunks` entry
(chunk-size, chunk-data, CRLF) plus a trailers list. Same per-frame-type structural
breakdown style as `http2-dissector.js`.

**Files**: `examples/dbdump/framer/http1-framer.js`,
`examples/dbdump/dissect/http1-dissector.js`; verified the same way as the HTTP/2 pair —
a throwaway Node smoke test (not committed) plus a real browser check against captured
traffic.

## Decisions made during implementation

- **Per-header `offset`/`length`**: yes — matches the HTTP/2 dissector's
  click-to-highlight-one-header granularity. The framer already scans the header block
  line by line to find its terminator, so tracking each line's own span while doing that
  is close to free.
- **`state.upgraded`/tunnel tracking stopping the framer from attempting further HTTP
  parsing**: yes, for both — originally unified into one shared `state.passthrough` flag
  (silent no-op once set); split 2026-08-24 into `state.upgraded` (101, stays silent —
  a real WebSocket framer is the intended eventual home for that traffic, not this
  script) and `state.tunneled` (CONNECT, now raw per-chunk frames instead of silence —
  see "Tunnel/HTTP-0.9 fallback" above) once the two stopped behaving the same way. A
  third, unilateral flag, `state.s2cUnframable`, handles HTTP/0.9 the same way as
  `state.tunneled` but only gates `s2c` — see the HTTP/0.9 section above for why `c2s`
  deliberately keeps running instead of joining it.
- **Truncation at connection close** (not an original open item, but came up
  implementing "Self-contained per message" above): a message cut short by `chunk.closed`
  mid-headers has nothing coherent to frame and is silently dropped; one cut short
  mid-body (content-length short of its declared length, or chunked encoding not yet
  reaching its terminator) is still flushed as a frame, with `body.truncated: true` set
  so a viewer can tell the difference from a message that completed normally.
- **Obsolete line folding** (RFC 9112 §5.2, added 2026-08-24): `scanHeaderLines`
  (shared by the main header block and chunked trailers) unfolds rather than rejects — a
  line starting with SP/HTAB is never itself a candidate header line (its grammar,
  `field-name`, can't start with whitespace), so the check is a reliable, zero-ambiguity
  discriminator, not a heuristic. A blank line can never be misread as a fold either:
  folding requires RWS (>=1 SP/HTAB) right after the CRLF, which an immediately following
  second CRLF can't satisfy, so the existing terminator check stays first and
  unconditional. Continuation lines are joined onto the *previous* header's `value` with
  a single SP (the RFC's own sanctioned fallback for a recipient that isn't rejecting),
  and that header's `length` is extended to cover every line it now spans, so
  click-to-highlight in hex view covers the whole folded field, not just its first line.
  A §2.2 orphan fold (whitespace-prefixed line with no preceding header in this block —
  no previous field-line, e.g. it's the very first line right after the start-line's
  CRLF, — to append to at all) is logged and discarded rather than folded into anything.
  One `framer.log` warning per folded header (tracked via a local `foldedHeader`
  reference, reset whenever a real header line is seen), not one per continuation line —
  a value folded across several lines would otherwise spam the log once per line. Minor,
  accepted imprecision: that per-header warning dedup is scoped to one `scanHeaderLines`
  call, so a fold whose continuation lines happen to be split across separate `frame()`
  calls (a chunk boundary landing mid-fold) could log twice instead of once — not worth
  carrying a dedup marker across calls for.

## Known limitations

- **A `close-delimited` response on a connection the peer doesn't actually close breaks
  framing for everything after it**, most plausibly a non-2xx `CONNECT` response (e.g.
  `407`) with no `Content-Length`/`Transfer-Encoding` on a connection kept alive for a
  client retry (standard proxy-auth flow) — subsequent bytes, including a *successful*
  retry's tunnel, get silently swallowed as more of the undelimited body instead of
  framed. Inherent to close-delimited framing itself (no terminator exists but the
  close), and the peer is already non-compliant in this scenario (RFC 9112 requires an
  explicit length to keep a connection alive) — not something a heuristic can safely fix.
- **A `Content-Length`+`Transfer-Encoding` combination on one message is logged, not
  rejected.** RFC 9112 §6.3 rule 3 says Transfer-Encoding overrides Content-Length in this
  case, calls the combination a possible request-smuggling/response-splitting signal, and
  says it "ought to be handled as an error" — specifically, an intermediary that forwards
  the message MUST strip the Content-Length field first. `dbdump`'s framer is read-only
  over a passive capture (there is no outgoing stream it controls or could sanitize before
  forwarding), so it cannot satisfy that MUST; `classifyRequestBody`/`classifyResponseBody`
  resolve the length per Transfer-Encoding as the spec requires and `framer.log` a warning
  naming the anomaly, but never throw for this case alone — the traffic still gets framed,
  since flagging-and-showing is more useful here than refusing to parse it. Accepted
  gap (2026-08-24).
- **A `frames.seq`-based "neat interleaving" toggle would not fix `Expect:
  100-continue`'s response-before-request display order**, even once built. With
  `100-continue`, the wire order is genuinely `request-headers → 100-Continue → request-
  body → final-response`; since one frame spans a whole message *including its body*, the
  request frame isn't complete (and so isn't emitted) until the request-body chunk is
  processed — chronologically *after* the interim response. Its `stid` (always resolved
  from a frame's own last byte) ends up larger than `100 Continue`'s, so it sorts after
  it in the default view. `frames.seq` doesn't help here: this framer never holds an
  already-complete frame back to reorder it — it emits synchronously the instant a
  message completes — so `seq` order and `stid` order are identical for every frame this
  script produces; there's nothing later to defer *to*. Actually fixing the display order
  would need a frame-granularity change (splitting a message into a headers-frame and a
  body-frame when they're chronologically split like this, similar to how
  `http2-framer.js` splits HEADERS/DATA) — a real reversal of this doc's explicit
  "one frame = one whole message" choice, not attempted given how rare
  `Expect: 100-continue` is in ordinary traffic. Found via real browser verification
  against httpbin.org (2026-08-12).
