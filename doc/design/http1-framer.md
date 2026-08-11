# HTTP/1 Framer — design notes

**Status: implemented (2026-08-11/12).** This documents
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
  - A 2xx response to `CONNECT` degrades gracefully for free: it has no
    `Content-Length`/`Transfer-Encoding` either, so it falls into the close-delimited case
    above and swallows the rest of the connection as one (mislabeled, but harmless)
    oversized "body" frame. No special-casing needed.
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
  - **`CONNECT` tunnels**: the `c2s` branch records "request N was CONNECT" in `state`;
    the `s2c` branch checks it when classifying the matching response, so the tunnel gets
    labeled correctly (`body.kind: 'tunnel'`) instead of merely falling into the
    close-delimited fallback by accident.

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
just for different reasons); `'tunnel'` is the `CONNECT`-response case — same
close-delimited wire behavior as `'close-delimited'`, but labeled correctly now that
`state` knows the paired request was `CONNECT`.

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
- **`state.upgraded`/tunnel tracking stopping the framer from *emitting* further
  frames**: yes, for both — unified into one shared `state.passthrough` flag, set once
  either a `101` response or a successful `CONNECT` (2xx) response is seen, checked by
  *both* directions at the top of `frame()`. Once set, neither direction attempts HTTP
  parsing again for the rest of the connection (cheap no-op return), rather than framing
  raw post-upgrade/tunneled bytes as (nonsensical) HTTP.
- **Truncation at connection close** (not an original open item, but came up
  implementing "Self-contained per message" above): a message cut short by `chunk.closed`
  mid-headers has nothing coherent to frame and is silently dropped; one cut short
  mid-body (content-length short of its declared length, or chunked encoding not yet
  reaching its terminator) is still flushed as a frame, with `body.truncated: true` set
  so a viewer can tell the difference from a message that completed normally.

## Known limitations

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
