# Framer Cross-Direction Correlation — design notes

**Status: implemented (2026-08-11).** Design settled on "combined mode" (2026-08-10),
replacing an earlier per-direction-snapshot sketch — see "Rejected alternative" below —
and both "Open, not yet decided" items below were resolved during implementation (now
folded into the body text above rather than left as open questions); see "Implementation
notes" at the end of this doc for what actually landed, including `frames.seq`, an
addition that came up during implementation planning and isn't part of the original
design below. Verified via Go unit tests (`intercept/dbdump/frames_test.go`), a throwaway
Node smoke test exercising all four existing example framer scripts'
(`tls-framer.js`/`http2-framer.js`/`simple-framer.js`/`length-prefix-framer.js`)
migration to the two-sub-state shape under interleaved chunks (not committed, same
convention as the example scripts' own verification), and **confirmed working end-to-end
in a real browser (2026-08-11)** against a real capture — `length-prefix-framer.js` run
against a two-way ~18.6MB/direction stream (`test/bulkclient-cli -enable
test-large-frame -length-prefix` through an echo server), producing correctly-parsed
frames (including one spanning several megabytes) and reaching
`processed_offset_c2s`/`s2c` equal to the stream's full length with both `closed_c2s`/
`closed_s2c` true.

Surfaced while planning [`doc/design/http1-framer.md`](http1-framer.md): a framer
script's `frame(state, chunk)` runs per direction today, with its persisted `state`
scoped to `(session, stream, direction, script, script_version)` — no channel exists for
the `c2s` run and the `s2c` run of the same stream/script to see anything about each
other. HTTP/1's message-length rules need exactly that (see that doc: a response's body
length can depend on its paired request's method). This doc designs the general
mechanism, not the HTTP/1-specific use of it.

## The actual problem: directions aren't independent

The current model treats `c2s` and `s2c` as two independent byte streams, each with its
own script instance, own `state`, own Worker, run concurrently. That's the wrong model
for any protocol with request/response correlation — the two directions of one stream
are one conversation, not two unrelated ones that happen to share a socket. Rather than
add a side-channel for one direction to hand facts to the other (considered below and
rejected), the fix is to stop pretending they're independent in the first place.

## Design: one script instance per stream, one shared state

A framer script runs **once per `(stream, script)`**, not once per direction, consuming
**both directions' chunks merged into one chronological sequence** ordered by `stid` —
the field that already establishes cross-direction chronological order for everything
else that needs it (`listFramesTimeline`'s frame-view interleaving; `/segments`, which
*already* returns raw chunks merged across both directions of one stream, ordered by
`stid` — the ordering primitive this needs already exists, nothing new to invent there).

- **Contract**: `frame(state, chunk)` — unchanged signature. The only difference:
  `chunk.direction` now varies call to call across one run, since chunks from both
  directions interleave through the single merged sequence. `state` is one value, read
  and written by one script instance — no concurrent writers, so no staleness/snapshot/
  convergence problem to design around. Correlation is just ordinary code: a script
  wanting request/response pairing keeps a plain queue in `state` (e.g.
  `state.pendingMethods`), pushed to on a `c2s` chunk, shifted on an `s2c` chunk.
- **Ordering guarantee this relies on**: a response's bytes are never captured before its
  request's bytes are (the server can't answer before it's asked), so by the time
  `frame()` sees an `s2c` chunk completing a response's headers, every `c2s` chunk
  chronologically before it — including the paired request — has already been fed
  through the same call sequence. No waiting, no deferral, no multi-pass convergence:
  **one pass over the merged stream is always enough.**
- **Schema**: `frame_progress` drops `direction` from its key — one row per `(session,
  stream, script, script_version)`, holding both directions' `processed_offset`, one
  shared `state`, and both directions' `closed` flags. Not a risky migration: frame data
  is already a purgeable/regenerable cache (the same reasoning `clearStreamFrames`/the
  purge functions already rely on for a script-version change), so old-shaped rows are
  simply dropped, not migrated in place.
- **`frames` table**: unchanged as originally designed — a frame still belongs to exactly
  one direction, still keyed/sequenced the same way, only `frame_progress`'s shape
  changes. (Gained one additive column, `seq`, during implementation — a separate
  addition beyond this design, see "Implementation notes" below.)
- **Client orchestration** (`framerRun.js`): `catchUpFramer` drops its `direction`
  parameter, fetches the merged chunk sequence (extending `/segments`'s existing
  merged-by-`stid` model into an unbounded catch-up fetch, the way `fetchDirectionChunks`
  does per-direction today), and drives one `runFramer` loop over it.
- **Connection-close signal**: each direction still closes independently and gets its own
  synthetic `{direction, closed: true}` chunk (unchanged from today) — just interleaved
  into the merged sequence at the point its real backlog is exhausted, instead of being a
  dedicated call at the end of a direction-scoped run.
- **Existing scripts**: every existing example framer script (`tls-framer.js`,
  `http2-framer.js`, `simple-framer.js`, `length-prefix-framer.js`) needs a small,
  mechanical update — keep two sub-states inside the one `state` object
  (`state.c2s`/`state.s2c`) and branch on `chunk.direction` at the top of `frame()`. No
  behavior change; they just lose the free direction-isolation the runtime used to
  provide for them, since none
  actually needs correlation.

## Bonus this unlocks for HTTP/1

Because `state` is shared and processed in true chronological order, the two
cross-direction cases `http1-framer.md` had marked as an accepted, unhandled gap turn out
to be cheaply solvable under this model, not just the HEAD-response case it was designed
for:
- **`101 Switching Protocols`**: the `s2c` branch sets `state.upgraded = true` on seeing
  it. Any post-upgrade `c2s` bytes arrive later in the merged sequence (the client waits
  for the response before switching protocols), so the `c2s` branch can check that flag
  and simply stop attempting HTTP parsing, cleanly, instead of throwing on the first
  unparseable start-line.
- **`CONNECT` tunnels**: the `c2s` branch records "request N was CONNECT" in `state`; the
  `s2c` branch checks it when classifying the matching response, so the tunnel gets
  labeled correctly instead of merely falling into the close-delimited fallback by
  accident.

`http1-framer.md` should be revisited once this lands — both are now in-scope, not
deferred.

## Rejected alternative: per-direction snapshot ("published"/"peer")

Earlier sketch: keep two independent per-direction `state`s, add a third `peer` param
carrying a snapshot of whatever the *other* direction last chose to publish. Rejected
because it never stops being two independent, concurrently-running instances papering
over a fundamentally shared problem — it needed a new `published` field on the wire, a
`peer` parameter, a rule for what a script does when the peer snapshot doesn't have what
it needs yet (defer and retry), and — because the two runs can each be started from a
stale/empty snapshot of the other — a fixed-bound two-pass convergence hack for the
"initial Run on an already-closed stream" case, purely to work around the two instances
never being in lockstep. All of that complexity disappears once there's only one
instance and one state to begin with.

## Non-goals

- Not a general pub/sub or streaming channel — there's exactly one `state`, one writer.
- Not synchronous/mid-call RPC — a script never blocks waiting on data that isn't in the
  merged sequence yet; if a chunk hasn't arrived, `frame()` simply hasn't been called
  with it yet, same as today.

## Implementation notes (2026-08-11)

Both items this doc originally left open were resolved as follows:

- **Merged-chunk catch-up fetch**: no new endpoint. `/stid-stream` (`api.js`'s
  `openStidStream()`) already returns both directions merged by `stid`, unfiltered,
  unbounded (`n=0`) — `fetchDirectionChunks` was already calling it and throwing away the
  other direction client-side. `catchUpFramer` (`web/framerRun.js`) just stopped
  filtering: it resolves each direction's own starting point via `getByteStid` (skipped
  for a direction with zero bytes ever captured, since `/byte-stid` 404s with nothing to
  floor-resolve against) and fetches from the earlier of the two onward in one call.
- **`frame_progress` column layout**: two pairs of columns, as guessed — `processed_offset_c2s`/
  `processed_offset_s2c`, `closed_c2s`/`closed_s2c`, one shared `state`, PK
  `(session, stream, script, script_version)`. See `intercept/dbdump/CLAUDE.md`'s schema
  section for the full shape and the drop-and-recreate migration off the old per-direction
  shape (frame data is a purgeable/regenerable cache, same reasoning `clearStreamFrames`
  already relies on — old-shaped `frame_progress`/`frames` rows are dropped together, not
  migrated in place).

**`frames.seq`** — an addition beyond this doc's original scope, which came up while
scoping the HTTP/1 framer's request/response interleaving (see `http1-framer.md`'s own
discussion): a script that holds a fully-parsed frame in `state` and returns it later
(e.g. a request, held until its matching response is also ready to emit, so the two can
be revealed together) doesn't change that frame's `stid` — `stid` is always resolved from
the frame's own byte offset via `chunkAtOffset`, never from when `frame()` happened to
return it — so `stid` order alone can't express "the order the script actually chose to
reveal frames in" (e.g. a neat request-then-response interleaving for display). `seq`
does: a single counter per `(session, stream, script, script_version)` (no `direction`
partition, unlike `id`), auto-assigned server-side in `appendFrames` from `newFrames`'
own array order — no script-facing API, deliberately: the runtime already knows emission
order from call order, so there's nothing for a script to manage (no monotonicity/
uniqueness/persistence-across-resumed-runs burden pushed onto script authors). Backend
(schema, write-side auto-assignment, `listFramesBySeq`/`listFramesBySeqBackward`,
`/frames/by-seq`) is complete; deliberately **not yet wired into any UI** — no shipped
script actually holds frames back yet, so there's nothing real to verify a toggle against
until the HTTP/1 framer (or similar) exists. See `intercept/dbdump/CLAUDE.md`'s
`frames.seq` note and `web/CLAUDE.md`'s "Framer scripts" section for the full mechanism.
