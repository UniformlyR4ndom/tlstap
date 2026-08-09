# dbdump interceptor (`intercept/dbdump/`)

Implementation notes for the `dbdump` interceptor, loaded automatically when working
under this directory. See the root `CLAUDE.md` for where `dbdump` fits into the wider
architecture — `ApiProvider`/REST API mechanics ("REST API" section), the config-args
table ("Built-in Interceptors"), and its relationship to `tamper` (documented in
`intercept/tamper/CLAUDE.md`) — and `test/tapctl/CLAUDE.md` for CLI usage against the
endpoints documented below.

Logs all captured traffic to an SQLite database (via `modernc.org/sqlite`, pure Go).

**Schema:**

```sql
sessions(id INTEGER PK AUTOINCREMENT, start INTEGER, config TEXT)
stream(id INTEGER, session INTEGER → sessions.id, src TEXT, dst TEXT, start INTEGER, end INTEGER)
  -- PK: (session, id)
chunks(id INTEGER, stream INTEGER, session INTEGER → sessions.id, direction INTEGER,
       offset INTEGER, time INTEGER, data BLOB, sgid INTEGER, stid INTEGER)
  -- PK: (session, stream, direction, id)
  -- INDEX: idx_chunks_sgid ON (session, sgid)
  -- INDEX: idx_chunks_stid ON (session, stream, stid)
frames(session INTEGER → sessions.id, stream INTEGER, direction INTEGER, script TEXT,
       script_version TEXT, id INTEGER, offset INTEGER, length INTEGER, meta TEXT,
       stid INTEGER, time INTEGER)
  -- PK: (session, stream, direction, script, script_version, id)
  -- INDEX: idx_frames_stid ON (session, stream, script, script_version, stid, id)
frame_progress(session INTEGER → sessions.id, stream INTEGER, direction INTEGER,
       script TEXT, script_version TEXT, processed_offset INTEGER, state BLOB)
  -- PK: (session, stream, direction, script, script_version)
```

- `sessions.config` — JSON snapshot of the full proxy config (proxy + TLS server/client + interceptors).
- `stream.id` — the proxy's `ConnID` (sequential per proxy run, restarts at 0 each run). Not globally unique; the PK is `(session, id)`.
- `chunks.session` — mirrors `stream.session`; scopes chunk rows to their capture session without requiring a join.
- `chunks.direction` — `0` = client→server, `1` = server→client.
- `chunks.id` — starts at `0`, increments independently per `(session, stream, direction)`.
- `chunks.offset` — byte offset of the chunk's first byte, independently per `(session, stream, direction)`.
- `chunks.sgid` — session-global direction-agnostic chunk counter; monotonically increasing across all streams in a session. Used by CombinedView.
- `chunks.stid` — per-stream direction-agnostic chunk counter; monotonically increasing across both directions within one stream. Used by TrafficView to maintain a single cursor.
- Timestamps are milliseconds since the Unix epoch.
- `frames`/`frame_progress` — persisted output of a client-run framer script (see
  "Framer scripts" below); no FK enforcement is relied on for either (SQLite's
  `foreign_keys` pragma is never turned on in this codebase, same as `chunks.session`).
- `frames.script`/`frame_progress.script` — the framer script's name (from the
  `scripts-dir` store, below); `script_version` is a sha256 hex digest of that script's
  *content*, computed client-side — a script edit is simply a different (and initially
  empty) key, not something requiring explicit staleness detection against a stored hash.
- `frames.id` — starts at `0`, increments independently per `(session, stream, direction,
  script, script_version)`, assigned server-side in `appendFrames` (continuing from
  `MAX(id)+1`, never client-supplied).
- `frames.meta` — free-form JSON text a framer script attaches per frame; opaque to the
  Go side (stored/returned as-is, never interpreted), nullable.
- `frame_progress.processed_offset`/`state` — how far framing has gotten and the
  framer's own opaque persisted state (also free-form, from the framer script's
  perspective) for resuming; both `0`/`NULL` before framing has started for a key, which
  is a normal state, not an error condition.
- `frames.stid` — added after `frames` first shipped, via `ensureColumn`'s idempotent
  `ALTER TABLE` rather than the `CREATE TABLE IF NOT EXISTS` above (a no-op on an
  already-existing table — see `ensureColumn`'s own doc comment in `dbdump.go`).
  Inherited from whichever raw chunk this frame completes on — the cross-direction
  ordering key `listFramesTimeline` sorts by, letting `TrafficView`'s frame view
  interleave both directions in one scroll the same way `chunks.stid` already does for
  the raw view. Ties (multiple frames completing on the same chunk — routine, not an
  edge case) are always within one direction (two different chunks, from either
  direction, never share a `stid`) and are broken by `id`.
- `frames.time` — added the same way and for the same reason as `stid` above: a frame has
  no timestamp of its own (frames aren't captured, they're computed), so it's inherited
  from that same completing chunk's own `time`.

**In-memory state** (protected by `sync.RWMutex`):
- `clientEndpoints map[uint32]string` — maps `ConnID` → client endpoint to derive direction in `Intercept`.
- `chunkStates map[chunkKey]chunkState` — tracks `(nextID, nextOffset)` per `(ConnID, direction)`; entries are deleted in `ConnectionTerminated`.
- `streamNextSTID map[uint32]int64` — tracks next stid per `ConnID`; deleted in `ConnectionTerminated`.
- `nextSGID int64` — session-global chunk counter, incremented under mutex on every `Intercept` call.
- `streamsVersion int64` — bumped under mutex whenever a stream row is actually inserted or its `end` is actually set (checked via `sql.Result.RowsAffected()`, since both `ConnectionEstablished` and `ConnectionTerminated` are called once per direction and the second call's write is a guarded no-op — see their doc comments). A cheap, payload-free "has the stream list changed" signal for `/latest`, since neither event bumps `nextSGID` (no chunk is involved). It's a plain incrementing counter, not tied to any stream's own id — comparing it against a previously-seen value is the only thing it's for (same "opaque version number" convention the web frontend already uses for e.g. `adjustVersion`/`scrollToVersion` — see `web/CLAUDE.md`).

**Async write buffer:** chunk INSERTs are decoupled from the forwarding path to avoid blocking on disk I/O.
- `Intercept()` copies the chunk data (the proxy reuses its read buffer immediately after) and enqueues a `chunkRecord` into `pendingChunks []chunkRecord` under `mu`, then returns immediately.
- A background goroutine (`flushLoop`) flushes the buffer in a single SQLite transaction either every second or when `pendingSize` crosses `bufFlushSize` (2 MB, soft trigger), whichever comes first.
- `bufMaxSize` (16 MB) is a hard cap: `Intercept()` blocks via `cond.Wait()` if the buffer reaches this size, providing backpressure without unbounded memory growth. Both thresholds are constants at the top of `dbdump.go`.
- `flush()` swaps `pendingChunks` for a fresh slice under the lock (fast), broadcasts on `cond` to wake any blocked callers, then commits the batch outside the lock so `Intercept()` can continue filling the new slice concurrently.
- `Finalize()` closes `stopCh` to trigger a final flush and waits on `flushDone` before closing the DB.

**Lazy session creation:** the session row is not written to the DB in `Init()`; it is deferred until the first `Intercept()` call, so idle sessions leave no row.
- `sessionOnce sync.Once` / `sessionErr error` — `ensureSession()` runs the INSERT exactly once; error is cached.
- `sessionCreated bool`, `sessionStart int64`, `pendingConfig string` — set in `Init()`, committed on first `Intercept()`.
- `pendingStreams []pendingStream` — connections that arrived before the session row existed are buffered here; flushed atomically (under `mu.Lock()`) inside `ensureSession()` so `sessionCreated = true` is only visible after all pending stream rows are committed.
- `ConnectionEstablished()`: if session not yet created → append to `pendingStreams`; else write stream row directly.
- `ConnectionTerminated()`: if session not yet created → remove from `pendingStreams` (connection produced no data); else UPDATE `stream.end`.

**Framer scripts (`frames.go`, script storage wired from `api.go`)** are the (entirely
frontend-driven — nothing on the Go side ever runs a script) mechanism for reassembling
a stream's raw chunks into logical "frames" and persisting the result, so the Analysis
tab's hex view can offer a framed partitioning alongside the raw-chunk one at near-zero
repeat cost once cached — implemented and confirmed working end-to-end (including
cross-direction interleaving) as of 2026-08-05. Full design/rationale lives in
[`doc/design/packet-dissector.md`](../../doc/design/packet-dissector.md) — the framer
half described there is done; the dissector half is a separate, not-yet-started stage
(see the root `CLAUDE.md`'s TODO section). This section covers the storage layer and
REST surface; the browser-side Worker execution and UI are documented in
`web/CLAUDE.md`'s "Framer scripts" section.

- `ScriptsDir` (`scripts-dir` config field): directory framer scripts are stored in,
  passed to `scriptstore.New` — same shared package `tamper`'s control scripts use (see
  `intercept/scriptstore/CLAUDE.md`). Empty disables the feature entirely, same
  501-when-unconfigured convention as everywhere else this pattern appears.
- `frameKey` (`frames.go`) bundles the five columns every per-direction `frames`/
  `frame_progress` query filters on: `Session, Stream, Direction, Script, ScriptVersion`.
  `frameTimelineKey` is the same minus `Direction` — `listFramesTimeline`'s key, since a
  merged cross-direction listing has no single direction to key on.
- `getFrameProgress(key)` — `(0, nil, nil)` for a key with no rows yet (a normal,
  common state, not an error); otherwise the stored `processed_offset`/`state`.
- `listFrames(key, start, n)` — frames with `id >= start`, ordered by `id`; `n <= 0`
  means unlimited. No extra index needed beyond `frames`' own PK: its btree is already
  ordered `(session, stream, direction, script, script_version, id)`, exactly the
  access pattern this (and `appendFrames`) needs. Shares `frameRecord`/`scanFrameRows`
  with `listFramesTimeline` below — both SELECT the same seven columns, so one scan
  implementation serves both, even though `direction` is technically redundant with
  `listFrames`' own request key.
- `listFramesTimeline(key, start, n)` — the cross-direction counterpart: frames from
  *both* directions, ordered by `(stid, id)`, `stid >= start`. See the "Cross-direction
  interleaving" note below for the full correctness argument (tie-breaking by `id`, and
  why pagination must never split a tied-`stid` group across a page — the reason this
  isn't just `ORDER BY stid LIMIT n`).
- `listFramesTimelineBackward(key, beforeStid, n)` — the backward counterpart, added
  alongside `/segments`' own `beforeStid` support for the same reason (a client-side
  "guess how far back" approximation isn't reliable once pagination is byte-budgeted, not
  just count-based — see doc/design/hexview-segment-buffer.md). Walks `stid < beforeStid`
  via `ORDER BY stid DESC, id DESC` (the reverse of the forward tie-break, so a tied
  group's raw query order is still contiguous), mirrors the same `n+1`-lookahead
  group-boundary-safety guarantee for the reverse direction, and always returns ascending
  `(stid, id)` order like the forward version — a caller never special-cases which
  direction produced a page.
- `appendFrames(key, expectedProcessedOffset, newFrames, newProcessedOffset, newState)` —
  one transaction: asserts `expectedProcessedOffset` still matches what's stored (`0` if
  framing hasn't started for `key`), assigns `newFrames` sequential ids continuing from
  `MAX(id)+1` (each carrying its own client-computed `stid`/`time`), then upserts
  `frame_progress` to `newProcessedOffset`/`newState`. A mismatch returns
  `errFrameProgressConflict` without writing anything — this is deliberately not a
  defended-against race: the browser UI enforces one writer per key, so a mismatch here
  always means a client bug, not real concurrent use to reconcile. No separate
  index/counter tracks "next id" — it's derived via `MAX(id)+1` inside the same
  transaction, cheap given the PK's own ordering.
- `purgeOtherFrameVersions(script, keepVersion)` / `purgeAllFrameVersions(script)` — the
  cleanup half of the versioning scheme: since `script_version` is a content hash with no
  history kept, a previous version's persisted data can never be reached again once
  overwritten (or the script deleted outright), so it's deleted rather than left to grow
  the DB forever. Both operate on `script` alone, across every session/stream/direction —
  a script's identity is global to the whole DB, not scoped to one capture. Only reachable
  from a script `PUT`/`DELETE` through `scriptstore`'s own REST endpoints (below) — a
  script edited directly on disk under `scripts-dir`, bypassing the API, never triggers
  either, which is exactly how one dev capture accumulated ~4M stale frame rows from a
  framer misapplied to the wrong protocol and repeatedly hand-edited; `clearStreamFrames`
  below is the fix that doesn't depend on the interceptor having observed the edit.
- `clearStreamFrames(keep frameTimelineKey)` — enforces "at most one framing view per
  stream": deletes every `frames`/`frame_progress` row for `keep`'s `(session, stream)`
  whose `(script, script_version)` isn't `keep`'s own, across both directions. Unlike the
  purge functions above, this is meant to be called on *every* framing run (`web/CLAUDE.md`'s
  "Framer scripts" section — `TrafficView.js`'s `handleRunFramer` calls it, keyed by
  whatever's about to run, before `catchUpFramer`), not just on an explicit script
  edit/delete — so it catches a stream switching to a different script, a new version of
  the same script, *and* a script edited directly on disk, none of which the PUT-triggered
  purges above can see. A rerun of the same `(script, script_version)` already active for
  a stream is a no-op (its `frame_progress` survives, so the client resumes instead of
  reprocessing from scratch).
- **Script storage wiring** (`api.go`): `RegisterRoutes` calls `scriptstore.RegisterRoutes(mux,
  basePath, i.scripts, i.onFramerScriptPut, i.onFramerScriptDelete)` — the same REST CRUD
  `tamper` gets, reused as-is. `onFramerScriptPut` re-reads the just-written content via
  `i.scripts.Get` (the callback contract only carries a name, not the content) and calls
  `purgeOtherFrameVersions` with its hash as `keepVersion`; `onFramerScriptDelete` calls
  `purgeAllFrameVersions`. Both just log-and-continue on failure (`i.logger.Error`) rather
  than surfacing an error to the already-completed `PUT`/`DELETE` response — the script
  write itself already succeeded by the time either callback runs, so there's no request
  left to fail.
- **REST endpoints** (base: `/<proxy-name>/api/i/dbdump` or canonical `/api/i/dbdump`,
  same convention as the rest of this API): `/scripts`, `/scripts/{name}` — script CRUD,
  identical shape to `tamper`'s (see `intercept/scriptstore/CLAUDE.md`), just pointed at
  this interceptor's own `scripts-dir`. `POST /frame-progress` → `frameKeyRequest` body →
  `{"processed_offset":N,"state":"<base64>"|null}`. `POST /frames` → `frameKeyRequest`
  plus `{"start":N,"n":N}` → JSON array of
  `{"id":N,"offset":N,"length":N,"meta":"..."|null,"direction":N,"stid":N,"time":N}`,
  ordered by `id`, `id >= start`; `n <= 0` means unlimited. `POST /frames/timeline` →
  `frameTimelineKeyRequest` (like `frameKeyRequest` but no `direction`) plus
  `{"start":N,"n":N}` (forward) or `{"beforeStid":N,"n":N}` (backward — exactly one of
  `start`/`beforeStid` required, `400` otherwise, same convention as `/segments`'
  `afterStid`/`beforeStid`) → same-shaped JSON array as `/frames`, but spanning both
  directions, always ordered ascending `(stid, id)` regardless of scan direction.
  `POST /frames/append` →
  `frameKeyRequest` plus
  `{"expected_processed_offset":N,"new_frames":[{"offset":N,"length":N,"meta":"..."|null,"stid":N,"time":N},...],"new_processed_offset":N,"new_state":"<base64>"|null}`
  → `204`, or `409` (body `{"error":"..."}`) on the staleness mismatch described above.
  `POST /frames/clear` → `frameTimelineKeyRequest` body → `204` — see `clearStreamFrames`
  above.
  `frameKeyRequest` (embedded by these requests' structs — encoding/json promotes an
  embedded struct's fields into the same JSON object) is
  `{"session":N,"stream":N,"direction":N,"script":"...","script_version":"..."}` — full
  schemas for all of these are in `doc/openapi.yaml` under the `framer` tag.
- Unit-tested (`frames_test.go`): progress/append/list round-trips (including
  incremental extension and paging), the conflict-on-stale-offset path, both purge
  functions directly, `clearStreamFrames` directly (including the same-version-is-a-no-op
  case and that other streams/sessions are untouched) plus its own HTTP-level pass,
  HTTP-level end-to-end passes for all four other REST endpoints, one
  confirming a real script `PUT`/`DELETE` through `RegisterRoutes` triggers the right
  purge, and `listFramesTimeline`'s ordering/tie-break/group-boundary-pagination
  correctness specifically (`TestListFramesTimeline_OrderingAndTieBreak` — the core test
  for the "one chunk, multiple frames" case). `ensureColumn` itself is separately
  unit-tested in `dbdump_test.go` (adds the column, is idempotent when called again, and
  works identically whether the table already existed or was just freshly created).

**Cross-direction interleaving (`listFramesTimeline` in `frames.go`):** `TrafficView`'s
frame view merges both directions into one scroll, the same way the raw-chunk view
already does via `chunks.stid` — via `frames.stid` (see above) and a second query
shape, since every other `frames`/`frame_progress` access (`frameKey`) is scoped to one
direction by construction.

- **Ties on `stid` are real and expected**, not an edge case: every frame produced from
  the *same* source chunk (e.g. a TCP segment containing several small application-layer
  records at once — routine for something like a TLS record framer) inherits that
  chunk's `stid` identically. Cross-direction ties are impossible (two different chunks,
  from either direction, never share a `stid`), so a tie only ever means "multiple frames
  from one chunk, same direction" — meaning a frame's own `id` is already the correct,
  meaningful secondary sort key: `listFramesTimeline` orders by `(stid, id)`, never bare
  `stid`.
- **Pagination never splits a tied-`stid` group across a page.** `useChunkBuffer`'s
  windowing (`web/useChunkBuffer.js`) assumes `getId(row) + 1` unambiguously starts the
  next page — true for `chunks.stid` today only because chunk-stid values are never
  duplicated. With frame-stid ties, a naive `LIMIT n` cutting off mid-group would make
  `lastRow.stid + 1` **silently skip** the rest of that group on the next fetch — not a
  display glitch, an actual loss of frames from view. `listFramesTimeline` fetches `n+1`
  rows; if the `n`-th and `(n+1)`-th share a `stid`, it drops everything from that
  boundary `stid` onward from the initial fetch and re-queries `stid = <value>` fresh, so
  the returned page always ends exactly at a `stid` boundary. With that guarantee,
  `getId(row) => row.stid` and `useChunkBuffer`'s existing `+1` cursor logic need no
  changes at all.
- Two known, accepted-as-known gaps in how the frontend consumes this ordering
  (`useChunkBuffer`'s internal buffer-trimming not being tied-`stid`-group-aware, and no
  pagination of an individual frame's own byte payload) are tracked in the root
  `CLAUDE.md`'s TODO section, not repeated here — both are being addressed by the
  byte-budgeted rework in `doc/design/hexview-segment-buffer.md`, which is what
  `listFramesTimelineBackward` (above) was added for.
- `listFramesTimelineBackward` mirrors this same group-boundary-safety guarantee for the
  reverse walk (`ORDER BY stid DESC, id DESC`, extending across a tied boundary group the
  same way), always resorted back to ascending `(stid, id)` before returning.

**API endpoints** (base: `/<proxy-name>/api/i/dbdump` or canonical `/api/i/dbdump`):

| Method | Path | Request body | Response |
|---|---|---|---|
| GET | `/status` | — | `{"status":"ok"}` |
| GET | `/sessions` | — | JSON array of `{id, start, config}` |
| POST | `/streams` | `{"session": N}` | JSON array of `{id, session, src, dst, start, end, length0, length1}` — end=0 if ongoing; length fields are total captured bytes per direction (-1 if none) |
| POST | `/chunklist` | `{"session": N, "stream": N}` | `{"latest0": int64, "latest1": int64, "length0": int64, "length1": int64}` — latest chunk ID and total byte length per direction; -1 if no chunks yet |
| POST | `/latest` | `{"session"?: N, "stream"?: N}` | `{"latest_session_id": int64, "latest_sgid": int64, "streams_version": int64, "latest_stid": int64}` — the one endpoint a live-poll client needs, one request per tick regardless of how many of session/stream/global it cares about. `session`/`stream` are both optional and independent. `latest_session_id` (global `MAX(id)` over `sessions`, -1 if none) is always computed regardless of the request body. `latest_sgid` (indexed `MAX(sgid)` over `chunks`) and `streams_version` (the in-memory counter above) are -1 unless `session` is given; `streams_version` is further -1 unless `session` is the one this interceptor instance is currently live on. `latest_stid` (indexed `MAX(stid)` over `chunks`) is -1 unless both `session` and `stream` are given |
| POST | `/chunk` | `{"session":N,"stream":N,"direction":N,"chunks":[...]}` | `multipart/form-data`; one part per chunk with raw bytes as body and `X-Chunk-Offset`/`X-Chunk-Time` headers |
| POST | `/chunk-stid` | `{"session":N,"stream":N,"direction":N,"id":N}` | `{"stid": N}` — resolves per-direction chunk `id` → `stid`; 404 if not found |
| POST | `/byte-stid` | `{"session":N,"stream":N,"direction":N,"offset":N}` | `{"stid": N}` — finds the stid of the chunk whose `offset <= N` (i.e. the chunk containing that byte); 404 if no chunk in that direction |
| POST | `/search-text` | see below | JSON array of `{stream, direction, offset, stid}` matches |
| WS | `/stid-stream` | — | WebSocket; streams chunks for one stream ordered by stid; see protocol below |
| WS | `/sgid-stream` | — | WebSocket; streams chunks for one session ordered by sgid (across all streams); see protocol below |
| WS | `/segments` | — | WebSocket; one-shot budgeted fetch of raw chunks in stid order, forward or backward; see protocol below |
| GET/PUT/DELETE | `/scripts`, `/scripts/{name}` | see "Framer scripts" above | script CRUD, same shape as `tamper`'s |
| POST | `/frame-progress` | see "Framer scripts" above | persisted framing progress for one key |
| POST | `/frames` | see "Framer scripts" above | JSON array of persisted frames for one key |
| POST | `/frames/timeline` | see "Framer scripts" above | JSON array of persisted frames for a stream+script across both directions, merged by stid, forward or backward |
| POST | `/frames/append` | see "Framer scripts" above | `204`, or `409` on a stale `expected_processed_offset` |
| POST | `/frames/clear` | see "Framer scripts" above (`clearStreamFrames`) | `204` — purges every other `(script, script_version)`'s frame data for the given stream |

**WebSocket `/stid-stream` protocol:**

Per request: send one JSON text frame, receive one text frame + one binary frame per chunk, then a `done` signal.

Request frame:
```json
{"session": N, "stream": N, "start": N, "n": N}
```
- `start` — first stid to fetch (inclusive)
- `n` — max chunks (0 = unlimited)

Per chunk — two frames in order:
1. Text frame: `{"stid":N,"chunk-id":N,"direction":N,"time":N,"offset":N}`
2. Binary frame: raw chunk bytes

Done signal: `{"done":true}`

**WebSocket `/sgid-stream` protocol:**

Same frame structure as `/stid-stream` but session-scoped and includes `stream` in metadata.

Request frame:
```json
{"session": N, "start": N, "n": N}
```

Per chunk metadata: `{"sgid":N,"stream":N,"chunk-id":N,"direction":N,"time":N,"offset":N}`

Done signal: `{"done":true}`

**WebSocket `/segments` protocol:**

Backs [`doc/design/hexview-segment-buffer.md`](../../doc/design/hexview-segment-buffer.md)'s
byte-budgeted hex-view rework (backend half; frontend migration not yet done — see that
document's "Migration plan"). Unlike `/stid-stream`/`/sgid-stream`, one request gets
exactly one response — a text frame then a binary frame, no per-chunk streaming and no
`done` signal. Every returned item is always a raw chunk — this endpoint has no
frame-awareness at all; once the frame-mode segment adapter lands, frame bytes will be
derived from these client-side, same role `/stid-stream` via `fetchDirectionChunks` plays
for framer scripts today.

Request frame — exactly one of `afterStid`/`beforeStid` selects scan direction
(deliberately no separate `direction` field, to avoid colliding with the unrelated
per-segment client→server/server→client `direction` in the response below):
```json
{"session": N, "stream": N, "afterStid": N, "maxSegments": N, "maxBytes": N}
{"session": N, "stream": N, "beforeStid": N, "maxSegments": N, "maxBytes": N}
```
- `afterStid` — walk stid ascending, exclusive of the given value
- `beforeStid` — walk stid descending, exclusive of the given value, then re-sorted
  ascending server-side before responding — the client never special-cases direction
- `maxSegments` — max chunks to return; `<= 0` = unlimited
- `maxBytes` — soft byte budget, checked only *between* whole chunks (never truncates
  one — a single maximal chunk can overshoot it by its own size); `<= 0` = unlimited

Response — one text frame then one binary frame:
1. Text: `{"segments":[{"stid":N,"segmentId":N,"direction":N,"time":N,"offset":N,"length":N}, ...],"reachedEnd":bool}`
   — `segments` always ascending by stid regardless of scan direction; `length` is each
   entry's own byte count, **not cumulative** — the client reconstructs slices from the
   binary frame with one linear pass accumulating `length` in array order. `reachedEnd`
   means "no more segments in the requested direction": no chunks after `afterStid`
   (forward) or none before `beforeStid` (backward, i.e. the stream's real start).
2. Binary: every listed segment's own bytes, concatenated in array order.

A malformed request (both or neither of `afterStid`/`beforeStid` given) or a database
error sends one `{"error":"..."}` text frame and closes the connection, same convention
as `/stid-stream`/`/sgid-stream`.

**`/search-text` request body:**
```json
{
  "session": N,
  "stream": N,          // optional; omit to search all streams
  "start": N,           // optional byte offset lower bound (inclusive), default 0
  "end": N,             // optional byte offset upper bound (exclusive)
  "pattern": "...",
  "pattern_encoding": "text|base64|regex",
  "direction": N,       // optional; 0=c→s, 1=s→c; omit for both
  "contiguous": bool    // optional; if true, chunks are concatenated before searching
}
```
- `pattern_encoding` `""` / `"text"` — raw UTF-8 literal; decoded pattern capped at `maxPatternLen` (4 KB) → 400 if exceeded, regardless of `contiguous`.
- `pattern_encoding` `"base64"` — arbitrary bytes base64-encoded (frontend always uses this for non-regex formats to support binary/UTF-16/hex patterns); same `maxPatternLen` cap applies to the decoded bytes.
- `pattern_encoding` `"regex"` — Go `regexp` syntax; invalid pattern → 400. `contiguous` flag still applies (chunks concatenated per `searchBatchSize` batch, 2 MB); cross-batch overlap is a fixed `regexOverlapSize` (4 KB) rather than pattern-length-based, since minimum match length is unknown — a match spanning further than that across a batch boundary is still missed.
- Non-contiguous mode: each chunk searched independently; cross-chunk matches not found.
- Contiguous mode (literal): chunks accumulated into `searchBatchSize` batches (2 MB); `len(pattern)-1` byte overlap between batches catches cross-batch splits. Implemented in `search.go` via `matchFinder` abstraction (`literalFinder` / `regexFinder`).
