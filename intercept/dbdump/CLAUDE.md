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
stream(id INTEGER, session INTEGER → sessions.id, src TEXT, dst TEXT, start INTEGER, end INTEGER,
       sni TEXT, alpn TEXT, tls_version INTEGER, cipher_suite INTEGER)
  -- PK: (session, id)
chunks(id INTEGER, stream INTEGER, session INTEGER → sessions.id, direction INTEGER,
       offset INTEGER, time INTEGER, data BLOB, sgid INTEGER, stid INTEGER)
  -- PK: (session, stream, direction, id)
  -- INDEX: idx_chunks_sgid ON (session, sgid)
  -- INDEX: idx_chunks_stid ON (session, stream, stid)
  -- INDEX: idx_chunks_offset ON (session, stream, direction, offset) -- backs /byte-ranges'
  --   and /byte-stid's offset-predicate queries, neither index-backed before this
frames(session INTEGER → sessions.id, stream INTEGER, direction INTEGER, script TEXT,
       script_version TEXT, id INTEGER, ranges TEXT, meta TEXT,
       stid INTEGER, time INTEGER, seq INTEGER, virtual_offset INTEGER)
  -- PK: (session, stream, direction, script, script_version, id)
  -- INDEX: idx_frames_stid ON (session, stream, script, script_version, stid, id)
  -- INDEX: idx_frames_seq ON (session, stream, script, script_version, seq)
frame_progress(session INTEGER → sessions.id, stream INTEGER, script TEXT,
       script_version TEXT, processed_offset_c2s INTEGER, processed_offset_s2c INTEGER,
       virtual_length_c2s INTEGER NOT NULL DEFAULT 0, virtual_length_s2c INTEGER NOT NULL DEFAULT 0,
       state BLOB, closed_c2s INTEGER NOT NULL DEFAULT 0, closed_s2c INTEGER NOT NULL DEFAULT 0)
  -- PK: (session, stream, script, script_version)
```

- **`frame_progress`'s reshape (combined mode)**: unlike every other schema addition here
  (all additive, via `ensureColumn`'s idempotent `ALTER TABLE ADD COLUMN`), moving
  `frame_progress` off its old per-`direction` PK required an actual shape change
  `ensureColumn` can't express. `dbdump.go`'s `NewDbDumpInterceptor` detects the old shape
  (presence of a `direction` column on `frame_progress`, via the same `columnExists`
  helper `ensureColumn` is now built on) and `DROP TABLE`s both `frames` and
  `frame_progress` together before their `CREATE TABLE IF NOT EXISTS`/`ensureColumn`
  calls run — frame data is a purgeable/regenerable cache (the same reasoning
  `clearStreamFrames` below already relies on), and leaving stale pre-reshape `frames`
  rows in place while `frame_progress` reset to `processed_offset 0` would desync the two
  (duplicate frames on the next run) and leave `frames.seq` (introduced in the same
  reshape) unpopulated for them. A no-op for a fresh database or one already on the new
  shape.
- **`frames.ranges`**: a frame's byte span is an ordered list of `(offset, length)` pairs,
  not one contiguous range — most framer scripts still emit exactly one, but
  `examples/dbdump/framer/http1-framer.js`'s WebSocket reassembly emits more than one for
  a fragmented message (see `doc/design/http1-framer.md`). `frames.ranges` is a `TEXT`
  column holding a JSON array of `{"offset":N,"length":N}` —
  chosen over a normalized child table (nothing ever queries frames by offset) or a
  binary encoding (`ranges` is one field inside a `Frame` object that also carries
  `id`/`direction`/`stid`/`time`/`seq`/`meta`, all staying JSON regardless, so there's no
  way to escape JSON overhead for the rest of the row anyway) — same free-form-but-typed
  treatment `frames.meta` gets, except unlike `meta` (genuinely opaque to Go end to end),
  `ranges` is unmarshaled into a real `[]frameRange` server-side (`frames.go`), since the
  wire response needs it as a nested JSON array, not a string-embedded blob. **No
  stored/derived length-sum column** — a frame's logical length is `sum(ranges[].length)`,
  computed by consumers wherever needed, never persisted redundantly. Migrates the same
  way the `frame_progress` reshape above does: detected via the now-gone `offset` column
  on `frames` (`columnExists`), drops both `frames` and `frame_progress` together (same
  desync reasoning as above), safe to run even on a doubly-old DB where the
  `frame_progress` migration already dropped both tables (`columnExists` on a
  now-missing table returns `(false, nil)`, making the second check a correct no-op).
  Arrival-time (`stid`/`time`) resolution is unaffected server-side — still "inherited
  from the completing chunk" — the generalization from one `offset+length` to
  `max(pair.offset + pair.length)` across a frame's ranges happens client-side in
  `catchUpFramer` (`web/framerRun.js`), before the existing single-chunk lookup.
  Frontend consumers (`frameSegmentsCore.js`/`frameSegments.js`) address a frame in its
  own 0-based virtual concatenation of `ranges`, never a real stream position — see
  `web/CLAUDE.md`'s "Frame-mode adapter" bullet.
- `sessions.config` — JSON snapshot of the full proxy config (proxy + TLS server/client + interceptors).
- `stream.id` — the proxy's `ConnID` (sequential per proxy run, restarts at 0 each run). Not globally unique; the PK is `(session, id)`.
- `stream.sni`/`alpn`/`tls_version`/`cipher_suite` — added after `stream` first shipped, via `ensureColumn`, all nullable: NULL for a plain connection or a `detecttls` one that hasn't upgraded yet. Captured once per connection, from the *downstream* (client-facing) TLS handshake specifically — the proxy's separate upstream handshake can legitimately negotiate differently without ALPN/SNI passthrough, and isn't exposed here. `tls_version`/`cipher_suite` are the raw numeric IDs (`tls.VersionTLS13`-style / `tls.CipherSuiteName`-lookupable), not decoded names — a consumer that wants a name looks it up itself. See `ConnectionUpgraded` below.
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
- `frames.seq` — added alongside combined mode's `frame_progress` reshape below, via
  `ensureColumn`. A single counter per `(session, stream, script, script_version)` —
  deliberately **not** scoped by `direction` the way `id` is — assigned server-side in
  `appendFrames`, continuing from `MAX(seq)+1`, in `newFrames`' own array order: exactly
  the order a combined-mode script actually returned each frame in, spanning both
  directions. This can genuinely differ from `stid` order: a script may hold a
  fully-parsed frame in its own `state` and return it later, once e.g. a correlated frame
  from the other direction is also ready (see `doc/design/framer-cross-direction-
  correlation.md`) — that frame's `stid` still reflects true wire-arrival order, but its
  `seq` reflects the order the script chose to reveal it. Unique per key by construction
  (a bare counter, never shared across two frames), so unlike `stid` no tie-break/
  group-boundary pagination logic is needed for it — see `listFramesBySeq` below. Not yet
  surfaced in any UI.
- `frames.virtual_offset` — a per-*direction* running byte total (unlike `seq`, which
  spans both directions): the position a frame would start at if every frame emitted so
  far on its own direction — in per-direction emission order — were concatenated with
  none missing and none overlapping, regardless of the frame's own real byte position.
  "Per-direction emission order" is provably identical to per-direction `id` order:
  `appendFrames` assigns both `id` and `seq` in the same single pass over `newFrames`, so
  for any two frames of the same direction, `id` order and `seq` order (restricted to that
  direction) always agree. A frame's contribution to the running total is a plain
  `sum(ranges[].length)`, not the length of a merged/deduplicated span — a frame whose
  ranges overlap each other, or another frame's, is simply counted (and later displayed)
  twice, matching `/byte-ranges`' and `selectByBudget`'s own no-dedup treatment of
  overlapping ranges elsewhere in this codebase. Backs frame view's "global offset" toggle
  (`web/CLAUDE.md`'s "Global/local offset" note) — real per-direction byte offsets stopped
  being a clean, always-non-overlapping number once a frame's span could span multiple
  `ranges`. The two running totals themselves live in `frame_progress.virtual_length_c2s`/
  `virtual_length_s2c` (added alongside, same purely-additive `ensureColumn` treatment),
  advanced inside `appendFrames`' existing per-frame loop — internal bookkeeping only,
  never read back by anything but that function itself; a caller only ever needs each
  frame's own resulting `virtual_offset`, not the running total, so it isn't exposed via
  `/frame-progress`.
- `frame_progress.processed_offset_c2s`/`processed_offset_s2c`/`state` — how far a
  combined-mode framer run has gotten, per direction, and the framer's own opaque
  persisted state (free-form, from the framer script's perspective, shared by both
  directions) for resuming; all zero/`NULL` before framing has started for a key, which
  is a normal state, not an error condition. One row per `(session, stream, script,
  script_version)` — no `direction` column, unlike `frames` — since a combined-mode
  script run (see "Framer scripts" below) tracks both directions' progress/state at once
  in a single instance; splitting that back into two rows would just recreate the
  pre-combined-mode staleness problem the design doc's "Rejected alternative" section
  describes.
- `frame_progress.closed_c2s`/`closed_s2c` — added after `frame_progress` first shipped
  (alongside the rest of this reshape), via `ensureColumn`, but `NOT NULL DEFAULT 0`
  (unlike `frames.stid`/`frames.time` below, which are nullable) since "not yet closed" is
  an unambiguous default for every row, old or new. Whether each direction's
  connection-close signal has already been delivered to (and persisted by) the script —
  see "Framer scripts"' "Connection-close signal" note below. Neither ever reverts to
  `false` once set: a closed direction's byte length is final. In practice both flip
  together in one `appendFrames` call — the whole stream closes at once (one `ConnID`,
  one `ConnectionTerminated`) — but they're independent columns because `frame_progress`
  itself no longer has a per-direction row to hang a single flag off of. Once both are
  `true`, `catchUpFramer` (`web/framerRun.js`) never calls `appendFrames` again for that
  key.
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
- `streamsVersion int64` — bumped under mutex whenever a stream row is actually inserted, its `end` is actually set, or its TLS columns are actually set (checked via `sql.Result.RowsAffected()`, since `ConnectionEstablished`/`ConnectionTerminated`/`ConnectionUpgraded` are all called once per direction and the second call's write is a guarded no-op — see their doc comments). A cheap, payload-free "has the stream list changed" signal for `/latest`, since none of those events bump `nextSGID` (no chunk is involved). It's a plain incrementing counter, not tied to any stream's own id — comparing it against a previously-seen value is the only thing it's for (same "opaque version number" convention the web frontend already uses for e.g. `adjustVersion`/`scrollToVersion` — see `web/CLAUDE.md`).

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
repeat cost once cached. Full design/rationale lives in
[`doc/design/packet-dissector.md`](../../doc/design/packet-dissector.md) — covers both
the framer and the separate dissector half (see "Dissector scripts" below), both
browser-verified. This section covers the storage layer and REST surface; the
browser-side Worker execution and UI are documented in `web/CLAUDE.md`'s "Framer scripts"
section.

- `ScriptsDir` (`scripts-dir` config field): directory framer scripts are stored in,
  passed to `scriptstore.New` — same shared package `tamper`'s control scripts use (see
  `intercept/scriptstore/CLAUDE.md`). Empty disables the feature entirely, same
  501-when-unconfigured convention as everywhere else this pattern appears.
- `frameKey` (`frames.go`) bundles the five columns `listFrames`' per-direction `frames`
  query filters on: `Session, Stream, Direction, Script, ScriptVersion`. `frameTimelineKey`
  is the same minus `Direction` — every other key in this file (`frame_progress`'s own
  key, `listFramesTimeline`/`listFramesBySeq`) uses this shape instead, since a
  combined-mode run has no single direction to key `frame_progress` on, and a merged
  cross-direction frame listing has none either.
- `getFrameProgress(key frameTimelineKey)` — a zero-value `frameProgress` (both offsets
  0, `state` nil, both closed flags false) for a key with no rows yet (a normal, common
  state, not an error); otherwise the stored row. `frameProgress` bundles
  `ProcessedOffsetC2S`/`ProcessedOffsetS2C`/`State`/`ClosedC2S`/`ClosedS2C` — used both as
  this function's return value and, in `appendFrames` below, as both the CAS check's
  expected value (`State` ignored there) and the new value to write.
- `listFrames(key frameKey, start, n)` — frames with `id >= start`, ordered by `id`;
  `n <= 0` means unlimited. No extra index needed beyond `frames`' own PK: its btree is
  already ordered `(session, stream, direction, script, script_version, id)`, exactly the
  access pattern this needs. Shares `frameRecord`/`scanFrameRows` with
  `listFramesTimeline`/`listFramesBySeq` below — all three SELECT the same eight columns,
  so one scan implementation serves all of them, even though `direction` is technically
  redundant with `listFrames`' own request key.
- `listFramesTimeline(key frameTimelineKey, start, n)` — the cross-direction counterpart:
  frames from *both* directions, ordered by `(stid, id)`, `stid >= start`. See the
  "Cross-direction interleaving" note below for the full correctness argument
  (tie-breaking by `id`, and why pagination must never split a tied-`stid` group across a
  page — the reason this isn't just `ORDER BY stid LIMIT n`).
- `listFramesTimelineBackward(key, beforeStid, n)` — the backward counterpart, added
  alongside `/segments`' own `beforeStid` support for the same reason (a client-side
  "guess how far back" approximation isn't reliable once pagination is byte-budgeted, not
  just count-based — see doc/design/hexview-segment-buffer.md). Walks `stid < beforeStid`
  via `ORDER BY stid DESC, id DESC` (the reverse of the forward tie-break, so a tied
  group's raw query order is still contiguous), mirrors the same `n+1`-lookahead
  group-boundary-safety guarantee for the reverse direction, and always returns ascending
  `(stid, id)` order like the forward version — a caller never special-cases which
  direction produced a page.
- `listFramesBySeq(key, start, n)` / `listFramesBySeqBackward(key, beforeSeq, n)` —
  `listFramesTimeline`/`listFramesTimelineBackward`'s `seq`-ordered siblings (see
  `frames.seq` above for what emission order means and why it can differ from `stid`
  order). Since `seq` is unique per key by construction, these are simpler than their
  `stid` counterparts: a plain `LIMIT` is always a safe page boundary, no `n+1`-lookahead
  group-boundary logic needed. Not yet surfaced in any UI.
- `appendFrames(key frameTimelineKey, expected frameProgress, newFrames []frameInput,
  newProgress frameProgress)` — one transaction: asserts `expected`'s
  `ProcessedOffsetC2S`/`S2C` still match what's stored (`0`/`0` if framing hasn't started
  for `key`), assigns `newFrames` sequential ids — continuing from `MAX(id)+1`,
  independently *per direction* (`frameInput.Direction`, since one combined-mode batch
  can mix frames from either direction; computed lazily, the first time each direction
  actually appears in `newFrames`) — and a sequential `seq` continuing from
  `MAX(seq)+1`, shared across both directions, assigned in `newFrames`' own array order
  (see `frames.seq` above), then upserts `frame_progress` to `newProgress`. A mismatch on
  either offset returns `errFrameProgressConflict` without writing anything — this is
  deliberately not a defended-against race: the browser UI enforces one writer per key,
  so a mismatch here always means a client bug, not real concurrent use to reconcile. No
  separate index/counter tracks "next id"/"next seq" — both are derived via `MAX(...)+1`
  inside the same transaction, cheap given the relevant index's own ordering.
  `newProgress.ClosedC2S`/`ClosedS2C` are `false` for every ordinary batch; see
  "Connection-close signal" below for the one caller that sets them `true`.
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
- **Connection-close signal**: a framer script only ever sees raw chunks via
  `frame(state, chunk)`, with no way on its own to learn a direction's connection has
  closed — needed for anything whose length is implicit in connection close (e.g. an
  HTTP/1 response with neither `Content-Length` nor chunked `Transfer-Encoding`). Nothing
  here on the Go side detects closure itself — `stream.end` (already set in
  `ConnectionTerminated`, already returned by `/streams`) is the existing source of
  truth. `catchUpFramer` (`web/framerRun.js`) delivers it as one more `frame(state,
  chunk)` call *per direction not already closed*, with a synthetic `{offset:
  totalLength, length: 0, direction, data: new Uint8Array(0), closed: true}` chunk —
  reusing the existing entry point rather than a second script-facing hook — once every
  real chunk has been processed and `stream.end` is nonzero. In practice both directions'
  signals are delivered together in the same run, since one TCP connection closes as a
  whole (one `ConnID`, one `ConnectionTerminated`), so both synthetic chunks land in the
  same call to `runFramer`. The dedicated closing `appendFrames(..., ClosedC2S: true,
  ClosedS2C: true)` call (empty `new_frames`, offsets unchanged) only fires after every
  batch of that run — including whichever one carried the synthetic chunk(s) — has
  already been persisted normally, so `frame_progress.closed_c2s`/`closed_s2c` can never
  be set before the signal they represent was actually delivered and saved. See
  `web/CLAUDE.md`'s "Framer scripts" section for the full client-side orchestration.
- **TLS info capture**: a framer script also has no way on its own to tell HTTP/1.1 from
  h2 on a stream — `ConnectionUpgraded` (`dbdump.go`, previously a no-op) captures
  `proxy.ConnInfo.TLS` (nil for a plain connection) into `stream.sni`/`alpn`/`tls_version`/
  `cipher_suite` (see the schema note above for why it's always the *downstream*
  handshake). Mirrors `ConnectionEstablished`'s own lazy-session care: if the session
  isn't created yet, sets the fields on every matching `pendingStreams` entry (there can
  be two — one per direction, per `ConnectionEstablished`'s own doc comment — and only
  whichever is enumerated first survives `ensureSession`'s `INSERT OR IGNORE`, so both
  need it); otherwise a direct `UPDATE ... WHERE ... AND tls_version IS NULL`, the guard
  making the second per-connection call (identical `info.TLS`) a no-op for the
  `streamsVersion` bump — which matters most for `detecttls`, where this fires
  well after `ConnectionEstablished` (mid-connection, once the Client Hello is seen), so
  an already-polling frontend needs the bump to know to refetch `/streams` promptly rather
  than waiting on some unrelated later event. Exposed via `/streams`' four new fields
  (below), then attached to every chunk a framer script sees — see `web/CLAUDE.md`'s
  "Framer scripts" section.
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
  this interceptor's own `scripts-dir`. `POST /frame-progress` → `frameTimelineKeyRequest`
  body →
  `{"processed_offset_c2s":N,"processed_offset_s2c":N,"state":"<base64>"|null,"closed_c2s":bool,"closed_s2c":bool}`.
  `POST /frames` → `frameKeyRequest` plus `{"start":N,"n":N}` → JSON array of
  `{"id":N,"ranges":[{"offset":N,"length":N}],"meta":"..."|null,"direction":N,"stid":N,"time":N,"seq":N,"virtual_offset":N}`,
  ordered by `id`, `id >= start`; `n <= 0` means unlimited. `POST /frames/timeline` →
  `frameTimelineKeyRequest` plus `{"start":N,"n":N}` (forward) or `{"beforeStid":N,"n":N}`
  (backward — exactly one of `start`/`beforeStid` required, `400` otherwise, same
  convention as `/segments`' `afterStid`/`beforeStid`) → same-shaped JSON array as
  `/frames`, but spanning both directions, always ordered ascending `(stid, id)`
  regardless of scan direction. `POST /frames/by-seq` — `listFramesBySeq`'s endpoint,
  identical request/response shape to `/frames/timeline` but `start`/`beforeSeq` and
  ascending `seq` order instead of `stid`. `POST /frames/append` → `frameTimelineKeyRequest`
  plus
  `{"expected_processed_offset_c2s":N,"expected_processed_offset_s2c":N,"new_frames":[{"direction":N,"ranges":[{"offset":N,"length":N}],"meta":"..."|null,"stid":N,"time":N},...],"new_processed_offset_c2s":N,"new_processed_offset_s2c":N,"new_state":"<base64>"|null,"closed_c2s":bool,"closed_s2c":bool}`
  (`closed_c2s`/`closed_s2c` default `false`) → `204`, or `409` (body `{"error":"..."}`)
  on the staleness mismatch described above. `POST /frames/clear` →
  `frameTimelineKeyRequest` body → `204` — see `clearStreamFrames` above.
  `frameKeyRequest`/`frameTimelineKeyRequest` (embedded by these requests' structs —
  encoding/json promotes an embedded struct's fields into the same JSON object) are
  `{"session":N,"stream":N,"direction":N,"script":"...","script_version":"..."}` and the
  same minus `"direction"` — full schemas for all of these are in `doc/openapi.yaml`
  under the `framer` tag.
- Unit-tested (`frames_test.go`): progress/append/list round-trips (including
  incremental extension and paging), the per-direction `id` vs. shared `seq` assignment
  and `seq`'s continuation across separate `appendFrames` calls, a scenario where
  `seq` order and `stid` order genuinely diverge (`TestListFramesBySeq_OrderCanDifferFromStid`
  — a response emitted before its held-back request, both directly exercising why `seq`
  exists), the conflict-on-stale-offset path (including a mismatch on only one
  direction's offset), both purge functions directly, `clearStreamFrames` directly
  (including the same-version-is-a-no-op case and that other streams/sessions are
  untouched) plus its own HTTP-level pass, HTTP-level end-to-end passes for every other
  REST endpoint including `/frames/by-seq`, one confirming a real script `PUT`/`DELETE`
  through `RegisterRoutes` triggers the right purge, and `listFramesTimeline`'s
  ordering/tie-break/group-boundary-pagination correctness specifically
  (`TestListFramesTimeline_OrderingAndTieBreak` — the core test for the "one chunk,
  multiple frames" case). `ensureColumn` itself is separately unit-tested in
  `dbdump_test.go` (adds the column, is idempotent when called again, and
  works identically whether the table already existed or was just freshly created).

**Dissector scripts** are the client-side counterpart to framer scripts: given one
frame's bytes, produce a labeled field-tree breakdown for the UI, à la Wireshark's
packet-details pane — browser-verified against `examples/dbdump/dissect/
http2-dissector.js`. Full design (field node schema, `dissect(bytes, frame)` contract)
lives in [`doc/design/packet-dissector.md`](../../doc/design/packet-dissector.md). This
section covers the storage layer and REST surface only — the browser-side Worker
execution and UI (`DissectPanel.js`, `dissectRuntime.js`) are documented in
`web/CLAUDE.md`'s "Dissector scripts" section:

- `DissectScriptsDir` (`dissect-scripts-dir` config field): directory dissector scripts
  are stored in, passed to a second, independent `scriptstore.New` call — its own
  `*scriptstore.Store` (`i.dissectScripts`), deliberately not sharing `ScriptsDir`'s store
  or directory with framer scripts (see the design doc's "Script storage" section). Empty
  disables the feature, same 501-when-unconfigured convention as everywhere else this
  pattern appears.
- **Script storage wiring** (`api.go`): a second `scriptstore.RegisterRoutes(mux,
  basePath+"/dissect", i.dissectScripts, nil, nil)` call, right after the framer's own.
  Nesting under `/dissect` (rather than reusing `basePath` directly) is what avoids a
  route collision — `RegisterRoutes` always registers at `<basePath>/scripts`, so a
  distinct `basePath` is the only thing keeping the two `Store`s' routes apart on one
  `http.ServeMux`. `nil`/`nil` callbacks: unlike the framer's `onFramerScriptPut`/
  `onFramerScriptDelete`, there is nothing to purge on a script write/delete — dissection
  output is never persisted, so no DB rows are ever keyed by a dissector script's name or
  version.
- **REST endpoints**: `/dissect/scripts`, `/dissect/scripts/{name}` — script CRUD,
  identical shape to the framer's own `/scripts` (and `tamper`'s), just pointed at this
  interceptor's own `dissect-scripts-dir`.
- Tested (`dissect_test.go`): full CRUD round-trip through the REST endpoints, that the
  dissector and framer stores are genuinely independent (same script name in both, one
  store's delete doesn't touch the other's), and the unconfigured-directory 501 path.

**Cross-direction interleaving (`listFramesTimeline` in `frames.go`):** `TrafficView`'s
frame view merges both directions into one scroll, the same way the raw-chunk view
already does via `chunks.stid` — via `frames.stid` (see above) and a second query
shape, since `listFrames`' own `frameKey` access to the `frames` table is scoped to one
direction by construction (`frame_progress` itself has no such per-direction shape to
begin with — see the schema note above).

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
- `useChunkBuffer.js`'s internal buffer-trimming not being tied-`stid`-group-aware, and no
  pagination of an individual frame's own byte payload, are both fixed by the
  byte-budgeted rework (`doc/design/hexview-segment-buffer.md`) for `TrafficView.js` —
  `listFramesTimelineBackward` (above) was added for it. `CombinedView.js` is still on
  `useChunkBuffer.js` and still has both gaps (root `CLAUDE.md`'s TODO).
- `listFramesTimelineBackward` mirrors this same group-boundary-safety guarantee for the
  reverse walk (`ORDER BY stid DESC, id DESC`, extending across a tied boundary group the
  same way), always resorted back to ascending `(stid, id)` before returning.

**API endpoints** (base: `/<proxy-name>/api/i/dbdump` or canonical `/api/i/dbdump`):

| Method | Path | Request body | Response |
|---|---|---|---|
| GET | `/status` | — | `{"status":"ok"}` |
| GET | `/sessions` | — | JSON array of `{id, start, config}` |
| POST | `/streams` | `{"session": N}` | JSON array of `{id, session, src, dst, start, end, length0, length1, sni, alpn, tls_version, cipher_suite}` — end=0 if ongoing; length fields are total captured bytes per direction (-1 if none); the last four are null unless/until the downstream TLS handshake completed (see "TLS info capture" above) |
| POST | `/chunklist` | `{"session": N, "stream": N}` | `{"latest0": int64, "latest1": int64, "length0": int64, "length1": int64}` — latest chunk ID and total byte length per direction; -1 if no chunks yet |
| POST | `/latest` | `{"session"?: N, "stream"?: N}` | `{"latest_session_id": int64, "latest_sgid": int64, "streams_version": int64, "latest_stid": int64}` — the one endpoint a live-poll client needs, one request per tick regardless of how many of session/stream/global it cares about. `session`/`stream` are both optional and independent. `latest_session_id` (global `MAX(id)` over `sessions`, -1 if none) is always computed regardless of the request body. `latest_sgid` (indexed `MAX(sgid)` over `chunks`) and `streams_version` (the in-memory counter above) are -1 unless `session` is given; `streams_version` is further -1 unless `session` is the one this interceptor instance is currently live on. `latest_stid` (indexed `MAX(stid)` over `chunks`) is -1 unless both `session` and `stream` are given |
| POST | `/chunk` | `{"session":N,"stream":N,"direction":N,"chunks":[...]}` | `multipart/form-data`; one part per chunk with raw bytes as body and `X-Chunk-Offset`/`X-Chunk-Time` headers |
| POST | `/chunk-stid` | `{"session":N,"stream":N,"direction":N,"id":N}` | `{"stid": N}` — resolves per-direction chunk `id` → `stid`; 404 if not found |
| POST | `/byte-stid` | `{"session":N,"stream":N,"direction":N,"offset":N}` | `{"stid": N}` — finds the stid of the chunk whose `offset <= N` (i.e. the chunk containing that byte); 404 if no chunk in that direction |
| POST | `/search-text` | see below | JSON array of `{stream, direction, offset, stid}` matches |
| WS | `/stid-stream` | — | WebSocket; streams chunks for one stream ordered by stid; see protocol below |
| WS | `/sgid-stream` | — | WebSocket; streams chunks for one session ordered by sgid (across all streams); see protocol below |
| WS | `/segments` | — | **Superseded by `/byte-ranges` + `/chunks/timeline` below — dead code pending removal, see root `CLAUDE.md`'s TODO.** WebSocket; one-shot budgeted fetch of raw chunks in stid order, forward or backward; see protocol below |
| POST | `/byte-ranges?session=N&stream=N` | binary — flat `(offset int64 BE, signedLength int64 BE)` pairs, no JSON | binary — length-prefixed byte blobs, one per request entry, in order; see "POST `/byte-ranges`" below |
| POST | `/chunks/timeline` | `{"session":N,"stream":N,"start":N,"n":N}` (forward) or `{"session":N,"stream":N,"beforeStid":N,"n":N}` (backward) | JSON array of `{id, direction, stid, time, offset, length}` — raw chunk metadata for a stream across both directions, merged by stid, forward or backward; see "POST `/chunks/timeline`" below |
| GET/PUT/DELETE | `/scripts`, `/scripts/{name}` | see "Framer scripts" above | script CRUD, same shape as `tamper`'s |
| GET/PUT/DELETE | `/dissect/scripts`, `/dissect/scripts/{name}` | see "Dissector scripts" above | dissector script CRUD, own namespace from `/scripts` above |
| POST | `/frame-progress` | see "Framer scripts" above | persisted framing progress for one key, both directions |
| POST | `/frames` | see "Framer scripts" above | JSON array of persisted frames for one key |
| POST | `/frames/timeline` | see "Framer scripts" above | JSON array of persisted frames for a stream+script across both directions, merged by stid, forward or backward |
| POST | `/frames/by-seq` | see "Framer scripts" above | same as `/frames/timeline`, merged by emission-order `seq` instead of `stid` |
| POST | `/frames/append` | see "Framer scripts" above | `204`, or `409` on a stale expected offset |
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

**WebSocket `/segments` protocol — superseded by `POST /byte-ranges`/`POST
/chunks/timeline` below.** Kept for reference; dead code pending removal (root
`CLAUDE.md`'s TODO). `chunkSegments.js`/`frameSegments.js` (`web/`) no longer use it.

Backed [`doc/design/hexview-segment-buffer.md`](../../doc/design/hexview-segment-buffer.md)'s
byte-budgeted hex-view rework. Unlike `/stid-stream`/`/sgid-stream`, one request gets
exactly one response — a text frame then a binary frame, no per-chunk streaming and no
`done` signal. Every returned item is always a raw chunk — this endpoint has no
frame-awareness at all; `/byte-ranges`/`/chunks/timeline` below replace this role, with
frame bytes derived client-side, same role `/stid-stream` via `fetchDirectionChunks` plays
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

**`POST /byte-ranges?session=N&stream=N`:**

Replaces `/segments`' byte-fetching role with a dumb, frame-unaware primitive — this is
what lets a single frame span multiple non-contiguous byte ranges (`frames.ranges`, see
above). `session`/`stream` are URL query parameters, not a JSON body — a new convention
for this package, unavoidable since the request body must be pure binary. No
dedup/overlap-awareness anywhere: two entries may reference identical or overlapping
physical bytes, resolved and returned fully independently — deliberate, not a gap.

Request body: raw binary, a flat sequence of 16-byte entries, each two big-endian `int64`s
— `(offset, signedLength)`. Entry count = `len(body)/16` (must be an exact multiple of 16).
`signedLength`'s **sign encodes direction** — negative = c2s, positive = s2c — since a
valid range's length is always non-zero while `offset` can legitimately be `0`, making
length the only field that can safely carry it (`decodeSignedLength`/`encodeSignedLength`,
`byteranges.go`, mirrored by `web/direction.js`'s identically named helpers).

The **whole request** is rejected (`400`, `{"error":"..."}`, nothing fetched) if: body
length isn't a multiple of 16; any `offset < 0`; any `signedLength == 0`; any entry's
`abs(signedLength)` still has its sign bit set after negation (the only way to detect
`math.MinInt64`'s two's-complement overflow — checked via the sign bit directly, not by
naming the constant); any entry's magnitude exceeds **128 MB**; entry count exceeds
**1024**; or the sum of magnitudes exceeds **128 MB**. An unknown `session`/`stream` is a
separate error class: `404`, checked only after the body itself validates.

Response body: raw binary — `application/octet-stream`, streamed directly (not built in
memory first). For each request entry, in the same order, one response entry: an 8-byte
big-endian `int64` length prefix followed by that many bytes. **The returned length is
always ≤ the requested magnitude, and may be less — this is never an error**, it's the
only signal for "not all requested bytes are currently available" (a still-live stream not
yet flushed that far, or the genuine end of a closed one); a returned length of exactly 0
is a normal, valid entry. Every entry is resolved fully independently — a short/zero read
on one has no effect on any other in the same request.

Bounds (128MB/1024/128MB) are deliberately generous relative to actual frontend usage
(`WINDOW_STEP`=32KB, `SEGMENT_STEP`=512 in `byteBufferCore.js`; max raw chunk size 64KB) —
they exist to catch rogue/malformed calls, not to constrain normal operation; no
client-side chunking logic is needed to stay under them.

Backend resolution (`resolveByteRange`, `byteranges.go`) finds every `chunks` row
overlapping `[offset, offset+magnitude)` (a range may legitimately span more than one
chunk) and slices exactly the requested sub-range out of them — the server-side
counterpart to what `web/frameSegments.js`'s now-deleted `sliceFrameBytes` used to do
client-side. Relies on chunk offsets being contiguous per `(session, stream, direction)`
(true by construction) rather than defending against a genuine gap — optimized for the
common case (a single, mostly-contiguous range resolving to a handful of chunk rows), not
adversarial worst-case input, per this endpoint's own design brief.

**`POST /chunks/timeline`:**

Raw-chunk metadata listing, mirroring `/frames/timeline`'s shape and semantics exactly
(see "Framer scripts" above) but scoped to `chunks` instead of `frames` — no `script`/
`script_version` key, since chunks have none. Request:
`{"session":N,"stream":N,"start":N,"n":N}` (forward, `stid >= start`) or
`{"session":N,"stream":N,"beforeStid":N,"n":N}` (backward, `stid < beforeStid`) — exactly
one of `start`/`beforeStid`, `400` otherwise. Response: a bare JSON array of
`{"id":N,"direction":N,"stid":N,"time":N,"offset":N,"length":N}`, always ascending `stid`
regardless of scan direction — no `reachedEnd` field on the wire, computed client-side the
same way frame mode already does (`selectByBudget`/`computeReachedEnd`,
`frameSegmentsCore.js`).

Deliberately does **no server-side budget selection**, unlike the old `/segments` — this
is a plain candidate listing; `chunkSegments.js` applies `selectByBudget` client-side, the
same function frame mode already uses, rather than the backend maintaining a second copy
of the "checked only between whole items" discipline. Also needs **no `n+1`-lookahead/
tied-group-boundary logic**, unlike `listFramesTimeline`: `chunks.stid` is unique per row
(two different chunks, from either direction, never share a `stid`), so a plain `LIMIT` is
always a safe page boundary — simpler than its `frames.go` counterpart.

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
