# tamper interceptor (`intercept/tamper/`)

Implementation notes for the `tamper` interceptor, loaded automatically when working
under this directory. See the root `CLAUDE.md` for where `tamper` fits into the wider
architecture (`ApiProvider`/REST API mechanics, `BufferingInterceptor` — "Buffering
Interceptors" section) and `web/CLAUDE.md`'s "Tamper tab"/"Scripted interception"
sections, which document the browser/script-facing side of everything below, and
`test/tapctl/CLAUDE.md` for CLI usage against these endpoints.

Lets a connected control client actively pause, inspect, edit, drop, or forward
individual chunks of live traffic, or just live-watch it without holding anything up.
Deliberately **not merged with `dbdump`** — see below.

**Relationship to dbdump:** `tamper` and `dbdump` are separate, single-responsibility
interceptors composed via a proxy's `interceptors` list, not merged. Ordering controls
what gets recorded: `dbdump` before `tamper` in the chain records untouched originals;
after `tamper` it records whatever actually got forwarded. Both share the same `ConnID`
numbering (the proxy's own per-run counter) and the same `/<proxy-name>/api/i/<name>`
URL convention, so a dbdump-recorded stream (Analysis tab) and its live `tamper` state
(Tamper tab) can be correlated purely by `ConnID`, with no backend coupling between the
two — the two tabs don't currently cross-link to each other, but nothing prevents it.

**Per-stream modes:**
- **watch** (default) — chunks pass straight through immediately (never blocked) and are
  best-effort mirrored to any attached `/watch` clients for that stream.
- **intercept** — chunks are held until a decision arrives on the control connection (or
  the hold timeout / a control disconnect releases them). A stream starts in this mode
  only if `auto-intercept` was enabled before it was established; otherwise it can be
  switched into intercept mode at any time via `set-mode`.
- With no control client connected at all, every stream behaves as if in watch mode with
  no watchers attached — i.e. pure pass-through, zero overhead — **unless**
  `hold-until-connected` is set (see below).

**`hold-until-connected`** (config): when true, every chunk is held while no control
client is connected, instead of the default pass-through, still bounded by
`hold-timeout-ms`. Guards against a test/debug client attaching after traffic has
already started flowing — the chunk just sits in the direction's held buffer until
someone connects and calls `list-streams` to discover it (see "Held-buffer lifecycle"
below), or the timeout releases it. Implemented as an additional OR-branch in
`Intercept()`'s hold decision: `holdNow := (intercepting && hasControl) ||
(holdUntilConnected && !hasControl)`.

**`TamperInterceptor` implements `proxy.BufferingInterceptor`** (see the root
`CLAUDE.md`'s "Buffering Interceptors" section): `Intercept()` never blocks — a held
chunk is appended to that direction's `heldBuffer` (see below) and `Intercept` returns
`(nil, nil)` immediately. `HasPending`/`ReleaseChannel` delegate directly to
`streamState.held[direction]`.

**In-memory state** (guarded by a single `mu sync.Mutex`, except `controlWriteMu`):
- `control *websocket.Conn` — the one control client (only one allowed at a time).
- `controlWriteMu sync.Mutex` — serializes writes to `control`; **never held at the same
  time as `mu`** — state is gathered under `mu`, released, and only then is a WebSocket
  write attempted, mirroring the "no I/O while holding the state lock" discipline dbdump
  uses for its DB writes.
- `autoInterceptNew bool` — mode newly-established connections start in.
- `streams map[uint32]*streamState` keyed by `ConnID`, each with its own `watchers` map
  and `held [2]*heldBuffer` (indexed by `directionC2S`/`directionS2C`; see `buffer.go`
  below) — created in `ConnectionEstablished`, closed in `ConnectionTerminated`.

**Direction detection** reuses dbdump's exact technique: `ConnectionEstablished` is
called once per direction for `direction: any` interceptors (the first call has
`src=client`); the client endpoint is recorded on first sight of a `ConnID`, and
`directionOf` (shared by `Intercept`, `HasPending`, `ReleaseChannel`) classifies c2s vs
s2c by comparing `info.SrcEndpoint` against it.

**Watcher mirroring never adds latency to the hot path:** each attached `/watch` client
gets its own goroutine draining a small buffered channel (depth 8); `Intercept()` does a
non-blocking send per watcher, dropping the frame on overflow rather than blocking the
proxy. Detaching a watcher (browser closes the tab, or the stream terminates) closes a
dedicated `stop` channel rather than the data channel itself, specifically to avoid a
"send on closed channel" panic if a mirror send from a still-live `Intercept()` call
races the teardown — see `detachWatcher`. Every write to a watch connection — both
`watcherWriteLoop`'s mirror frames and `handlePeek`'s replies (see below) — goes through
a per-watcher `writeMu`, since gorilla websocket doesn't support concurrent writers and
those two now write to the same connection from different goroutines (`writeMu` plays
the same role for a `/watch` connection that `controlWriteMu` plays for control).

**Held-buffer lifecycle:** `Intercept()` decides whether to hold and (if so) appends the
chunk to `st.held[direction]` in one `mu`-protected step (closing the race window the old
per-chunk design needed a two-phase lock-and-recheck for — see `Intercept`'s doc comment
in `tamper.go`), sends a **metadata-only** `held` notification (no binary frame — see
below) carrying just the new chunk's own offset/length, and returns `(nil, nil)`
immediately — it never blocks. Release — forwarding, dropping, or aborting the connection
— happens later and asynchronously, driven by a control client's `release`/
`drop-connection` command (`api.go`'s `handleRelease`/`handleDropConnection`, calling
`heldBuffer.performAction`/`abort`), a per-buffer hold-timeout, or a control disconnect
sweep, all of which deliver a `proxy.ReleasedData` on the buffer's release channel for
`ConnHandler`'s async forwarding loop to pick up (see the root `CLAUDE.md`'s "Buffering
Interceptors" section). Switching a stream from intercept back to watch mode (`set-mode`)
immediately force-releases (forwards, unmodified) everything currently held for it via
`releaseAll()`, rather than leaving it to time out.

**Possible future option (not implemented):** held chunks could survive a control
disconnect instead of always force-releasing, gated by a new config flag — would let a
one-shot client like `tapctl` do "edit now, decide whether to release later" across
separate invocations (today it can't; see `test/tapctl/CLAUDE.md`'s note on this
limitation).

**No goroutine is parked per held chunk** — see the root `CLAUDE.md`'s "Buffering
Interceptors" section for why that matters. One residual, harmless race:
`ConnectionTerminated` can `close()` both directions' `heldBuffer`s concurrently with the
*other* direction's `Intercept()` still mid-`appendChunk` (the `wg.Done()` quirk under
the root `CLAUDE.md`'s "Key Implementation Details" section). `appendChunk` doesn't
check `closed`, so this never panics — the appended bytes just sit unread until
`streamState` is GC'd, harmless since the connection is already tearing down.

**A held buffer's bytes are never pushed inline** — `held` and `stream-list` are pure
metadata, specifically so that (re)connecting to control at any time is enough to
discover and act on everything outstanding, without having had to be connected at the
exact moment a chunk was held. To actually read the bytes, connect to that stream's
`/watch` socket and send `peek` (see below); this is *only* a way to read held bytes and
only ever reads, never releases — decisions still exclusively happen over control (this
was floated the other way during design and deliberately reverted).

**Control WebSocket** (`/api/i/tamper/control`; only one connection at a time; all
release/edit/drop/drop-connection decisions happen here, never on `/watch`):

Proxy → browser (JSON text frame only — no bytes ever flow over control):
- `{"type":"stream-created","conn":N,"src":"...","dst":"..."}`
- `{"type":"stream-terminated","conn":N}`
- `{"type":"held","conn":N,"direction":0|1,"offset":N,"length":N,"time":N}` — announces
  one newly-appended chunk (metadata only; fetch bytes via `peek` on that stream's
  `/watch` connection). `offset`/`length` describe just the new chunk, not the buffer as
  a whole, so a connected client can extend its own locally-tracked bounds model
  incrementally rather than re-`peek`ing on every arrival; `offset` doubles as a
  consistency check against that local model (see `buffer.go`'s wiring notes below).
- `{"type":"stream-list","streams":[{"conn":N,"src":"..","dst":"..","intercepting":bool,"pending":[{"direction":0|1,"chunks":N,"length":N},...]}]}`
  (reply to `list-streams`; `pending` has 0-2 entries — one per direction with something
  currently held, summarized as chunk count + byte length, not itemized — which is what
  makes reconnecting to control at any time a full resync, not just a feed of future
  events)
- `{"type":"ok","command":"set-auto-intercept"|"set-mode"|"release"|"drop-connection"}` —
  acknowledges one of those four commands succeeded; each gets exactly one `ok` or
  `error` reply (never both, never neither). `set-mode`/`release`/`drop-connection` error
  on an unknown stream; `release` also errors if `prefix_length` exceeds the buffer's
  current length (see below) or `release_chunks` exceeds the resulting chunk count; all
  four error on missing required fields.
- `{"type":"error","message":"..."}` — either the above per-command failure, or an
  unrecognized command type entirely.

Browser → proxy (JSON text frame; `release` with `"edited":true` must be immediately
followed by a binary frame with the replacement bytes):
- `{"type":"set-auto-intercept","enabled":bool}`
- `{"type":"set-mode","conn":N,"intercepting":bool}`
- `{"type":"release","conn":N,"direction":0|1,"edited":bool,"prefix_length":N,"bounds":[...],"release_chunks":N,"action":"forward"|"drop"}` —
  combines an optional edit with a release in one atomic step, mapping directly onto
  `heldBuffer.performAction`. `edited:false` means "release `release_chunks` chunks of
  the buffer exactly as it stands" (`prefix_length`/`bounds` ignored); `edited:true`
  replaces the buffer's first `prefix_length` bytes (as the client last knew them) with
  the bytes in the following binary frame, described by `bounds`, before releasing.
  `prefix_length` anchors the edit against the buffer's actual current length — a stale
  value (e.g. a hold-timeout flushed the buffer in the meantime) is rejected rather than
  silently misapplied, the concurrency-safety mechanism this protocol uses in place of a
  synthetic version counter.
- `{"type":"drop-connection","conn":N,"direction":0|1}` — terminates the connection
  outright via `heldBuffer.abort()`, independent of `release`: dropping the connection
  isn't parameterized by buffer content the way an edit/release is, so it's its own
  command rather than a third `release` action value.
- `{"type":"list-streams"}`
- `{"type":"script-log","level":"log"|"error","text":"..."}` — pushes one already-formatted
  script log line for optional server-side persistence (see `log-file` above); a no-op if
  unconfigured. Fire-and-forget: no `ok` reply on success, only `error` for an invalid `level`.

**Watch WebSocket** (`/api/i/tamper/watch?conn=N`; any number of clients per stream):
- **Live mirror** (proxy → client, unsolicited): `{"direction":0|1,"time":N,"length":N}`
  followed by a binary frame, for every chunk actually forwarded on that stream
  (best-effort — see watcher mirroring above).
- **`peek`** (client → proxy): `{"type":"peek","direction":0|1,"offset":N,"length":N}` —
  the only way to read a direction's currently-held (not-yet-released) bytes; fetches the
  *whole* buffer, optionally sliced by `offset`/`length` (`length` 0 or omitted = to the
  end). Reply is one
  `{"type":"pending","direction":0|1,"time":N,"offset":N,"length":N,"total_length":N,"bounds":[...]}`
  + binary-slice pair (`offset`/`length` describe the *returned* slice; `total_length`
  and `bounds` always describe the whole buffer, regardless of what was sliced, since a
  resync always wants the complete picture and both are cheap), terminated by
  `{"type":"peek-done"}` — or a single `{"type":"error","message":"..."}` for an invalid
  `direction` value. Unlike the old per-chunk protocol, peeking a *valid* direction with
  nothing currently held is not an error (just a zero-length reply) — an empty direction
  is a perfectly normal state. `peek` never releases anything; it's read-only, same as
  the mirror.

**`heldBuffer` (`buffer.go`)** is what makes the above possible: a growing `[]byte` per
`(stream, direction)` plus a `bounds []int` list of where each appended chunk started —
one instance per direction, held in `streamState.held`. Chunks are purely a
review/release-granularity aid (merging/splitting is just editing `bounds`), since TCP
has no message framing to preserve; this is also why the old design could only ever hold
one chunk per direction at a time — the new one can hold arbitrarily many, since holding
no longer blocks the read loop at all (see the root `CLAUDE.md`'s "Buffering
Interceptors" section). `bounds` itself is otherwise a bookkeeping/`peek` concern only —
the *editing* of chunk boundaries (splitting, merging, dropping individual chunks) is a
control-client-owned concept, built up locally from `held` pushes and reconciled via
`peek`, never pushed incrementally by the server beyond each new chunk's own
offset/length (see the `held`/`stream-list` messages above).

`performAction(prefixLen, newData, newBounds, releaseChunks, act)` is the one
control-driven entry point: replaces the buffer's first `prefixLen` bytes with
`newData`/`newBounds` (empty `newData` = deletion, `prefixLen=0` = pure insertion), then
releases the resulting buffer's first `releaseChunks` chunks per `act` (`actForward`
sends real bytes; `actDrop` sends empty data, reusing the chain's existing "empty data
drops" convention). Edit and release happen in one call specifically to avoid a window
where a concurrent `appendChunk`/hold-timeout `releaseAll` could interleave; `prefixLen`
also doubles as the wire protocol's staleness check for a `release` command. `abort()`
(terminates the connection) and `releaseAll()` (unmodified release — hold-timeout and
`TamperInterceptor`'s disconnect/`setMode` sweeps) are separate entry points, since
neither carries an edit. A single per-buffer hold-timeout timer (reset on append)
replaces what would otherwise need a timer per chunk. `performAction`/`releaseAll`/
`abort`/`close` hold the buffer's mutex across their channel send/close — the one
deliberate exception to the "no I/O while holding the lock" rule elsewhere in this
codebase, so a send can't race a concurrent `close()`. Unit-tested in isolation
(`buffer_test.go`).

**Script storage (`scripts.go`)** is the storage layer for the programmatic,
callback-driven alternative to manual control-client decisions: JavaScript run in a
browser Web Worker, dispatched from the same control-channel events a human client
reacts to (`stream-created`/`stream-terminated`/`held`), deciding forward/edit/drop
imperatively (not forced to return a verdict synchronously — a script can hold a chunk
and decide later, same as the existing human flow) via the same `peek`/`release`
primitives already documented above. The runtime itself (Worker bootstrap, RPC bridge,
`self.tamper` framework API, and the "Scripts" sub-tab UI) lives entirely in the
frontend — see `scriptRuntime.js`/`TamperScriptsPanel.js`, documented in
`web/CLAUDE.md`'s "Scripted interception" section; nothing on
the Go side executes a script. This module deliberately stays a flat name→text-blob
store with no opinion about which script is "main" or a "library" — that's a
runtime-level concern (explicit load-by-name), not a storage-level one.
[`doc/interceptor/tamper.md`](../../doc/interceptor/tamper.md) is the standalone,
script-author-facing guide to this API (overview, architecture, full `tamper`/`ctx`
function reference with a short example per method, worked examples) — the root
`CLAUDE.md`/this file's coverage is implementation-notes-for-Claude, not a substitute
for it.

- `ScriptsDir` (`scripts-dir` config field): directory scripts are read from/written to,
  one `<name>.js` file per script. Empty disables the feature entirely — the REST
  endpoints still exist but every request gets `501`, rather than silently defaulting to
  an implicit directory. The directory (including any missing parents) is created in
  `NewTamperInterceptor` itself, not `Init`: `RegisterRoutes` runs synchronously while
  the proxy is being built, before `Init` runs asynchronously in the proxy's own start
  goroutine, so the scripts REST handlers must find `i.scripts` already usable the
  moment they're registered — an error here fails proxy construction outright, matching
  how a bad `cert-pem`/`file` path already fails other interceptors' setup.
- **The server is the single source of truth**, not the browser — a save is a plain
  overwrite, no version/etag field, and a script has no `modified` timestamp in the API
  at all (deliberately dropped from the design: nothing depends on it, since staleness
  detection on the client side is driven by the `script-updated` push event below, not a
  timestamp comparison). This is also what makes CLI-driven editing (`tapctl tamper
  script-*`, see `test/tapctl/CLAUDE.md`) a first-class citizen alongside the browser
  rather than a bolted-on afterthought — both just `PUT`/`GET`/`DELETE` the same REST
  resource.
- **Name validation** (`validateScriptName`): charset `[A-Za-z0-9_.\- ]` (letters, digits,
  `_`, `-`, `.`, and spaces — space is discouraged but not forbidden). Path separators are
  excluded outright, so a name is always joined as a single path segment; the only
  dot-sequences that could still resolve outside the scripts directory when joined
  (`"."`/`".."`) are rejected explicitly, along with a leading/trailing `.`/` ` (avoids
  confusable near-duplicates like `"foo"` vs `"foo "`, and — with those covered — dots are
  otherwise harmless). Note `net/http`'s own `ServeMux` already cleans/redirects a
  path containing `..` before it would ever reach the handler, so the explicit check here
  is defense in depth, and the one actually reachable path for verifying it is a direct
  `scriptStore`/`validateScriptName` unit test (`scripts_test.go`), not an HTTP round trip.
- **REST endpoints** (base: `/<proxy-name>/api/i/tamper` or canonical `/api/i/tamper`,
  same convention as the rest of the tamper API): `GET /scripts` → `[{name, size}]`
  (metadata only, no bodies, so listing stays cheap); `GET /scripts/{name}` → raw script
  content, `Content-Type: application/javascript`; `PUT /scripts/{name}` → raw body,
  creates or overwrites, `204` on success; `DELETE /scripts/{name}` → `204`. Content is
  a raw body rather than JSON/base64-wrapped on every one of these — deliberately
  different from dbdump/tamper's other REST responses — since script content is always
  UTF-8 text, and wrapping it would be pure overhead as well as friction for `curl`/CLI
  push-pull. A `PUT`/`DELETE` also pushes a `script-updated` control-channel event
  (`{"name":"..."}`, no separate "deleted" flag — a plain `GET`/list is enough to learn
  whether it still exists) so a connected browser can react without polling.
  `GET /log-file` (same base) → `{"enabled":bool,"filename":"..."}`, static for the
  interceptor's whole run — lets the frontend show "Logged to `<filename>`" (see the root
  `CLAUDE.md`'s "Scripted interception" section, "Log panel" note) without a push event
  to track.
- **`Put` is atomic**: written to a `.tmp-*` temp file in the same directory, then
  `os.Rename`d into place, so a concurrent `Get` can never observe a partial write. Temp
  files never appear in `List()` regardless of timing, since listing filters strictly by
  the `.js` suffix.
- Unit-tested in isolation (`scripts_test.go`): name validation (valid/invalid, including
  traversal attempts), `scriptStore` list/get/put/delete round-trips, directory
  auto-creation, and an HTTP-level end-to-end pass over the real REST handlers.

**Filesystem access (`fs.go`)** grants a running script scoped read/write/list access to
one host directory, for reading fixtures or persisting artifacts across a session —
independent of script storage above (that's the script's own source code; this is
arbitrary data the script reads/writes at runtime). Deliberately a plain REST API, not
folded into the control WebSocket protocol: file I/O has no relation to connection/hold
state or the control channel's push-event model, so REST (mirroring the `/scripts`
convention) keeps it uniform and — like `/scripts` — usable from `curl`/`tapctl` too, not
just the browser.

- `FsRoot` (`fs-root` config field): the directory exposed. Empty disables the feature
  entirely — the REST endpoints still exist but every request gets `501`, same convention
  as `scripts-dir`. Unlike `scripts-dir`, this directory is **not** auto-created: it's
  expected to already exist (e.g. a test-fixtures folder the operator chose), so a
  typo'd path fails interceptor construction outright rather than silently creating an
  arbitrary directory tree — checked in `newFsStore`, called from `NewTamperInterceptor`
  for the same "must be ready the moment `RegisterRoutes` runs" reason `scripts-dir` is.
- **Path containment** (`fsStore.resolve`): a request path is always slash-separated
  (arrives via a URL wildcard) and is neither charset-restricted nor symlink-resolved —
  unlike script names, nested subdirectories are the whole point, and a symlink planted
  inside `fs-root` escaping it is treated as a host-filesystem concern out of scope for
  this store to solve. Containment instead falls out structurally: `path.Clean("/" +
  relPath)` is computed first, with the synthetic leading `/` making any leading `..`
  segments collapse against that boundary before the result is ever joined onto the root
  — so the cleaned path can never climb above where it started, regardless of how many
  `..` segments a request throws at it. `filepath.Join(root, ...)` plus a
  boundary-aware suffix check (`strings.HasPrefix(full, root+separator)`, not a bare
  prefix check, which would wrongly accept a sibling directory like `<root>-evil`) is a
  second, independent guard against the same escape. Unit-tested directly
  (`fs_test.go`), including deep `../../..` traversal attempts.
- **REST endpoints** (base: `/<proxy-name>/api/i/tamper` or canonical `/api/i/tamper`):
  `GET /fs/list` and `GET /fs/list/{path...}` → `[{name, dir, size}]`, one directory level
  (not recursive — `dir:true` entries are listed again by requesting that path); `size` is
  whatever the OS reports for a directory (meaningless — callers should key off `dir`
  instead). `GET /fs/file/{path...}` → raw bytes, `Content-Type:
  application/octet-stream` (unlike `/scripts`, content here is arbitrary binary, not
  always UTF-8 JS, hence the generic content type and no JSON/base64 wrapping either).
  `PUT /fs/file/{path...}` → raw body, `204` on success; creates/overwrites, and
  auto-creates missing parent directories (a script writing into a new subdirectory
  shouldn't need a separate mkdir call this store doesn't offer). `POST
  /fs/file/{path...}` → raw body, `204` on success; **appends** rather than overwriting
  (creating the file, and any missing parent directories, if it doesn't exist yet) — see
  `Append` below for why this is `POST`, not `PUT`. No `DELETE` in this first cut. Two
  patterns are registered for `list` (with and without the trailing wildcard) because
  Go's `{path...}` wildcard doesn't match an empty trailing segment, so root and
  subdirectory listing need separate routes to the same handler.
- **`Put` is atomic**, same `.tmp-*`-then-`os.Rename` discipline as `scripts.go`, except
  the temp file is created alongside the target (which may be nested under a
  subdirectory, not `fs-root` itself) rather than in a single fixed directory.
- **`Append`** opens the target with `O_APPEND` (creating it if needed) rather than
  being a client-side `Get`+concatenate+`Put`: two scripts (or their `onReceive`
  handlers for different connections, which run on independent per-conn goroutines — see
  the root `CLAUDE.md`'s "Per-connection event serialization" note, under "Scripted
  interception") appending to the same file around the same time would otherwise race,
  silently losing one side's data. `O_APPEND` delegates the seek-to-end-and-write to the
  kernel, which performs it atomically per `Write` call — the same mechanism the
  interceptor's own `log-file` already relies on (`writeScriptLog`/`Init` in
  `tamper.go`) — so no locking of our own is needed. `handleFsAppend` is registered as
  `POST`, not `PUT`: `PUT` is expected to be idempotent (repeat = same result), which an
  append explicitly isn't (repeat = appended twice); `POST` is the generic "process this
  at the target resource, non-idempotent" verb, despite every other `fs-root` endpoint
  being `GET`/`PUT`.
- Unit-tested in isolation (`fs_test.go`): path resolution (including traversal attempts
  and the boundary-vs-bare-prefix distinction), construction requiring an existing
  directory, put/get/list/append round-trips including nested subdirectories, atomic-write
  cleanup, an HTTP-level end-to-end pass over the real REST handlers (including `POST`),
  and a concurrent-append race test (20 goroutines × 50 appends each to the same file,
  asserting no lost or duplicated lines) verifying the `O_APPEND` safety claim above.
