# tlstap — TLS Intercepting Proxy

Go module: `tlstap`  
Entry point: `tlstap.go` → `cli.StartWithCli(nil)`  
Build: `go build .`; custom interceptors build their own `main` under `examples/`.

> **High priority:** read the **Code Style** section below before writing or editing
> any code. Its rules override default habits and must be followed exactly.

## Tooling

Available on demand — prefer these over hand-rolled equivalents:
- `jq` — JSON processing.
- `yq` — YAML processing (e.g. `doc/openapi.yaml`).
- `tapctl` — CLI for the tamper/dbdump WebSocket + REST APIs; see "Testing interceptor
  APIs" below.

If one of these isn't installed when needed, ask the user to install it rather than
working around its absence.

## Code Style

### Comment Policy

Default to no comment at all; add one only when skipping it would leave a reader
surprised or misled. When a comment is warranted, it must:

1. Be brief — no more than the fact and, if needed, a short reason why.
2. State only what is true and non-obvious about the code it annotates — if the code
   already shows it, the comment isn't earning its place.
3. Never narrate history — no past bugs, no design alternatives once tried.
4. Never narrate relationships to other code — no "only called from X," no "same as Y
   does it," no caller/sibling enumeration. Describe this code, not the rest of the
   codebase.

### Code Duplication

Default to sharing logic that two or more call sites must always change together;
default to leaving logic separate when it only resembles another spot today. When
consolidating:

1. Extract only when a bug fix or behavior change would have to be applied
   identically everywhere it currently appears — that's one piece of logic, not
   several accidental copies of it.
2. Don't force a shared abstraction to swallow a genuine per-caller difference (e.g.
   a different data shape) via an extra parameter or branch — two separate copies are
   usually clearer than one that needs a flag to behave differently per caller.
3. When refactoring several files at once, judge each small pure helper on its own —
   don't bundle a genuinely shared one in with a neighbor whose reason for staying
   separate doesn't actually apply to it.
4. Prefer a few similar lines over a new shared file/hook for something used in
   exactly one place today; extract once a second real use exists.

## Architecture

```
cli/cli.go          ← parses config.json, wires everything together, starts proxies
proxy/              ← core proxy logic
  proxy.go          ← Proxy struct, Start(), mode dispatch, ALPN negotiation
  conn_handler.go   ← ConnHandler: per-connection forwarding, intercept pipeline
  interceptor.go    ← Interceptor interface + ConnInfo
  config.go         ← ConfigFile, ProxyConfig, TlsServerConfig, TlsClientConfig structs
  mux.go            ← Mux + Handler: SNI-based TLS multiplexing
  tls.go            ← TLS config parsing (ParseServerConfig, ParseClientConfig)
  probe.go          ← Prober: ALPN probe via deliberate TLS handshake
  mode.go           ← Mode constants: ModePlain/ModeTls/ModeDetectTls/ModeMux
  settings.go       ← ConnSettings (per-connection resolved config)
  buf_conn.go       ← BufferedConn: peek-capable wrapper for TLS detection
  asn1.go, util.go  ← certificate formatting helpers
  api.go            ← ApiProvider optional interface for interceptor REST APIs
intercept/          ← built-in interceptor implementations
  null.go           ← NullInterceptor: embed to skip unused methods
  hexdump/          ← logs data as hex to logger
  pcapdump/         ← writes traffic to a .pcap file (uses gopacket)
  match_replace/    ← regex-based find/replace on payload bytes
  bridge/           ← forwards data to a TCP endpoint (custom binary framing)
  drop/             ← drops connection on TLS upgrade (for TLS downgrade testing)
  dbdump/           ← logs traffic to an SQLite database; exposes a REST API + WebSocket
    dbdump.go       ← interceptor lifecycle, DB schema, data capture
    api.go          ← REST API handlers (RegisterRoutes + endpoints + WebSocket); also
                      wires scriptstore.RegisterRoutes for /scripts (framer scripts)
    search.go       ← /search-text handler; literal and regex search across chunks
    frames.go       ← frames/frame_progress storage layer for a client-run framer script
  scriptstore/      ← shared name→content *.js store + REST CRUD handlers; used by tamper's
                      control scripts and dbdump's framer scripts
  tamper/           ← live hold/edit/drop/forward of traffic; control + watch WebSocket API
    tamper.go       ← interceptor lifecycle, hold/resolve logic, direction detection
    api.go          ← WebSocket handlers (control: commands/acks/events; watch: mirror + peek);
                      also wires scriptstore.RegisterRoutes for /scripts
    protocol.go     ← wire message types for both WebSockets
    buffer.go       ← heldBuffer: per-(stream,direction) growing buffer + chunk bounds
    fs.go           ← fs-root: scoped REST read/write/list of one host directory, for scripts
web/                ← embedded web frontend (Preact + htm, no build step)
  server.go         ← //go:embed; exports FS (embedded into binary)
  index.html        ← HTML shell, importmap, all CSS (dark theme)
  main.js           ← mounts App into #root
  api.js            ← fetch/WebSocket wrappers for /api/i/dbdump/*
  tamperApi.js      ← WebSocket wrappers for /api/i/tamper/* (openTamperControl, peekBuffer) plus plain REST wrappers (scripts, fs-root)
  dbdumpFramerApi.js ← REST wrappers for /api/i/dbdump/* framer-script CRUD + frame-progress/frames/frames-append (see "Framer scripts" in web/CLAUDE.md)
  frameRuntime.js   ← Worker bootstrap that runs a framer script's frame() function over pre-fetched chunks (no RPC bridge, unlike scriptRuntime.js — see web/CLAUDE.md)
  framerRun.js      ← catchUpFramer(): orchestrates fetching un-framed chunks, running frameRuntime.js, and persisting each batch via dbdumpFramerApi.js
  framerPrefs.js    ← localStorage: global default framer script + per-stream override (see "Framer scripts" in web/CLAUDE.md)
  format.js         ← shared byte-encoding helpers (fmtAsRaw/Base64/Hex/Ascii/Hexdump, mergeUint8Arrays)
  direction.js      ← direction constants/helpers (DIRNUM_C2S/DIRNUM_S2C, DIR_C2S/DIR_S2C, dirClass, dirLabel)
  download.js       ← file-save helpers (downloadBlob anchor-click fallback; acquireSaveHandle/writeToFileHandle for the File System Access API)
  markers.js        ← marker localStorage helpers (loadMarkers, saveMarkers, makeMarkerId)
  layout.js         ← panel-size localStorage helpers (loadLayout, saveLayoutValue, clamp)
  useResizableLayout.js ← hook backing every resizable-panel dimension (see "Resizable panels" below)
  useDismissOnOutsideClick.js ← hook backing outside-click/Escape popover dismissal (see below; HexDump.js's context menu is a deliberate non-user)
  useChunkBuffer.js ← hook backing TrafficView.js's/CombinedView.js's windowed/paginated chunk buffer (see below)
  transforms.js     ← aggregates transforms/* into OPERATIONS + ALGORITHM_SECTIONS for the Transform panel
  transforms/       ← one module per transform category (basic.js, numbers.js, compression.js, zip.js, ...); see "transforms.js" section below
  package.json      ← "type":"module" + `npm test` for the transforms/* unit tests (Node's built-in test runner; not embedded into the binary)
  vendor/           ← vendored ES modules (preact 10.25.4, htm 3.1.1, fflate 0.8.3)
  components/
    App.js          ← root; owns top-level view (Analysis/Tamper), session/stream selection, view mode, menu bar, bottom panel, jumpTo, extract state, sidebar/bottom-panel sizing
    ListPanel.js    ← shared panel-header (title/badge/sort-toggle) + sorted/selectable item list, used by SessionList.js/StreamList.js
    SessionList.js  ← sessions panel, built on ListPanel.js (sort toggle asc/desc)
    StreamList.js   ← streams panel, built on ListPanel.js (sort toggle resets to asc on session change)
    TrafficView.js  ← single-stream view, built on useChunkBuffer.js (stid-keyed): metadata bar + virtual scroll + jump-to + markers-panel sizing; also owns the Framer control + frame-view toggle (a second, frame-keyed useChunkBuffer instance — see "Framer scripts" in web/CLAUDE.md)
    CombinedView.js ← combined-stream view, built on useChunkBuffer.js (sgid-keyed): all streams in a session merged chronologically
    HexDump.js      ← virtual-scroll hex dump with prefetch, scroll correction, byte selection, context menu (read-only, for captured traffic)
    HexEditor.js    ← small non-virtualized editable hex/ASCII grid with an insertion cursor; used by TransformPanel and the Tamper tab (editable input, read-only output)
    ResizeHandle.js ← generic draggable divider (vertical/horizontal) used for every resizable panel boundary
    GoToPanel.js    ← "Goto" bottom-panel tab: jump to chunk/offset by stid or direction-specific ID
    SearchPanel.js  ← "Search" bottom-panel tab: pattern search with format/direction/contiguous options
    ExtractPanel.js ← "Extract" bottom-panel tab: fetch and save/copy a byte range in various formats
    TransformPanel.js ← "Transform" bottom-panel tab: a step pipeline that runs input bytes through encode/decode operations into an output panel
    MarkersPanel.js ← side panel listing session markers with inline label editing; import/export
    TamperView.js   ← Tamper tab root: control connection lifecycle, live queue state, layout
    TamperStreamsList.js ← Tamper tab: per-stream list with intercept/watch toggle
    TamperQueueList.js   ← Tamper tab: list of currently-held buffers (one per stream+direction) across all streams
    TamperDetailPanel.js ← Tamper tab: selected buffer's chunks (via peek), segmented/continuous view, forward/drop/drop-connection, and a per-chunk context menu (drop/forward/split/merge)
logging/            ← thin slog wrapper
assert/             ← assert.Assertf — panics with message; used for "this is a bug" invariants
examples/           ← standalone binaries showing how to write custom interceptors, plus
                      framer/tamper script examples (e.g. dbdump/framer/tls-framer.js — a
                      TLS record-layer framer; see "Framer scripts" below)
test/               ← echo server/client helpers, CLI wrappers for manual testing, and tapctl/
                      (one-shot test client for the tamper/dbdump WebSocket + REST APIs)
```

## Proxy Modes

| Config string | Mode constant | Behavior |
|---|---|---|
| `plain` | `ModePlain` | Plain TCP forwarding; TLS configs ignored |
| `tls` | `ModeTls` | Full TLS MITM; terminates TLS on both sides |
| `detecttls` | `ModeDetectTls` | Starts plain; detects TLS Client Hello and upgrades in-place |
| `tls-mux` | `ModeMux` | TLS MITM with per-SNI routing to different upstreams/configs |

## Interceptor Interface (`proxy/interceptor.go`)

```go
type Interceptor interface {
    Init(addr net.TCPAddr) error              // called once before first connection
    Finalize(addr net.TCPAddr)               // called on shutdown
    ConnectionEstablished(info *ConnInfo) error
    ConnectionUpgraded(info *ConnInfo) error  // TLS upgrade completed; return ErrAbort to drop
    ConnectionTerminated(info *ConnInfo) error
    Intercept(info *ConnInfo, data []byte) ([]byte, error)
    // return empty slice to drop data; return ErrAbort to terminate connection
}
```

- `ErrAbort` (`proxy/interceptor.go`) terminates the connection immediately.
- Embed `intercept.NullInterceptor` to avoid implementing unused methods.
- Interceptors are chained: each gets the output of the previous. Empty return drops the data.
- Direction is set in config (`up`, `down`, `any`/`""`); the same instance is added to both up and down slices for `any`.

## Buffering Interceptors (`proxy/buffering.go`)

An interceptor that holds data across multiple `Intercept()` calls (rather than deciding
synchronously within one) can opt into an additional interface:

```go
type BufferingInterceptor interface {
    Interceptor
    HasPending(info *ConnInfo) bool
    ReleaseChannel(info *ConnInfo) <-chan ReleasedData
}

type ReleasedData struct {
    Data []byte
    Err  error // e.g. ErrAbort, to terminate the connection instead of forwarding Data
}
```

**Why this exists:** without it, an interceptor that blocks inside `Intercept()` (e.g. to wait
for a human decision) blocks the entire read loop for that direction — a second chunk can't even
be read off the socket while the first is held. `tamper`'s original design (before adopting this
interface) hit exactly this limit, holding at most one chunk per direction at a time — see
`intercept/tamper/CLAUDE.md`'s "No goroutine is parked per held chunk" note for how that changed.

**Contract for implementers:**
- No constraint on combining a non-empty `Intercept()` return with something still pending — an
  implementation may forward part of what it received and keep holding the rest.
- Must never release data that arrived later before data that arrived earlier, for a given
  `(ConnID, direction)` — i.e. must preserve its own local FIFO. Global ordering across a chain
  with multiple buffering interceptors falls out of composing this local guarantee at each stage;
  `ConnHandler` enforces nothing itself beyond calling interceptors in chain order.
- Must close the channel returned by `ReleaseChannel` once `ConnectionTerminated` has fired for
  that `ConnID`, and never send on it afterward.

**`ConnHandler` mechanics** (`proxy/conn_handler.go`):
- `forwardOneWay` (phase 1) is the direct blocking-read loop, unchanged in cost for any chain
  without a buffering interceptor (`scanBuffering`, run once per connection, makes the check a
  single cheap boolean). The first time a buffering interceptor reports pending data, it
  transitions once, between loop iterations, into `forwardOneWayAsync` (phase 2): a `select`
  between a `readPump` goroutine (owns all further `Read` calls for that direction, since Go can't
  `select` on a plain blocking `net.Conn.Read`) and a merged release channel (`fanInReleases`,
  supports multiple buffering interceptors per chain). A released chunk resumes the chain via
  `interceptFrom(idx+1, ...)` (`intercept()` is a thin wrapper `interceptFrom(0, ...)`).
- Every goroutine `forwardOneWayAsync` spawns races its sends against a `stop` channel closed via
  `defer` on return, so nothing blocks forever handing data to an already-exited consumer (same
  discipline `tamper`'s watcher teardown uses — see `intercept/tamper/CLAUDE.md`).
- Wired into `forwardGeneric` (plain/tls/tls-mux) and post-upgrade `forwardDetectTls`; the
  down-direction of `detecttls` and `drainConn` are a deliberate scope cut (still synchronous).
- `tamper` is the one production implementer (via `heldBuffer`); `proxy/buffering_test.go` has a
  test-only fake for exercising `ConnHandler`'s mechanics in isolation.

## Writing a Custom Interceptor

Pattern (see `examples/rot-interceptor/main.go`):

```go
// 1. Embed NullInterceptor for boilerplate
type MyInterceptor struct {
    intercept.NullInterceptor
    // ... fields
}

// 2. Implement only what you need
func (i *MyInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
    // transform data; return modified bytes
    return data, nil
}

// 3. Register via callback in main()
func configCallback(config proxy.ResolvedProxyConfig, iConfig proxy.InterceptorConfig, logger *logging.Logger) (proxy.Interceptor, error) {
    var myConf MyConfig
    json.Unmarshal(iConfig.ArgsJson, &myConf)
    return &MyInterceptor{...}, nil
}

func main() {
    cli.StartWithCli(configCallback)
}
```

The interceptor name in `config.json` must match what the callback checks in `iConfig.Name`.

## Config File (`config.json`)

Top-level keys: `proxies`, `tls-server-configs`, `tls-client-configs`, `interceptors`, `api`.

Proxies reference server/client configs and interceptors by name (string keys). The `--enable` CLI flag selects which proxies to run (default: all).

Key TLS server options: `cert-pem`, `cert-key`, `alpn-preference`, `alpn-probe`, `alpn-probe-cache`, `keylog`.  
Key TLS client options: `skip-verify`, `sni-passthrough`, `alpn-passthrough`, `roots`, `server-name`, `alpn`, `keylog`.  
`api` key: `{"listen": "127.0.0.1:9090"}` — starts the REST API HTTP server on the given address.

## ALPN Negotiation

Three strategies (configured on the server side):
1. `alpn-preference` list — proxy picks the first mutually acceptable protocol.
2. Single protocol offered by client — automatically accepted.
3. `alpn-probe: true` — proxy opens a real TLS connection to upstream to discover its preference, then mirrors it back to the client. Results can be cached with `alpn-probe-cache: true`.

`alpn-passthrough` on the client side passes the negotiated protocol through to upstream.

## Built-in Interceptors

| Name | Type | Config args |
|---|---|---|
| `hexdump` | `HexDumpInterceptor` | none |
| `pcapdump` | `PcapDumpInterceptor` | `file` (path), `truncate` (bool) |
| `match-replace` | `MatchReplaceInterceptor` | `replacements`: ordered list of `{regex: replacement}` maps |
| `bridge` | `BridgeInterceptor` | `connect` (endpoint); streams data to a TCP server using a custom binary framing protocol |
| `droptls` | `DropTlsInterceptor` | none; aborts on `ConnectionUpgraded` to attempt TLS downgrade |
| `dbdump` | `DbDumpInterceptor` | `file` (path), `truncate` (bool), `scripts-dir` (string, optional — storage for user-authored framer scripts; see `intercept/dbdump/CLAUDE.md`'s "Framer scripts" section); logs all traffic to SQLite; exposes REST API |
| `tamper` | `TamperInterceptor` | `hold-timeout-ms` (int, `<=0` = infinite), `hold-until-connected` (bool), `scripts-dir` (string, optional), `fs-root` (string, optional — grants scripts scoped read/write/list access to this host directory via REST; see `intercept/tamper/CLAUDE.md`'s "Filesystem access" section), `log-file` (string, optional — persists a running script's `tamper.log`/`ctx.log` output server-side, always appended to; see `intercept/tamper/CLAUDE.md`'s "Script storage" section and `web/CLAUDE.md`'s "Scripted interception" section); lets a connected control client actively pause, inspect, edit, drop, or forward live chunks, or just live-watch them; exposes a WebSocket API |

## REST API

Interceptors can optionally expose HTTP endpoints by implementing `proxy.ApiProvider` (`proxy/api.go`):

```go
type ApiProvider interface {
    RegisterRoutes(mux *http.ServeMux, basePath string)
}
```

`cli.go` checks each built interceptor for this interface and calls `RegisterRoutes` with `/<proxy-name>/api/i/<interceptor-name>` as `basePath`. A single `http.ServeMux` is shared across all proxies; the server is started once after all proxies are wired up, only if `"api": {"listen": "..."}` is present in `config.json`.

**Canonical alias:** each interceptor type is also registered at `/api/i/<interceptor-name>` (once, on first occurrence). This is what the web frontend uses — it never needs to know the proxy name. The `canonicalRegistered map[string]bool` in `cli.go` prevents duplicate-pattern panics.

The web frontend is served unconditionally at `/ui/` (`GET /ui` → 302 redirect). It is embedded into the binary via `web.FS`.

All API responses use `Content-Type: application/json`. Errors are returned as `{"error": "..."}` with an appropriate HTTP status code.

## dbdump Interceptor (`intercept/dbdump/`)

Passively records all captured traffic to SQLite and exposes a pull/replay history API
via REST/WebSocket. **Full schema, in-memory state, and endpoint/protocol reference live
in `intercept/dbdump/CLAUDE.md`**, loaded automatically when working in that directory.

## tamper Interceptor (`intercept/tamper/`)

Lets a connected control client actively pause, inspect, edit, drop, or forward
individual chunks of live traffic, or just live-watch it without holding anything up;
also exposes script-storage (`scripts-dir`) and filesystem-access (`fs-root`) REST APIs
for the programmatic scripting alternative documented in `web/CLAUDE.md`.
**Full backend implementation reference — wire protocol, `heldBuffer`, script/fs-root
storage — lives in `intercept/tamper/CLAUDE.md`**, loaded automatically when working in
that directory.

## Testing interceptor APIs (`test/tapctl/`)

`tapctl` is a one-shot Go CLI (`tapctl <group> <command> [flags]`, one group per
interceptor: `tamper`, `dbdump`) for driving the `dbdump`/`tamper` REST/WebSocket APIs
by hand — build via `go build -o tapctl ./test/tapctl`. **Full command reference, usage
examples, and `tapctl`-specific design notes live in `test/tapctl/CLAUDE.md`**, kept
separate from this file (loaded only when working in that directory) since it's a
sizable, fairly self-contained document that mirrors the API rather than defining it.

## Key Implementation Details

- **`ConnHandler.intercept()` / `interceptFrom()`** (`conn_handler.go`): `intercept` is a thin wrapper over `interceptFrom(0, ...)`, which folds interceptors from a given start index — used both for a normal full pass and to resume the chain right after a buffering interceptor releases data. On non-abort errors, logs a warning and forwards the previous data unchanged; the fold also breaks the moment data becomes empty, so remaining interceptors in that pass are never called.
- **`forwardOneWay` / `forwardOneWayAsync`** (`conn_handler.go`): see "Buffering Interceptors" above for the full two-phase design (direct blocking read vs. pump+select).
- **`forwardDetectTls`**: uses `BufferedConn.Peek()` to look for a TLS Client Hello without consuming bytes. On detection it sets a deadline on the upstream conn, signals via `upgradeChan`, drains outstanding data, then upgrades both sides.
- **`terminate()`** uses `sync.Once` to set deadlines on both conns — this is the shutdown mechanism; errors in `forwardOneWay` trigger it. Note: `terminate()` calls `wg.Done()` unconditionally (once, via the `sync.Once`) regardless of which direction's goroutine called it — so `ConnHandler.forwardGeneric()`'s `wg.Wait()` can return, and `ConnectionTerminated` can fire, *before* the other direction's `forwardOneWay` goroutine has actually returned (e.g. while it's still mid-`Intercept()` call, or — for a `BufferingInterceptor` like `tamper` — mid-append to a buffer `ConnectionTerminated` is about to close; see `intercept/tamper/CLAUDE.md`'s "No goroutine is parked per held chunk" note). Interceptor code that reacts to `ConnectionTerminated` must not assume no other goroutine for the same `ConnID` can still be mid-`Intercept()`.
- **`Prober`**: makes a real TLS dial with a `VerifyConnection` hook that captures the negotiated protocol then returns an error to abort immediately. Failures are counted; after `maxFailures=5` the cache gives up.
- Package name in `proxy/` is `proxy`, matching the directory name. Import as `"tlstap/proxy"`.
- `bufSize = 1<<16` (64 KB) — single shared read buffer per direction per connection.
- `drainTimeoutMs = 10` microseconds (not milliseconds despite the name).
- **Graceful shutdown** (`cli.StartWithCli`, `proxy.Proxy`): `SIGINT`/`SIGTERM` trigger a
  bounded sequence — stop every proxy's listener (`Proxy.Stop()`) and start the API
  server's `http.Server.Shutdown()` together, wait (bounded, `drainTimeout`/
  `apiShutdownTimeout`) for in-flight connections/requests to drain, *then* call every
  interceptor's `Finalize()` (`Proxy.Finalize()`, concurrently, bounded by
  `finalizeTimeout`) — draining before finalizing is what stops `Finalize()` (e.g.
  `dbdump` closing its DB) from racing a still-in-flight `Intercept()`/REST call against
  the same interceptor instance. A second signal at any point forces an immediate
  `os.Exit(1)`. `Proxy.InterceptorsAll` plus each `Mux` handler's own `InterceptorAll`
  are already the complete, de-duplicated set of every interceptor instance built for
  that proxy — no separate registry needed. Known accepted gap: hijacked WebSocket
  connections (`tamper`/`dbdump`'s control/watch/segments sockets) aren't drained by
  `http.Server.Shutdown()` (documented Go behavior) — simply abandoned at exit.

## Web Frontend (`web/`)

Served at `/ui/` by the API HTTP server — Preact 10.25.4 + htm 3.1.1, no build step,
vendored ES modules loaded via an importmap. Two top-level tabs: **Analysis** (browse
captured/combined traffic, search, extract, and transform bytes) and **Tamper** (live
intercept — hold/edit/drop/forward traffic by hand, or via a scripted `tamper.*`/`ctx.*`
API running in a Worker). **Full component/hook reference, wire-level UI mechanics, and
the Transform panel's operation catalog live in `web/CLAUDE.md`**, loaded automatically
when working in that directory.

## Documentation

- `doc/openapi.yaml` — OpenAPI 3.1.0 specification for all REST and WebSocket endpoints

## TODO

Known gaps and deferred work, collected here so they aren't rediscovered from scratch.

- **`doc/openapi.yaml`'s `{path}` parameters don't survive standard OpenAPI tooling.**
  `/api/i/tamper/fs/list/{path}` and `/fs/file/{path}` document `path` as a single
  `in: path` string, but the real route is a `{path...}` wildcard that can embed
  `/`-separated segments — standard tooling (Swagger UI, most codegen) percent-encodes
  `/` in a path parameter, so it can't actually drive a nested path through these
  operations as written. Needs a parameter-modeling redesign (e.g. prose-only
  documentation for the parameter, or a vendor extension), not a safe drive-by edit.
- **Packet dissector stage — not started.** `doc/design/packet-dissector.md` covers two
  stages: framer (done — see `intercept/dbdump/CLAUDE.md`'s "Framer scripts" section)
  and dissector (deferred, no work begun).
- **Byte-budgeted segment buffer — `TrafficView.js` fully migrated, `CombinedView.js`
  still pending (deliberately deferred).** `doc/design/hexview-segment-buffer.md` has the
  full migration plan; all of `TrafficView.js` (raw and frame mode) now runs on
  `useByteBuffer.js` (see `web/CLAUDE.md`'s "Byte-budgeted segment buffer" section);
  `CombinedView.js` is unchanged, still on `useChunkBuffer.js` — its migration is about
  consistency, not fixing a bug (it never shows huge segments), so it's left open until
  asked for rather than done proactively.
- **Frame view has no explicit "no frames found" empty state.** A successful Run with
  zero resulting frames (stale `frame_progress`, or a script that legitimately finds
  nothing for that stream) renders silently blank in `TrafficView.js`, indistinguishable
  from "still loading." Low-risk, small; do it if asked, not proactively.
- **Framer return protocol could avoid enumerating `{offset, length}` per frame.** A
  script currently returns a `frames` array explicitly, one entry per frame, each call.
  An alternative: the script just reports "the current frame ends at position N" (an
  incremental watermark), and the platform derives each frame's `[start, end)` from
  successive watermarks itself — fewer round-tripped fields per frame, closer to the
  "pure function over bytes" framer already aims for. A genuine protocol redesign, not a
  drive-by fix — needs its own scoping pass before starting.
- **`isWindowFull` (`web/byteBufferCore.js`) can't tell a backward-opened huge frame is
  still incomplete.** It only checks the *end* boundary (`loadedEnd >= segment.offset +
  segment.length`); a window opened while scrolling backward into a huge frame has
  `loadedEnd` pinned to the segment's true end from its very first partial load (see
  `initialWindowRange`'s backward case in `web/CLAUDE.md`'s "Byte-budgeted segment
  buffer"), so it reads as "full" immediately even while its front is still unloaded.
  Practical effect: `extendResumeWindow` for backward is unreachable once that window's
  boundary is revisited, so scrolling further up into a huge frame silently stops growing
  its loaded range instead of continuing to load its front. Needs a real
  backward-completeness check (e.g. tracking `loadedStart <= segment.offset` separately)
  plus a test exercising backward extension of an oversized segment across multiple
  quanta, which nothing currently does.

## Dependencies

- `github.com/google/gopacket` — pcap writing in `intercept/pcapdump/`
- `github.com/smallnest/ringbuffer` — used in `proxy/buf_conn.go`
- `modernc.org/sqlite` — pure-Go SQLite driver (no CGO), used by `intercept/dbdump/`
- `github.com/gorilla/websocket` — WebSocket server in `intercept/dbdump/api.go`/`intercept/tamper/api.go`; also used client-side by `test/tapctl` (the web frontend uses the browser's native `WebSocket` instead)
- `fflate` 0.8.3 (`web/vendor/fflate.module.js`) — zip/gzip/deflate/zlib support in `web/transforms/zip.js`/`compression.js`. Unmodified copy of the package's own unminified browser ESM build.
- `crypto-js` 4.2.0 (`web/vendor/crypto-js.module.js`) — MD5/SHA1/SHA2 family + HMAC (`web/transforms/hash.js`/`mac.js`) and DES/TripleDES/RC4 (`web/transforms/encryption.js`). esbuild bundle, unminified; rebuild recipe in the file's header comment.
- `hash-wasm` 4.12.0 (`web/vendor/hash-wasm-whirlpool.module.js`) — Whirlpool hash in `web/transforms/hash.js` (the one algorithm crypto-js lacks). esbuild bundle, unminified; rebuild recipe in the file's header comment.
- `@noble/ciphers` 2.2.0 (`web/vendor/noble-ciphers/`) — AES (CBC/CTR/GCM) and Salsa20/ChaCha20 in `web/transforms/encryption.js` (crypto-js has no GCM/AEAD support). Unmodified copy of the package's own source files.
- CodeMirror 6 (`web/vendor/codemirror.module.js`) — script editor (`web/components/ScriptEditor.js`) for the Tamper "Scripts" sub-tab. esbuild bundle, unminified; rebuild recipe in the file's header comment.
