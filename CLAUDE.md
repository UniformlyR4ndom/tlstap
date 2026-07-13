# tlstap — TLS Intercepting Proxy

Go module: `tlstap`  
Entry point: `tlstap.go` → `cli.StartWithCli(nil)`  
Build: `go build .`; custom interceptors build their own `main` under `examples/`.

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
    api.go          ← REST API handlers (RegisterRoutes + endpoints + WebSocket)
    search.go       ← /search-text handler; literal and regex search across chunks
web/                ← embedded web frontend (Preact + htm, no build step)
  server.go         ← //go:embed; exports FS (embedded into binary)
  index.html        ← HTML shell, importmap, all CSS (dark theme)
  main.js           ← mounts App into #root
  api.js            ← fetch/WebSocket wrappers for /api/i/dbdump/*
  format.js         ← shared byte-encoding helpers (fmtAsRaw/Base64/Hex/Ascii/Hexdump, mergeUint8Arrays)
  markers.js        ← marker localStorage helpers (loadMarkers, saveMarkers, makeMarkerId)
  layout.js         ← panel-size localStorage helpers (loadLayout, saveLayoutValue)
  transforms.js     ← aggregates transforms/* into OPERATIONS + ALGORITHM_SECTIONS for the Transform panel
  transforms/       ← one module per transform category (basic.js, numbers.js, compression.js, zip.js, ...); see "transforms.js" section below
  package.json      ← "type":"module" + `npm test` for the transforms/* unit tests (Node's built-in test runner; not embedded into the binary)
  ringbuffer.js     ← ring buffer utility
  vendor/           ← vendored ES modules (preact 10.25.4, htm 3.1.1, fflate 0.8.3)
  components/
    App.js          ← root; owns session/stream selection, view mode, menu bar, bottom panel, jumpTo, extract state, sidebar/bottom-panel sizing
    SessionList.js  ← sessions panel with sort toggle (asc/desc)
    StreamList.js   ← streams panel with sort toggle (resets to asc on session change)
    TrafficView.js  ← single-stream view: metadata bar + stid-based chunk buffer + virtual scroll + markers-panel sizing
    CombinedView.js ← combined-stream view: sgid-based chunk buffer across all streams in a session
    HexDump.js      ← virtual-scroll hex dump with prefetch, scroll correction, byte selection, context menu (read-only, for captured traffic)
    HexEditor.js    ← small non-virtualized editable hex/ASCII grid with an insertion cursor; used by TransformPanel (editable input, read-only output)
    ResizeHandle.js ← generic draggable divider (vertical/horizontal) used for every resizable panel boundary
    GoToPanel.js    ← "Goto" bottom-panel tab: jump to chunk/offset by stid or direction-specific ID
    SearchPanel.js  ← "Search" bottom-panel tab: pattern search with format/direction/contiguous options
    ExtractPanel.js ← "Extract" bottom-panel tab: fetch and save/copy a byte range in various formats
    TransformPanel.js ← "Transform" bottom-panel tab: a step pipeline that runs input bytes through encode/decode operations into an output panel
    MarkersPanel.js ← side panel listing session markers with inline label editing; import/export
logging/            ← thin slog wrapper
assert/             ← assert.Assertf — panics with message; used for "this is a bug" invariants
examples/           ← standalone binaries showing how to write custom interceptors
test/               ← echo server/client helpers and CLI wrappers for manual testing
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
| `dbdump` | `DbDumpInterceptor` | `file` (path), `truncate` (bool); logs all traffic to SQLite; exposes REST API |

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

**In-memory state** (protected by `sync.RWMutex`):
- `clientEndpoints map[uint32]string` — maps `ConnID` → client endpoint to derive direction in `Intercept`.
- `chunkStates map[chunkKey]chunkState` — tracks `(nextID, nextOffset)` per `(ConnID, direction)`; entries are deleted in `ConnectionTerminated`.
- `streamNextSTID map[uint32]int64` — tracks next stid per `ConnID`; deleted in `ConnectionTerminated`.
- `nextSGID int64` — session-global chunk counter, incremented under mutex on every `Intercept` call.

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

**API endpoints** (base: `/<proxy-name>/api/i/dbdump` or canonical `/api/i/dbdump`):

| Method | Path | Request body | Response |
|---|---|---|---|
| GET | `/status` | — | `{"status":"ok"}` |
| GET | `/sessions` | — | JSON array of `{id, start, config}` |
| POST | `/streams` | `{"session": N}` | JSON array of `{id, session, src, dst, start, end, length0, length1}` — end=0 if ongoing; length fields are total captured bytes per direction (-1 if none) |
| POST | `/chunklist` | `{"session": N, "stream": N}` | `{"latest0": int64, "latest1": int64, "length0": int64, "length1": int64}` — latest chunk ID and total byte length per direction; -1 if no chunks yet |
| POST | `/chunk` | `{"session":N,"stream":N,"direction":N,"chunks":[...]}` | `multipart/form-data`; one part per chunk with raw bytes as body and `X-Chunk-Offset`/`X-Chunk-Time` headers |
| POST | `/chunk-stid` | `{"session":N,"stream":N,"direction":N,"id":N}` | `{"stid": N}` — resolves per-direction chunk `id` → `stid`; 404 if not found |
| POST | `/byte-stid` | `{"session":N,"stream":N,"direction":N,"offset":N}` | `{"stid": N}` — finds the stid of the chunk whose `offset <= N` (i.e. the chunk containing that byte); 404 if no chunk in that direction |
| POST | `/search-text` | see below | JSON array of `{stream, direction, offset, stid}` matches |
| WS | `/stid-stream` | — | WebSocket; streams chunks for one stream ordered by stid; see protocol below |
| WS | `/sgid-stream` | — | WebSocket; streams chunks for one session ordered by sgid (across all streams); see protocol below |

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
- `pattern_encoding` `""` / `"text"` — raw UTF-8 literal.
- `pattern_encoding` `"base64"` — arbitrary bytes base64-encoded (frontend always uses this for non-regex formats to support binary/UTF-16/hex patterns).
- `pattern_encoding` `"regex"` — Go `regexp` syntax; invalid pattern → 400. `contiguous` flag still applies (chunks concatenated per 1 MB batch), but no cross-batch overlap since minimum match length is unknown.
- Non-contiguous mode: each chunk searched independently; cross-chunk matches not found.
- Contiguous mode (literal): chunks accumulated into 1 MB batches; `len(pattern)-1` byte overlap between batches catches cross-batch splits. Implemented in `search.go` via `matchFinder` abstraction (`literalFinder` / `regexFinder`).

## Key Implementation Details

- **`ConnHandler.intercept()`** (`conn_handler.go:399`): runs the interceptor chain; on non-abort errors, logs a warning and forwards original data unchanged.
- **`forwardDetectTls`**: uses `BufferedConn.Peek()` to look for a TLS Client Hello without consuming bytes. On detection it sets a deadline on the upstream conn, signals via `upgradeChan`, drains outstanding data, then upgrades both sides.
- **`terminate()`** uses `sync.Once` to set deadlines on both conns — this is the shutdown mechanism; errors in `forwardOneWay` trigger it.
- **`Prober`**: makes a real TLS dial with a `VerifyConnection` hook that captures the negotiated protocol then returns an error to abort immediately. Failures are counted; after `maxFailures=5` the cache gives up.
- Package name in `proxy/` is `proxy`, matching the directory name. Import as `"tlstap/proxy"`.
- `bufSize = 1<<16` (64 KB) — single shared read buffer per direction per connection.
- `drainTimeoutMs = 10` microseconds (not milliseconds despite the name).

## Web Frontend (`web/`)

Served at `/ui/` by the API HTTP server. No build step — uses vendored ES modules loaded via an importmap.

**Technology:** Preact 10.25.4 + htm 3.1.1, vendored under `web/vendor/`. The importmap in `index.html` maps bare specifiers (`preact`, `preact/hooks`, `htm`) to the vendored files so the Preact hooks module (which imports bare `"preact"`) resolves correctly.

**Layout:** Header bar (title + refresh button) → menu bar → sidebar (sessions + streams) + main area (traffic view) + collapsible bottom panel.

**Menu bar (`App.js`, `index.html`):**
- `App.js` owns `openMenu` (null | `'view'`), `globalOffset` (bool, default `true`), and `autoRefresh` (bool, default `false`).
- A `mousedown` listener on `document` (active only while a menu is open) closes the menu when clicking outside the `.menubar` element.
- Currently one menu: **View** → **Global offset** toggle, **View mode** (Single stream / Combined streams), and **Auto-Refresh** toggle, each a separate separator-delimited group. The checkmark (✓) uses `.menu-check` styled with `var(--accent)`.
- `globalOffset` is passed down: `App` → `TrafficView`/`CombinedView` → `HexDump` → `HexRow`.

**Refresh (`App.js`):**
- The header's `↺` button (`.btn-refresh` — icon-only, ~34×30px, no label) increments `refreshKey` (a plain counter) on click.
- `refreshKey` is threaded into `SessionList`, `StreamList`, `TrafficView`, and `CombinedView`; each re-fetches whatever it owns when the value changes (see their respective sections below).
- **Auto-Refresh** (View menu toggle): while `autoRefresh` is true, a `setInterval` in `App.js` calls `setRefreshKey(k => k + 1)` every 1000ms — i.e. it's just a timer clicking the same button; no separate code path. Interval is cleared on toggle-off/unmount.

**Bottom panel (`App.js`):**
- `bottomTab` state: `null` (collapsed) | `'goto'` | `'search'` | `'extract'` | `'transform'`.
- `selectBottomTab(name)`: sets tab; does not toggle (panel only collapses via the `▼` button at the right of the tab bar).
- Tab bar contains: **Goto**, **Search**, **Extract**, **Transform**, and a collapse button (`▼`) on the right.
- Content area (`.bottom-content`, resizable — see "Resizable panels" below) renders `GoToPanel`, `SearchPanel`, `ExtractPanel`, or `TransformPanel` based on `bottomTab`.
- A `ResizeHandle` (`orientation="h"`) sits at the top edge of `.bottom-panel`, shown only while `bottomTab` is set (nothing to resize when collapsed).

**Session/stream sort toggles:**
- `SessionList.js` — `desc` state (default `false` = ascending/oldest first); `▼`/`▲` button in panel header.
- `StreamList.js` — same pattern; `desc` resets to `false` when the selected session changes (its own effect, kept separate from the fetch effect so a refresh doesn't reset sort order).
- Both `SessionList.js` and `StreamList.js` re-fetch (`getSessions()` / `getStreams()`) whenever `refreshKey` changes, in addition to their own natural triggers (mount / session change) — this is what makes the Refresh button pick up newly-initiated streams and updated end-times/byte-counts in the sidebar.

**Duration formatting:**
- `fmtDuration(start, end)` (duplicated in `StreamList.js` and `TrafficView.js`) — for finished streams (`end` set) formats `end - start`; for ongoing streams (`end` falsy) formats `Date.now() - start` the same way and appends `" (ongoing)"`, e.g. `12.34s (ongoing)`. Re-renders (including ones triggered by Refresh/Auto-Refresh) naturally advance this since it's computed fresh each render.

**Resizable panels (`ResizeHandle.js`, `layout.js`):**
- `ResizeHandle.js` is a generic draggable divider: `<${ResizeHandle} orientation="v"|"h" onResize=${deltaPx => ...} />`. On `mousedown` it attaches document-level `mousemove`/`mouseup` listeners for the duration of the drag (removed on `mouseup`); each `mousemove` calls `onResize(ev.movementX)` (orientation `v`) or `onResize(ev.movementY)` (orientation `h`). The caller owns the resulting size state, clamping and sign convention (a handle placed *after* the sized element in DOM order treats a positive delta as "grow"; a handle placed *before* it treats a negative delta as "grow").
- `layout.js`: `loadLayout()` / `saveLayoutValue(key, value)` — reads/writes a single `localStorage` key (`tlstap-layout`) holding `{ sidebarWidth, markersWidth, bottomHeight, encdecOptionsWidth, encdecInputHeight }`, merged with defaults on load (same pattern as `markers.js`).
- **Sidebar** (`App.js`): `sidebarWidth` (default 280, clamped 180–600), handle between `.sidebar` and `.main`.
- **Bottom panel** (`App.js`): `bottomHeight` (default 160, clamped 80–70% of `window.innerHeight`), handle at the top of `.bottom-panel` (only rendered while a tab is open).
- **Markers panel** (`TrafficView.js`): `markersWidth` (default 240, clamped 150–500), handle between `HexDump`/`HexEditor` and `MarkersPanel` (only rendered while not collapsed); width passed down as a `width` prop to `MarkersPanel`, applied via inline style on `.markers-side`.
- **Transform panel** (`TransformPanel.js`): `encdecOptionsWidth` (default 160, clamped 100–400, handle between the options column and the input/output column) and `encdecInputHeight` (default 120, clamped 30–2000, handle between the input and output areas).
- All of the above apply their size via inline `style` (not fixed CSS) so the persisted value always wins; each resize handler both updates local state and calls `saveLayoutValue`.

**Virtual scroll (`HexDump.js`):**
- Exports `ROW_HEIGHT = 22`. Constants: `BUFFER = 8` (overdraw rows), `PREFETCH_FRACTION = 0.1`.
- Props: `rows`, `onScrollEnd`, `scrollAdjust`, `adjustVersion`, `scrollTo`, `scrollToVersion`, `globalOffset`, `onSetMarker`, `onClearMarker`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`, `onViewportChange`, `markers`.
- Encoding helpers imported from `../format.js` (not defined locally).
- Flattens all loaded chunks into a flat `rows[]` array: one `{type:'header'}` row + N `{type:'hex'}` rows per chunk.
- A `ResizeObserver` tracks container height; `onScroll` tracks `scrollTop`. Visible window is `[startIdx, endIdx)`. Inner div height = `rows.length * ROW_HEIGHT`; top/bottom spacer divs fill the rest.
- **Prefetch trigger** (`scrollend` event): fires `onScrollEnd(1)` when fewer than `rows.length * PREFETCH_FRACTION` rows remain below the viewport; `onScrollEnd(-1)` when fewer remain above.
- **Scroll correction** (`useLayoutEffect([adjustVersion])`): applies signed `scrollAdjust` to `scrollTop` synchronously before paint. Negative = scroll up (after front eviction); positive = scroll down (after prepend).
- **Absolute scroll** (`useLayoutEffect([scrollToVersion])`): sets `scrollTop = scrollTo` synchronously before paint. Used by jump-to. `scrollToVersion` must change to trigger even if `scrollTo` value is the same.
- **Global/local offset**: `HexRow` displays `row.offset` (stream-global byte offset) when `globalOffset` is true, or `row.localOffset` (offset within the chunk, resets to 0 at each chunk start) when false.
- **Byte selection**: `sel` state `{direction, start, end}` (byte offsets, inclusive). `onMouseDown` starts selection; `onMouseMove` extends it if same direction as anchor; document-level `mouseup` ends drag. Per-byte `<span data-off=N data-dir=D>` elements carry `.sel-hl` class when highlighted. Selection is scoped to one direction (cannot drag across c2s/s2c boundary).
- **Byte markers**: `markedC2S` / `markedS2C` — `Set<offset>` derived from `markers` prop. Marked bytes receive `.hex-byte-marked` / `.asc-byte-marked` CSS classes.
- **Chunk header** format: `[+T.TTTs] [#stid] DIRECTION  #chunkId  N B` (stid shown when present; stream number shown in CombinedView).
- **Context menu** (right-click on a hex row or chunk header):
  - Copy as hex / ASCII / hexdump / base64 — copies chunk bytes (header click) or selection/chunk bytes (row click).
  - Separator, then (when right-clicking a hex byte and extract props present):
    - **Set selection (range)** — only when a selection is active; sets both From and To offsets in the Extract tab.
    - **Set selection start** — sets the From offset in the Extract tab.
    - **Set selection end** — sets the To offset in the Extract tab.
  - Separator, then **Set marker** / **Clear marker** — toggles based on whether the byte is already marked.

**Editable hex grid (`HexEditor.js`):**
- Small, non-virtualized hex/ASCII editor (all rows render directly — no windowing), unlike the read-only `HexDump.js` which is built for large captured-traffic streams. Reuses `HexDump.js`'s exported `ROW_HEIGHT` constant for visual consistency only; otherwise fully independent.
- Controlled component: `<${HexEditor} bytes=${Uint8Array} onChange=${bytes => ...} readOnly? style? />`.
- **Cursor model**: `cursor = { index, area }` — `index` is a byte position `0..bytes.length` (an insertion point *before* that byte, like a text cursor), `area` is `'hex'` or `'ascii'`. `pendingNibble` holds a single typed hex character awaiting its pair (shown as a half-entered `hexed-pending` cell); cleared by Backspace, arrow movement, Tab, or clicking elsewhere.
- **Typing inserts, never overwrites** (this is the "arbitrary insertion/deletion" requirement it was built for):
  - Hex column: only `[0-9a-fA-F]` accepted (guarded against `Ctrl`/`Cmd`/`Alt` so shortcuts like Ctrl+C aren't swallowed, even though `c`/`d`/`e`/`f` are valid hex chars); two nibbles combine into one inserted byte, cursor advances by one byte.
  - ASCII column: any single printable keystroke inserts one byte (`charCodeAt(0) & 0xFF`), same modifier guard.
  - Backspace removes the byte before the cursor (or just cancels a pending nibble); Delete removes the byte at the cursor; both shift subsequent bytes.
  - Arrow keys move by one byte (Up/Down by one row = 16 bytes); Home/End jump to row start/end, Ctrl+Home/End to buffer start/end; Tab toggles `area` at the same `index`; click on any byte/char cell sets the cursor directly.
  - Paste: clipboard text is filtered per the active column's rules (hex chars paired up in the hex column; every character mapped to a byte in the ASCII column) and inserted in one `onChange` call.
- Row layout mirrors `fmtAsHexdump`'s conventions (16 bytes/row, 8-hex-digit offset, `|ascii|` column) via `.hexed-*` CSS classes — deliberately distinct from `HexDump.js`'s `.hex-*` classes so nothing is shared/at risk between the two components.
- A synthetic trailing cell (`byte === null`) exists at `bufferLength` within the last row so the cursor can be positioned after the last byte, whenever that row isn't already completely full. An empty buffer gets exactly one row (holding just that synthetic cell) since the normal per-row loop produces none. When the buffer length is a non-zero exact multiple of 16, no extra row is added purely to hold the cursor — that would render as an empty hexdump line with no bytes on it; the cursor position past the last byte is still reachable (e.g. via arrow keys), just without a dedicated rendered cell to click on in that one case.
- `readOnly` prop: every mutating path (hex/ASCII insert, Backspace, Delete, paste) becomes a no-op; navigation (arrows/Home/End/Tab) and click-to-position still work. Used for `TransformPanel`'s output panel so it can reuse the same grid without being editable.

**Chunk loading and sliding buffer (`TrafficView.js`):**
- Props: `stream`, `globalOffset`, `jumpTo`, `markers`, `onAddMarker`, `onRemoveMarker`, `onUpdateMarkerLabel`, `onMarkerJumpRequest`, `onImportMarkers`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`.
- `handleSetMarker` / `handleClearMarker` are local (not lifted); `onSetExtractStart/End/Range` are forwarded directly to `HexDump`.
- `display = {rows, scrollAdjust, adjustVersion, scrollTo, scrollToVersion}` — single state object for atomic render, prevents split-render glitch.
- `BATCH = 50` chunks fetched per request.
- Refs: `nextStidRef` (exclusive upper bound of buffer), `prevStidRef` (stid of first chunk in buffer), `hasMoreRef`, `loadingMoreRef`, `generationRef`, `streamRef`, `wsRef` (single WS connection per stream).
- On stream selection: opens one persistent `/stid-stream` WebSocket, fetches initial BATCH from stid=0.
- **Jump effect** (`useEffect([jumpTo?.version])`): closes old WS, opens fresh one, then:
  - `chunks` unit: `targetStid = jumpTo.value`
  - `chunks-c2s` / `chunks-s2c`: calls `POST /chunk-stid` to resolve per-direction `id` → `stid`
  - `offset-c2s` / `offset-s2c`: calls `POST /byte-stid` to resolve byte offset → `stid`; also records `targetByteOffset` and `targetDirection` (0/1, derived from the unit)
  - Fetches `BATCH` chunks starting at `max(0, targetStid - BATCH/2)`
  - Scans rows: for byte-offset jumps finds the hex row matching **both** `row.direction === targetDirection` and `row.offset <= targetByteOffset < row.offset + row.bytes.length` (the direction check matters because c2s/s2c offsets both start at 0 independently, so byte ranges collide across directions); otherwise finds the header row with `row.stid === targetStid`
  - Sets `scrollTo` = target row pixel, `scrollToVersion = jumpTo.version`. Default (Goto/Search jumps) centers the row in the viewport (`targetRowPx - viewHeight/2`); if `jumpTo.align === 'top'` (set only by marker jumps — see `App.js`'s `handleMarkerTabJump`/`handleStreamLoad`), the row is instead placed at the very top of the viewport (`scrollTo = targetRowPx` directly).
- `handleScrollEnd(scrollDir)` (stable `useCallback([])`):
  - **Forward** (scrollDir=1): fetches next BATCH from `nextStidRef`, appends rows, evicts front half at nearest chunk-header boundary, updates `prevStidRef`, sets negative `scrollAdjust`.
  - **Backward** (scrollDir=-1): fetches `n = prevStidRef - start` chunks before `prevStidRef`, prepends rows, evicts back half, updates `nextStidRef`/`hasMoreRef`, sets positive `scrollAdjust`.
- `generationRef` increments on each stream change or jump; captured at async start and checked after every `await` to abort stale fetches.
- `findChunkBoundaryNearHalf(rows, fallback)`: scans forward from midpoint for a `header` row, falls back to scanning backward.
- `buildRows(chunks, streamStart)`: each hex row carries both `offset` (global stream byte offset) and `localOffset` (byte offset within the chunk).

**Refresh top-up (`TrafficView.js`, mirrored in `CombinedView.js`):**
- `MAX_BUFFERED_CHUNKS = BATCH * 2` (100) is a soft cap on how many chunks the refresh path is allowed to hold in the buffer at once; `countChunks(rows)` counts `header` rows to measure current occupancy against it.
- A `useEffect` keyed on `refreshKey` (guarded by `hasMountedRef` so the initial mount is a no-op) does the top-up: skip if no stream selected, the stream is closed (`stream.end` set — closed streams can't have new data), a scroll-triggered load is already in flight (`loadingMoreRef.current`), or the buffer has no spare room (`room = MAX_BUFFERED_CHUNKS - countChunks(...) <= 0`, checked via a `displayRef` mirror of `display` so the effect doesn't need `display` in its deps). Otherwise it fetches exactly `room` chunks from `nextStidRef.current` onward.
- Unlike `handleScrollEnd`, this path **never evicts and never touches `scrollAdjust`/`adjustVersion`** — new rows are appended straight to the end of `display.rows`. Since virtualization only cares about total row count, appending below the viewport doesn't move anything already on screen; this is what makes Refresh/Auto-Refresh visually silent when new data isn't currently visible. Once the cap is hit, top-up goes inert until the user scrolls forward (which evicts via the normal path and frees up room).
- Same `generationRef`/`loadingMoreRef` race-safety pattern as `handleScrollEnd`.
- `CombinedView.js` implements the identical mechanism keyed on `session` (no `end` field, so no closed-check) and `lastSgidRef.current + 1` in place of `nextStidRef.current`.

**Goto panel (`GoToPanel.js`):**
- Text input (accepts decimal or `0x`-prefixed hex).
- Unit select (option values / labels): `chunks` / "chunks (total)", `chunks-c2s` / "chunks (c→s)", `chunks-s2c` / "chunks (s→c)", `offset-c2s` / "offset (c→s)", `offset-s2c` / "offset (s→c)".
- No separate direction dropdown — direction is encoded in the unit choice.
- Shows "Select a stream first" placeholder when no stream selected.
- `onGoTo({value: N, unit})` is called on submit (Enter or button click).

**Search panel (`SearchPanel.js`):**
- Props: `session`, `stream`, `onJump`.
- Shows "Select a session first" placeholder when no session selected.
- Form fields: pattern input (monospace, dynamic placeholder), format select, direction select (`both` / `c→s` / `s→c`), **Contiguous** checkbox, stream number input (empty = all streams in session).
- Format select options and encoding behaviour:
  - `ascii` — unescape `\n \r \t \\` then UTF-8 encode; sent as base64.
  - `utf16le` / `utf16be` — encode string with `DataView.setUint16`; sent as base64.
  - `hex` — accepts `0xff 0x00`, `\xff\x00`, `ff00`, space/comma-separated; sent as base64.
  - `regex` — sent as raw text with `pattern_encoding: "regex"`; no base64.
- All non-regex formats are always sent as base64 (`pattern_encoding: "base64"`).
- Results list: match count header + scrollable rows showing stream id, direction (coloured), hex offset. Clicking a row calls `onJump({streamId, direction, offset})`.
- `App.js` wires `onJump` → `handleSearchJump`: finds the stream in `streamList`, switches to it if needed (sets `stream` state), then sets `jumpTo` with unit `offset-c2s` or `offset-s2c`.
- `streamList` state in `App.js` is populated via `StreamList`'s `onLoad` prop (called after each fetch).

**`format.js` (shared encoding helpers):**
- `fmtAsRaw(bytes)` — UTF-8 decode (non-fatal).
- `fmtAsBase64(bytes)` — standard base64 string.
- `fmtAsHex(bytes)` — lowercase hex string (no separators).
- `fmtAsAscii(bytes)` — printable ASCII, `.` for non-printable.
- `fmtAsHexdump(bytes, baseOffset)` — `xxd`-style: `OOOOOOOO  gg gg … gg  gg gg … gg  |ascii|` per 16-byte line.
- `mergeUint8Arrays(arrays)` — concatenates an array of `Uint8Array`s into one.
- Imported by `HexDump.js` (context menu copy), `ExtractPanel.js` (extraction encoding), and `transforms.js` (`fmtAsBase64` for the Base64 encode operation). **Must be listed in the `//go:embed` directive in `web/server.go` — any new top-level `.js` file added under `web/` must be added there explicitly.** The same applies to `transforms/*.js`: `web/server.go` lists each category source file individually (`transforms/basic.js`, `transforms/numbers.js`, `transforms/hash.js`, ...) rather than embedding the `transforms` directory wholesale — this is deliberate, so that `web/package.json` (Node test tooling, see "Testing" below) and any `transforms/*.test.js` file are never pulled into the binary. Any new category module must be added to that embed line by name; test files must not be.

**Extract panel (`ExtractPanel.js`):**
- Props (all controlled from `App.js`): `session`, `stream`, `direction` (string `'0'`/`'1'`), `from` (string), `to` (string), `onDirectionChange`, `onFromChange`, `onToChange`.
- Local state: `format` (`'raw'`|`'base64'`|`'hex'`|`'hexdump'`), `method` (`'file'`|`'clipboard'`), `working`, `status`.
- Shows "Select a stream first" placeholder when no stream selected.
- `parseOffset(s)`: accepts decimal or `0x`/`0X`-prefixed hex; returns `null` on invalid input.
- `fetchRange(session, stream, dir, fromOffset, toOffset)`: resolves both offsets to stids via parallel `getByteStid` calls, fetches `endStid - startStid + 1` chunks via `openStidStream`, filters by direction, trims to exact byte boundaries.
- **Extract button is `type="button"` with `onclick` handler** — NOT a form submit. This is required for `showSaveFilePicker` (Chrome/Edge File System Access API): the browser only grants a file-picker dialog from a direct click event, not from a form `submit` event.
- For file method: `acquireFileHandle(format)` is called **before** `fetchRange` to preserve the transient user activation; Chrome consumes activation on the first relevant `await`.
- Fallback for browsers without `showSaveFilePicker` (Firefox): uses an anchor-click download; status message notes "no save dialog in this browser".
- File extensions/MIME: raw → `.bin`/`application/octet-stream`, base64 → `.b64`/`text/plain`, hex → `.hex`/`text/plain`, hexdump → `.txt`/`text/plain`.
- `App.js` extract state: `extractDir` (useState `'0'`), `extractFrom`, `extractTo` (both useState `''`).
  - `handleSetExtractStart(direction, offset)`: sets dir+from as `'0x'+hex`, opens extract tab.
  - `handleSetExtractEnd(direction, offset)`: sets dir+to as `'0x'+hex`, opens extract tab.
  - `handleSetExtractRange(direction, fromOffset, toOffset)`: sets all three, opens extract tab.
  - Direction/from/to are always overwritten from the chunk that was right-clicked.

**Transform panel (`TransformPanel.js`, `transforms.js`):**
- Layout: resizable options column (`.encdec-options`, left) + input/output column (`.encdec-io`, right), split by `ResizeHandle`s — see "Resizable panels" above.
- **Canonical state is `bytes: Uint8Array`**, regardless of which input view is active:
  - Text mode: the `<textarea>`'s displayed value is *derived* each render via `new TextDecoder('utf-8', {fatal:false}).decode(bytes)` — never stored back into `bytes` except via its own `oninput` (`setBytes(new TextEncoder().encode(value))`). This means toggling "Hexdump view" off and back on without typing never loses data, even if the decoded text contains `�` (U+FFFD, from invalid UTF-8) — a warning line (`.encdec-warning`) appears near the checkbox when that's the case, since typing while it's shown *would* bake in the loss.
  - Hexdump mode: `<${HexEditor} bytes=${bytes} onChange=${setBytes} />` operates on `bytes` directly, no text serialization involved.
- **Steps** (`steps: [{id, op, label, params}]`), built from the `+` button's dropdown menu:
  - The menu (`algo-menu`) is generated from `transforms.js`'s `ALGORITHM_SECTIONS`; sections can have `subsections` (rendered as a nested indent level) or a flat `algorithms` list.
  - An algorithm entry whose `op` has no matching `OPERATIONS` registration renders with a `[TODO]` suffix (`.algo-menu-item-todo`) and isn't clickable — this is how still-unimplemented algorithms (Checksum, Hash, Encryption — see below; Compression is now fully implemented) are shown without being selectable.
  - `addStep(op, label)` seeds `params` from the op's `params` definitions' `default` values.
  - Step rows are `draggable="true"` (HTML5 DnD) for reordering: `dragIdRef` holds the dragged id, `dragOverId` state highlights the hovered row (`.encdec-step-drag-over`), and `handleDrop` splices the dragged step to the target's index.
  - **Per-step parameters** (`renderStepParam`): `param.type` is `'number'` (`<input type=number>`, clamped to `min`/`max` via `updateStepParam`), `'boolean'` (checkbox), `'select'` (`<select>` populated from `param.options: [{value,label}]`), or `'text'` (plain `<input type=text>`, e.g. `zip-compress`'s `filename` / `zip-decompress`'s `entry`) — only `'number'` values get coerced/clamped; boolean/select/text values pass through as-is.
- **Execution is manual** (`handleGo`, a "Go" button — not live, and `async` so it can `await` each step): runs `bytes` through `steps` in order via `await OPERATIONS[step.op].run(current, step.params)`. `run()` may return a plain `Uint8Array` (most ops) or a `Promise<Uint8Array>` (the Compression ops, which are stream-based) — `await` on a plain value just resolves immediately, so both work uniformly. A thrown/rejected error halts the pipeline immediately: `outputBytes = null`, `outputError = "<step label>: <message>"`, shown in red (`.encdec-output-error`) in place of any output. On success, `outputBytes` is set and `outputHexdumpView` is defaulted to `!isPrintable(outputBytes)` (printable = every byte in `0x20–0x7e` or `\t`/`\n`/`\r`) — the checkbox is a normal manual toggle after that, until the next Go.
- **Output panel** mirrors the input's Hexdump-view checkbox, but its hex view reuses `<${HexEditor} readOnly=${true} />` on `outputBytes` (same grid as the input, not a separate plain-text rendering); its text view is a read-only `<textarea>` derived from `outputBytes` the same way the input's text mode is derived from `bytes`.

**`transforms.js` + `transforms/*` (operation registry + algorithm catalog):**

Operations are implemented in per-category modules under `transforms/`; `transforms.js` itself only aggregates them into the two exports `TransformPanel.js` consumes, plus the still-unimplemented placeholder catalog entries. Category grouping (which file an op lives in) is independent of UI grouping (which section/subsection it appears under in the menu) — e.g. `transforms/numbers.js` feeds two separate top-level UI sections.

- **Category module contract** (e.g. `transforms/basic.js`, `transforms/numbers.js`): each exports
  - `OPERATIONS` — object keyed by op id, each entry `{ label, params?, run(bytes, params) }`. `run` returns the transformed `Uint8Array` or throws a plain `Error` with a human-readable message (caught by `TransformPanel`'s `handleGo`).
  - one or more plain catalog arrays of `{ label, op }`, named for the UI slot(s) they feed (e.g. `ENCODE_ALGORITHMS`/`DECODE_ALGORITHMS`).
  - All other helpers/tables (e.g. `HEX_SEPARATOR_CHARS`, `NUMBER_TYPES`) are private to the module.
- **`transforms.js`**:
  - `OPERATIONS`: merges every category module's `OPERATIONS` into one registry.
  - `ALGORITHM_SECTIONS`: catalog grouped into UI sections — `Basic` (subsections `Encode`/`Decode`, sourced from `transforms/basic.js`), `Encode Number`/`Decode Number` (sourced from `transforms/numbers.js`), `Compression` (subsections `Compress`/`Uncompress`, each concatenating `transforms/compression.js`'s and `transforms/zip.js`'s algorithm arrays — two category modules feeding the same UI subsection), `Checksum`, `Encryption` (subsections `Encrypt`/`Decrypt`, currently empty) — these two have no implementing module yet, so their `{label, op}` entries are hardcoded directly in `transforms.js` — and `Hash` (sourced from `transforms/hash.js`'s `HASH_ALGORITHMS`). Each leaf is `{ label, op }`.
  - **`[E]`/`[D]` label prefixing**: `sectionPrefix(name)` (exported) returns `'[E] '`/`'[D] '` for any section/subsection name that **starts with** `"Encode"`/`"Decode"` — this covers both `Basic > Encode/Decode` and the flat `Encode Number`/`Decode Number` sections uniformly, while `Encrypt`/`Decrypt` and `Compress`/`Uncompress` are deliberately excluded (they don't match the `Encode`/`Decode` prefix test). Catalog entries (`ALGORITHM_SECTIONS`) keep plain, unprefixed `label`s — the menu shows just the algorithm name, since the Encode/Decode grouping is already visible from the section/subsection header. `TransformPanel.js`'s `renderAlgoItem(entry, prefix)` applies `sectionPrefix(...)` only when constructing the label stored on a step (`addStep`), so the prefix appears in the step chain but not the selection menu.
  - Algorithms within each (sub)section are sorted alphabetically by plain `label` — applying the same fixed prefix to every entry in a group never changes their relative order, so sorting doesn't need to account for it.
- **Implemented operations:**
  - `hex-encode`/`hex-decode` (`transforms/basic.js`): `separator` param (`select`: `0x`, `\x`, `,`, `;`, `:`, Space, `\n` — default Space). `0x`/`\x` are per-byte prefixes (`0x48 0x65 ...` / `\x48\x65...`); the rest are plain join characters between byte pairs. Decode strips the selected separator's literal characters (plus any incidental whitespace) before the existing hex-digit-pair parsing/validation.
  - `base64-encode`/`base64-decode` (`transforms/basic.js`): `urlSafe` boolean param (default `false`). Encode swaps `+`/`/` for `-`/`_` and strips trailing `=` padding; decode reverses the substitution and restores correct padding (based on length mod 4) before `atob`.
  - `octal-encode`/`octal-decode` (`transforms/basic.js`): each byte as 3-digit zero-padded octal, space-separated.
  - `basen-encode`/`basen-decode` (`transforms/basic.js`): `base` param (`number`, 2–64, default 64). Arbitrary-base big-integer encoding via `BigInt`; alphabet is the first *N* characters of the standard base64 char ordering (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`); leading zero bytes are preserved as leading zero-symbol characters (same convention as Base58).
  - `encnum-*`/`decnum-*` (`transforms/numbers.js`; 14 types: `Int8`/`UInt8`, `Int16`/`UInt16`/`Int32`/`UInt32`/`Int64`/`UInt64` each big/little endian — see `NUMBER_TYPES`): decode requires the exact byte width for the type (throws otherwise) and outputs the decimal text representation (`-` prefix for negatives) via `DataView`; encode parses decimal text back into the fixed-width binary form, validating it's a plain integer and in range for the type. 64-bit types use `getBigInt64`/`setBigInt64`/`BigInt` throughout to avoid precision loss.
  - `gzip-compress`/`gzip-decompress`, `deflate-compress`/`deflate-decompress` (`transforms/compression.js`): built on the native `CompressionStream`/`DecompressionStream` APIs (same browser support floor as `MarkersPanel.js`'s marker-export compression: Chrome 80+, Firefox 113+, Safari 16.4+) — no params. `run()` returns a `Promise<Uint8Array>` (see `handleGo` above). `runStream()` drains the stream via a write-then-read-until-done loop, reusing `mergeUint8Arrays` from `format.js`; the writer's `write()`/`close()` promise is explicitly given a no-op `.catch()` — on malformed input the stream can reject *both* the write side and the read side with the same underlying error, and the write-side rejection would otherwise surface as an unhandled promise rejection since nothing else awaits it (the read loop is what surfaces the real error to the caller). Decode errors are re-thrown as `invalid <format> data: <detail>`, falling back through `err.message || err.cause?.message` since Node/browsers report malformed-input errors differently.
  - `zip-compress`/`zip-decompress` (`transforms/zip.js`, via the vendored `fflate` library's `zipSync`/`unzipSync` — synchronous, no `Promise` needed): `zip-compress` has a `filename` text param (default `data.bin`) naming the archive's single entry. `zip-decompress` has an `entry` text param (default `''` = auto): if the archive has exactly one entry it's extracted automatically; otherwise (zero or multiple entries) it throws, listing the available entry names, rather than guessing which one the user wants — the pipeline is single-blob-in/single-blob-out, so a multi-entry archive has no single correct output without the user picking one.
  - `md2`/`md4`/`ntlm`/`md5`/`sha1`/`sha224`/`sha256`/`sha384`/`sha512`/`whirlpool` (`transforms/hash.js`; no params on any of them): MD5/SHA1/SHA224/SHA256/SHA384/SHA512 run through the vendored `crypto-js` (`../vendor/crypto-js.module.js`) via `WordArray.create(bytes)` in / `bytesFromWordArray()` out. MD2 and MD4 are hand-rolled directly from RFC 1319/1320 (no well-established JS library covers these legacy algorithms) — cross-checked against an independent implementation's source and RFC test vectors before use; NTLM is just `md4(UTF-16LE(text))`, where `text` is the input bytes decoded as UTF-8 (consistent with `SearchPanel.js`'s `utf16le` search format). Whirlpool runs through the vendored `hash-wasm` (`../vendor/hash-wasm-whirlpool.module.js`, WASM-backed) instead of being hand-rolled, since it's the one algorithm where a hand-written S-box/MDS-matrix implementation was judged too error-prone to trust without a reference; its `run()` returns a `Promise<Uint8Array>` (hash-wasm's `whirlpool()` is async and returns a hex string, converted via a small local `bytesFromHex()`) — the only async op in this module, same `Promise<Uint8Array>` convention as the Compression ops.
- **Not yet implemented** (catalogued but no `OPERATIONS` entry, shown as `[TODO]`): `Checksum` (CRC16, CRC32, Adler32), `Encryption` subsections (no named algorithms yet).

**Testing (`transforms/*.test.js`):**
- Unit tests for category modules live alongside their source (e.g. `transforms/numbers.test.js` tests `transforms/numbers.js`), using Node's built-in `node:test` + `node:assert/strict` — no external test dependency.
- `web/package.json` (`"type": "module"`, scoped to `web/` only) exists solely so Node treats these `.js` files as ES modules; it does not affect the browser, which resolves modules via the `index.html` importmap instead. Run the suite with `npm test` (from `web/`) or `node --test` (from `web/`, relying on Node's default recursive `*.test.js` discovery — passing an explicit directory path like `node --test transforms` does *not* recurse the same way, so prefer the no-args form).
- Neither `package.json` nor any `*.test.js` file is listed in `web/server.go`'s `//go:embed` directive, so they're never compiled into the binary or served — see the embed note below.
- `transforms/numbers.test.js` covers all 14 integer types: fixed known-byte-vector checks (independent of round-tripping, so a symmetric encode/decode bug can't hide), boundary round-trips, byte-length validation, out-of-range/non-integer rejection, and BE/LE byte-order cross-checks.
- `transforms/compression.test.js` covers gzip/deflate round-trips (including empty input), that compression actually shrinks repetitive input, malformed-input rejection, a fixed known-vector gzip buffer (pre-calculated via Node's `zlib.gzipSync`, a different code path than the `CompressionStream` under test), and that gzip/deflate framing is mutually non-interchangeable.
- `transforms/zip.test.js` covers the default-filename round-trip, that `zip-compress`'s `filename` param controls the actual archive entry name (checked via the vendored `unzipSync` directly, independent of `zip-decompress`), auto-extraction of single-entry archives, name-based entry selection from multi-entry archives, the multi-entry/unknown-entry/malformed-input error messages, all imported from `../vendor/fflate.module.js` by relative path for the same reason `zip.js` itself does.
- `transforms/hash.test.js` covers all 10 hash ops against known test vectors (RFC 1319/1320 Appendix A for MD2/MD4; FIPS PUB 180/181 and RFC 1321 "abc"/empty-string vectors for MD5/SHA1/SHA224/SHA256/SHA384/SHA512, independently cross-checked against Node's own `crypto.createHash` during development; the canonical NESSIE/ISO vectors for Whirlpool), the well-known empty and `"password"` NTLM vectors, that NTLM differs from a plain MD4 of the same bytes, and fixed-digest-length checks across short and long input. Its `runHex()` helper always `await`s the op's `run()` result so the same test code covers both the synchronous ops and Whirlpool's async (WASM) one uniformly.

**Markers panel (`MarkersPanel.js`):**
- Props: `markers[]`, `onRemove`, `onUpdateLabel`, `onJump`, `onImport(markers[])`, `collapsed`, `onToggle`, `width` (px, applied as inline style on `.markers-side`; see "Resizable panels" above — not used when `collapsed`).
- `collapsed` renders a vertical strip (`◀ Markers`); expanded renders the full side panel.
- Marker rows: show `[streamId] direction  0xOFFSET` + inline editable label. Click row → `onJump`; `×` → `onRemove`.
- **Import/export** (bottom bar of expanded panel): `[clipboard ▾] [Import] [Export]` + status line.
  - File format: deflate-compressed JSON, base64-encoded, extension `.tlstap-markers`. Content is the raw `tlstap-markers` localStorage JSON (`{ version: 1, markers: [{id, session, stream, direction, offset, label?}] }`).
  - `compress(str)` / `decompress(b64)`: use `CompressionStream`/`DecompressionStream` with `'deflate'` (Chrome 80+, Firefox 113+, Safari 16.4+).
  - Export to file: `showSaveFilePicker` called **before** `compress()` to preserve user activation; falls back to anchor download.
  - Import from file: programmatic `<input type="file" accept=".tlstap-markers,.txt">` click (no activation constraint on read).
  - Import replaces all markers (`onImport` prop wired to `setMarkers` in `App.js`).
  - `parseImport(text)`: validates JSON has `markers` array with required typed fields; returns `null` on invalid data.
- `onImport` prop is threaded: `App.js (setMarkers) → TrafficView (onImportMarkers) → MarkersPanel (onImport)`.

**`api.js`:**
- `openStidStream()` → `{ fetch(sessionId, streamId, start, n), close() }`: persistent WS to `/stid-stream`.
- `openSgidStream()` → `{ fetch(session, start, n), close() }`: persistent WS to `/sgid-stream`.
- `getSessions()`, `getStreams(sessionId)`, `getChunkList(sessionId, streamId)`.
- `getChunkStid(sessionId, streamId, direction, id)`: POST `/chunk-stid`.
- `getByteStid(sessionId, streamId, direction, offset)`: POST `/byte-stid`.
- `searchText(req)`: POST `/search-text`; `req` is the full request object.

## Documentation

- `doc/openapi.yaml` — OpenAPI 3.1.0 specification for all REST and WebSocket endpoints

## Dependencies

- `github.com/google/gopacket` — pcap writing in `intercept/pcapdump/`
- `github.com/smallnest/ringbuffer` — used in `proxy/buf_conn.go`
- `modernc.org/sqlite` — pure-Go SQLite driver (no CGO) used by `intercept/dbdump/`
- `github.com/gorilla/websocket` — WebSocket server in `intercept/dbdump/api.go`
- `fflate` 0.8.3 (JS, vendored under `web/vendor/fflate.module.js`) — zip archive support in `web/transforms/zip.js`. Vendored as a whole-library minify (`esbuild --minify`, no bundling/tree-shaking) so future code can pull in more of its exports (gzip/deflate/zlib) without re-vendoring; imported by relative path (not the importmap) since `transforms/*.js` must also run under the Node test suite, which has no importmap support.
- `crypto-js` 4.2.0 (JS, vendored under `web/vendor/crypto-js.module.js`) — MD5/SHA1/SHA224/SHA256/SHA384/SHA512 support in `web/transforms/hash.js`. Upstream ships CommonJS/UMD modules with bare `require(...)` calls (not valid syntax for a native browser ES module import), so this is a real `esbuild --bundle --format=esm` build covering just `core.js`, `lib-typedarrays.js` (patches `WordArray.init` to accept a `Uint8Array` directly), `x64-core.js` (needed for SHA384/512), `enc-hex.js`, and the five hash algorithm modules — deliberately **not minified** (unlike `fflate.module.js`) so the bundled source stays readable/debuggable; the file's header comment has the exact entry-file contents needed to rebuild it after upgrading crypto-js.
- `hash-wasm` 4.12.0 (JS+WASM, vendored under `web/vendor/hash-wasm-whirlpool.module.js`) — Whirlpool support in `web/transforms/hash.js` (the one hash algorithm `crypto-js` doesn't cover, and risky to hand-roll correctly given its S-box/MDS-matrix complexity). Only `dist/whirlpool.umd.min.js` is vendored — a single self-contained, dependency-free per-algorithm bundle (the WASM binary is inlined as base64, no separate `.wasm` fetch) — reformatted from UMD to a real ES module via `esbuild --bundle --format=esm`. Left minified as vendored upstream: unlike crypto-js, there's no more-readable JS form to preserve since the actual hashing logic is compiled WASM, not JS.
