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
  vendor/           ← vendored ES modules (preact 10.25.4, htm 3.1.1)
  components/
    App.js          ← root; owns session/stream selection, view mode, menu bar, bottom panel, jumpTo
    SessionList.js  ← sessions panel with sort toggle (asc/desc)
    StreamList.js   ← streams panel with sort toggle (resets to asc on session change)
    TrafficView.js  ← single-stream view: metadata bar + stid-based chunk buffer + virtual scroll
    CombinedView.js ← combined-stream view: sgid-based chunk buffer across all streams in a session
    HexDump.js      ← virtual-scroll hex dump with prefetch, scroll correction, byte selection
    GoToPanel.js    ← "Goto" bottom-panel tab: jump to chunk/offset by stid or direction-specific ID
    SearchPanel.js  ← "Search" bottom-panel tab: pattern search with format/direction/contiguous options
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
- `App.js` owns `openMenu` (null | `'view'`) and `globalOffset` (bool, default `true`).
- A `mousedown` listener on `document` (active only while a menu is open) closes the menu when clicking outside the `.menubar` element.
- Currently one menu: **View** → **Global offset** toggle. The checkmark (✓) uses `.menu-check` styled with `var(--accent)`.
- `globalOffset` is passed down: `App` → `TrafficView`/`CombinedView` → `HexDump` → `HexRow`.

**Bottom panel (`App.js`):**
- `bottomTab` state: `null` (collapsed) | `'goto'` | `'search'`.
- `selectBottomTab(name)`: sets tab; does not toggle (panel only collapses via the `▼` button at the right of the tab bar).
- Tab bar contains: **Goto**, **Search**, and a collapse button (`▼`) on the right.
- Content area (`.bottom-content`, 160 px) renders `GoToPanel` when `bottomTab === 'goto'`, `SearchPanel` when `bottomTab === 'search'`.

**Session/stream sort toggles:**
- `SessionList.js` — `desc` state (default `false` = ascending/oldest first); `▼`/`▲` button in panel header.
- `StreamList.js` — same pattern; `desc` resets to `false` when the selected session changes.

**Virtual scroll (`HexDump.js`):**
- Exports `ROW_HEIGHT = 22`. Constants: `BUFFER = 8` (overdraw rows), `PREFETCH_FRACTION = 0.1`.
- Props: `rows`, `onScrollEnd`, `scrollAdjust`, `adjustVersion`, `scrollTo`, `scrollToVersion`, `globalOffset`.
- Flattens all loaded chunks into a flat `rows[]` array: one `{type:'header'}` row + N `{type:'hex'}` rows per chunk.
- A `ResizeObserver` tracks container height; `onScroll` tracks `scrollTop`. Visible window is `[startIdx, endIdx)`. Inner div height = `rows.length * ROW_HEIGHT`; top/bottom spacer divs fill the rest.
- **Prefetch trigger** (`scrollend` event): fires `onScrollEnd(1)` when fewer than `rows.length * PREFETCH_FRACTION` rows remain below the viewport; `onScrollEnd(-1)` when fewer remain above.
- **Scroll correction** (`useLayoutEffect([adjustVersion])`): applies signed `scrollAdjust` to `scrollTop` synchronously before paint. Negative = scroll up (after front eviction); positive = scroll down (after prepend).
- **Absolute scroll** (`useLayoutEffect([scrollToVersion])`): sets `scrollTop = scrollTo` synchronously before paint. Used by jump-to. `scrollToVersion` must change to trigger even if `scrollTo` value is the same.
- **Global/local offset**: `HexRow` displays `row.offset` (stream-global byte offset) when `globalOffset` is true, or `row.localOffset` (offset within the chunk, resets to 0 at each chunk start) when false.
- **Byte selection**: `sel` state `{direction, start, end}` (byte offsets, inclusive). `onMouseDown` starts selection; `onMouseMove` extends it if same direction as anchor; document-level `mouseup` ends drag. Per-byte `<span data-off=N data-dir=D>` elements carry `.sel-hl` class when highlighted. Selection is scoped to one direction (cannot drag across c2s/s2c boundary).
- **Chunk header** format: `[+T.TTTs] [#stid] DIRECTION  #chunkId  N B` (stid shown when present; stream number shown in CombinedView).

**Chunk loading and sliding buffer (`TrafficView.js`):**
- `display = {rows, scrollAdjust, adjustVersion, scrollTo, scrollToVersion}` — single state object for atomic render, prevents split-render glitch.
- `BATCH = 50` chunks fetched per request.
- Refs: `nextStidRef` (exclusive upper bound of buffer), `prevStidRef` (stid of first chunk in buffer), `hasMoreRef`, `loadingMoreRef`, `generationRef`, `streamRef`, `wsRef` (single WS connection per stream).
- On stream selection: opens one persistent `/stid-stream` WebSocket, fetches initial BATCH from stid=0.
- **Jump effect** (`useEffect([jumpTo?.version])`): closes old WS, opens fresh one, then:
  - `chunks` unit: `targetStid = jumpTo.value`
  - `chunks-c2s` / `chunks-s2c`: calls `POST /chunk-stid` to resolve per-direction `id` → `stid`
  - `offset-c2s` / `offset-s2c`: calls `POST /byte-stid` to resolve byte offset → `stid`; also records `targetByteOffset`
  - Fetches `BATCH` chunks starting at `max(0, targetStid - BATCH/2)`
  - Scans rows: for byte-offset jumps finds the hex row where `row.offset <= targetByteOffset < row.offset + row.bytes.length`; otherwise finds the header row with `row.stid === targetStid`
  - Sets `scrollTo` = target row pixel, `scrollToVersion = jumpTo.version`
- `handleScrollEnd(scrollDir)` (stable `useCallback([])`):
  - **Forward** (scrollDir=1): fetches next BATCH from `nextStidRef`, appends rows, evicts front half at nearest chunk-header boundary, updates `prevStidRef`, sets negative `scrollAdjust`.
  - **Backward** (scrollDir=-1): fetches `n = prevStidRef - start` chunks before `prevStidRef`, prepends rows, evicts back half, updates `nextStidRef`/`hasMoreRef`, sets positive `scrollAdjust`.
- `generationRef` increments on each stream change or jump; captured at async start and checked after every `await` to abort stale fetches.
- `findChunkBoundaryNearHalf(rows, fallback)`: scans forward from midpoint for a `header` row, falls back to scanning backward.
- `buildRows(chunks, streamStart)`: each hex row carries both `offset` (global stream byte offset) and `localOffset` (byte offset within the chunk).

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
