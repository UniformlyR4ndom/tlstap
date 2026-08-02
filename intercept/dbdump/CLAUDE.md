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
- `pattern_encoding` `""` / `"text"` — raw UTF-8 literal; decoded pattern capped at `maxPatternLen` (4 KB) → 400 if exceeded, regardless of `contiguous`.
- `pattern_encoding` `"base64"` — arbitrary bytes base64-encoded (frontend always uses this for non-regex formats to support binary/UTF-16/hex patterns); same `maxPatternLen` cap applies to the decoded bytes.
- `pattern_encoding` `"regex"` — Go `regexp` syntax; invalid pattern → 400. `contiguous` flag still applies (chunks concatenated per `searchBatchSize` batch, 2 MB); cross-batch overlap is a fixed `regexOverlapSize` (4 KB) rather than pattern-length-based, since minimum match length is unknown — a match spanning further than that across a batch boundary is still missed.
- Non-contiguous mode: each chunk searched independently; cross-chunk matches not found.
- Contiguous mode (literal): chunks accumulated into `searchBatchSize` batches (2 MB); `len(pattern)-1` byte overlap between batches catches cross-batch splits. Implemented in `search.go` via `matchFinder` abstraction (`literalFinder` / `regexFinder`).
