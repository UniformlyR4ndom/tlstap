# Core services (`core/`)

Implementation notes for tlstap's **core services**, loaded automatically when working
under this directory. See the root `CLAUDE.md`'s "Core Services" section for what these
are and how they're configured/wired, and `cli/core.go` for the `CoreService` interface
itself. Unlike an interceptor, a core service isn't tied to any one proxy or interceptor
chain — each is constructed once in `cli.go` (alongside `/ui/`'s own registration) and
reachable at `/api/core/<name>/...` regardless of which proxies/interceptors are
configured.

Two packages today: `core/kv` (a general-purpose key-value store) and `core/fs` (scoped
host-directory access — see `intercept/tamper/CLAUDE.md`'s "Filesystem access" note for
how tamper scripts use it). Both follow the same shape: a `Store` type wrapping
whatever backing resource it has, a `New(...)` constructor that must leave `Store` fully
usable the instant it returns (since `RegisterRoutes` is called synchronously while
`cli.go` builds the proxy, before anything like a `core/kv` DB open could plausibly be
deferred to some later async step), and `RegisterRoutes`/`Finalize` implementing
`cli.CoreService` together with `proxy.ApiProvider`.

## `core/kv` — general-purpose key-value store

Full design/rationale: [`doc/design/core-kv-store.md`](../doc/design/core-kv-store.md).
Storage layer: `kv.go`. REST layer: `api.go`.

- **Schema**: its own SQLite file (`core.kv.file` config, independent of any `dbdump`
  instance), one table: `core_kv(key TEXT PRIMARY KEY, value BLOB NOT NULL)`. Both
  columns are opaque — no validation, parsing, or interpretation beyond the size limits
  below. `New` opens/creates the file, sets `PRAGMA journal_mode=WAL` and `PRAGMA
  busy_timeout=5000` (`busyTimeoutMs`), and runs `CREATE TABLE IF NOT EXISTS`.
- **Coexistence with a `dbdump` database sharing the same file** (deliberate, not just
  tolerated — see the design doc's "Coexistence" section for the full argument): safe by
  construction, for three independent reasons — (1) `core_kv` is a distinctly-named
  table, so it can never collide with `dbdump`'s own schema; (2) both `dbdump.go` and
  this package set `PRAGMA busy_timeout`, so two separate connections legitimately
  writing the same physical file wait for each other's lock instead of failing
  immediately with `SQLITE_BUSY`; (3) `dbdump`'s `truncate: true` deleting the whole file
  (and thus `core_kv`'s data with it, if the paths happen to coincide) is a documented,
  accepted risk, not defended against in code — see that section for the reasoning.
- **`Write` is a plain upsert** (`INSERT ... ON CONFLICT(key) DO UPDATE`) — no separate
  "update" operation, no CAS/versioning, plain last-writer-wins. A `nil` value is
  normalized to an empty slice before the write (the column is `NOT NULL`).
- **Limits**: `maxKeyBytes = 256`, `maxValueBytes = 1 << 20` (1 MiB) — named constants in
  `kv.go`, not user-configurable. `Write` returns `ErrKeyTooLong`/`ErrValueTooLarge`
  (`errors.Is`-checkable) on violation; `api.go`'s `handleWrite` maps either to `400`.
  The HTTP handler caps its own body read at `maxValueBytes+1` via `io.LimitReader`
  before ever calling `Write`, so an oversized upload is rejected without buffering an
  unbounded body into memory first.
- **`List`'s prefix filter is a byte-range scan, not `LIKE`**: `prefixUpperBound(prefix)`
  walks from the end of `prefix`'s bytes for the last one that isn't `0xFF`, increments
  it, and truncates everything after — giving an exclusive upper bound `U` such that
  `{K : K has byte-prefix prefix} == {K : prefix <= K < U}` under SQLite's default
  `BINARY` (byte-lexicographic) collation on `TEXT`. All-`0xFF` prefix → no finite upper
  bound → falls back to `key >= prefix` unbounded. Chosen over `LIKE ... ESCAPE`
  specifically to avoid hand-escaping `%`/`_`/the escape character in arbitrary
  user-supplied prefixes, and because SQLite's `LIKE`-to-index optimization has
  documented restrictions around a custom `ESCAPE` clause that a plain range scan doesn't
  need to worry about. Verified against a real `modernc.org/sqlite` database (not just
  reasoned about): plain ASCII prefixes, a multi-byte UTF-8 prefix (confirms `BINARY`
  collation really is byte-lexicographic, not codepoint-aware — required for correctness
  here), the carry case (prefix ending in `0xFF`), the all-`0xFF` fallback, and that
  `TEXT` storage round-trips arbitrary — including deliberately invalid-UTF-8 — byte
  sequences exactly. Covered directly in `kv_test.go`'s `TestList`.
- **REST API** (base `/api/core/kv`, no `/kv/` segment repeated under it — see the design
  doc's "REST API" section for why `key`/`prefix` live in the query string here rather
  than this codebase's usual JSON-body convention): `POST /list?prefix=` →
  `{"keys": [...]}`; `POST /read?key=` → raw bytes, `200`, or `404` if absent; `POST
  /write?key=` → request body is the raw value, `204`, or `400` on a size violation;
  `POST /delete?key=` → `204`, idempotent regardless of prior existence.
- Unit-tested (`kv_test.go`): round-trip, upsert-overwrite, idempotent delete, both size
  limits (including exact-boundary acceptance), every `List` case above, reopening an
  existing file (schema idempotency + data survival across restarts), and opening a file
  pre-seeded with an unrelated table (simulating a shared `dbdump` file). HTTP-level
  (`api_test.go`): the same round-trip/limits/list behavior over real `net/http`, plus
  missing-`key`-param `400`s and confirming the JSON `list` response is `{"keys":[]}`,
  never `null`, for an empty store.

## `core/fs` — scoped filesystem access

Storage layer: `fs.go`. REST layer: `api.go`. Package name is `fs`, same as the standard
library's `io/fs` — every importer must alias it (`corefs "tlstap/core/fs"`; `cli.go`
does this since it already imports `io/fs` for `web.FS`).

- **`Store`** exposes read/write/list access to one host directory (`core.fs.dir`
  config) — `New` requires it to already exist (unlike `core/kv`'s file, which is
  created if missing): this exposes a directory the operator specifically chose (e.g. a
  test-fixtures folder), so a typo'd path fails startup loudly rather than silently
  creating an arbitrary directory tree.
- **Path containment** (`Store.resolve`): a request path is always slash-separated
  (arrives via a URL wildcard) and is neither charset-restricted nor symlink-resolved —
  nested subdirectories are the whole point, and a symlink planted inside the root
  escaping it is treated as a host-filesystem concern out of scope for this store to
  solve. Containment instead falls out structurally: `path.Clean("/" + relPath)` is
  computed first, with the synthetic leading `/` making any leading `..` segments
  collapse against that boundary before the result is ever joined onto the root — so the
  cleaned path can never climb above where it started, regardless of how many `..`
  segments a request throws at it. `filepath.Join(root, ...)` plus a boundary-aware
  suffix check (`strings.HasPrefix(full, root+separator)`, not a bare prefix check, which
  would wrongly accept a sibling directory like `<root>-evil`) is a second, independent
  guard against the same escape. Unit-tested directly (`fs_test.go`), including deep
  `../../..` traversal attempts.
- **`Put` is atomic**, the same `.tmp-*`-then-`os.Rename` discipline `intercept/scriptstore`
  uses for its own writes (a separate copy here, not shared code — this store's target
  may be nested under a subdirectory, not the root itself, rather than always a single
  fixed directory).
- **`Append`** opens the target with `O_APPEND` (creating it, and any missing parent
  directories, if needed) rather than being a client-side `Get`+concatenate+`Put`: two
  concurrent callers appending to the same file around the same time would otherwise
  race, silently losing one side's data. `O_APPEND` delegates the seek-to-end-and-write
  to the kernel, which performs it atomically per `Write` call, so no locking of our own
  is needed. `handleAppend` is registered as `POST`, not `PUT`: `PUT` is expected to be
  idempotent (repeat = same result), which an append explicitly isn't (repeat = appended
  twice) — `POST` is the generic "process this at the target resource, non-idempotent"
  verb, despite every other endpoint here being `GET`/`PUT`.
- **REST API** (base `/api/core/fs`, no `/fs/` segment repeated under it — this service
  already *is* the `fs` namespace, so repeating it would be redundant): `GET /list` and `GET
  /list/{path...}` → `[{name, dir, size}]`, one directory level (not recursive —
  `dir:true` entries are listed again by requesting that path); `size` is whatever the OS
  reports for a directory (meaningless — callers should key off `dir` instead). `GET
  /file/{path...}` → raw bytes, `Content-Type: application/octet-stream`. `PUT
  /file/{path...}` → raw body, `204` on success; creates/overwrites, auto-creating
  missing parent directories. `POST /file/{path...}` → raw body, `204` on success;
  appends rather than overwriting (creating the file, and any missing parent
  directories, if it doesn't exist yet). No `DELETE`. Two patterns are registered for
  `list` (with and without the trailing wildcard) because Go's `{path...}` wildcard
  doesn't match an empty trailing segment, so root and subdirectory listing need separate
  routes to the same handler.
- **No "disabled" `501` response** — `cli.go` doesn't call `RegisterRoutes` at all when
  `core.fs` isn't configured, so a request to `/api/core/fs/...` on an unconfigured
  server gets a plain `404` from the mux — same convention `core/kv` uses.
- Unit-tested (`fs_test.go`): path resolution (including traversal attempts and the
  boundary-vs-bare-prefix distinction), construction requiring an existing directory,
  put/get/list/append round-trips including nested subdirectories, atomic-write cleanup,
  and a concurrent-append race test (20 goroutines × 50 appends each to the same file,
  asserting no lost or duplicated lines) verifying the `O_APPEND` safety claim above.
  HTTP-level (`api_test.go`): the real REST handlers end-to-end, including `POST`
  append and the `404` cases for a missing file/directory.

## Frontend

`web/coreApiClient.js` is the shared script-facing client for both services — a plain ES
module, dynamically imported directly inside each script runtime's own Worker (framer's
`frameRuntime.js`, dissector's `dissectRuntime.js`, tamper's `scriptRuntime.js`), calling
`fetch()` straight from there rather than through any RPC bridge; `baseUrl` is an absolute
URL computed on the main thread and baked into the Worker's bootstrap source, since a
Blob-URL worker's own relative-URL resolution isn't reliable. `createKvApi(baseUrl)` backs
`framer.kv.*`/`dissector.kv.*`/`tamper.kv.*` uniformly (`read`/`write`/`readBytes`/
`writeBytes`/`list`/`delete`); `createFsApi(baseUrl)` backs `framer.fs.*`/`dissector.fs.*`/
`tamper.fs.*` the same way — `tamper.fs.*` initially stayed on `scriptRuntime.js`'s
pre-existing RPC bridge as a smaller first step, then got migrated onto this same
direct-fetch path too in a same-day follow-up; `web/coreFsApi.js` (that RPC path's
main-thread REST wrappers) and its `TamperView.js` wiring were deleted once nothing else
consumed them. See `web/CLAUDE.md`'s "Framer scripts"/"Dissector scripts"/"Scripted
interception" sections for the full script-facing contract and error-handling convention
(a plain thrown `Error` on any non-2xx, "not found" and "service not configured" both
included, matching what `core/fs`'s/`core/kv`'s own REST handlers already collapse into
one status code).
