# Core KV Store — design notes

**Status: designed, not yet implemented (2026-08-12).**

## Motivation

Some protocols split related information across multiple TCP connections — e.g. an
initial connection exchanges a crypto key, and a second, otherwise-unrelated connection
needs that key to be parseable. A framer script instance is scoped to one `(session,
stream, script, script_version)` key (see `intercept/dbdump/CLAUDE.md`'s "Framer
scripts" section) — there is no channel today for one stream's script run to hand
anything to another's. Nothing here is framer-specific either: a `tamper` script
watching the handshake connection and a framer script parsing the data connection are
just as plausible a pairing as two framer runs.

## Rejected alternatives

Two narrower designs were considered and rejected in favor of the general-purpose store
below:

- **Client-side-only ephemeral state, merged into `state.global` before every `frame()`
  call.** No backend involvement, simplest possible option. Rejected: doesn't survive a
  `tlstap` restart (not just a browser reload — losing accumulated cross-stream state
  silently changes a later run's output rather than erroring, since already-persisted
  frames stay correct but a *resumed* run silently restarts from empty), and is
  framer-only — no way for a `tamper` script to participate.
- **A DB-backed blob scoped to `(session, script)` or `session` alone**, mirroring
  `frame_progress`'s own shape (one JSON blob, read at run start, written back on a
  batch-boundary CAS). Rejected once the actual use case — two *different* scripts, or
  two different scripting mechanisms, sharing one piece of data — came into focus: a
  script-scoped blob can't be shared across scripts at all, and even session-scoped, a
  single shared blob means rewriting the whole thing (and re-resolving a version conflict
  against every other concurrent writer touching *any* field in it) just to change one
  small value. A real key-value store, where each key is its own row, sidesteps both
  problems — scoping is whatever key names scripts agree on, and an update to one key
  never touches another's.

## Design: a general-purpose store, not owned by any interceptor

Not hosted under `dbdump` or `tamper` — those are per-proxy interceptor instances, and
this needs to be reachable regardless of which interceptors (if any) a given proxy runs.
Introduces a new kind of thing this codebase doesn't have yet: a service that isn't tied
to any interceptor or proxy, wired directly into `cli.go` the same way `/ui/` already is
today (`apiMux.Handle("/ui/", ...)`, registered once, independent of the interceptor
discovery loop).

```go
// cli/core.go (new)
type CoreService interface {
    Finalize()
    proxy.ApiProvider // RegisterRoutes(mux *http.ServeMux, basePath string)
}
```

No `Init(addr)` — unlike `Interceptor`, a `CoreService` isn't per-proxy, so there's no
per-proxy address to receive. Schema setup happens in the constructor, not a separate
`Init`, for the same reason `NewDbDumpInterceptor` already does it there: `RegisterRoutes`
runs synchronously while building the proxy, so the DB must already be usable the moment
routes are registered, not deferred to whenever a proxy's own start goroutine gets to it.

**Wiring in `cli.go`**: right where `/ui/` is registered, before the per-proxy loop:

```go
var coreServices []CoreService
if configFile.Core.Kv != nil {
    kv, err := corekv.New(configFile.Core.Kv.File)
    if err != nil { /* fatal, same as any other startup config error */ }
    kv.RegisterRoutes(apiMux, "/api/core/kv")
    coreServices = append(coreServices, kv)
}
```

`configFile.Core.Kv == nil` (the section simply absent from `config.json`) disables the
feature — same "absence = disabled" convention as `scripts-dir`/`fs-root`/
`dissect-scripts-dir` today, no separate boolean flag needed.

**Graceful shutdown**: `coreServices` needs to be threaded into the existing bounded
shutdown sequence (root `CLAUDE.md`'s "Graceful shutdown" note) — each `CoreService`'s
`Finalize()` called alongside every interceptor's own, concurrently, bounded by the same
`finalizeTimeout`, *after* listeners have stopped and connections have drained. Nothing
about `core.kv` needs its own draining step (it has no in-flight connections, only HTTP
requests already covered by `apiServer`'s own `Shutdown()`), but its `Finalize()` (closing
the DB) must not race a still-in-flight REST call the way any interceptor's would.

**Config shape**: a new section, one named block per service — `core.fs` (a future move
of `tamper`'s existing `fs-root`, out of scope here) and `core.kv` are both meant to
eventually live here. Originally specced as a top-level `core` key; later nested under
`api` instead (`api.core-services`, root `CLAUDE.md`'s "Core Services" section), since
these services have no purpose except being reached through that same API server:

```json
{
  "api": {
    "base-urls": ["http://127.0.0.1:9090"],
    "core-services": {
      "kv": { "file": "kv.sqlite" }
    }
  }
}
```

## Storage

Its own SQLite file (own `core.kv.file` config field), independent of `dbdump` — this
must work on a `tamper`-only proxy with no `dbdump` configured at all.

```sql
core_kv(key TEXT PRIMARY KEY, value BLOB NOT NULL)
```

- `key`/`value` are both opaque as far as the server is concerned — no validation, no
  parsing, no interpretation. Users are fully responsible for what they store and how
  they namespace keys against collisions with other scripts (e.g. a `"myproto."` prefix
  convention) — the server enforces nothing beyond the size limits below.
- Limits, as named constants (not user-configurable — deliberately easy to bump in code
  if they turn out too tight): `maxKeyBytes = 256`, `maxValueBytes = 1 << 20` (1 MiB).
  Measured in bytes, not runes — consistent with every other size limit in this codebase
  (`maxPatternLen`, `bufMaxSize`, etc.). A `write` exceeding either returns `400`.
- Write is a plain upsert (`INSERT ... ON CONFLICT(key) DO UPDATE SET value =
  excluded.value`) — no separate "update" endpoint; there's no meaningful difference from
  "write" without partial-merge semantics, which were deliberately not built (would
  require interpreting value structure, and can't apply uniformly to arbitrary bytes
  anyway).
- **No CAS, no versioning — plain last-writer-wins.** Consistent with "users fully
  responsible": two scripts racing to write the *same* key is expected to be rare (the
  motivating use case writes a key once, at handshake time, well before anything reads
  it), and a lost update here just means the loser's write silently didn't happen —
  no corruption, no error, nothing partially applied (each write is a single-row upsert).
  If this turns out to matter in practice, an optional CAS variant is a compatible
  addition later (e.g. a `write-if-absent` or a version-check parameter), not something
  designed in from the start speculatively.

### Coexistence with `dbdump`'s own database

Nothing stops `core.kv.file` from coincidentally (or deliberately) pointing at the same
path as a `dbdump` instance's own file. Three things make this safe:

1. **Schema**: `core_kv` is a distinctly-named table, reserved against collision with
   anything `dbdump` uses now or in the future (`sessions`/`stream`/`chunks`/`frames`/
   `frame_progress`) — `CREATE TABLE IF NOT EXISTS` is purely additive, so opening a file
   already containing years of `dbdump`'s own captured-traffic tables (a real scenario:
   pointing a freshly-enabled `core.kv` at an already-populated `dbdump.sqlite`) just adds
   `core_kv` alongside them, no different from `dbdump`'s own idempotent startup schema
   creation running against its own pre-existing file across restarts.
2. **Concurrent access**: `dbdump` already opens its file with `PRAGMA journal_mode=WAL`
   and `SetMaxOpenConns(1)` (`intercept/dbdump/dbdump.go`) to serialize its *own* writes
   through one connection — sufficient when it's the only thing touching the file, not
   sufficient once a second, independent `*sql.DB` (this service's) can legitimately write
   the same physical file concurrently. WAL mode still allows only one writer transaction
   system-wide at an instant; without a `busy_timeout`, the loser of that race gets an
   immediate `SQLITE_BUSY` error instead of waiting. Fix, applied to **both** `dbdump`'s
   and this service's `sql.Open` setup: add `PRAGMA busy_timeout=5000` (5s, a named
   constant). With WAL + `busy_timeout` on both sides, two independent connections
   legitimately sharing one file is a standard, well-supported SQLite pattern, not
   something fragile. (Internal note, not end-user-relevant: `journal_mode=WAL` is a
   property of the database file itself, not the connection — once either service sets
   it, it's already in effect for the other.)
3. **`truncate: true` interaction — documented, not defended against.** `dbdump`'s
   `NewDbDumpInterceptor` does `os.Remove(path)` unconditionally when `truncate` is set,
   *before* anything else — if that path coincides with `core.kv.file`, the KV table is
   deleted along with everything else, silently, as a side effect of `dbdump`'s own reset.
   Accepted on the reasoning that a cleared `dbdump` database implies a fresh analysis
   run, and in the absence of some *other* interceptor still depending on old KV values,
   there's nothing meaningful left to preserve either. `core.kv` itself has no truncate
   concept of its own — the only way its data disappears is this coincidental case, or an
   explicit per-key `delete` call. To be documented in `core.kv`'s own doc section, not
   guarded against in code.

## REST API

Base path `/api/core/kv` (nested under `core` to mirror the config shape, and to leave
room for `/api/core/fs` alongside it later). All four endpoints put `key`/`prefix` in the
query string, keeping every request/response *body* reserved purely for value bytes —
deliberately not this codebase's usual all-JSON-body convention (see `/streams`,
`/frame-progress`, etc.), for the same reason `tamper`'s `fs-root` endpoints already make
that exception for file content: a key can be percent-encoded safely in a query string
(unlike `fs-root`'s own `{path...}` wildcard, which breaks on embedded `/` — not a
concern here, since a KV key is one opaque string, not a multi-segment path).

| Method | Path | Request | Response |
|---|---|---|---|
| POST | `/api/core/kv/list?prefix=` | — (`prefix` optional, omitted/empty = all keys) | `200 {"keys": ["...", ...]}` |
| POST | `/api/core/kv/read?key=` | — | `200`, raw bytes, `Content-Type: application/octet-stream`; `404 {"error":"..."}` if absent |
| POST | `/api/core/kv/write?key=` | raw bytes (any `Content-Type`, ignored) | `204`; `400 {"error":"..."}` if `key`/value exceeds its size limit |
| POST | `/api/core/kv/delete?key=` | — | `204` (idempotent regardless of prior existence) |

`list`'s prefix filter is a byte-range scan, not `LIKE`:

```sql
-- prefix given, and not all-0xFF (the common case):
SELECT key FROM core_kv WHERE key >= ? AND key < ? ORDER BY key  -- (prefix, upperBound(prefix))
-- prefix given, all-0xFF bytes (no finite upper bound — see below):
SELECT key FROM core_kv WHERE key >= ? ORDER BY key
-- prefix omitted:
SELECT key FROM core_kv ORDER BY key
```

`upperBound(prefix)`: scan from the end of `prefix`'s bytes for the last byte that isn't
`0xFF`, increment it, and truncate everything after it; if every byte is `0xFF`, there is
no finite byte-string upper bound (falls back to the unbounded form above). Chosen over
`LIKE ... ESCAPE` specifically to avoid hand-escaping `%`/`_`/the escape character itself
in arbitrary user-supplied prefixes, and because SQLite's `LIKE`-to-index optimization has
documented restrictions around a custom `ESCAPE` clause that a plain range scan doesn't
need to worry about — a range scan is also a direct, index-friendly walk of the `key TEXT
PRIMARY KEY` btree.

Verified against a real `modernc.org/sqlite` (this repo's own version) in-memory
database, not just reasoned about: plain ASCII prefixes, a multi-byte UTF-8 prefix
(confirming SQLite's default `BINARY` collation on `TEXT` really is byte-lexicographic,
not codepoint-aware — required for the algorithm to be correct at all), the carry case
(a prefix ending in `0xFF`, correctly incrementing the preceding byte), the all-`0xFF`
edge case (falls back to the unbounded query, no crash), and that `TEXT` storage
round-trips arbitrary — including deliberately invalid-UTF-8 — byte sequences exactly.
Throwaway test, not committed (same convention as this repo's other scripted/example
verification).

## Non-goals

- **No pub/sub or push notifications.** Every request hits the real DB directly — reads
  are always fresh, but there's no "notify me when key X changes" mechanism; a consumer
  has to poll/re-read.
- **No automatic pruning, eviction, or TTL.** Same "users fully responsible" reasoning as
  everywhere else this store touches — a script that wants to bound its own footprint
  (e.g. dropping a connection's key material once that connection's `chunk.closed` signal
  fires) does so itself via explicit `delete` calls.
- **`core.fs`/`/api/core/fs` already exist as their own package**, not unified with this
  one — `core/kv` and `core/fs` are siblings under `core`, sharing the namespace only by
  config-key/URL convention (`core.kv`/`core.fs`, `/api/core/kv`/`/api/core/fs`), not code.

## Follow-up work (not designed here)

- **Script-facing convenience wrappers — done (2026-08-12).** `framer.kv.*`/
  `dissector.kv.*`/`tamper.kv.*`: `kv.read`/`kv.write` (JSON) alongside `kv.readBytes`/
  `kv.writeBytes` (raw), plus `kv.list`/`kv.delete` (beyond this note's original
  read/write-only scope, added for parity with the raw endpoints), layered over the four
  raw endpoints above. No RPC bridge for any of the three script runtimes, as anticipated
  here: `fetch()` runs directly inside each script's own Worker (`web/coreApiClient.js`,
  shared by all three), with the KV base URL computed once on the main thread as an
  absolute URL and baked into each Worker's bootstrap source as a string literal — exactly
  the mechanical detail anticipated here. The same module also grew `fs.*` over
  `/api/core/fs`, uniformly across all three runtimes including `tamper.fs.*` — that one
  initially stayed on its pre-existing RPC bridge as a smaller first step, then got
  migrated onto this same direct-fetch path too in a same-day follow-up (see
  `core/CLAUDE.md`'s "Frontend" section). See `web/CLAUDE.md`'s "Framer scripts"/
  "Dissector scripts"/"Scripted interception" sections for the full script-facing
  contract. Verified end-to-end in a real browser, before and after the `tamper.fs.*`
  migration.
- **Pagination for `list`**, if the "modest number of keys" assumption this design leans
  on (a handful of protocol artifacts, not `frames`-table-scale volume) turns out wrong in
  practice.
