# tapctl — CLI reference

`tapctl` is a one-shot Go CLI for driving the `dbdump`/`tamper` interceptor APIs by
hand, organized as `tapctl <group> <command> [flags]` — one group per interceptor, so
the flat command list doesn't get confusing as more interceptors gain commands. Every
command opens a fresh connection, performs one action, prints JSON to stdout, and
exits — no persistent connection needed for anything, by design.

Build: `go build -o tapctl ./test/tapctl`. Run `./tapctl help` (or `tapctl <group>
help`) for the same usage text reproduced below. Source split by concern, mirroring the
interceptor packages themselves: `main.go` (dispatch + shared HTTP/WS/flag/output
helpers), `tamper.go`, `dbdump.go`.

This file documents `tapctl` itself — protocol/wire-format details (message shapes,
config fields, server-side rationale) live in the root `CLAUDE.md`, referenced by
section name below rather than duplicated here.

## `tapctl tamper`

```
tapctl tamper streams [--api URL]
tapctl tamper peek --conn N --direction 0|1 [--offset N] [--length N] [--api URL]
tapctl tamper release --conn N --direction 0|1 [--action forward|drop] [--release-chunks N]
                       [--edit PATH|- | --edit-base64 STRING] [--prefix-length N] [--bounds "0,10"]
                       [--api URL]
tapctl tamper drop-connection --conn N --direction 0|1 [--api URL]
tapctl tamper set-mode --conn N --intercepting=true|false [--api URL]
tapctl tamper set-auto-intercept --enabled=true|false [--api URL]
tapctl tamper script-log --level log|error --text TEXT [--api URL]
tapctl tamper script-list [--api URL]
tapctl tamper script-get --name NAME [--api URL]
tapctl tamper script-put --name NAME (--file PATH | --file -) [--api URL]
tapctl tamper script-delete --name NAME [--api URL]
tapctl tamper fs-list [--path PATH] [--api URL]
tapctl tamper fs-get --path PATH [--api URL]
tapctl tamper fs-put --path PATH (--file PATH2 | --file -) [--api URL]
tapctl tamper fs-append --path PATH (--file PATH2 | --file -) [--api URL]
tapctl tamper log-file [--api URL]
```

`--api` defaults to `http://127.0.0.1:9090` and is treated as the API server root
(canonical `/api/i/tamper/...` paths, i.e. single-proxy usage) in every command.

- `streams`, `peek`, `release`, `drop-connection`, `set-mode`, `set-auto-intercept` —
  see the root `CLAUDE.md`'s "tamper Interceptor" section for the full protocol; the
  notes below cover only `tapctl`-specific behavior. Reconnecting to control at any
  time is always enough to discover and act on everything outstanding (no
  FIFO/persistent-process trick needed even for the hold→release workflow), which is
  what makes every `tapctl` invocation being a fresh, disconnecting connection fine.
- `release` combines an optional edit with an optional release in one call, mirroring
  `heldBuffer.performAction` directly: `--release-chunks` defaults to `0` (edit-only,
  nothing released); replacement bytes for an edit come from `--edit PATH|-` or inline
  `--edit-base64 STRING` (mutually exclusive) — the latter is what makes a `peek` →
  edit → `release` round-trip scriptable without a temp file, since `peek`'s own output
  is already base64. No `--release-chunks all` convenience is provided deliberately —
  editing already requires a prior `peek` to learn `--prefix-length`, and that same
  `peek` reply already gives you the chunk count, so there's no ergonomic gap left to
  fill; every `tapctl` command stays a direct 1:1 wire passthrough.
- **`--release-chunks 0` (edit-only, don't release yet) is of limited use from tapctl
  specifically**, discovered while smoke-testing this against a real server: `peek` (on
  `/watch`) never touches `/control` and so is freely repeatable, but *any*
  `/control`-touching command (`streams`, `release`, `drop-connection`, `set-mode`)
  releases everything on that connection's disconnect — and every `tapctl` invocation
  is a fresh connection that disconnects when the process exits. So an edit-only
  `release` call gets its own edit flushed out anyway the moment that command's process
  exits; there's no way to do "edit now, decide whether to release later" as two
  separate `tapctl` invocations. The one workflow that actually works end-to-end from
  `tapctl` alone is: hold via `hold-until-connected` (so nothing needs an active
  control connection to begin with), `peek` freely to inspect, then a single combined
  edit+`release` call. See `intercept/tamper/CLAUDE.md`'s "Held-buffer lifecycle"
  section, "Possible future option" note, for what would actually lift this limitation.
- `script-log` pushes one already-formatted log line for optional server-side
  persistence (the tamper interceptor's `log-file` config arg — see
  `web/CLAUDE.md`'s "Log panel" note under "Scripted interception"). Unlike every other
  control command it never gets a reply on success — fire-and-forget by design (see
  `intercept/tamper/protocol.go`'s `cmdScriptLog`) — so `cmdTamperScriptLog` doesn't
  call `readAck` at all; it validates `--level` (`log` or `error`) client-side instead,
  which already covers the one case the server would otherwise report an error for.
- `script-list`/`script-get`/`script-put`/`script-delete` — flat commands, not a nested
  `tapctl tamper script <action>` subgroup, consistent with every other tamper command
  being a single verb, and no dispatch-level restructuring needed to add them. They're
  plain REST wrappers over `scripts.go`'s CRUD endpoints (see `intercept/tamper/CLAUDE.md`'s
  "Script storage" section): `script-get` prints the raw script source (not
  JSON-wrapped) so it's directly pipeable; `script-put` reads from `--file PATH|-`,
  mirroring `release`'s `--edit` convention.
- `fs-list`/`fs-get`/`fs-put`/`fs-append` — same flat-verb, plain-REST-wrapper shape as the
  `script-*` commands, over `fs.go`'s endpoints (see `intercept/tamper/CLAUDE.md`'s
  "Filesystem access" section). `--path` is slash-separated for subdirectories, percent-encoded
  per-segment (`encodeFsPath`, mirroring `web/tamperApi.js`'s helper of the same name)
  so literal slashes survive as separators rather than becoming `%2F`. `fs-list`'s
  `--path` defaults to `""` (list `fs-root` itself). `fs-get` prints raw file bytes to
  stdout, same pipeable convention as `script-get` — except fs content is arbitrary
  binary, not always printable text, unlike a script. There is no `fs-delete`: the
  server exposes no `DELETE` endpoint for `fs-root`. A `--path` containing literal `..`
  segments never reaches `fs.go`'s own containment check at all when sent over real
  HTTP — Go's `ServeMux` cleans and 301-redirects such paths before routing, and
  `http.Client` follows that by resending as `GET` (dropping a `PUT`'s body), so a
  traversal attempt via `tapctl` just silently no-ops rather than writing anywhere;
  `fs.go`'s own `resolve()` containment logic is unit-tested directly in `fs_test.go`
  instead, same reasoning `scripts_test.go` documents for script names. `fs-append`
  uses `httpPostRawBody` (`POST`, not `PUT`), mirroring `fs.go`'s `handleFsAppend`
  non-idempotent-verb reasoning — everything else here is `GET`/`PUT`. It's a real
  server-side append (`fs.go`'s `Append`, opened with `O_APPEND`), safe under concurrent
  appends to the same file from elsewhere, not a client-side read-modify-write.
- `log-file` — plain GET wrapper over `handleLogFileInfo` (see `intercept/tamper/CLAUDE.md`'s
  note under "Script storage" REST endpoints): reports whether the interceptor was
  configured with `log-file` and, if so, its display filename. Static for the server's
  whole run, same as every other bare-GET dbdump command (`status`, `sessions`).

### Usage examples

```sh
# List streams and what's currently held on each.
tapctl tamper streams

# Turn on auto-intercept so newly-established connections start held.
tapctl tamper set-auto-intercept --enabled=true

# Escalate an already-open stream (ConnID 3) from watch into intercept mode.
tapctl tamper set-mode --conn 3 --intercepting=true

# Inspect what's held on the client->server (0) direction of connection 3.
tapctl tamper peek --conn 3 --direction 0

# Forward everything held on that direction, unmodified.
tapctl tamper release --conn 3 --direction 0 --action forward --release-chunks 1

# Edit-and-forward: replace the first 42 bytes (as learned via the peek above) with
# the contents of patched.bin, then release the resulting single chunk.
tapctl tamper release --conn 3 --direction 0 --action forward --release-chunks 1 \
    --edit patched.bin --prefix-length 42

# Same, but the replacement bytes come from peek's own base64 output — no temp file.
tapctl tamper release --conn 3 --direction 0 --action forward --release-chunks 1 \
    --edit-base64 "aGVsbG8=" --prefix-length 42

# Drop what's held instead of forwarding it.
tapctl tamper release --conn 3 --direction 1 --action drop --release-chunks 1

# Terminate a connection outright.
tapctl tamper drop-connection --conn 3 --direction 0

# Push a line to the server-side script log (only persisted if the interceptor was
# configured with log-file; no reply either way).
tapctl tamper script-log --level log --text "manual test note"

# Script storage: list, push a new/updated script, fetch one back, remove one.
tapctl tamper script-list
tapctl tamper script-put --name my-filter --file ./my-filter.js
cat ./my-filter.js | tapctl tamper script-put --name my-filter --file -
tapctl tamper script-get --name my-filter > my-filter.js
tapctl tamper script-delete --name my-filter

# fs-root: list the root, push a fixture into a subdirectory (auto-created), read
# it back, list that subdirectory.
tapctl tamper fs-list
tapctl tamper fs-put --path fixtures/response.json --file ./response.json
tapctl tamper fs-get --path fixtures/response.json > response.json
tapctl tamper fs-list --path fixtures

# Append instead of overwrite — creates the file on first use.
echo "run started" | tapctl tamper fs-append --path notes.log --file -
echo "run finished" | tapctl tamper fs-append --path notes.log --file -

# Check whether server-side script-log persistence is configured, and where.
tapctl tamper log-file
```

## `tapctl dbdump`

```
tapctl dbdump status [--api URL]
tapctl dbdump sessions [--api URL]
tapctl dbdump streams --session N [--api URL]
tapctl dbdump chunklist --session N --stream N [--api URL]
tapctl dbdump latest [--session N] [--stream N] [--api URL]
tapctl dbdump chunk --session N --stream N --direction N --chunks 0,1,2 [--api URL]
tapctl dbdump chunk-stid --session N --stream N --direction N --id N [--api URL]
tapctl dbdump byte-stid --session N --stream N --direction N --offset N [--api URL]
tapctl dbdump search --session N --pattern STR [--stream N] [--start N] [--end N]
                      [--pattern-encoding text|base64|regex] [--direction N] [--contiguous] [--api URL]
tapctl dbdump stid-stream --session N --stream N [--start N] [--n 50] [--api URL]
tapctl dbdump sgid-stream --session N [--start N] [--n 50] [--api URL]
```

`stid-stream`/`sgid-stream` default `--n` to 50 (the web frontend's own `BATCH`
constant), not the protocol's `0`/unlimited, since the whole reply is buffered into one
JSON blob before printing; pass `--n 0` explicitly for unlimited.

Thin wrappers over the REST/WS endpoints documented in full under the root `CLAUDE.md`'s
"dbdump Interceptor" section; no protocol documentation duplicated here. `chunk` (a
`multipart/form-data` response) and `stid-stream`/`sgid-stream` (WebSocket,
chunk-metadata-then-binary-frame pairs) are each collected into a single
`{"chunks":[...]}` JSON object with each chunk's bytes as a `data_base64` field — the
same convention `tamper peek` uses, for consistency across the tool.

### Usage examples

```sh
# Health check and session listing.
tapctl dbdump status
tapctl dbdump sessions

# Streams within session 1, and what's been captured on stream 0 so far.
tapctl dbdump streams --session 1
tapctl dbdump chunklist --session 1 --stream 0

# Consolidated cheap "anything new?" check: latest session id, plus (since both are
# given) latest sgid/streams_version for session 1 and latest stid for its stream 0.
# Omit --session/--stream to narrow which fields come back non-(-1).
tapctl dbdump latest --session 1 --stream 0

# Fetch specific chunks (client->server, chunk ids 0-2) of that stream.
tapctl dbdump chunk --session 1 --stream 0 --direction 0 --chunks 0,1,2

# Resolve a chunk id / byte offset to its stid (stream-local cursor position).
tapctl dbdump chunk-stid --session 1 --stream 0 --direction 0 --id 2
tapctl dbdump byte-stid --session 1 --stream 0 --direction 0 --offset 512

# Literal search across the whole session, both directions.
tapctl dbdump search --session 1 --pattern "GET /login"

# Regex search on one stream, server->client only.
tapctl dbdump search --session 1 --stream 0 --direction 1 \
    --pattern "^HTTP/1\.[01] [0-9]{3}" --pattern-encoding regex

# Pull the next batch of chunks off a stream/session, in order.
tapctl dbdump stid-stream --session 1 --stream 0 --start 0 --n 50
tapctl dbdump sgid-stream --session 1 --start 0 --n 0   # 0 = unlimited
```
