# tapctl — CLI reference

`tapctl` is a one-shot Go CLI for driving the `dbdump`/`tamper` interceptor APIs by
hand, organized as `tapctl <group> <command> [flags]` — one group per interceptor, so
the flat command list doesn't get confusing as more interceptors gain commands. Every
command opens a fresh connection, performs one action, prints JSON to stdout, and
exits — no persistent connection needed for anything, by design.

Build: `go build -o tapctl ./tapctl`. Run `./tapctl help` (or `tapctl <group>
help`) for the same usage text reproduced below. Source split by concern, mirroring the
interceptor packages themselves: `main.go` (dispatch + shared HTTP/WS/flag/output
helpers), `tamper.go`, `dbdump.go`, `core.go`.

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
tapctl tamper script-get --name NAME [--hash] [--api URL]
tapctl tamper script-put --name NAME (--file PATH | --file -) [--api URL]
tapctl tamper script-delete --name NAME [--api URL]
tapctl tamper framer-script-list [--api URL]
tapctl tamper framer-script-get --name NAME [--hash] [--api URL]
tapctl tamper framer-script-put --name NAME (--file PATH | --file -) [--api URL]
tapctl tamper framer-script-delete --name NAME [--api URL]
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
- **`script-get --hash`** requests `?hash=1` (`intercept/scriptstore/CLAUDE.md`) and
  prints `{"sha256":"..."}` instead of the content — the same "version" value
  `frames.script_version`/`frame_progress.script_version` use, so a script's current
  version can be learned directly instead of fetching content just to hash it (or
  falling back to raw SQLite access, the only alternative before this existed).
- `framer-script-list`/`framer-script-get`/`framer-script-put`/`framer-script-delete` —
  the same four flat commands (including `-get`'s `--hash`), against the tamper
  interceptor's separate `framer-scripts-dir` store (see `intercept/tamper/CLAUDE.md`'s
  "Script storage" section) rather than `scripts-dir`; same name in both stores is not a
  collision.
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

# Learn a script's current version (sha256 hex) without fetching its content.
tapctl tamper script-get --name my-filter --hash

# Framer script storage: same four verbs (+ -get --hash), separate store.
tapctl tamper framer-script-list
tapctl tamper framer-script-put --name length-prefix --file ./length-prefix-framer.js
tapctl tamper framer-script-get --name length-prefix > length-prefix-framer.js
tapctl tamper framer-script-delete --name length-prefix

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
tapctl dbdump search --pattern STR [--session N [--stream N]] [--start N] [--end N]
                      [--pattern-encoding text|base64|regex] [--direction N] [--contiguous] [--api URL]
tapctl dbdump stid-stream --session N --stream N [--start N] [--n 50] [--api URL]
tapctl dbdump sgid-stream --session N [--start N] [--n 50] [--api URL]
tapctl dbdump frame-progress --session N --stream N --script NAME --script-version HASH [--api URL]
tapctl dbdump frames-timeline --session N --stream N --script NAME --script-version HASH
                               [--start N | --before-stid N] [--n 50] [--api URL]
tapctl dbdump chunks-timeline --session N --stream N [--start N | --before-stid N] [--n 50] [--api URL]
tapctl dbdump byte-range --session N --stream N --direction N --offset N --length N [--api URL]
tapctl dbdump chunks-follow --session N --stream N [--start N] [--poll-ms 500] [--api URL]
tapctl dbdump frames-follow --session N --stream N --script NAME --script-version HASH
                             [--start N] [--poll-ms 500] [--api URL]
tapctl dbdump run-framer --session N --stream N --script NAME [--api URL]
tapctl dbdump run-dissector --session N --stream N --direction N --frame-id N
                             --framer-script NAME --framer-script-version HASH
                             --dissect-script NAME [--api URL]
tapctl dbdump script-list [--api URL]
tapctl dbdump script-get --name NAME [--hash] [--api URL]
tapctl dbdump script-put --name NAME (--file PATH | --file -) [--api URL]
tapctl dbdump script-delete --name NAME [--api URL]
tapctl dbdump dissect-script-list [--api URL]
tapctl dbdump dissect-script-get --name NAME [--hash] [--api URL]
tapctl dbdump dissect-script-put --name NAME (--file PATH | --file -) [--api URL]
tapctl dbdump dissect-script-delete --name NAME [--api URL]
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

- **`search`'s `--session` is optional — client-side-only fan-out, no backend change**:
  `/search-text` itself stays single-session server-side (`searchTextRequest.Session` is
  still a plain non-optional `int64` there); omitting `--session` instead fetches
  `sessions` and calls `search-text` once per session, merging the results and tagging
  each hit with a `session` field the raw per-session response doesn't have on its own
  (a match is always implicit in that single-session request today). A search failing
  partway through one session's call fails the whole command immediately (`fail`,
  identifying which session) rather than returning partial results, same as every other
  `tapctl` command's error handling. **`--stream` requires `--session`**: a stream id is
  only unique *within* a session, so a bare `--stream` without `--session` would
  silently apply that numeric id to a different actual stream in each session searched
  — rejected client-side rather than allowed to produce a misleading merged result.
  Given `--session`, output is passed through unchanged (`printRawJSON`, no `session`
  field added, since it's a single already-known session); omitted, output is freshly
  built (`printJSON`) with `session` added to each match, `[]` rather than `null` when
  nothing/no sessions exist.
- `frame-progress`/`frames-timeline` — both key on `(session, stream, script,
  script_version)`, mirroring `intercept/dbdump/frames.go`'s own `frameTimelineKeyRequest`
  exactly, including its one wire-format wart: `frames-timeline`'s `--before-stid` maps
  to a `beforeStid` JSON field (camelCase), unlike every snake_case field around it — a
  real inconsistency in the protocol itself, reproduced faithfully rather than smoothed
  over client-side. `script_version` is the exact hash a framer run was persisted
  under — get it via `script-get --hash` above rather than fetching+hashing content
  yourself. `frame-progress` reports bookkeeping only (each direction's processed byte
  offset, the framer's opaque `state`, each direction's close-signal status) — no frame
  content — useful for checking whether/how-far a stream has actually been framed with
  this exact script/version before pulling `frames-timeline`'s real data.
  `frames-timeline` returns the persisted frames themselves (byte ranges, script-attached
  `meta`, direction, `stid`, `time`) merged across both directions in chronological
  order (see `intercept/dbdump/CLAUDE.md`'s "Framer scripts" section for the schema) —
  this is the one that answers "what did the framer/dissector actually see", e.g. a
  parsed HTTP message's header/body byte boundaries straight from `meta`, no manual
  byte-scanning needed. Defaults to forward pagination from `--start` (`0` unless
  given); `--before-stid` paginates backward instead — exactly one of the two, the same
  rule the server enforces, checked client-side here too for a clearer error than the
  server's own 400. `--n` defaults to 50, same reasoning as `stid-stream`/`sgid-stream`
  above.
- `chunks-timeline` — `frames-timeline`'s raw-chunk counterpart (`POST
  /chunks/timeline`, `intercept/dbdump/CLAUDE.md`'s "dbdump Interceptor" section): same
  `(session, stream)` scoping and `--start`/`--before-stid`/`--n` pagination convention,
  minus a script/script-version key (chunks have none — no prior `script-get --hash`
  needed). Returns metadata only — `{id, direction, stid, time, offset, length}` per
  chunk, merged across both directions in `stid` order — no chunk bytes; fetch those
  separately via `chunk`/`chunk-stid` above. This is `/segments`' retired role's
  metadata half, reborn as a plain paged listing (no server-side budget selection,
  unlike `/segments` — the frontend applies its own byte budget client-side).
- `byte-range` — a single-range convenience wrapper over `POST /byte-ranges`
  (`intercept/dbdump/CLAUDE.md`'s "dbdump Interceptor" section), which fetches an
  arbitrary `[offset, offset+length)` span for one direction, possibly spanning
  multiple underlying chunks — unlike `chunk` above, which only ever returns whole
  chunks by id. The real endpoint batches several ranges into one binary
  request/response; this command always sends exactly one entry (encoding direction
  into the wire length field's sign, per the endpoint's own convention) and decodes the
  single length-prefixed reply. Prints `{"offset","direction","requested_length",
  "length","data_base64"}` — `length` (and the decoded bytes) may come back shorter
  than `--length`, even `0`: not an error, just means that much of the span isn't
  captured yet (a still-live stream) or ever will be (the stream's genuine end).
- `chunks-follow`/`frames-follow` — the only commands in this group that don't exit
  once their initial request is answered: every other command here is a one-shot
  snapshot, so watching an actively-growing capture otherwise means polling by hand in
  a loop. Both run until killed, printing **one JSON object per line (NDJSON)** as new
  data appears — unlike every other command's single pretty-printed blob, since the
  whole point here is a caller can read output as it arrives — and re-poll after
  `--poll-ms` (default `500`, clamped to a minimum of `100` regardless of what's
  passed, to avoid an accidental busy-loop) whenever a poll comes back empty. Neither
  takes an `--n`: there's no fixed batch size to ask for, just "keep going forever."
  `chunks-follow` reuses `/stid-stream`'s WebSocket — its request/response loop already
  accepts a fresh request after each `done` over one connection, so no server change
  was needed — repeatedly asking for `stid >= cursor` and advancing `cursor` past the
  last stid seen; each line matches `stid-stream`'s own per-chunk shape
  (`{"stid","chunk_id","direction","time","offset","data_base64"}`). `frames-follow`
  instead repolls `POST /frames/timeline` (no WebSocket variant exists for frames),
  same `(session, stream, script, script_version)` key as `frame-progress`/
  `frames-timeline`; each line matches `frames-timeline`'s own entry shape
  (`{"id","ranges","meta","direction","stid","time","seq","virtual_offset"}`). Frames
  are never computed server-side — `frames-follow` only ever shows what some client
  (a browser tab running `catchUpFramer`, whether by hand or via `run-framer` below) is
  actively persisting via `/frames/append` for that exact key; starting it doesn't make
  anything happen on its own, it only observes.
- `run-framer` is the one command in this group that *does* make framing happen: it asks
  a currently-connected browser tab (the web UI's View menu → "Remote framer runs"
  toggle, opted in explicitly — see `web/CLAUDE.md`'s "Remote framer job listener"
  section) to run a script for real, through that tab's own already-loaded
  `frameRuntime.js` — the exact same code path a manual Run click uses, not a second
  implementation `tapctl` would otherwise need to carry. Blocks until that browser
  reports success or failure, or the request times out server-side (`504`), or fails
  immediately (`503`) if no browser is connected right now. `--script` is a name only, no
  `--script-version` — the browser resolves the script's own current content and version
  itself, the same way a manual Run does. On success, use `frames-follow`/
  `frames-timeline` afterward to inspect what got persisted.
- `run-dissector` is `run-framer`'s dissector-script sibling — same "ask a connected
  browser tab" plumbing, but its own separate connection/toggle ("Remote dissector runs"
  in the View menu, opted in independently from "Remote framer runs"), matching this
  codebase's convention of keeping framer/dissector as separate systems throughout. It
  identifies one already-persisted frame directly rather than a whole stream:
  `--direction`/`--framer-script`/`--framer-script-version` name the framer run that
  produced it (the same key `frame-progress`/`frames-timeline` use), and `--frame-id` is
  that frame's own id within that key — learnable from `frames-timeline`'s or
  `frames-follow`'s own `"id"` field. Unlike `run-framer`, dissection output is never
  persisted anywhere — there's nothing to go inspect afterward the way `frames-timeline`
  works for a framer run — so a successful call prints the dissector script's own
  `FieldNode[]` tree directly (the same shape `DissectPanel.js` renders in the UI), not
  just `{"status":"ok"}`.
- `script-list`/`script-get`/`script-put`/`script-delete` — the same flat-verb shape as
  `tamper script-*` above (including `-get`'s `--hash`), but against dbdump's own
  framer-script store (`scripts-dir`; see `intercept/dbdump/CLAUDE.md`'s "Framer
  scripts" section) rather than tamper's.
- `dissect-script-list`/`dissect-script-get`/`dissect-script-put`/`dissect-script-delete`
  — the same four commands again, against dbdump's separate `dissect-scripts-dir` store
  (see `intercept/dbdump/CLAUDE.md`'s "Dissector scripts" section) — a distinct
  namespace from `scripts-dir` above, same as tamper's `scripts-dir`/
  `framer-scripts-dir` split.

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

# Same pattern, but across every session — don't already know which one has it.
# Each hit comes back tagged with its own "session" field.
tapctl dbdump search --pattern "GET /login"

# Pull the next batch of chunks off a stream/session, in order.
tapctl dbdump stid-stream --session 1 --stream 0 --start 0 --n 50
tapctl dbdump sgid-stream --session 1 --start 0 --n 0   # 0 = unlimited

# Pull the next batch of raw chunk metadata across both directions, in stid order.
tapctl dbdump chunks-timeline --session 1 --stream 0 --start 0 --n 50

# Fetch an arbitrary byte span (here spanning two 14-byte chunks) as base64.
tapctl dbdump byte-range --session 1 --stream 0 --direction 0 --offset 10 --length 20

# Watch a stream's chunks land live (NDJSON, one line per chunk) instead of polling by
# hand — run this, then drive traffic through the proxy in another terminal.
tapctl dbdump chunks-follow --session 1 --stream 0

# Same, for a framer run's persisted frames (only shows something once some client,
# typically a browser tab, is actively running the framer for this exact key).
tapctl dbdump frames-follow --session 1 --stream 0 --script http1-framer --script-version "$V"

# Learn the framer script's current version, then check progress and pull its frames.
V=$(tapctl dbdump script-get --name http1-framer --hash | python3 -c 'import json,sys;print(json.load(sys.stdin)["sha256"])')
tapctl dbdump frame-progress --session 1 --stream 0 --script http1-framer --script-version "$V"
tapctl dbdump frames-timeline --session 1 --stream 0 --script http1-framer --script-version "$V"

# Ask a connected browser tab (View menu -> "Remote framer runs" enabled) to actually
# run the framer for real, then inspect what it persisted.
tapctl dbdump run-framer --session 1 --stream 0 --script http1-framer
tapctl dbdump frames-timeline --session 1 --stream 0 --script http1-framer --script-version "$V"

# Ask a connected browser tab (View menu -> "Remote dissector runs" enabled) to dissect
# one already-persisted frame (id 3, from the frames-timeline output above) for real.
tapctl dbdump run-dissector --session 1 --stream 0 --direction 0 --frame-id 3 \
    --framer-script http1-framer --framer-script-version "$V" --dissect-script http1-dissector

# Framer script storage: list, fetch a script's content and its current version.
tapctl dbdump script-list
tapctl dbdump script-get --name http1-framer > http1-framer.js
tapctl dbdump script-get --name http1-framer --hash

# Dissect script storage: same four verbs, separate store.
tapctl dbdump dissect-script-list
tapctl dbdump dissect-script-get --name http1-dissector --hash
```

## `tapctl core`

```
tapctl core fs-list [--path PATH] [--api URL]
tapctl core fs-get --path PATH [--api URL]
tapctl core fs-put --path PATH (--file PATH2 | --file -) [--api URL]
tapctl core fs-append --path PATH (--file PATH2 | --file -) [--api URL]
tapctl core kv-list [--prefix PREFIX] [--api URL]
tapctl core kv-read --key KEY [--api URL]
tapctl core kv-write --key KEY (--file PATH | --file -) [--api URL]
tapctl core kv-delete --key KEY [--api URL]
```

`--api` defaults to `http://127.0.0.1:9090`, same as every other group — core services
have no per-proxy variant to begin with (they aren't tied to a proxy at all), so
`/api/core/...` is simply *the* path, not a canonical alias for something else.

Drives `core/fs` and `core/kv` — see `core/CLAUDE.md`'s "`core/fs`"/"`core/kv`" sections
for the REST APIs these wrap. Either group of commands 404s (not a `tapctl`-side error —
the server itself doesn't register the routes) if that core service isn't configured.

- `fs-list`/`fs-get`/`fs-put`/`fs-append` — flat-verb, plain-REST-wrapper shape, over
  `core/fs`'s endpoints (see `core/CLAUDE.md`'s "core/fs" section). `--path` is
  slash-separated for subdirectories, percent-encoded per-segment (`encodeFsPath`,
  mirroring `web/coreApiClient.js`'s `encodeSegments` helper) so literal slashes survive
  as separators rather than becoming `%2F`. `fs-list`'s `--path` defaults to `""` (list the
  configured root itself). `fs-get` prints raw file bytes to stdout, same pipeable
  convention as `tamper script-get` — except fs content is arbitrary binary, not always
  printable text, unlike a script. There is no `fs-delete`: the server exposes no
  `DELETE` endpoint. A `--path` containing literal `..` segments never reaches
  `core/fs`'s own containment check at all when sent over real HTTP — Go's `ServeMux`
  cleans and 301-redirects such paths before routing, and `http.Client` follows that by
  resending as `GET` (dropping a `PUT`'s body), so a traversal attempt via `tapctl` just
  silently no-ops rather than writing anywhere; `core/fs`'s own `resolve()` containment
  logic is unit-tested directly in `core/fs/fs_test.go` instead, same reasoning
  `scripts_test.go` documents for script names. `fs-append` uses `httpPostRawBody`
  (`POST`, not `PUT`), mirroring `core/fs`'s `handleAppend` non-idempotent-verb
  reasoning — everything else here is `GET`/`PUT`. It's a real server-side append
  (`core/fs`'s `Append`, opened with `O_APPEND`), safe under concurrent appends to the
  same file from elsewhere, not a client-side read-modify-write.
- `kv-list`/`kv-read`/`kv-write`/`kv-delete` — same flat-verb shape, over `core/kv`'s
  endpoints (see `core/CLAUDE.md`'s "core/kv" section) — a general-purpose key-value
  store independent of `core/fs` above, e.g. for a value a script stashed via
  `tamper.kv.*`/`framer.kv.*`/`dissector.kv.*` (a crypto key exchanged on one
  connection, shared across streams/scripts). **Key/prefix travel in the query string,
  not a JSON body or path segment** — the one place `tapctl` departs from its usual
  per-endpoint shape, because the REST API itself does (`core/kv/api.go` reserves the
  request/response body purely for value bytes). `kv-list`'s `--prefix` defaults to
  `""` (every key) — same byte-range-scan semantics as `core/kv`'s own `List`, not
  `LIKE`. `kv-read` prints the raw value to stdout, same pipeable convention as
  `fs-get`, or fails with "key not found" (`404`) if absent. `kv-write` reads from
  `--file` (a path, or `-` for stdin), same convention as `fs-put`/`fs-append` — a
  plain upsert (`core/kv`'s own semantics: last-writer-wins, no separate create/update).
  `kv-delete` is idempotent regardless of prior existence, matching the REST endpoint.

### Usage examples

```sh
# List the configured root, push a fixture into a subdirectory (auto-created), read
# it back, list that subdirectory.
tapctl core fs-list
tapctl core fs-put --path fixtures/response.json --file ./response.json
tapctl core fs-get --path fixtures/response.json > response.json
tapctl core fs-list --path fixtures

# Append instead of overwrite — creates the file on first use.
echo "run started" | tapctl core fs-append --path notes.log --file -
echo "run finished" | tapctl core fs-append --path notes.log --file -

# kv: write a value, list keys under a prefix, read one back, delete it.
echo -n "hello" | tapctl core kv-write --key demo:key1 --file -
tapctl core kv-list --prefix demo:
tapctl core kv-read --key demo:key1
tapctl core kv-delete --key demo:key1
```
