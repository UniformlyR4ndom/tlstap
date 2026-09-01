# Tamper Scripting API

The `tamper` interceptor's "Scripts" sub-tab runs a JavaScript program against live
traffic — the automated equivalent of clicking around the "Intercept" sub-tab
(`TamperQueueList`/`TamperDetailPanel`) to hold, inspect, edit, drop, or forward chunks.

For the control/watch WebSocket protocol this runtime is built on, see
[`intercept/tamper/CLAUDE.md`](../../intercept/tamper/CLAUDE.md). For where this fits
into the web frontend, see the root [`CLAUDE.md`](../../CLAUDE.md)'s "Web Frontend"
section.

## 1. Overview

A script is a plain JavaScript `.js` file, stored server-side (`GET`/`PUT`/`DELETE
/api/i/tamper/scripts/<name>`) and edited via the Scripts sub-tab's CodeMirror editor.
Clicking **Run** starts it; only one script runs at a time per browser tab. Nothing on
the Go side executes a script — `intercept/tamper/scripts.go` is a flat name→text-blob
store; the Worker, event dispatch, and `tamper`/`ctx` API all live in the browser.

A running script registers handlers for `onConnect`/`onReceive`/`onClose`, decides per
held chunk whether to forward it (unmodified or edited), drop it, or pause for an
operator decision, can call any Transform-panel operation (hashing, encoding,
compression, encryption, checksums, MAC) on the bytes it holds, can read/write a scoped
area of the host filesystem or a general-purpose key-value store (state otherwise
doesn't survive a restart — see
["Custom state across invocations"](#27-custom-state-across-invocations)), and can log
output, in-browser and optionally server-side. A separately-selected, separately-stored
*framer* script can reassemble raw chunks into logical frames first, so the
interception script reacts to whole units via `onFrame` instead — see
["Framer scripts"](#4-framer-scripts).

**Trust model:** a script runs with the same privileges as any other code on the page —
no sandboxing beyond the Worker boundary (no DOM/page access, full access to whatever
traffic tlstap is proxying). Only run scripts you wrote or trust.

## 2. Architecture

### 2.1 Where a script runs

`scriptRuntime.js`'s `createScriptRuntime()` manages one Web Worker at a time.
`start(name, source)` builds two separate Blobs: a bootstrap template (`BOOTSTRAP`, the
Worker's actual entry point) and the script's own text (wrapped in its own IIFE, so its
top-level declarations can't collide with the runtime's). `BOOTSTRAP` wires up
`self.tamper`/`self.onmessage`/error listeners, then `importScripts()`s the script's
Blob into that same global scope — the script sees the bare `tamper` global as if
everything were one file. Each Blob ends with its own `//# sourceURL=...` so
DevTools/stack traces name the actual failing file. It's a classic (non-module) Worker,
since `importScripts()` requires one.

If a framer script is also selected (§4), `start()` takes two extra arguments and builds
a *third* Blob for it — loaded first, and deliberately **not** IIFE-wrapped (its `frame`
function must resolve as a bare global, unlike the interception script's side-effecting
`tamper.register(...)` call). Whether a framer is active is decided per dispatch, purely
by `typeof frame === 'function'` — no separate flag crosses into the Worker.

### 2.2 The `tamper` object and the RPC bridge

`BOOTSTRAP` defines `self.tamper` synchronously. `peek`/`release`/`dropConnection`/
`setIntercept`/`listStreams` are thin `postMessage`-based RPC wrappers: each is a
live-connection-scoped operation that needs state the main thread already tracks (the
control WebSocket, stream metadata), so a call posts to the main thread, which performs
the real operation (via handlers mirroring `tamperApi.js`) and posts back the result.

Direction is `'c2s'`/`'s2c'` everywhere in this API; translation to/from the wire
protocol's numeric `0`/`1` happens only at this bridge.

`fs.*`/`kv.*` (§3.3) don't go through this bridge at all — they're a plain `fetch()`
straight from inside the Worker (`coreApiClient.js`), since neither is scoped to a
connection or needs anything the main thread tracks. This is possible despite the Worker
having no page origin of its own to resolve a relative URL against, because the base URL
(`/api/core/fs` or `/api/core/kv`) is computed as an *absolute* URL on the main thread
and baked into `BOOTSTRAP`'s own source before the Worker is even built.

### 2.3 Events in, and per-connection ordering

`TamperView.js` forwards every control-channel push
(`stream-created`/`held`/`stream-terminated`) into the script via
`runtime.dispatch(name, conn, rawArgs)`. Each event is queued per-`conn` (FIFO); a
`pump(conn)` loop dispatches one at a time, only advancing once every handler for the
previous event (including any `ctx.pause()` suspension) has resolved. Different
connections run fully independently. If a hook is registered more than once, all
handlers run, awaited in registration order.

`onReceive` also builds `ctx` (§3.4): it `peek`s the buffer's current contents,
constructs the working copy, runs the registered handler(s), then auto-commits any
mutation the handler left uncommitted.

**Not guaranteed one dispatch per `held` notification.** TCP gives no guarantee how
incoming data is split into physical reads, so `pump()` coalesces consecutive
still-queued `onReceive` entries for the same `(conn, direction)` into one dispatch
rather than running redundant round trips against an already-drained buffer — this never
reorders anything relative to an interleaved other-direction/other-connection event.
Guarantee: at least one `onReceive` will eventually see the complete, not-yet-processed
buffer, just not necessarily one dispatch per notification. A script that wants to
suppress the occasional empty trailing dispatch can add `if (ctx.get().length === 0)
return` at the top of its handler.

### 2.4 Why `tamper.transform.*` doesn't use the RPC bridge

Every other `tamper.*` method is a network operation; running a Transform-panel
operation isn't — `transforms.js`'s operation registry is synchronous JavaScript with no
network dependency, so it runs directly inside the Worker. `scriptRuntime.js` splices
`transforms.js`'s real absolute URL into `BOOTSTRAP`, which dynamically imports it (a
relative import can't resolve from a Blob-URL worker) and flips a `ready` flag once
loaded and Whirlpool is warmed up. `pump()` won't dispatch anything until `ready`, so a
script's own hook handlers never observe the registry as unpopulated — every
`tamper.transform.*` call from inside a hook is genuinely synchronous. A call from the
script's own top level, before `ready`, gets a `Promise` instead.

### 2.5 `ctx`: a local working copy

`makeCtx(conn, direction, newLength, initial)` builds the object passed to `onReceive`:
a local `Uint8Array` copy of the buffer (`get()`/`set()`/`append()` never touch the
network) plus a `committedLength` staleness guard. `release(n)`/`drop(n)`/`pause()`
compute a `release`-command payload (`prefixLength: committedLength`, `bounds`/
`releaseChunks`), send it with the edited bytes as a following binary frame, then trim
the local copy — mirroring the wire protocol's own edit+release command
(`intercept/tamper/protocol.go`).

### 2.6 Pause / Continue

`ctx.pause()` commits any pending edit, then calls the `'pause'` RPC method, which
doesn't resolve immediately: it records a pending entry and notifies `TamperView`, which
jumps the UI to the Intercept sub-tab and swaps the toolbar to a single **Continue**
button (editing stays available). Clicking it commits any further edit and resolves the
pending `Promise` — control returns to the script, which typically re-`peek`s (done
automatically before `pause()` returns) and decides what to do next. If the connection
terminates while paused, the pending `Promise` is rejected immediately so the
per-connection queue can still advance.

### 2.7 Custom state across invocations

`ctx` is rebuilt from scratch on every `onReceive` dispatch — nothing attached to it
survives past that call. Since one script instance runs in one Worker for its whole
lifetime (until Stop/Restart, an error, or the control connection dropping), an ordinary
top-level JS closure survives across calls, with no framework support needed:

```js
const perStream = new Map()  // keyed by conn
tamper.register('onConnect', c => perStream.set(c.conn, { count: 0 }))
tamper.register('onReceive', ctx => { perStream.get(ctx.conn).count++ })
tamper.register('onClose', c => perStream.delete(c.conn))
```

This state is memory-only — gone on Stop/Restart/error/disconnect; `tamper.fs.*`/
`tamper.kv.*` (§3.3) are for anything that needs to survive that. `count` above counts `onReceive`
*dispatches*, not physical TCP reads (see §2.3's coalescing) — a lower bound on chunk
arrivals under load, not an exact count.

### 2.8 Error handling

A syntax error in the script's own source kills the Worker permanently — reported (with
a stack trace naming the actual failing file) and treated as an explicit `stop()`.
`BOOTSTRAP` always finishes initializing regardless of whether the script's
`importScripts()` call succeeds; a failure there is caught and reported as a `'fatal'`
message, which triggers the same `stop()`. An exception thrown inside a handler is
caught per-event without stopping the Worker — the queue just moves on. Losing the
control WebSocket connection also stops the running script.

### 2.9 Logging

`tamper.log(...)`/`ctx.log(...)` post to the main thread, which appends a line to the
in-browser log panel (capped at 500 lines) and, if the interceptor is configured with
`log-file`, forwards it over the control connection for server-side persistence —
independent of the "Skip browser log" checkbox, which only affects the in-memory copy.
`ctx.log` gets an automatic `[time] #conn src -> dst (direction)` prefix.

## 3. API Reference

### 3.1 Hooks

```js
tamper.register(name, handler)
tamper.register('onConnect', conn => tamper.log('connected', conn.src))
```

`name` is one of `'onConnect'`, `'onReceive'`, `'onFrame'`, `'onClose'` — anything else
reports an error and is ignored. A hook may be registered more than once; all handlers
run, awaited in registration order.

| Hook | Fires | Handler signature |
|---|---|---|
| `onConnect` | A new connection is established | `(conn) => ...` |
| `onReceive` | A chunk was newly held on an intercepted stream, either direction — only when no framer script is selected for this run (see §4) | `(ctx) => ...` |
| `onFrame` | A framer script resolved a complete frame — only when one *is* selected for this run (see §4); fires in place of `onReceive`, not alongside it | `(ctx, frame) => ...` |
| `onClose` | A connection terminated | `(conn) => ...` |

A script may register both `onReceive` and `onFrame` — whichever applies to a given run
is the one that actually fires, so the same script works whether or not a framer is
selected alongside it.

`conn` (for `onConnect`/`onClose`): `{ conn, src, dst }` — `conn` is the numeric
connection id (stable for the connection's lifetime, never reused within one proxy run),
`src`/`dst` are `"host:port"` strings. `onClose`'s `conn`/`src`/`dst` are recalled from
the matching `onConnect` if this script instance saw it; if the connection was already
open before the script started, only `{conn}` is available.

**A stream only ever reaches `onReceive` while it's in intercept mode** — new
connections start in watch mode (pass-through) unless `hold-until-connected`/
`auto-intercept` is set. Call `tamper.setIntercept(conn, true)` (typically from
`onConnect`) to switch a stream into intercept mode, or check the "Auto-intercept new
connections" toggle in the toolbar.

### 3.2 Low-level primitives

Available directly on `tamper` as an escape hatch — for use outside `onReceive`, or to
bypass `ctx`'s bookkeeping entirely. Direction is always `'c2s'`/`'s2c'`.

```js
tamper.peek(conn, direction)
// -> Promise<{ direction, time, offset, length, totalLength, bounds, data: Uint8Array }>
// Reads a direction's entire held buffer. Nothing held -> empty data, not an error.
const { data } = await tamper.peek(conn, 'c2s')

tamper.release(conn, direction, opts, editedBytes)
// -> Promise. opts: { action: 'forward'|'drop', releaseChunks, edited, prefixLength, bounds }
// edited: false -> release `releaseChunks` chunks as-is (prefixLength/bounds ignored).
// edited: true -> replace the first `prefixLength` bytes (a stale value is rejected)
// with `editedBytes`, described by `bounds`, then release. editedBytes required iff edited.
await tamper.release(conn, 'c2s', { action: 'forward', releaseChunks: 1 })

tamper.dropConnection(conn, direction)   // -> Promise. Terminates the connection outright.
await tamper.dropConnection(conn, 's2c')

tamper.setIntercept(conn, intercepting)  // -> Promise. Switches watch <-> intercept mode.
tamper.register('onConnect', c => tamper.setIntercept(c.conn, true))

tamper.listStreams()
// -> Promise<Array<{ conn, src, dst, intercepting, pending }>>
// pending: [{ direction, chunks, length }, ...] - 0-2 entries, one per direction held.
const streams = await tamper.listStreams()

tamper.log(...args)  // Prints to the Scripts sub-tab's log panel (§2.9).
tamper.log('handshake complete', conn.src)
```

Most scripts won't need `tamper.peek`/`tamper.release` directly — `ctx` (§3.4) wraps
them with a friendlier, buffer-local API for reacting inside `onReceive`.

### 3.3 Filesystem and key-value access

Both are usable from `framer.*`/`dissector.*` too (see those scripting APIs), with the
identical method shapes below — a script author doesn't need different syntax per
runtime.

**Filesystem.** Only usable if the server's `core.fs` service is configured (a separate
config section from `tamper` itself — not one of `tamper`'s own settings) — otherwise
every call rejects, mirroring the REST API's error response. Paths are always
slash-separated, relative to `core.fs`'s configured root directory; `''` refers to the
root itself.

```js
tamper.fs.listFiles(path)          // -> Promise<Array<{ name, dir, size }>>, one directory level
const files = await tamper.fs.listFiles('')

tamper.fs.readFile(path)           // -> Promise<Uint8Array>
const fixture = await tamper.fs.readFile('fixtures/payload.bin')

tamper.fs.writeFile(path, bytes)   // -> Promise<void>; creates or overwrites (+ parent dirs)
await tamper.fs.writeFile('out/last.bin', bytes)

tamper.fs.appendFile(path, bytes)  // -> Promise<void>; appends, creating the file if needed
await tamper.fs.appendFile('audit.log', new TextEncoder().encode('line\n'))
```

`appendFile` is a genuine server-side append (not read-modify-write) — safe to call
concurrently from different connections' independently-scheduled `onReceive` handlers
without losing data.

**Key-value store.** Only usable if the server's `core.kv` service is configured
(likewise a separate config section, its own SQLite file). Unlike `fs.*`, there's no
path/directory structure — just opaque string keys, useful for sharing a small value
across streams/scripts/interceptors (e.g. a crypto key derived on one connection, needed
to decrypt traffic on another).

```js
tamper.kv.write(key, value)   // -> Promise<void>; value is JSON-serialized
await tamper.kv.write('session-key', { alg: 'aes-256-gcm', key: hexKey })

tamper.kv.read(key)           // -> Promise; JSON-parses the stored value
const { key: hexKey } = await tamper.kv.read('session-key')

tamper.kv.writeBytes(key, bytes)  // -> Promise<void>; raw bytes, no JSON encoding
await tamper.kv.writeBytes('raw-blob', someBytes)

tamper.kv.readBytes(key)          // -> Promise<Uint8Array>
const blob = await tamper.kv.readBytes('raw-blob')

tamper.kv.list(prefix)        // -> Promise<string[]>; prefix optional, omitted = all keys
const keys = await tamper.kv.list('session-')

tamper.kv.delete(key)         // -> Promise<void>; idempotent, no error if already absent
await tamper.kv.delete('session-key')
```

`read`/`readBytes` reject (a thrown `Error`, same as every other call in this section)
if `key` doesn't exist — there's no "missing key" sentinel return value, so a script
reading an optional key should `try`/`catch` or `list` first to check.

### 3.4 `ctx` (passed to `onReceive`)

```js
ctx.conn        // number - the connection id
ctx.direction   // 'c2s' | 's2c'
ctx.newLength   // number - size of just the newly-arrived chunk that triggered this
                // dispatch (not ctx.get().length, the whole currently-held buffer)
tamper.register('onReceive', ctx => ctx.log(`#${ctx.conn} ${ctx.direction} +${ctx.newLength}B`))

ctx.get()                       // -> Uint8Array, a snapshot copy; local, no network
const bytes = ctx.get()

ctx.set(bytes, start?, end?)    // Python-slice-assignment style: buf[start:end] = bytes
                                 // (omitting both replaces the whole buffer)
ctx.set(new TextEncoder().encode('replaced'))

ctx.append(bytes)               // shorthand for ctx.set(bytes, buf.length, buf.length)
ctx.append(new Uint8Array([0x0a]))

await ctx.release(n?)   // release the first n bytes (default: everything held);
                         // any remainder stays held
await ctx.release()

await ctx.drop(n?)      // same, but discards instead of forwarding
await ctx.drop()

await ctx.pause()       // commit any pending edit, then suspend until Continue (§2.6);
                         // re-peeks before returning
await ctx.pause(); await ctx.release()

ctx.log(...args)   // like tamper.log, auto-prefixed with a connection/time summary
ctx.log('suspicious payload')
```

**`release`/`drop`/`pause` must be `await`ed** — nothing auto-serializes them, so an
un-awaited `ctx.pause()` immediately followed by `ctx.release()` races. `release`/`drop`
are always prefix-based (the first *N* bytes), never an arbitrary interior range,
matching the backend's own constraint.

If a handler mutates the buffer (`set`/`append`) but returns without calling an
explicit `release`/`drop`/`pause`, the framework auto-commits the remainder as an
edit-only hold — an oversight never silently drops data.

### 3.5 `tamper.transform.*`

Exposes every implemented Transform-panel operation, synchronous from inside a hook
(§2.4) — one flat function per operation, grouped by category:

```js
tamper.transform.<category>.<function>(bytes, params)  // -> Uint8Array
const digest = tamper.transform.hash.sha256(bytes)
const cipher = tamper.transform.encryption.aesEncrypt(bytes, { mode: 'ctr', key, iv })
```

| Category | Example functions |
|---|---|
| `basic` | `hexEncode`, `hexDecode`, `base64Encode`, `base64Decode`, `octalEncode`, `basenEncode`, ... |
| `numeric` | `encnumI32le`, `decnumU64be`, ... (14 fixed-width integer types, big/little endian) |
| `compression` | `gzipCompress`, `gzipDecompress`, `deflateCompress`, `zipCompress`, `zipDecompress`, ... |
| `checksum` | `crc16`, `crc32`, `adler32` |
| `encryption` | `aesEncrypt`, `aesDecrypt`, `desEncrypt`, `tripleDesEncrypt`, `rc4Encrypt`, `chacha20Encrypt`, `xorCrypt`, ... |
| `mac` | `hmacSha256`, `hmacMd5`, ... |
| `hash` | `md5`, `sha1`, `sha256`, `sha512`, `whirlpool`, `ntlm`, ... |

Function names are a mechanical camelCase of the underlying operation id (e.g.
`hmac-sha256` → `hmacSha256`), with two exceptions: `3des-encrypt`/`3des-decrypt` become
`tripleDesEncrypt`/`tripleDesDecrypt` (`3desEncrypt` isn't a valid property name), and
`xor-encrypt`/`xor-decrypt` — a repeating-key XOR is its own inverse — both collapse to a
single `xorCrypt`. `params` is passed straight through to the operation — the same shape
the Transform panel's UI itself builds; see the root `CLAUDE.md`'s "Transform panel"
section for every operation's exact `params` (e.g. `{mode, key, iv, aad}` for a cipher,
`{prefix, separator}` for `hexEncode`).

A call made *before* the script has finished its own startup returns a
`Promise<Uint8Array>` instead of a plain `Uint8Array`; from inside any registered hook,
it's always the latter. `await` works either way.

### 3.6 `tamper.encode.*` / `tamper.decode.*`

A smaller convenience layer, separate from `tamper.transform.*`, for turning a buffer
into a loggable/matchable string and back:

```js
tamper.encode.hex(bytes, params)          // -> string;  params: {prefix, separator}, both default ''
tamper.encode.hex(new Uint8Array([0xde, 0xad]))  // 'dead'

tamper.encode.base64(bytes, params)       // -> string;  params: {urlSafe}, default false
tamper.encode.base64(bytes)

tamper.encode.hexdump(bytes, baseOffset)  // -> string (xxd-style); baseOffset default 0
tamper.log(tamper.encode.hexdump(bytes))

tamper.decode.hex(text, params)     // -> Uint8Array; same params as tamper.encode.hex
tamper.decode.base64(text, params)  // -> Uint8Array; same params as tamper.encode.base64
tamper.decode.hexdump(text)         // -> Uint8Array
```

Unlike `tamper.transform.*`, `hex`/`base64` return a plain string, not `Uint8Array`, so
they aren't chainable pipeline steps; `hexdump` has no Transform-panel equivalent at
all. Same synchronous-after-startup behavior as `tamper.transform.*` (§3.5).

## 4. Framer scripts

### 4.1 What a framer script does

A framer script reassembles a stream's raw chunks into logical frames — an HTTP/1
message, a length-prefixed record, a TLS record — so an interception script can react to
whole units via `onFrame` instead of reimplementing that reassembly itself inside
`onReceive`. It's a second, separately-authored and separately-stored script, run
composed with (wrapping) whichever interception script is actually driving
forward/edit/drop decisions — not a replacement for one.

This mirrors dbdump's own framer feature (Analysis tab, "Framer" control) closely enough
that a script can often be copied between the two with little or no change, but the two
are otherwise unrelated: dbdump's framer is a read-only, offline analysis aid over
already-captured, immutable bytes; a tamper framer script operates on live, in-flight,
editable traffic, and has its own separate script store (`GET`/`PUT`/`DELETE
/api/i/tamper/framer/scripts/<name>` — the "Framer Scripts" sub-tab's CRUD editor, not
the "Scripts" sub-tab used for interception scripts). See
[`doc/design/tamper-framer.md`](../design/tamper-framer.md) for the full design rationale.

### 4.2 Selecting a framer alongside an interception script

The Scripts sub-tab's toolbar has a **framer** dropdown next to **Run**/**Stop** —
`(none)` (the default; `onReceive` fires as normal) or one of the scripts stored in the
Framer Scripts sub-tab. The dropdown is disabled while a script is running: composition
is fixed for the run's whole lifetime, same as the interception script itself — **Stop**
first to pick a different framer (or none).

### 4.3 The `frame(state, chunk)` contract

A framer script defines one top-level function, looked up by name (no registration
call, unlike `tamper.register`):

```js
function frame(state, chunk) {
    // chunk: { direction, data: Uint8Array, closed? }
    // returns { frames: [{ length, meta? }, ...], state } — or nothing, meaning
    // "no new frames, state unchanged"
}
```

- **Combined mode**: one script instance/`state` per connection, fed both directions'
  chunks — `direction` (`'c2s'`/`'s2c'`) varies call to call. A script correlating the
  two directions (e.g. an HTTP/1 response's length depending on its request's method)
  keeps its own per-direction sub-state inside the one shared `state`
  (`state.c2s`/`state.s2c`), the same pattern this codebase's example dbdump framers use.
- **`chunk.data` is only the genuinely new bytes** since `frame()` was last called for
  this direction — never the whole accumulated buffer. Carrying forward an incomplete
  tail across calls is the script's own job via `state`, exactly like dbdump's framer
  scripts already do (a `carry` byte array kept in `state`, prepended to `chunk.data` at
  the top of the next call).
- **One call may resolve several frames at once** — `frames` is an array precisely so a
  script's own internal loop (draining its buffered state as far as it currently can)
  doesn't need the platform to call `frame()` again just to find a second already-decided
  frame. Each entry `{length, meta?}` consumes exactly that many bytes from the front of
  whatever's currently buffered (starting right after the previous entry's own bytes) —
  unlike dbdump's framer, there's no `offset` field, since nothing is persisted to
  address by absolute offset.
- **The framer only ever sees original incoming bytes** — an interception script's edit
  to a frame doesn't feed back into the framer's own decisions for the next one. If an
  edit changes something framing depends on (e.g. rewriting a length-prefix field),
  keeping downstream framing consistent is the interception script's own responsibility.
- `chunk.closed = true` (with empty `data`) is the last call for a direction, once that
  direction's connection has closed — see §4.5.

### 4.4 `onFrame(ctx, frame)`

Fires once per frame a selected framer script resolves, in place of `onReceive` (§3.1).
`ctx` is the *same* object shape `onReceive` gets (§3.4) — `get`/`set`/`append`/
`release`/`drop`/`pause`/`log` — scoped to just this one frame's bytes rather than the
whole held buffer; `release(n)`/`drop(n)`'s prefix-based semantics apply to the frame,
not the connection's raw stream.

```js
tamper.register('onFrame', async (ctx, frame) => {
    // frame: { direction, data: Uint8Array, meta, final }
    tamper.log(frame.direction, frame.meta, ctx.get().length, 'bytes')
    await ctx.release()  // forward this frame's bytes unedited
})
```

`frame.meta` is whatever the framer script's own `{length, meta}` entry carried —
opaque, script-defined (e.g. decoded header fields), `null` if the framer didn't set one.
`frame.final` is `true` only for a frame produced during close handling (§4.5); `false`
for every normal, live frame.

Same auto-commit rule as `onReceive` (§3.4): a handler that mutates `ctx` but returns
without an explicit `release`/`drop`/`pause` has that mutation auto-committed as an
edit-only hold. If a framer is selected but the interception script registers no
`onFrame` handler at all — or a handler runs but never touches `ctx` — there's nothing
to auto-commit, so the frame simply stays held (same as an `onReceive` with no
registered handler) until the hold-timeout releases it.

### 4.5 Connection close and the synthetic final frame

Once a direction's connection closes, its framer gets one last `frame(state, {direction,
data: new Uint8Array(0), closed: true})` call — empty `data`, since by this point the
framer's own `state` already has everything it needs (mirrors dbdump's identical
convention) — to flush anything whose length was implicit in the connection closing
(e.g. an HTTP/1 response with neither `Content-Length` nor chunked encoding).

Whatever bytes that call still doesn't resolve into a frame are exposed to the
interception script as **one final synthetic frame** — `meta: null`, `final: true` —
rather than silently bypassing `onFrame`. Every frame produced during close handling
(both what the `closed: true` call itself resolves, and this synthetic leftover) has
`final: true`; there's no live server-side buffer left to act on by this point, so
`ctx.release()`/`drop()`/`pause()` on a close-triggered frame are safe no-ops (they
never throw) — `get()`/`set()`/`append()`/`log()` all still behave normally, purely
locally.

### 4.6 `framer.*`

The framer script's own global, parallel to `tamper.*` (§3.2/§3.5/§3.6) but scoped to
what a pure reassembly function needs — no `register`/`peek`/`release`/live-connection
primitives, since a framer script has no hooks and no direct network access of its own:

```js
framer.transform.<category>.<function>(bytes, params)  // same as tamper.transform.*, §3.5
framer.encode.*  / framer.decode.*                      // same as tamper.encode.*/decode.*, §3.6
framer.number.decode<Type>(bytes) / encode<Type>(value)  // real numbers/bigints, not decimal text
framer.fs.*  / framer.kv.*                                // same as tamper.fs.*/kv.*, §3.3
framer.log(...args)                                        // prints to the same Scripts sub-tab
                                                             // log panel as tamper.log/ctx.log,
                                                             // prefixed [framer] to tell them apart
```

## 5. Examples

### 5.1 Pass-through digest logger

The bundled starter script (`examples/tamper/scripts/hash-logger.js`, `scripts-dir` in
this repo's `config.json`): logs a SHA256 digest of every chunk in either direction,
then forwards it unmodified. A good template for "instrument, don't intercept" scripts:

```js
tamper.register('onConnect', (conn) => {
    tamper.log(`[connect] #${conn.conn} ${conn.src} -> ${conn.dst}`)
    tamper.setIntercept(conn.conn, true)
})

tamper.register('onClose', (conn) => {
    tamper.log(`[close] #${conn.conn} ${conn.src} -> ${conn.dst}`)
})

tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    if (bytes.length === 0) return
    const sha256Hex = tamper.encode.hex(tamper.transform.hash.sha256(bytes))
    ctx.log(`(${ctx.direction}) SHA256(<data> ${bytes.length} bytes): ${sha256Hex}`)
    await ctx.release(bytes.length)
})
```

The `bytes.length === 0` guard matters under load: per §2.3's `onReceive` coalescing, a
trailing dispatch can find the buffer already drained by an earlier one — without the
guard you'd see occasional harmless but noisy `SHA256(<data> 0 bytes): e3b0c442...` lines.

### 5.2 Find-and-replace on the fly

Rewrites an HTTP response header on the way back to the client:

```js
tamper.register('onConnect', c => tamper.setIntercept(c.conn, true))

tamper.register('onReceive', async (ctx) => {
    if (ctx.direction !== 's2c') { await ctx.release(); return } // only touch responses
    const text = new TextDecoder().decode(ctx.get())
    const patched = text.replace(/Server: nginx/i, 'Server: tlstap')
    if (patched !== text) ctx.set(new TextEncoder().encode(patched))
    await ctx.release()
})
```

### 5.3 Pause client requests for manual review

Holds every client→server chunk, logs a preview, then hands off to an operator via
`ctx.pause()`:

```js
tamper.register('onConnect', c => tamper.setIntercept(c.conn, true))

tamper.register('onReceive', async (ctx) => {
    if (ctx.direction !== 'c2s') { await ctx.release(); return }
    const preview = new TextDecoder('utf-8', { fatal: false }).decode(ctx.get().slice(0, 64))
    ctx.log(`review needed: ${JSON.stringify(preview)}`)
    await ctx.pause()          // suspends until Continue
    await ctx.release()        // forwards the current buffer
})
```

### 5.4 Durable per-session audit log

Appends a one-line summary of every chunk to a file under `core.fs`'s configured root,
demonstrating state
that survives a script Stop/Restart (unlike the in-memory `Map` pattern in §2.7):

```js
tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    const line = `${new Date().toISOString()} #${ctx.conn} (${ctx.direction}) ${bytes.length} bytes\n`
    await tamper.fs.appendFile('audit.log', new TextEncoder().encode(line))
    await ctx.release()
})
```

### 5.5 Transparent gzip inspection

Auto-decompresses a gzip-framed response body for logging, without altering what's
actually forwarded:

```js
tamper.register('onConnect', c => tamper.setIntercept(c.conn, true))

tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    if (ctx.direction === 's2c' && bytes[0] === 0x1f && bytes[1] === 0x8b) { // gzip magic
        try {
            const plain = tamper.transform.compression.gzipDecompress(bytes)
            ctx.log(`decompressed (${bytes.length} -> ${plain.length} bytes): ` +
                new TextDecoder('utf-8', { fatal: false }).decode(plain))
        } catch (err) {
            ctx.log(`gzip decompress failed: ${err.message}`)
        }
    }
    await ctx.release()
})
```

### 5.6 Sharing a derived key across connections via `kv`

Stashes a value derived on one connection (e.g. a session key parsed out of a handshake)
in `core.kv` under a key namespaced by the client's address, so a *different*
connection — potentially handled by a different interceptor, script, or even the
`framer`/`dissector` scripting APIs — can look it up later:

```js
tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    if (ctx.direction === 'c2s' && looksLikeHandshake(bytes)) {
        const derivedKey = deriveKeyFrom(bytes) // however this connection's protocol works
        await tamper.kv.write(`session-key:${ctx.conn}`, { key: [...derivedKey] })
    }
    await ctx.release()
})

tamper.register('onClose', async (c) => {
    await tamper.kv.delete(`session-key:${c.conn}`) // don't leak state past the connection
})
```
