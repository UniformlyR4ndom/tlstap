# Tamper Scripting API

The `tamper` interceptor's "Scripts" sub-tab lets you write a JavaScript program that
reacts to live traffic programmatically - the automated equivalent of a operator clicking
around the "Intercept" sub-tab (`TamperQueueList`/`TamperDetailPanel`) to hold, inspect,
edit, drop, or forward chunks. This document covers that scripting API: what it is, how
it's implemented, its full function reference, and worked examples.

For the wire-level control/watch WebSocket protocol the scripting runtime itself is built
on top of, see [`intercept/tamper/CLAUDE.md`](../../intercept/tamper/CLAUDE.md). For how
this fits into the rest of the web frontend (the Tamper tab's layout, the manual
Intercept sub-tab, the Transform panel whose operations `tamper.transform.*` exposes),
see the root [`CLAUDE.md`](../../CLAUDE.md)'s "Web Frontend" section.

## 1. Overview

A script is plain JavaScript, stored server-side as a named `.js` file (`GET`/`PUT`/
`DELETE /api/i/tamper/scripts/<name>`) and edited in-browser via the Scripts sub-tab's
CodeMirror editor. Clicking **Run** starts it; only one script instance runs at a time
per browser tab - starting a new one, or navigating away and back, stops whatever was
running before. **Nothing on the Go side ever executes a script** - `intercept/tamper/
scripts.go` is a flat name→text-blob store with no opinion about what the content means.
All of the logic below (the Worker, the event dispatch, the `tamper`/`ctx` API surface)
lives entirely in the browser.

A running script:
- Registers handlers for three connection-lifecycle events (`onConnect`, `onReceive`,
  `onClose`) - the same events a operator control client implicitly reacts to by watching
  the Streams/Held-buffers lists.
- Decides, per held chunk, whether to forward it (unmodified or edited), drop it, or
  pause and hand the decision to an operator - imperatively, from code, rather than by
  clicking. A handler doesn't have to decide synchronously either: it can hold a chunk
  and act on it later, exactly like an operator leaving something in the queue.
- Can call any Transform-panel operation (hashing, encoding, compression, encryption,
  checksums, MAC) directly on the bytes it's looking at.
- Can read/write a small scoped area of the host filesystem, for fixtures or for
  persisting state across runs (a script's own JS state is memory-only - see
  ["Custom state across invocations"](#27-custom-state-across-invocations) below).
- Can log output, visible in-browser and optionally persisted server-side.

**Why scripting is useful:** the manual Intercept UI is for one-off inspection and
editing; a script is for anything you'd otherwise do by hand, repeatedly, on every
matching chunk - instrumenting traffic with digests, auto-decompressing/decrypting
payloads for display, rewriting specific fields, injecting fault conditions, or driving a
protocol fuzzer. See ["Examples"](#4-examples) below for concrete cases.

**Trust model:** a script runs with the same privileges as any other code on the page -
there's no sandboxing beyond the Worker boundary itself (no DOM/page access, but full
access to whatever traffic tlstap is proxying while the script runs). Only run scripts
you wrote or trust, the same caution you'd apply to any browser extension or userscript.

## 2. Architecture

### 2.1 Where a script runs

`scriptRuntime.js`'s `createScriptRuntime()` manages one Web Worker at a time. `start(name,
source)` builds **two separate Blobs**, not one concatenated file: one for the bootstrap
template (`BOOTSTRAP`), one for the script's own text (wrapped in its own IIFE, so its
top-level `const`/`function` declarations can't collide with the runtime's own). `BOOTSTRAP`'s
Blob is the Worker's actual entry point (`new Worker(bootstrapBlobUrl)`); after wiring up
`self.tamper`/`self.onmessage`/the error listeners, it synchronously `importScripts()`s the
script's Blob into that same global scope. `importScripts`, unlike an ES module import, runs
the imported code in the *same* scope as the caller rather than a separate module namespace -
the script still sees the bare `tamper` global exactly as if everything were one file; nothing
about how you write a script changes because of this split.

Each Blob ends with its own `//# sourceURL=...` magic comment - `BOOTSTRAP`'s as
`tamper-bootstrap.js`, the script's as its own name (sanitized to end in `.js`) - so
DevTools/stack traces show a real, correctly-line-numbered file name for whichever side
actually failed, instead of one opaque `blob:http://.../<uuid>` URL covering both. See §2.8 for
why this split (rather than one Blob) matters for error handling, not just naming.

It's a classic (non-module) Worker, not `{type: 'module'}` - this matters both for how
`tamper.transform.*` is wired (§2.4) and because `importScripts()` itself is only available
in classic Workers to begin with.

### 2.2 The `tamper` object and the RPC bridge

`BOOTSTRAP` defines `self.tamper` synchronously, before anything else, so it's available
immediately once the script's own code starts running. Most of its methods
(`peek`/`release`/`dropConnection`/`setIntercept`/`listStreams`, and all of `fs.*`) are
thin wrappers around a `postMessage`-based RPC: the Worker has no way to reach the
network directly (no page origin to resolve a relative `fetch()` against from a Blob-URL
worker), so a call posts `{kind:'call', id, method, args}` to the main thread, which
performs the real operation - via handlers passed into `createScriptRuntime` by
`TamperView.js`, each mirroring a `tamperApi.js` wrapper - and posts back `{kind:'result',
id, value}` or `{kind:'result', id, error}`. The Worker resolves/rejects a `Map`-tracked
`Promise` per call `id`. `fs.*`'s underlying transport is a plain REST `fetch` rather than
the control WebSocket, but it's routed through the same bridge for the same reason
(no direct network access from inside the Worker).

Direction is `'c2s'`/`'s2c'` everywhere in this API; translation to/from the wire
protocol's numeric `0`/`1` happens only at this bridge (`dirToStr`/`dirFromStr`).

### 2.3 Events in, and per-connection ordering

`TamperView.js` forwards every relevant control-channel push
(`stream-created`/`held`/`stream-terminated`) into the running script via
`runtime.dispatch(name, conn, rawArgs)`, which posts `{kind:'event', conn, name, args}`.
Inside the Worker, each event is pushed onto a **per-`conn` FIFO queue**; a `pump(conn)`
loop drains it strictly one event at a time - the next event for that connection only
dispatches once every handler registered for the previous one (including any suspension
inside a `ctx.pause()`) has fully resolved. **Different connections run fully
independently** and can interleave freely. If a hook is registered more than once, all of
its handlers run, awaited in registration order.

`onReceive` specifically also does the work of building `ctx` (§3.4): it `peek`s the
buffer's current full contents, constructs the working copy, runs the registered
`onReceive` handler(s), then - if the handler mutated the buffer but never called an
explicit `release`/`drop`/`pause` - auto-commits the remainder as an edit-only hold, so
nothing is silently lost.

**`onReceive` isn't guaranteed one dispatch per `held` notification.** A `held` push only
ever means "go look at the buffer again" - and TCP itself gives no guarantee about how
incoming data gets split into physical reads in the first place, so there's nothing
meaningful tied to any one notification individually, only to whatever `ctx.get()`
actually observes. `pump()` coalesces **consecutive still-queued** `onReceive` entries for
the same `(conn, direction)` into a single dispatch instead of running them one after
another: once the Go side (appending is near-instant) outpaces how fast a dispatch can
round-trip (peek, decide, release), several notifications routinely queue up for the same
direction before the first one even starts - without coalescing, only that first dispatch
finds anything to do, and every one behind it is a redundant round trip that finds an
already-drained, empty buffer. Coalescing merges those trailing round trips into one; it
never reorders anything relative to an interleaved other-direction/other-connection event,
since only entries adjacent in the same per-connection queue, for the same direction, are
ever merged. The guarantee this leaves you with: **at least one `onReceive` will
eventually see the complete, not-yet-processed buffer** - just not necessarily one
dispatch per notification. In practice this reduces empty dispatches rather than
eliminating them outright (the very first notification of a fresh burst can't be
pre-merged with anything not yet queued, and typically drains everything itself before the
next, merged dispatch runs) - a script that wants to suppress the remainder entirely can
add `if (ctx.get().length === 0) return` at the top of its handler.

### 2.4 Why `tamper.transform.*` doesn't use the RPC bridge

Every other `tamper.*` method is a genuine network operation (it either has to go over
the control WebSocket or hit a REST endpoint), so RPC to the main thread is required.
Running a Transform-panel operation isn't - `transforms.js`'s whole operation registry
(`OPERATIONS`, covering Basic/Numeric/Compression/Checksum/Encryption/MAC/Hash) is plain,
synchronous JavaScript with no network dependency, so it makes more sense to run it
directly inside the Worker.

The obstacle was that a classic Worker loaded from a Blob URL can't resolve *relative*
`import`s (it has no meaningful base URL of its own) - but it *can* resolve an absolute
one. `scriptRuntime.js` computes `transforms.js`'s real absolute URL on the main thread
(`new URL('./transforms.js', import.meta.url).href`) and splices it into `BOOTSTRAP`. A
trailing `async` IIFE at the end of `BOOTSTRAP` - appended only after `self.tamper`,
`self.onmessage`, and the error listeners are already wired up synchronously, so nothing
is missed while this is in flight - does:

```js
const mod = await import(TRANSFORMS_URL)   // resolves transforms.js's own relative
await mod.warmupWhirlpool()                // imports into transforms/*, vendor/* correctly
OPERATIONS = mod.OPERATIONS
ready = true
// flush any events that queued while this was loading
```

`pump()` refuses to dispatch anything until `ready` is `true`, so **a script's own hook
handlers never observe `OPERATIONS` as unpopulated** - by the time any `onConnect`/
`onReceive`/`onClose` handler runs, the transform registry is guaranteed loaded, so every
`tamper.transform.*` call made from inside one is genuinely synchronous, no `await`
needed. (`callTransform()`'s internal `ready` check exists only for the unusual case of
calling a transform function at the script's own top level, before any event has been
dispatched - that gets a `Promise` instead of a crash, `await`-compatible like the rest
of this API.) Every op in `OPERATIONS` really is synchronous, including compression
(`fflate`'s sync functions) and Whirlpool (a `hash-wasm` hasher, pre-warmed by the
`warmupWhirlpool()` call above) - see `transforms/compression.js` and
`transforms/hash.js`'s header comments for how each got there.

### 2.5 `ctx`: a local working copy

`makeCtx(conn, direction, newLength, initial)` builds the object passed to `onReceive`.
It holds a local `Uint8Array` copy of the buffer (`get()`/`set()`/`append()` never touch
the network) plus a `committedLength` bookkeeping value used to detect staleness. Calling
`release(n)`/`drop(n)`/`pause()` computes a `release`-command payload - `prefixLength:
committedLength` (a staleness guard: the server rejects it if the buffer's actual length
has moved since, e.g. a hold-timeout flushed it) and `bounds`/`releaseChunks` describing
the edit - sends it (with the edited bytes as a following binary frame), then trims the
local copy to whatever's left. This mirrors the wire protocol's own edit+release command
directly (see `intercept/tamper/protocol.go`).

### 2.6 Pause / Continue

`ctx.pause()` first commits any pending local edit (so the operator sees it), then calls the
`'pause'` RPC method. Unlike every other call, the main-thread side of this one doesn't
resolve immediately: it records a pending entry (keyed by `conn`) and notifies
`TamperView`, which jumps the UI to the Intercept sub-tab, selects the paused entry, and
swaps `TamperDetailPanel`'s toolbar to a single **Continue** button (editing stays
available while paused). Clicking it commits whatever the operator edited, then resolves the
pending `Promise` - control returns to the *script*, which typically re-`peek`s
(`ctx.pause()` does this automatically before returning) to see the operator's changes and
decide what to do next, e.g. `ctx.release()`. If the connection terminates while a script
is suspended in `ctx.pause()`, the pending `Promise` is rejected immediately instead
(`rejectPause`), so the per-connection event queue can still advance even though nobody
clicked Continue.

### 2.7 Custom state across invocations

`ctx` is rebuilt from scratch on every `onReceive` dispatch - nothing you attach to it
survives past that one call. Since one script instance runs in one Worker for its whole
lifetime (until Stop/Restart, an error, or the control connection dropping), an ordinary
top-level JS closure *does* survive across calls, with no framework support needed:

```js
const perStream = new Map()  // keyed by conn - this is "per-stream" storage
tamper.register('onConnect', c => perStream.set(c.conn, { count: 0 }))
tamper.register('onReceive', ctx => { perStream.get(ctx.conn).count++ })
tamper.register('onClose', c => perStream.delete(c.conn))
```

This state is memory-only - gone on Stop/Restart/error/disconnect. `tamper.fs.*` (§3.3)
is what you'd use for anything that needs to survive that.

Note `count` above counts `onReceive` *dispatches*, not physical TCP reads - per §2.3,
consecutive still-queued notifications for the same `(conn, direction)` can be coalesced
into one dispatch, so this is a lower bound on chunk arrivals under load, not an exact
count of them.

### 2.8 Error handling

A syntax error in the script's own source kills the Worker permanently - reported (with a
full stack trace naming the actual failing file, per §2.1) and treated as an explicit
`stop()`. Since `BOOTSTRAP` and the script are two separate Blobs (§2.1), `BOOTSTRAP` always
finishes initializing `self.tamper`/`self.onmessage`/its own error listeners regardless of
whether the script's `importScripts()` call succeeds; that call is wrapped in its own
`try`/`catch`, and a failure there is reported as a `'fatal'` message, which
`createScriptRuntime` turns into the same `stop()` the old single-Blob design got
incidentally from `worker.onerror` (back when a script syntax error meant the *whole*
concatenated file failed to parse, so `BOOTSTRAP` itself never ran either). An exception
thrown *inside* a registered handler is still just caught per-event (inside `pump()`'s loop)
and reported to the log panel with `level: 'error'`, but the Worker keeps running - the
queue just moves on to the next event. Losing the control WebSocket connection stops the
running script outright.

### 2.9 Logging

`tamper.log(...)` and `ctx.log(...)` both post a message to the main thread, which
appends a line to the in-browser log panel (capped at the last 500 lines) and - if the
interceptor was configured with `log-file` - also forwards it over the control connection
for server-side persistence, independent of the panel's "Skip browser log" checkbox
(which only affects the in-memory copy, for scripts that log a lot). `ctx.log` gets an
automatic `[time] #conn src -> dst (direction)` prefix built on the main thread (from a
small `conn -> {src, dst}` cache populated on `onConnect`), since the underlying message
only carries `conn`/`direction`/`time`, not a ready-made string.

## 3. API Reference

### 3.1 Hooks

```js
tamper.register(name, handler)
```

`name` is one of `'onConnect'`, `'onReceive'`, `'onClose'` - anything else reports an
error and is ignored. A hook may be registered more than once; all of its handlers run,
awaited in registration order.

| Hook | Fires | Handler signature |
|---|---|---|
| `onConnect` | A new connection is established | `(conn) => ...` |
| `onReceive` | A chunk was newly held on an intercepted stream, either direction | `(ctx) => ...` |
| `onClose` | A connection terminated | `(conn) => ...` |

`conn` (for `onConnect`/`onClose`): `{ conn, src, dst }` - `conn` is the numeric
connection id (stable for the connection's lifetime, never reused within one proxy run),
`src`/`dst` are `"host:port"` strings. `onClose`'s `conn`/`src`/`dst` are recalled from
the matching `onConnect` if this script instance saw it; if the connection was already
open before the script started, only `{conn}` is available.

**A stream only ever reaches `onReceive` while it's in intercept mode** - new connections
start in watch mode (pass-through, nothing to act on) unless `hold-until-connected`/
`auto-intercept` is set. Call `tamper.setIntercept(conn, true)` (typically from
`onConnect`) to switch a stream into intercept mode, or check the "Auto-intercept new
connections" toggle in the toolbar.

### 3.2 Low-level primitives

Available directly on `tamper` as an escape hatch - for use outside `onReceive`, or when
you want to bypass `ctx`'s bookkeeping entirely. Direction is always `'c2s'`/`'s2c'`.

```js
tamper.peek(conn, direction)
// -> Promise<{ direction, time, offset, length, totalLength, bounds, data: Uint8Array }>
// Reads a direction's entire currently-held buffer. totalLength/bounds always describe
// the whole buffer; data/offset/length describe what was actually returned (the whole
// thing, here). A direction with nothing held resolves with an empty data array, not an
// error.

tamper.release(conn, direction, opts, editedBytes)
// -> Promise
// opts: { action: 'forward' | 'drop', releaseChunks, edited, prefixLength, bounds }
// Combines an optional edit with a release in one call, mirroring the wire protocol's
// own combined command:
//  - edited: false -> release `releaseChunks` chunks of the buffer exactly as they
//    stand (prefixLength/bounds ignored).
//  - edited: true -> replace the buffer's first `prefixLength` bytes (as you last knew
//    them - a stale value is rejected) with `editedBytes`, described by `bounds`
//    (chunk-boundary offsets into the replacement), then release. editedBytes is
//    required whenever opts.edited is true.

tamper.dropConnection(conn, direction)
// -> Promise. Terminates the connection outright (not parameterized by buffer content).

tamper.setIntercept(conn, intercepting)
// -> Promise. Switches a stream between watch and intercept mode; the resolved value is
// just a command acknowledgement, not meaningful to inspect.

tamper.listStreams()
// -> Promise<Array<{ conn, src, dst, intercepting, pending }>>
// pending: [{ direction, chunks, length }, ...] - 0-2 entries, one per direction with
// something currently held.

tamper.log(...args)
// No return value. Prints to the Scripts sub-tab's log panel (see §2.9).
```

Most scripts won't need `tamper.peek`/`tamper.release` directly - `ctx` (§3.4) wraps them
with a friendlier, buffer-local API for the common case of reacting inside `onReceive`.

### 3.3 Filesystem access

Only usable if the interceptor was configured with `fs-root` - otherwise every call
rejects (mirroring the REST API's `501`). Paths are always slash-separated, relative to
`fs-root`; `''` refers to the root itself.

```js
tamper.fs.listFiles(path)          // -> Promise<Array<{ name, dir, size }>>, one directory level
tamper.fs.readFile(path)           // -> Promise<Uint8Array>
tamper.fs.writeFile(path, bytes)   // -> Promise<void>; creates or overwrites (+ parent dirs)
tamper.fs.appendFile(path, bytes)  // -> Promise<void>; appends, creating the file if needed
```

`appendFile` is a genuine server-side append (not read-modify-write) - safe to call
concurrently from different connections' independently-scheduled `onReceive` handlers
without losing data, which a client-side read+concatenate+write would not be.

### 3.4 `ctx` (passed to `onReceive`)

```js
ctx.conn        // number - the connection id
ctx.direction   // 'c2s' | 's2c'
ctx.newLength   // number - length of just the newly-arrived chunk that triggered this
                // dispatch (NOT the same as ctx.get().length, which is the whole
                // currently-held buffer, including anything held from earlier chunks)

ctx.get()                       // -> Uint8Array, a snapshot copy; local, no network
ctx.set(bytes, start?, end?)    // Python-slice-assignment style: buf[start:end] = bytes
                                 // (defaults: start=0, end=buf.length - i.e. omitting
                                 // both replaces the whole buffer)
ctx.append(bytes)               // shorthand for ctx.set(bytes, buf.length, buf.length)

await ctx.release(n?)   // release the first n bytes (default: everything currently held);
                         // any remainder stays held
await ctx.drop(n?)      // same, but discards instead of forwarding
await ctx.pause()       // commit any pending edit, then suspend until a operator clicks
                         // Continue (see §2.6); re-peeks before returning

ctx.log(...args)   // like tamper.log, auto-prefixed with a connection/time summary
```

**`release`/`drop`/`pause` must be `await`ed** - nothing here auto-serializes them, so an
un-awaited `ctx.pause()` immediately followed by `ctx.release()` races (the release could
complete before the pause's suspend logic even runs). `release`/`drop` are always
prefix-based (the first *N* bytes), never an arbitrary interior range, matching the
backend's own constraint.

If a handler mutates the buffer (`set`/`append`) but returns without calling an explicit
`release`/`drop`/`pause`, the framework auto-commits the remainder as an edit-only hold -
so an oversight never silently drops data, it just leaves the (possibly edited) buffer
held for next time.

### 3.5 `tamper.transform.*`

Exposes every implemented Transform-panel operation, synchronous from inside a hook (see
§2.4) - one flat function per operation, grouped by category:

```js
tamper.transform.<category>.<function>(bytes, params)  // -> Uint8Array
```

| Category | Example functions |
|---|---|
| `basic` | `hexEncode`, `hexDecode`, `base64Encode`, `base64Decode`, `octalEncode`, `basenEncode`, ... |
| `numeric` | `encnumI32le`, `decnumU64be`, ... (14 fixed-width integer types, big/little endian) |
| `compression` | `gzipCompress`, `gzipDecompress`, `deflateCompress`, `zipCompress`, `zipDecompress`, ... |
| `checksum` | `crc16`, `crc32`, `adler32` |
| `encryption` | `aesEncrypt`, `aesDecrypt`, `desEncrypt`, `tripleDesEncrypt`, `rc4Encrypt`, `chacha20Encrypt`, `xorEncrypt`, ... |
| `mac` | `hmacSha256`, `hmacMd5`, ... |
| `hash` | `md5`, `sha1`, `sha256`, `sha512`, `whirlpool`, `ntlm`, ... |

Function names are a mechanical camelCase of the underlying operation id (e.g.
`hmac-sha256` → `hmacSha256`), with one exception: `3des-encrypt`/`3des-decrypt` become
`tripleDesEncrypt`/`tripleDesDecrypt` (`3desEncrypt` isn't a valid property name). `params`
is passed straight through to the operation - the same shape the Transform panel's UI
itself builds; see the root `CLAUDE.md`'s "Transform panel" section for every operation's
exact `params` (e.g. `{mode, key, iv, aad}` for a cipher, `{prefix, separator}` for
`hexEncode`) - this document doesn't duplicate that full catalog.

A call made *before* the script has finished its own startup (i.e. before any hook has
fired) returns a `Promise<Uint8Array>` instead of a plain `Uint8Array`; from inside any
registered hook, it's always the latter. `await` works either way if you don't want to
special-case it.

### 3.6 `tamper.encode.*` / `tamper.decode.*`

A smaller convenience layer, separate from `tamper.transform.*`, for the common case of
turning a buffer into a loggable/matchable string and back:

```js
tamper.encode.hex(bytes, params)          // -> string;  params: {prefix, separator}, both default ''
tamper.encode.base64(bytes, params)       // -> string;  params: {urlSafe}, default false
tamper.encode.hexdump(bytes, baseOffset)  // -> string (xxd-style); baseOffset default 0

tamper.decode.hex(text, params)     // -> Uint8Array; same params as tamper.encode.hex
tamper.decode.base64(text, params)  // -> Uint8Array; same params as tamper.encode.base64
tamper.decode.hexdump(text)         // -> Uint8Array
```

Unlike `tamper.transform.*`, `hex`/`base64` aren't Transform-panel operations you could chain
into a pipeline step - they return a plain string, not `Uint8Array`. `hexdump` in particular has
no Transform-panel/`tamper.transform.*` equivalent at all today. Same synchronous-after-startup
behavior as `tamper.transform.*` (§3.5): a `Promise` only if called before the script's own
startup has finished.

## 4. Examples

### 4.1 Pass-through digest logger

The bundled starter script (`examples/tamper/scripts/sha256-logger.js`, `scripts-dir` in
this repo's `config.json`): logs a SHA256 digest of every chunk in either
direction, then forwards it unmodified. A good template for "instrument, don't
intercept" scripts:

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
    const sha256Hex = tamper.encode.hex(tamper.transform.hash.sha256(bytes))
    ctx.log(`(${ctx.direction}) SHA256(${bytes.length} bytes) = ${sha256Hex}`)
    await ctx.release()
})
```

Under load (many chunks arriving faster than a dispatch can round-trip), you'll likely
see occasional `SHA256(0 bytes) = e3b0c442...` lines - this is expected, not a bug: per
§2.3's `onReceive` coalescing, a run of several queued notifications for the same
direction can still leave one trailing dispatch that finds the buffer already drained by
an earlier one. It's harmless here (an empty `ctx.release()` is a no-op, nothing is
double-logged or double-forwarded) but if the noise is unwanted, guard the top of the
handler:

```js
tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    if (bytes.length === 0) return
    ...
})
```

### 4.2 Find-and-replace on the fly

Rewrites an HTTP response header on the way back to the client - the scripted equivalent
of the `match-replace` interceptor, but conditional/stateful logic is just JavaScript:

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

### 4.3 Pause client requests for manual review

Holds every client→server chunk, logs a preview, then hands off to a operator via
`ctx.pause()` before deciding what to do with whatever they left it as:

```js
tamper.register('onConnect', c => tamper.setIntercept(c.conn, true))

tamper.register('onReceive', async (ctx) => {
    if (ctx.direction !== 'c2s') { await ctx.release(); return }
    const preview = new TextDecoder('utf-8', { fatal: false }).decode(ctx.get().slice(0, 64))
    ctx.log(`review needed: ${JSON.stringify(preview)}`)
    await ctx.pause()          // suspends here until a operator clicks "Continue"
    await ctx.release()        // forward whatever the buffer looks like now
})
```

### 4.4 Durable per-session audit log

Appends a one-line summary of every chunk to a file under `fs-root`, demonstrating state
that survives a script Stop/Restart (unlike the in-memory `Map` pattern in §2.7):

```js
tamper.register('onReceive', async (ctx) => {
    const bytes = ctx.get()
    const line = `${new Date().toISOString()} #${ctx.conn} (${ctx.direction}) ${bytes.length} bytes\n`
    await tamper.fs.appendFile('audit.log', new TextEncoder().encode(line))
    await ctx.release()
})
```

### 4.5 Transparent gzip inspection

Auto-decompresses a gzip-framed response body for logging, without altering what's
actually forwarded - useful when eyeballing traffic that's normally opaque in the
Intercept tab's hex view:

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
