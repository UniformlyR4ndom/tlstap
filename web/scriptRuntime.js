// Runs one user script in a Worker and bridges it to the tamper control/watch
// connections, which the Worker itself never touches directly (only one control
// connection is allowed at a time, already owned elsewhere). The Worker's
// `self.tamper` API (defined by BOOTSTRAP below) does most things via postMessage RPC:
// `call` messages go out to the main thread, which performs the real peek/release/etc.
// through the handlers passed to createScriptRuntime and posts a matching `result` back;
// `event` messages carry onConnect/onReceive/onClose pushes in, matching the same events a
// human control client reacts to. `tamper.transform.*` is the one exception — see
// "Transform calls" below.
//
// Loading: BOOTSTRAP and the script are two separate Blobs, not one concatenated file — the
// Worker's actual entry point is BOOTSTRAP's own Blob, which (after wiring up self.tamper/
// self.onmessage/the error listeners) synchronously importScripts() the script's Blob into
// that same global scope (importScripts, unlike an ES module import, runs the imported code
// in the *same* scope as the caller — no separate module namespace, so the script sees the
// bare `tamper` global exactly as if everything were still one file). Both Blobs end with
// their own `//# sourceURL=...` comment (buildWorkerSource/buildScriptSource below) so
// DevTools/stack traces show "tamper-bootstrap.js" or the script's own name — with accurate,
// file-local line numbers — instead of an opaque `blob:http://.../<uuid>` URL covering both.
// A failure loading the script (syntax error, or a top-level throw outside any hook) is
// caught explicitly around the importScripts() call and reported as a 'fatal' message (see
// handleWorkerMessage below) rather than left to the ambient error-event machinery, so it
// reliably stops the running script — matching the "kills the Worker permanently" contract
// documented below (see "Error handling") even though BOOTSTRAP itself, now a separate,
// always-well-formed Blob, successfully initializes regardless of whether the script does.
//
// Transform calls: `tamper.transform.<category>.<function>` does NOT go through that RPC
// bridge. Every transform operation is synchronous (gzip/deflate via sync functions,
// Whirlpool via a pre-warmed hasher), so BOOTSTRAP dynamically imports the operation
// registry directly by its real absolute URL (computed here, on the main thread, as
// TRANSFORMS_URL — a *relative* specifier is what can't resolve from a Blob-URL worker,
// not an absolute one) and calls OPERATIONS[opId].run() straight from inside the Worker:
// no round trip, and — once the one-time import+warmup during bootstrap has finished,
// which every hook dispatch is gated on (see BOOTSTRAP's `ready` flag) — no `await`
// needed by the script either.
//
// Encode/decode calls: `tamper.encode.{hex,base64,hexdump}`/`tamper.decode.{hex,base64,
// hexdump}` are a separate, smaller convenience layer for the common case of turning a
// buffer into a loggable/matchable string (and back) — as opposed to `tamper.transform.*`,
// whose every op is bytes-in/bytes-out so pipeline steps can chain. `hex`/`base64` are thin
// wrappers around the same encode/decode operations used above (TextEncoder/TextDecoder
// at the boundary, same params, so there's exactly one implementation of each codec);
// `hexdump` has no operation-registry entry to wrap at all, so it calls a shared hexdump
// formatter/parser directly — both already string in/out, needing no TextEncoder/
// TextDecoder step. That module is dynamically imported the same way (see FORMAT_URL
// below) and gated on the same `ready` flag.
//
// Direction is 'c2s' | 's2c' everywhere in the tamper.* surface (both the ctx-based API
// and the raw peek/release/etc. escape hatch) — the numeric 0/1 the rest of the app uses
// is purely a wire-protocol/internal detail, translated at this file's main-thread
// boundary (dispatch() converts outbound number -> string, invoke() converts inbound
// string -> number) so nothing else in the codebase needs to change.
//
// Only one script instance runs at a time — start() tears down any previous worker first.

import { OPERATIONS_BY_CATEGORY } from './transforms.js'
import { DIRNUM_C2S, DIRNUM_S2C } from './direction.js'

// Real absolute URL of transforms.js, resolved from this module's own URL (a real network
// URL, since scriptRuntime.js is loaded as part of the page's module graph) — this is what
// lets BOOTSTRAP's dynamic import() resolve transforms.js's own relative imports into
// transforms/* and vendor/* correctly from inside a Blob-URL-loaded Worker (see the header
// comment above).
const TRANSFORMS_URL = new URL('./transforms.js', import.meta.url).href

// Same reasoning as TRANSFORMS_URL above, for the hexdump formatter/parser backing
// tamper.encode.hexdump/tamper.decode.hexdump (see "Encode/decode calls" above).
const FORMAT_URL = new URL('./format.js', import.meta.url).href

// tamper.transform.<category>.<function> exposes every implemented transform operation to
// scripts (see transforms.js's OPERATIONS_BY_CATEGORY) — one flat function per op id, regardless
// of how the UI groups Encode/Decode/Encrypt/Decrypt/Compress/Uncompress into subsections, since
// that grouping is a menu-presentation concern with no bearing on a script-facing API. Function
// names are a mechanical camelCase of the op id (e.g. `hmac-sha256` -> `hmacSha256`) with two
// exceptions: `3des-encrypt`/`3des-decrypt` would camelCase to `3desEncrypt`, which isn't a valid
// property name for dot-access (an identifier can't start with a digit), so those two are spelled
// out as `tripleDesEncrypt`/`tripleDesDecrypt` instead; and `xor-encrypt`/`xor-decrypt` — a
// repeating-key XOR is its own inverse (see encryption.js's xorTransform) — both map to a single
// `xorCrypt`, deduplicated in buildTransformApiSource below rather than exposing two identical
// functions under different names. The registry keeps `xor-encrypt`/`xor-decrypt` as distinct op
// ids regardless, since the Transform panel still needs them in separate Encrypt/Decrypt menu
// subsections.
const TRANSFORM_NAME_OVERRIDES = {
    '3des-encrypt': 'tripleDesEncrypt',
    '3des-decrypt': 'tripleDesDecrypt',
    'xor-encrypt': 'xorCrypt',
    'xor-decrypt': 'xorCrypt',
}

// Exported for ScriptEditor.js's tamper.transform.* autocomplete shape, which must name
// the same functions this generates for the real Worker-side API.
export function camelCaseOpId(opId) {
    return TRANSFORM_NAME_OVERRIDES[opId] ?? opId.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase())
}

// Built once here (not per-script) since the op catalog is static for the lifetime of the page;
// the generated source is spliced directly into BOOTSTRAP below. Only op ids/categories are
// needed here (to generate the right function names) — the actual OPERATIONS values are looked
// up inside the Worker itself, once BOOTSTRAP's own dynamic import of transforms.js (see
// TRANSFORMS_URL above) has resolved; callTransform() (defined in BOOTSTRAP) is what does that
// lookup and gates on readiness.
//
// A category's op ids can collide on their camelCased name (see xor-encrypt/xor-decrypt in
// TRANSFORM_NAME_OVERRIDES above) — the first op id to claim a name wins and later ones are
// skipped, rather than emitting a second, later-overriding property with the same key. Safe
// precisely because such a collision only ever happens between op ids whose run() is the same
// function, so which op id the generated call actually names makes no behavioral difference.
function buildTransformApiSource() {
    const categories = Object.entries(OPERATIONS_BY_CATEGORY).map(([category, ops]) => {
        const seenNames = new Set()
        const fns = []
        for (const opId of Object.keys(ops)) {
            const fnName = camelCaseOpId(opId)
            if (seenNames.has(fnName)) continue
            seenNames.add(fnName)
            fns.push(`${fnName}: (bytes, params) => callTransform(${JSON.stringify(opId)}, bytes, params)`)
        }
        return `${category}: { ${fns.join(', ')} }`
    })
    return `{ ${categories.join(', ')} }`
}

const BOOTSTRAP = `
(function () {
    let nextCallId = 1
    const pending = new Map()
    const handlers = Object.create(null) // hook name -> array of fns, run in registration order
    const queues = new Map()              // conn -> { items: [{name, args}], busy }
    const VALID_HOOKS = ['onConnect', 'onReceive', 'onClose']

    // Populated once the trailing async IIFE at the bottom of this file finishes dynamically
    // importing the transform/format modules and warming up Whirlpool (see this file's
    // header comment and TRANSFORMS_URL/FORMAT_URL). pump() won't dispatch any hook until ready is
    // true, so a script's own handlers never observe OPERATIONS/FORMAT as null — the only
    // caller that can see the "not ready yet" state is a script calling a transform/encode/
    // decode function at its own top level, outside any hook, which whenReady() below handles
    // by falling back to a Promise.
    let OPERATIONS = null
    let FORMAT = null
    let ready = false
    let resolveReady
    const readyPromise = new Promise(r => { resolveReady = r })

    function whenReady(fn) {
        return ready ? fn() : readyPromise.then(fn)
    }

    function callTransform(opId, bytes, params) {
        return whenReady(() => OPERATIONS[opId].run(bytes, params))
    }

    // Most-common-case defaults so tamper.encode.hex(bytes)/tamper.encode.base64(bytes) work
    // without a params argument at all — a plain contiguous hex/base64 string, matching what
    // e.g. a hash digest is normally printed as. Explicit params still override individually
    // (\`{...DEFAULTS, ...params}\`).
    const HEX_DEFAULTS = { prefix: '', separator: '' }
    const BASE64_DEFAULTS = { urlSafe: false }

    function makeEncoder(opId, defaults) {
        return (bytes, params) => whenReady(() => new TextDecoder().decode(OPERATIONS[opId].run(bytes, { ...defaults, ...params })))
    }
    function makeDecoder(opId, defaults) {
        return (text, params) => whenReady(() => OPERATIONS[opId].run(new TextEncoder().encode(text), { ...defaults, ...params }))
    }
    const callEncodeHex    = makeEncoder('hex-encode', HEX_DEFAULTS)
    const callDecodeHex    = makeDecoder('hex-decode', HEX_DEFAULTS)
    const callEncodeBase64 = makeEncoder('base64-encode', BASE64_DEFAULTS)
    const callDecodeBase64 = makeDecoder('base64-decode', BASE64_DEFAULTS)

    function callEncodeHexdump(bytes, baseOffset) {
        const off = baseOffset ?? 0
        return whenReady(() => FORMAT.fmtAsHexdump(bytes, off))
    }
    function callDecodeHexdump(text) {
        return whenReady(() => FORMAT.parseHexdump(text))
    }

    function call(method, args) {
        return new Promise((resolve, reject) => {
            const id = nextCallId++
            pending.set(id, { resolve, reject })
            postMessage({ kind: 'call', id, method, args })
        })
    }

    function reportError(err) {
        postMessage({ kind: 'error', message: (err && (err.stack || err.message)) || String(err) })
    }

    // Low-level primitives — direction is always 'c2s' | 's2c'. Kept available directly on
    // tamper (not just wrapped by ctx below) as an escape hatch for use outside onReceive,
    // or for scripts that want to bypass ctx's bookkeeping entirely.
    const raw = {
        peek:           (conn, direction) => call('peek', [conn, direction]),
        release:        (conn, direction, opts, editedBytes) => call('release', [conn, direction, opts, editedBytes]),
        dropConnection: (conn, direction) => call('dropConnection', [conn, direction]),
        setIntercept:   (conn, intercepting) => call('setIntercept', [conn, intercepting]),
        listStreams:    () => call('listStreams', []),
    }

    // fs-root access. Routed through the same postMessage RPC bridge as everything else
    // above, even though the underlying transport is a plain REST fetch rather than the
    // control WebSocket — the Worker never does network I/O directly anywhere else in
    // this file, and a Worker created from a Blob URL has no well-defined page origin to
    // resolve a relative fetch() against, so keeping this uniform avoids relying on
    // browser-specific blob-URL fetch behavior. No-op (rejects) if fs-root isn't
    // configured server-side — see handlers.fsList/fsRead/fsWrite/fsAppend. appendFile is
    // a genuinely different server-side operation from writeFile, not a client-side
    // read+concatenate+write — the latter would race across different connections'
    // independently-scheduled onReceive handlers.
    const fs = {
        listFiles:  (path) => call('fsList', [path]),
        readFile:   (path) => call('fsRead', [path]),
        writeFile:  (path, bytes) => call('fsWrite', [path, bytes]),
        appendFile: (path, bytes) => call('fsAppend', [path, bytes]),
    }

    // Builds the ctx handed to onReceive: a local working copy of the buffer (get/set/
    // append never touch the network) plus release/drop/pause, which do. Committing
    // always describes the buffer's *entire* current content as a replacement of
    // committedLength bytes (never a hand-picked partial prefix) — set()/append() discard
    // original chunk-boundary structure, since a script reasons about "the buffer", not
    // original TCP chunk boundaries.
    function makeCtx(conn, direction, newLength, initial) {
        let buf = new Uint8Array(initial.data)
        let committedLength = initial.totalLength
        let touched = false

        function replace(bytes, start, end) {
            const cur = buf
            const s = start === undefined ? 0 : start
            const e = start === undefined ? cur.length : (end === undefined ? cur.length : end)
            if (!(s >= 0 && e >= s && e <= cur.length)) throw new Error(\`ctx.set: invalid range [\${s}, \${e}) for a \${cur.length}-byte buffer\`)
            const insert = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
            const next = new Uint8Array(s + insert.length + (cur.length - e))
            next.set(cur.subarray(0, s), 0)
            next.set(insert, s)
            next.set(cur.subarray(e), s + insert.length)
            buf = next
            touched = true
        }

        // amount: bytes to release/drop from the front (0 = commit-only, nothing released).
        async function commit(amount, action) {
            if (!(amount >= 0 && amount <= buf.length)) throw new Error(\`amount \${amount} out of range for a \${buf.length}-byte buffer\`)
            if (amount === 0 && !touched) return // nothing changed and nothing to release
            const bounds = (amount === 0 || amount === buf.length) ? [0] : [0, amount]
            const releaseChunks = amount === 0 ? 0 : 1
            await raw.release(conn, direction, {
                action, edited: true, prefixLength: committedLength, bounds, releaseChunks,
            }, buf)
            buf = new Uint8Array(buf.subarray(amount)) // detach from the pre-release backing buffer
            committedLength = buf.length
            touched = false
        }

        return {
            conn, direction, newLength,
            get()                  { return buf.slice() },
            set(bytes, start, end) { replace(bytes, start, end) },
            append(bytes)           { replace(bytes, buf.length, buf.length) },
            release(n)               { return commit(n === undefined ? buf.length : n, 'forward') },
            drop(n)                   { return commit(n === undefined ? buf.length : n, 'drop') },
            async pause() {
                await commit(0, 'forward') // sync any pending local edit before yielding to the human
                await call('pause', [conn, direction])
                const fresh = await raw.peek(conn, direction) // pick up whatever the human left it as
                buf = new Uint8Array(fresh.data)
                committedLength = fresh.totalLength
                touched = false
            },
            // Internal — not part of the public surface. Invoked by the dispatch loop after
            // the registered onReceive handlers return, so a script that only mutated the
            // buffer (set/append) without an explicit release/drop/pause still persists that
            // mutation as a held edit rather than silently losing it on the next onReceive.
            __flush() { return commit(0, 'forward') },
            // Same as tamper.log, but prefixes a connection-summary + timestamp line, built
            // on the main thread (createScriptRuntime's handleWorkerMessage — it already
            // tracks src/dst via connMeta, which the Worker itself never sees) since a
            // 'ctxlog' message carries conn/direction/time rather than a ready-made string.
            log(...args) { postMessage({ kind: 'ctxlog', conn, direction, time: Date.now(), args }) },
        }
    }

    self.tamper = {
        register(name, fn) {
            if (!VALID_HOOKS.includes(name)) {
                reportError(new Error(\`tamper.register: unknown hook "\${name}" (expected one of \${VALID_HOOKS.join(', ')})\`))
                return
            }
            ;(handlers[name] || (handlers[name] = [])).push(fn)
        },
        peek: raw.peek,
        release: raw.release,
        dropConnection: raw.dropConnection,
        setIntercept: raw.setIntercept,
        listStreams: raw.listStreams,
        fs,
        transform: ${buildTransformApiSource()},
        encode: {
            hex: callEncodeHex,
            base64: callEncodeBase64,
            hexdump: callEncodeHexdump,
        },
        decode: {
            hex: callDecodeHex,
            base64: callDecodeBase64,
            hexdump: callDecodeHexdump,
        },
        log(...args) { postMessage({ kind: 'log', args }) },
    }

    async function runHandlers(name, args) {
        for (const fn of handlers[name] || []) await fn(...args)
    }

    async function handleOnReceive(conn, direction, offset, length) {
        const initial = await raw.peek(conn, direction)
        const ctx = makeCtx(conn, direction, length, initial)
        await runHandlers('onReceive', [ctx])
        await ctx.__flush()
    }

    // Serializes all events for one connection (both directions together) strictly one at
    // a time — the next queued event only dispatches once the previous handler(s),
    // including any ctx.pause() suspension, have fully resolved. Different conns run
    // independently.
    //
    // Consecutive still-queued onReceive entries for the same (conn, direction) are
    // coalesced into one dispatch: TCP gives no guarantee about how data is chunked into
    // physical reads, so a 'held' notification only ever means "go look at the buffer
    // again" — nothing is tied to any one notification individually. Once accumulation
    // outpaces how fast a dispatch can round-trip, several can pile up before the first
    // even starts; without coalescing, every one behind the first is a redundant round
    // trip against an already-drained buffer. This never reorders anything relative to
    // an interleaved other-direction/other-conn event — only adjacent same-direction
    // entries merge. offset is kept from the earliest entry, length is summed across all
    // merged entries, so ctx.newLength still means "new bytes since the last dispatch,"
    // not one chunk's size. A script is still guaranteed to eventually see an onReceive
    // whose ctx.get() reflects the complete, unprocessed buffer — just not necessarily
    // one dispatch per notification.
    function pump(conn) {
        if (!ready) return // flushed for every queued conn once the trailing IIFE below resolves
        const q = queues.get(conn)
        if (!q || q.busy) return
        q.busy = true
        ;(async () => {
            let closed = false
            while (q.items.length) {
                const item = q.items.shift()
                try {
                    if (item.name === 'onReceive') {
                        let [direction, offset, length] = item.args
                        while (q.items.length && q.items[0].name === 'onReceive' && q.items[0].args[0] === direction) {
                            length += q.items.shift().args[2]
                        }
                        await handleOnReceive(conn, direction, offset, length)
                    } else {
                        await runHandlers(item.name, item.args)
                    }
                } catch (err) { reportError(err) }
                if (item.name === 'onClose') closed = true
            }
            q.busy = false
            if (closed) queues.delete(conn) // conn ids are never reused within a proxy run
        })()
    }

    self.onmessage = (e) => {
        const msg = e.data
        if (msg.kind === 'event') {
            let q = queues.get(msg.conn)
            if (!q) { q = { items: [], busy: false }; queues.set(msg.conn, q) }
            q.items.push({ name: msg.name, args: msg.args })
            pump(msg.conn)
        } else if (msg.kind === 'result') {
            const p = pending.get(msg.id)
            if (!p) return
            pending.delete(msg.id)
            if (msg.error != null) p.reject(new Error(msg.error))
            else p.resolve(msg.value)
        }
    }

    self.addEventListener('error', (e) => { reportError(e.error || e.message); e.preventDefault() })
    self.addEventListener('unhandledrejection', (e) => { reportError(e.reason); e.preventDefault() })

    // Deferred on purpose: everything above (self.tamper, self.onmessage, the error listeners)
    // is wired up synchronously first, so a failure here is never missed for lack of a handler
    // to catch it, and so events arriving before this resolves still queue correctly (pump()'s
    // ready guard just leaves them queued rather than dropping them). Once resolved, every
    // tamper.transform.* call for the rest of this script's run is a plain synchronous call.
    ;(async () => {
        try {
            const [transformsMod, formatMod] = await Promise.all([
                import(${JSON.stringify(TRANSFORMS_URL)}),
                import(${JSON.stringify(FORMAT_URL)}),
            ])
            await transformsMod.warmupWhirlpool()
            OPERATIONS = transformsMod.OPERATIONS
            FORMAT = formatMod
            ready = true
            resolveReady()
            for (const conn of queues.keys()) pump(conn)
        } catch (err) {
            reportError(err)
        }
    })()
})();
`

// sourceURL is a single-line magic comment — strip anything that would break out of it, and
// fall back to a stable name if the script has no name yet (e.g. an unsaved new script).
function sanitizeScriptSourceUrl(name) {
    const base = String(name ?? '').replace(/[\r\n]/g, ' ').trim() || 'script'
    return base.endsWith('.js') ? base : `${base}.js`
}

// The script's own Blob: wrapped in its own IIFE so its top-level declarations don't collide
// with BOOTSTRAP's, or with a later restart's script sharing the same Worker global scope
// (moot today since start() always creates a fresh Worker, but harmless either way). The
// trailing sourceURL is what makes this show up as its own correctly-named, correctly
// line-numbered file in stack traces/DevTools, separate from BOOTSTRAP's own (see
// buildWorkerSource below and this file's header comment).
function buildScriptSource(name, source) {
    return `;(function(){\n${source}\n})();\n//# sourceURL=${sanitizeScriptSourceUrl(name)}\n`
}

// BOOTSTRAP's own Blob: BOOTSTRAP itself plus a trailing importScripts() of the script's
// separate Blob (scriptBlobUrl) — this is the Worker's actual entry point. importScripts()
// runs the script in the same global scope as BOOTSTRAP (self.tamper etc. stay visible), but
// as its own parse/compilation unit, so a syntax error in the script can never prevent
// BOOTSTRAP itself from initializing — that failure is instead caught right here and
// reported as 'fatal' (see handleWorkerMessage), which explicitly stops the running script,
// preserving the documented "a syntax error in the script kills the Worker permanently"
// contract (see "Error handling").
function buildWorkerSource(scriptBlobUrl) {
    return `${BOOTSTRAP}
try {
    importScripts(${JSON.stringify(scriptBlobUrl)})
} catch (err) {
    postMessage({ kind: 'fatal', message: (err && (err.stack || err.message)) || String(err) })
}
//# sourceURL=tamper-bootstrap.js
`
}

const DIR_STR = ['c2s', 's2c']
const DIR_NUM = { c2s: DIRNUM_C2S, s2c: DIRNUM_S2C }

function dirToStr(d) { return DIR_STR[d] }
function dirFromStr(s) {
    if (!(s in DIR_NUM)) throw new Error(`invalid direction: "${s}"`)
    return DIR_NUM[s]
}

function formatLogTime(ms) {
    const d = new Date(ms)
    const pad = (n, w = 2) => String(n).padStart(w, '0')
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}

// handlers: { peek(conn, direction), release(conn, direction, opts, editedBytes),
// dropConnection(conn, direction), setIntercept(conn, intercepting), listStreams(),
// fsList(path), fsRead(path), fsWrite(path, bytes), fsAppend(path, bytes),
// onLog(level, args, prefix?), onStatusChange(runningName | null), onPauseChange(conn,
// direction, paused) } — all nine calls mirror the control/watch/fs REST wrappers
// directly (numeric direction, as used throughout the rest of the app) and must return
// Promises; the fs quartet has no conn/direction at all, since fs-root access isn't
// scoped to a connection. onLog receives level: 'log' | 'error'; prefix is only set for
// a ctx.log call (see handleWorkerMessage's 'ctxlog' branch below) — a ready-made
// connection-summary + timestamp line the caller should render above the formatted
// args, not merged into them, since tamper.log's plain args are meant to stay on one
// line. onPauseChange fires when a script's ctx.pause() call starts/stops waiting on a
// human "Continue".
export function createScriptRuntime(handlers) {
    let worker = null
    let blobUrls = []  // [scriptBlobUrl, bootstrapBlobUrl] — both revoked together in stop()
    let runningName = null
    const connMeta = new Map()      // conn -> {conn,src,dst}, cached from onConnect for onClose
                                     // and ctx.log's connection-summary prefix (see below)
    const pendingPauses = new Map() // conn -> {direction, resolve, reject} — at most one per conn,
                                     // since per-conn event serialization guarantees only one
                                     // onReceive invocation (and so at most one pause) is ever
                                     // in flight for a given conn at a time.

    function invoke(method, args) {
        switch (method) {
            case 'peek':           return handlers.peek(args[0], dirFromStr(args[1]))
            case 'release':        return handlers.release(args[0], dirFromStr(args[1]), args[2], args[3])
            case 'dropConnection': return handlers.dropConnection(args[0], dirFromStr(args[1]))
            case 'setIntercept':   return handlers.setIntercept(args[0], args[1])
            case 'listStreams':    return handlers.listStreams()
            case 'fsList':         return handlers.fsList(args[0])
            case 'fsRead':         return handlers.fsRead(args[0])
            case 'fsWrite':        return handlers.fsWrite(args[0], args[1])
            case 'fsAppend':       return handlers.fsAppend(args[0], args[1])
            case 'pause':          return invokePause(args[0], dirFromStr(args[1]))
            default:                return Promise.reject(new Error(`unknown method: ${method}`))
        }
    }

    // Doesn't resolve immediately like every other call — it waits for a human to click
    // "Continue" in the Intercept sub-tab (continuePause) or for the connection to
    // terminate out from under it (rejectPause), both driven externally.
    function invokePause(conn, direction) {
        return new Promise((resolve, reject) => {
            pendingPauses.set(conn, { direction, resolve, reject })
            handlers.onPauseChange?.(conn, direction, true)
        })
    }

    function settlePause(conn, kind, value) {
        const p = pendingPauses.get(conn)
        if (!p) return
        pendingPauses.delete(conn)
        handlers.onPauseChange?.(conn, p.direction, false)
        kind === 'resolve' ? p.resolve(value) : p.reject(value)
    }

    function handleWorkerMessage(e) {
        const msg = e.data
        if (msg.kind === 'call') {
            Promise.resolve()
                .then(() => invoke(msg.method, msg.args))
                .then(value => worker?.postMessage({ kind: 'result', id: msg.id, value }))
                .catch(err => worker?.postMessage({ kind: 'result', id: msg.id, error: err?.message || String(err) }))
        } else if (msg.kind === 'log') {
            handlers.onLog?.('log', msg.args)
        } else if (msg.kind === 'ctxlog') {
            // meta can be missing if this conn's onConnect predates the running script (see
            // dispatch()'s onClose fallback below for the same case) or if the connection
            // already closed — connMeta.delete() on 'onClose' can race a still-queued
            // onReceive's own ctx.log call, same race dispatch() already tolerates there.
            const meta = connMeta.get(msg.conn)
            const endpoints = meta ? `${meta.src} -> ${meta.dst} ` : ''
            const prefix = `[${formatLogTime(msg.time)}] #${msg.conn} ${endpoints}(${msg.direction})`
            handlers.onLog?.('log', msg.args, prefix)
        } else if (msg.kind === 'error') {
            handlers.onLog?.('error', [msg.message])
        } else if (msg.kind === 'fatal') {
            // Explicitly reported by BOOTSTRAP's own importScripts() try/catch (see
            // buildWorkerSource) — a syntax error in the script, or a top-level throw
            // outside any hook. Unlike a plain 'error' (which leaves the script running —
            // see "Error handling" in CLAUDE.md), this always stops it, matching the
            // documented "a syntax error in the script kills the Worker permanently"
            // contract.
            handlers.onLog?.('error', [msg.message])
            runtime.stop()
        }
    }

    const runtime = {
        get running() { return runningName },

        // Stops any previously running script first — only one instance at a time.
        start(name, source) {
            runtime.stop()
            const scriptBlobUrl = URL.createObjectURL(new Blob([buildScriptSource(name, source)], { type: 'text/javascript' }))
            const bootstrapBlobUrl = URL.createObjectURL(new Blob([buildWorkerSource(scriptBlobUrl)], { type: 'text/javascript' }))
            blobUrls = [scriptBlobUrl, bootstrapBlobUrl]
            worker = new Worker(bootstrapBlobUrl)
            worker.onmessage = handleWorkerMessage
            // Defensive fallback only at this point — BOOTSTRAP's own Blob is fixed,
            // trusted, always-well-formed source, so a genuine parse failure here would
            // mean something more fundamental broke (e.g. the Blob failed to load at
            // all). A syntax error in the *script* is caught explicitly inside BOOTSTRAP
            // itself and reported as 'fatal' (see handleWorkerMessage) instead of reaching
            // this handler, since BOOTSTRAP now always finishes initializing regardless of
            // whether the script does (see this file's header comment).
            worker.onerror = (e) => {
                handlers.onLog?.('error', [e.message || String(e)])
                e.preventDefault()
                runtime.stop()
            }
            runningName = name
            handlers.onStatusChange?.(name)
        },

        stop() {
            if (!worker) return
            worker.terminate()
            worker = null
            for (const url of blobUrls) URL.revokeObjectURL(url)
            blobUrls = []
            runningName = null
            connMeta.clear()
            // The worker's gone — nothing to resolve into, and nothing left to notify.
            pendingPauses.clear()
            handlers.onStatusChange?.(null)
        },

        // Forwards a control-channel push event into the running script. name is
        // 'onConnect' | 'onReceive' | 'onClose'; rawArgs carries the wire-shaped
        // (numeric-direction) payload, translated here into what the worker expects:
        //  - onConnect: rawArgs = [{conn, src, dst}] — cached for onClose's lookup below.
        //  - onReceive: rawArgs = [direction, offset, length] — direction converted to string.
        //  - onClose:   rawArgs = [] — conn's cached {conn,src,dst} is looked up and used
        //    instead, falling back to {conn} alone if this script never saw that
        //    connection's onConnect (e.g. it was already open when the script started).
        dispatch(name, conn, rawArgs) {
            if (!worker) return
            let args = rawArgs
            if (name === 'onConnect') {
                connMeta.set(conn, rawArgs[0])
            } else if (name === 'onClose') {
                const meta = connMeta.get(conn)
                connMeta.delete(conn)
                args = [meta ?? { conn }]
            } else if (name === 'onReceive') {
                const [direction, offset, length] = rawArgs
                args = [dirToStr(direction), offset, length]
            }
            worker.postMessage({ kind: 'event', conn, name, args })
        },

        // Called once a human clicks "Continue" and any pending edit has been committed.
        // A no-op if this conn has no pending pause.
        continuePause(conn) { settlePause(conn, 'resolve', undefined) },

        // Called when a connection terminates while a ctx.pause() for it is outstanding —
        // its Intercept-sub-tab entry (and so the human's only way to click Continue) is
        // about to disappear, so the suspended call must be unstuck rather than left
        // hanging forever. A no-op if this conn has no pending pause.
        rejectPause(conn) { settlePause(conn, 'reject', new Error('connection terminated while paused')) },
    }
    return runtime
}
