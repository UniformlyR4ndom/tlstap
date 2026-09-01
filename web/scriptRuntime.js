// Runs one user script in a Worker and bridges it to the tamper control/watch
// connections via postMessage RPC: `call` messages invoke a handler on the main thread and
// get a matching `result` back; `event` messages push onConnect/onReceive/onFrame/onClose
// in. `tamper.transform.*`/`encode.*`/`decode.*`/`fs.*`/`kv.*` bypass this bridge and run
// directly inside the Worker instead — `fs.*`/`kv.*` via a real `fetch()`
// (coreApiClient.js), the rest synchronously.
//
// BOOTSTRAP and the script are separate Blobs, not one file, so a script syntax error
// can't stop BOOTSTRAP itself from initializing self.tamper/self.onmessage/the error
// listeners; importScripts() then runs the script in that same global scope. Each Blob
// ends with its own `//# sourceURL=...` so DevTools/stack traces show a real file name
// instead of an opaque blob: URL.
//
// Direction is 'c2s' | 's2c' on this file's tamper.* surface, translated to/from the
// numeric 0/1 the rest of the app uses at dispatch()/invoke().
//
// Only one script instance runs at a time — start() tears down any previous worker first.
//
// Optional framer composition: start() accepts a second (framerName, framerSource) pair.
// A framer script's own Blob is loaded unwrapped (its `frame` must resolve as a global,
// unlike the IIFE-wrapped interception script — mirrors dbdump's frameRuntime.js), and
// BOOTSTRAP switches its per-connection dispatch from onReceive to onFrame whenever
// `typeof frame === 'function'`. See doc/design/tamper-framer.md for the full mechanism.

import { DIRNUM_C2S, DIRNUM_S2C } from './direction.js'
import { buildTransformApiSource, buildNumberApiSource, HEX_DEFAULTS, BASE64_DEFAULTS } from './transformWorkerApi.js'

// Absolute URLs, so BOOTSTRAP's dynamic import() can resolve their own relative imports
// (transforms/*, vendor/*) from inside a Blob-URL worker, where a relative specifier
// wouldn't resolve.
const TRANSFORMS_URL = new URL('./transforms.js', import.meta.url).href
const FORMAT_URL = new URL('./format.js', import.meta.url).href
const CORE_API_URL = new URL('./coreApiClient.js', import.meta.url).href

// Absolute origin, for the same relative-URL-resolution reason as the module URLs above —
// baked into BOOTSTRAP as string literals and handed to createFsApi/createKvApi.
const FS_BASE_URL = new URL('/api/core/fs', location.href).href
const KV_BASE_URL = new URL('/api/core/kv', location.href).href

// <namespace>.transform.<category>/<namespace>.number.decode<Type>/encode<Type>'s function
// bodies are Promise-wrapped (callTransform/whenReady) since they must be callable before
// the module import below resolves. Shared verbatim between self.tamper and self.framer
// (built once, referenced from both) — the generated source only calls into
// callTransform/whenReady/decodeNumberValue/encodeNumberValue, none of which differ
// per-namespace.
const TRANSFORM_API_SOURCE = buildTransformApiSource(
    opId => `(bytes, params) => callTransform(${JSON.stringify(opId)}, bytes, params)`,
)
const NUMBER_API_SOURCE = buildNumberApiSource((type, kind) => {
    const typeJson = JSON.stringify(type)
    return kind === 'decode'
        ? `(bytes) => whenReady(() => decodeNumberValue(bytes, ${typeJson}))`
        : `(value) => whenReady(() => encodeNumberValue(value, ${typeJson}))`
})

const BOOTSTRAP = `
(function () {
    let nextCallId = 1
    const pending = new Map()
    const handlers = Object.create(null) // hook name -> array of fns, run in registration order
    const queues = new Map()              // conn -> { items: [{name, args}], busy }
    const VALID_HOOKS = ['onConnect', 'onReceive', 'onFrame', 'onClose']

    // pump() gates all hook dispatch on ready, so a script's handlers never see
    // OPERATIONS/FORMAT as null; a call made before ready (e.g. at the script's own top
    // level) falls back to a Promise via whenReady().
    let OPERATIONS = null
    let FORMAT = null
    let decodeNumberValue = null
    let encodeNumberValue = null
    let fsApi = null
    let kvApi = null
    let ready = false
    let resolveReady
    const readyPromise = new Promise(r => { resolveReady = r })

    function whenReady(fn) {
        return ready ? fn() : readyPromise.then(fn)
    }

    function callTransform(opId, bytes, params) {
        return whenReady(() => OPERATIONS[opId].run(bytes, params))
    }

    const HEX_DEFAULTS = ${JSON.stringify(HEX_DEFAULTS)}
    const BASE64_DEFAULTS = ${JSON.stringify(BASE64_DEFAULTS)}

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

    // <namespace>.fs.*/<namespace>.kv.* — real network calls (coreApiClient.js, direct
    // fetch, no RPC bridge), but still whenReady-gated like transform/encode/decode above
    // so a script can reference either at any point without special-casing "not ready
    // yet" itself. appendFile is a real server-side op, not a client
    // read+concatenate+write, which would race independently-scheduled onReceive/onFrame
    // handlers across connections. Shared verbatim between self.tamper and self.framer.
    function callFs(method) {
        return (...args) => whenReady(() => fsApi[method](...args))
    }
    const fs = {
        listFiles: callFs('listFiles'),
        readFile: callFs('readFile'),
        writeFile: callFs('writeFile'),
        appendFile: callFs('appendFile'),
    }
    function callKv(method) {
        return (...args) => whenReady(() => kvApi[method](...args))
    }
    const kv = {
        read: callKv('read'),
        write: callKv('write'),
        readBytes: callKv('readBytes'),
        writeBytes: callKv('writeBytes'),
        list: callKv('list'),
        delete: callKv('delete'),
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

    // Escape hatch: available directly on tamper, not just through ctx, for use outside
    // onReceive/onFrame or to bypass ctx's bookkeeping.
    const raw = {
        peek:           (conn, direction) => call('peek', [conn, direction]),
        release:        (conn, direction, opts, editedBytes) => call('release', [conn, direction, opts, editedBytes]),
        dropConnection: (conn, direction) => call('dropConnection', [conn, direction]),
        setIntercept:   (conn, intercepting) => call('setIntercept', [conn, intercepting]),
        listStreams:    () => call('listStreams', []),
    }

    // ctx handed to onReceive/onFrame. get/set/append are purely local; release/drop/pause
    // touch the network — unless opts.live is false (a close-triggered onFrame call, with
    // no live server-side buffer left to act on: see resolveFramerClose), in which case
    // they're safe local-only no-ops instead, sharing every other bit of buffer bookkeeping
    // with the live path rather than a separate parallel implementation. A commit always
    // replaces the buffer's entire current content, never a partial prefix — set()/
    // append() discard original chunk-boundary structure since a script reasons about "the
    // buffer," not TCP chunk boundaries.
    function makeCtx(conn, direction, newLength, initial, opts) {
        const live = !(opts && opts.live === false)
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
            if (live) {
                const bounds = (amount === 0 || amount === buf.length) ? [0] : [0, amount]
                const releaseChunks = amount === 0 ? 0 : 1
                await raw.release(conn, direction, {
                    action, edited: true, prefixLength: committedLength, bounds, releaseChunks,
                }, buf)
            }
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
                if (!live) return // no live buffer/human to hand off to — a no-op, not an error
                await commit(0, 'forward') // sync any pending local edit before yielding to the human
                await call('pause', [conn, direction])
                const fresh = await raw.peek(conn, direction) // pick up whatever the human left it as
                buf = new Uint8Array(fresh.data)
                committedLength = fresh.totalLength
                touched = false
            },
            // Internal, not part of the public surface: persists a buffer mutation
            // (set/append) as a held edit even if the handler never called
            // release/drop/pause explicitly.
            __flush() { return commit(0, 'forward') },
            // Posts conn/direction/time rather than a ready-made string; the main thread
            // builds the connection-summary prefix, since only it tracks src/dst.
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
        kv,
        transform: ${TRANSFORM_API_SOURCE},
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
        number: ${NUMBER_API_SOURCE},
        log(...args) { postMessage({ kind: 'log', args }) },
    }

    // A selected framer script's surface — present regardless of whether a framer is
    // actually selected for this run (harmless if unused): transform/encode/decode/
    // number/fs/kv are byte-for-byte tamper's own, since none of them are namespace-
    // specific. log is distinguished (source: 'framer') so the main thread can prefix
    // its log lines distinctly from the interception script's own tamper.log output.
    self.framer = {
        transform: ${TRANSFORM_API_SOURCE},
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
        number: ${NUMBER_API_SOURCE},
        fs,
        kv,
        log(...args) { postMessage({ kind: 'log', args, source: 'framer' }) },
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

    // frameState: conn -> the selected framer script's own opaque state, threaded through
    // successive frame(state, chunk) calls (combined mode: one state per stream, shared
    // across both directions).
    //
    // lastRemaining: "conn:direction" -> Uint8Array, the tail of that direction's held
    // buffer not yet consumed into a dispatched frame, as of the last dispatch. Serves two
    // purposes: (1) its *length* is what makes each new dispatch's chunk.data only the
    // genuinely new bytes since the framer last saw data for this direction — a fresh
    // peek() always returns lastRemaining ++ whatever's newly arrived, so
    // peeked.subarray(lastRemaining.length) is exactly that — mirroring dbdump's own
    // framer contract, where chunk.data is one new raw chunk, never the whole
    // accumulated buffer (a script's own state is where "still-undecided carry bytes"
    // are meant to live, e.g. tls-framer.js's carry pattern; feeding the same bytes twice
    // would make the framer see them twice too). (2) its *content* is close handling's
    // only way to reconstruct that tail's bytes, since a fresh peek/release is impossible
    // once a stream has terminated (ConnectionTerminated deletes server-side state before
    // sending stream-terminated — see doc/design/tamper-framer.md).
    //
    // Both maps are updated incrementally, after each individual frame is processed (not
    // just once per frame() call) specifically so that a later frame's handler throwing
    // mid-batch can't roll back state/tail bookkeeping for frames already released to the
    // wire earlier in the same batch.
    const frameState = new Map()
    const lastRemaining = new Map()

    async function handleOnFrame(conn, direction, offset, length) {
        const initial = await raw.peek(conn, direction)
        const buf = new Uint8Array(initial.data)
        const key = \`\${conn}:\${direction}\`
        const prevTail = lastRemaining.get(key) ?? new Uint8Array(0)
        const newBytes = buf.subarray(prevTail.length) // see lastRemaining's doc comment above

        let state = frameState.has(conn) ? frameState.get(conn) : null
        const result = (await frame(state, { direction, data: newBytes, closed: false })) || {}
        if ('state' in result) state = result.state
        frameState.set(conn, state)

        // Frames a single frame() call returns partition buf from its very front (byte 0)
        // — not from newBytes' own start — since a frame may be made partly or wholly of
        // bytes the framer already had buffered internally from an earlier, still-
        // undecided call.
        let consumed = 0
        for (const f of (result.frames || [])) {
            if (!(Number.isInteger(f.length) && f.length >= 0 && f.length <= buf.length - consumed)) {
                throw new Error(\`frame(): returned frame length \${f.length} out of range for a \${buf.length - consumed}-byte buffer\`)
            }
            const frameBytes = buf.subarray(consumed, consumed + f.length)
            const ctx = makeCtx(conn, direction, f.length, { data: frameBytes, totalLength: f.length })
            await runHandlers('onFrame', [ctx, { direction, data: frameBytes.slice(), meta: f.meta ?? null, final: false }])
            await ctx.__flush()
            consumed += f.length
            lastRemaining.set(key, buf.subarray(consumed))
        }
        if (consumed === 0) lastRemaining.set(key, buf) // no frames resolved this dispatch: the whole buffer is still the tail
    }

    // dispatchClosedFrame hands one frame extracted during close handling to onFrame,
    // via a ctx built with live:false — release/drop/pause are safe local no-ops (there's
    // no server-side buffer left to act on), get/set/append/log behave normally.
    async function dispatchClosedFrame(conn, direction, data, meta) {
        const ctx = makeCtx(conn, direction, data.length, { data, totalLength: data.length }, { live: false })
        await runHandlers('onFrame', [ctx, { direction, data: data.slice(), meta, final: true }])
        await ctx.__flush() // no-op wire-wise (live:false); keeps ctx symmetric with the live path
    }

    // resolveFramerClose gives a selected framer one last chance to resolve whatever's
    // left of a direction's buffer (per the connection-close signal, chunk.closed:true —
    // empty data, mirroring dbdump's own convention: the framer's own state already has
    // everything it needs) once that direction's connection has closed — working from the
    // client-cached tail (lastRemaining above), since a fresh peek is no longer possible
    // by this point. Anything the closed:true call still doesn't resolve into a frame is
    // exposed to the interception script as one final synthetic frame (meta:null) rather
    // than silently bypassing onFrame.
    async function resolveFramerClose(conn, direction) {
        if (typeof frame !== 'function') return
        const key = \`\${conn}:\${direction}\`
        const buf = lastRemaining.get(key) ?? new Uint8Array(0)
        let state = frameState.has(conn) ? frameState.get(conn) : null

        const result = (await frame(state, { direction, data: new Uint8Array(0), closed: true })) || {}
        if ('state' in result) state = result.state
        frameState.set(conn, state)

        let consumed = 0
        for (const f of (result.frames || [])) {
            if (!(Number.isInteger(f.length) && f.length >= 0 && f.length <= buf.length - consumed)) {
                throw new Error(\`frame(): returned frame length \${f.length} out of range for a \${buf.length - consumed}-byte buffer (closed)\`)
            }
            const frameBytes = buf.subarray(consumed, consumed + f.length)
            await dispatchClosedFrame(conn, direction, frameBytes, f.meta ?? null)
            consumed += f.length
            lastRemaining.set(key, buf.subarray(consumed))
        }
        const leftover = buf.subarray(consumed)
        if (leftover.length > 0) {
            await dispatchClosedFrame(conn, direction, leftover, null)
            lastRemaining.set(key, new Uint8Array(0))
        }
    }

    // Serializes events per connection (both directions together), one at a time;
    // different conns run independently.
    //
    // Consecutive queued onReceive entries for the same (conn, direction) coalesce into
    // one dispatch — TCP gives no guaranteed chunking, so a 'held' notification just means
    // "look at the buffer again." offset comes from the earliest entry, length is summed,
    // so ctx.newLength still means "new bytes since the last dispatch." Whether that
    // dispatch actually calls handleOnReceive or handleOnFrame is decided per call, purely
    // by whether a selected framer script defined a global \`frame\` function — the wire
    // event name itself stays 'onReceive' either way; this is internal Worker-side
    // routing only.
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
                        if (typeof frame === 'function') {
                            await handleOnFrame(conn, direction, offset, length)
                        } else {
                            await handleOnReceive(conn, direction, offset, length)
                        }
                    } else if (item.name === 'onClose') {
                        if (typeof frame === 'function') {
                            // Each direction's close handling is independently guarded: one
                            // direction's framer throwing must not prevent the other
                            // direction's handling, the interception script's own onClose,
                            // or the cleanup below from running.
                            for (const d of ['c2s', 's2c']) {
                                try { await resolveFramerClose(conn, d) } catch (err) { reportError(err) }
                            }
                        }
                        await runHandlers('onClose', item.args)
                        frameState.delete(conn)
                        lastRemaining.delete(\`\${conn}:c2s\`)
                        lastRemaining.delete(\`\${conn}:s2c\`)
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

    // Deferred until after self.tamper/onmessage/the error listeners are wired up, so a
    // failure here is never missed and events arriving first just queue (pump()'s ready
    // guard).
    ;(async () => {
        try {
            const [transformsMod, formatMod, coreApiMod] = await Promise.all([
                import(${JSON.stringify(TRANSFORMS_URL)}),
                import(${JSON.stringify(FORMAT_URL)}),
                import(${JSON.stringify(CORE_API_URL)}),
            ])
            await transformsMod.warmupWhirlpool()
            OPERATIONS = transformsMod.OPERATIONS
            FORMAT = formatMod
            decodeNumberValue = transformsMod.decodeNumberValue
            encodeNumberValue = transformsMod.encodeNumberValue
            fsApi = coreApiMod.createFsApi(${JSON.stringify(FS_BASE_URL)})
            kvApi = coreApiMod.createKvApi(${JSON.stringify(KV_BASE_URL)})
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

// Wrapped in its own IIFE so top-level declarations can't collide with BOOTSTRAP's; the
// trailing sourceURL names it correctly in DevTools/stack traces.
function buildScriptSource(name, source) {
    return `;(function(){\n${source}\n})();\n//# sourceURL=${sanitizeScriptSourceUrl(name)}\n`
}

// Deliberately NOT wrapped in an IIFE, unlike buildScriptSource above: the framer contract
// looks up `frame` by name (typeof frame === 'function') in global scope, mirroring
// dbdump's frameRuntime.js — an IIFE would trap the declaration in its own local scope,
// making it permanently invisible to BOOTSTRAP's dispatch logic.
function buildFramerScriptSource(name, source) {
    return `${source}\n//# sourceURL=${sanitizeScriptSourceUrl(name)}\n`
}

// BOOTSTRAP plus a trailing importScripts() of the framer script's Blob (if any) and the
// interception script's own Blob — the Worker's actual entry point. A syntax error in
// either is caught here and reported as 'fatal' without preventing BOOTSTRAP itself from
// finishing initialization — a broken framer selection stops the runtime exactly like a
// broken interception script does today, rather than silently degrading to raw dispatch.
// The framer (if given) loads first, though load order doesn't matter functionally: unlike
// the interception script's tamper.register(...) side effect, a framer script's only
// required top-level effect is declaring the global `frame` function.
function buildWorkerSource(scriptBlobUrl, framerBlobUrl) {
    return `${BOOTSTRAP}
try {
    ${framerBlobUrl ? `importScripts(${JSON.stringify(framerBlobUrl)})\n    ` : ''}importScripts(${JSON.stringify(scriptBlobUrl)})
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
// onLog(level, args, prefix?), onStatusChange(runningName | null), onPauseChange(conn,
// direction, paused) }. All must return Promises except onLog/onStatusChange/onPauseChange.
// onLog's level is 'log' | 'error'; prefix (set for a ctx.log call, or a framer.log call)
// is a ready-made line meant to render above the args, not merged into them. onPauseChange
// fires when a script's ctx.pause() call starts/stops waiting on a human "Continue".
export function createScriptRuntime(handlers) {
    let worker = null
    let blobUrls = []  // revoked together in stop() — [scriptBlobUrl, bootstrapBlobUrl], or
                        // [scriptBlobUrl, framerBlobUrl, bootstrapBlobUrl] when a framer is selected
    let runningName = null
    const connMeta = new Map()      // conn -> {conn,src,dst}, cached from onConnect for onClose
    const pendingPauses = new Map() // conn -> {direction, resolve, reject}; at most one per
                                     // conn, since per-conn serialization allows only one
                                     // in-flight onReceive/onFrame (and so pause) at a time.

    function invoke(method, args) {
        switch (method) {
            case 'peek':           return handlers.peek(args[0], dirFromStr(args[1]))
            case 'release':        return handlers.release(args[0], dirFromStr(args[1]), args[2], args[3])
            case 'dropConnection': return handlers.dropConnection(args[0], dirFromStr(args[1]))
            case 'setIntercept':   return handlers.setIntercept(args[0], args[1])
            case 'listStreams':    return handlers.listStreams()
            case 'pause':          return invokePause(args[0], dirFromStr(args[1]))
            default:                return Promise.reject(new Error(`unknown method: ${method}`))
        }
    }

    // Doesn't resolve on its own — waits for an external continuePause/rejectPause call.
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
            // msg.source is 'framer' for a framer.log(...) call, absent for tamper.log(...)
            // — distinguished with a prefix rather than a separate log stream, so both
            // render interleaved in arrival order in one panel.
            handlers.onLog?.('log', msg.args, msg.source === 'framer' ? '[framer]' : undefined)
        } else if (msg.kind === 'ctxlog') {
            // meta can be missing if this conn's onConnect predates the running script, or
            // if connMeta was already cleared on 'onClose' while an onReceive's/onFrame's
            // ctx.log call was still queued behind it.
            const meta = connMeta.get(msg.conn)
            const endpoints = meta ? `${meta.src} -> ${meta.dst} ` : ''
            const prefix = `[${formatLogTime(msg.time)}] #${msg.conn} ${endpoints}(${msg.direction})`
            handlers.onLog?.('log', msg.args, prefix)
        } else if (msg.kind === 'error') {
            handlers.onLog?.('error', [msg.message])
        } else if (msg.kind === 'fatal') {
            // A script syntax error, or a top-level throw outside any hook. Unlike a
            // plain 'error', which leaves the script running, this always stops it.
            handlers.onLog?.('error', [msg.message])
            runtime.stop()
        }
    }

    const runtime = {
        get running() { return runningName },

        // Stops any previously running script first — only one instance at a time.
        // framerName/framerSource are optional: when given, the framer script's frame()
        // reassembles frames for the interception script's onFrame hook instead of
        // onReceive firing directly on raw chunks — see BOOTSTRAP's pump().
        start(name, source, framerName, framerSource) {
            runtime.stop()
            const scriptBlobUrl = URL.createObjectURL(new Blob([buildScriptSource(name, source)], { type: 'text/javascript' }))
            let framerBlobUrl = null
            if (framerSource != null) {
                framerBlobUrl = URL.createObjectURL(new Blob([buildFramerScriptSource(framerName, framerSource)], { type: 'text/javascript' }))
            }
            const bootstrapBlobUrl = URL.createObjectURL(new Blob([buildWorkerSource(scriptBlobUrl, framerBlobUrl)], { type: 'text/javascript' }))
            blobUrls = framerBlobUrl ? [scriptBlobUrl, framerBlobUrl, bootstrapBlobUrl] : [scriptBlobUrl, bootstrapBlobUrl]
            worker = new Worker(bootstrapBlobUrl)
            worker.onmessage = handleWorkerMessage
            // Defensive fallback only: BOOTSTRAP's own source is fixed and well-formed, so
            // reaching this means something more fundamental broke (e.g. the Blob failed
            // to load at all) — a script syntax error is caught inside BOOTSTRAP itself
            // and reported as 'fatal' instead.
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

        // Forwards a control-channel push event into the running script, translating
        // rawArgs from its wire shape (numeric direction) into what the worker expects:
        //  - onConnect: [{conn, src, dst}] — cached for onClose's lookup.
        //  - onReceive: [direction, offset, length] — direction converted to string. May
        //    end up dispatched inside the worker as either onReceive or onFrame handlers,
        //    depending on whether a framer script is selected — this call site doesn't
        //    need to know which.
        //  - onClose: looks up the cached {conn,src,dst}, falling back to {conn} alone if
        //    this script never saw the connection's onConnect.
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

        // Unsticks a pending pause when its connection terminates instead of leaving it
        // hanging forever. A no-op if this conn has no pending pause.
        rejectPause(conn) { settlePause(conn, 'reject', new Error('connection terminated while paused')) },
    }
    return runtime
}
