// Runs one user script in a Worker and bridges it to the tamper control/watch
// connections via postMessage RPC: `call` messages invoke a handler on the main thread and
// get a matching `result` back; `event` messages push onConnect/onReceive/onClose in.
// `tamper.transform.*`/`encode.*`/`decode.*` bypass this bridge and run synchronously
// inside the Worker instead.
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

import { OPERATIONS_BY_CATEGORY } from './transforms.js'
import { DIRNUM_C2S, DIRNUM_S2C } from './direction.js'

// Absolute URLs, so BOOTSTRAP's dynamic import() can resolve their own relative imports
// (transforms/*, vendor/*) from inside a Blob-URL worker, where a relative specifier
// wouldn't resolve.
const TRANSFORMS_URL = new URL('./transforms.js', import.meta.url).href
const FORMAT_URL = new URL('./format.js', import.meta.url).href

// Maps an op id that can't camelCase into a valid identifier (leads with a digit, e.g.
// `3des-encrypt`) or that collides with its own inverse (`xor-encrypt`/`xor-decrypt` is a
// self-inverse repeating-key XOR) to the name actually exposed on tamper.transform.<category>.
const TRANSFORM_NAME_OVERRIDES = {
    '3des-encrypt': 'tripleDesEncrypt',
    '3des-decrypt': 'tripleDesDecrypt',
    'xor-encrypt': 'xorCrypt',
    'xor-decrypt': 'xorCrypt',
}

// Exported so its output can be mirrored by an autocomplete shape elsewhere.
export function camelCaseOpId(opId) {
    return TRANSFORM_NAME_OVERRIDES[opId] ?? opId.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase())
}

// Built once (the op catalog is static for the page's lifetime) and spliced directly into
// BOOTSTRAP; the actual OPERATIONS values are looked up inside the Worker itself. A
// camelCase collision keeps the first op id and skips the rest — safe since a collision
// only happens between op ids whose run() is the same function.
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

    // pump() gates all hook dispatch on ready, so a script's handlers never see
    // OPERATIONS/FORMAT as null; a call made before ready (e.g. at the script's own top
    // level) falls back to a Promise via whenReady().
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

    // Defaults for the no-params case: plain contiguous hex/base64, matching how a digest
    // is normally printed.
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

    // Escape hatch: available directly on tamper, not just through ctx, for use outside
    // onReceive or to bypass ctx's bookkeeping.
    const raw = {
        peek:           (conn, direction) => call('peek', [conn, direction]),
        release:        (conn, direction, opts, editedBytes) => call('release', [conn, direction, opts, editedBytes]),
        dropConnection: (conn, direction) => call('dropConnection', [conn, direction]),
        setIntercept:   (conn, intercepting) => call('setIntercept', [conn, intercepting]),
        listStreams:    () => call('listStreams', []),
    }

    // Routed through the same RPC bridge as everything else, even though the transport is
    // a REST fetch, since a Blob-URL worker has no page origin to resolve a relative
    // fetch() against. Rejects if fs-root isn't configured server-side. appendFile is a
    // real server-side op, not a client read+concatenate+write, which would race
    // independently-scheduled onReceive handlers across connections.
    const fs = {
        listFiles:  (path) => call('fsList', [path]),
        readFile:   (path) => call('fsRead', [path]),
        writeFile:  (path, bytes) => call('fsWrite', [path, bytes]),
        appendFile: (path, bytes) => call('fsAppend', [path, bytes]),
    }

    // ctx handed to onReceive. get/set/append are purely local; release/drop/pause touch
    // the network. A commit always replaces the buffer's entire current content, never a
    // partial prefix — set()/append() discard original chunk-boundary structure since a
    // script reasons about "the buffer," not TCP chunk boundaries.
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

    // Serializes events per connection (both directions together), one at a time;
    // different conns run independently.
    //
    // Consecutive queued onReceive entries for the same (conn, direction) coalesce into
    // one dispatch — TCP gives no guaranteed chunking, so a 'held' notification just means
    // "look at the buffer again." offset comes from the earliest entry, length is summed,
    // so ctx.newLength still means "new bytes since the last dispatch."
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

    // Deferred until after self.tamper/onmessage/the error listeners are wired up, so a
    // failure here is never missed and events arriving first just queue (pump()'s ready
    // guard).
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

// Wrapped in its own IIFE so top-level declarations can't collide with BOOTSTRAP's; the
// trailing sourceURL names it correctly in DevTools/stack traces.
function buildScriptSource(name, source) {
    return `;(function(){\n${source}\n})();\n//# sourceURL=${sanitizeScriptSourceUrl(name)}\n`
}

// BOOTSTRAP plus a trailing importScripts() of the script's own Blob — the Worker's
// actual entry point. A script syntax error is caught here and reported as 'fatal'
// without preventing BOOTSTRAP itself from finishing initialization.
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
// direction, paused) }. All must return Promises except onLog/onStatusChange/onPauseChange.
// The fs calls take no conn/direction — fs-root access isn't scoped to a connection.
// onLog's level is 'log' | 'error'; prefix (set only for a ctx.log call) is a ready-made
// connection-summary + timestamp line meant to render above the args, not merged into
// them. onPauseChange fires when a script's ctx.pause() call starts/stops waiting on a
// human "Continue".
export function createScriptRuntime(handlers) {
    let worker = null
    let blobUrls = []  // [scriptBlobUrl, bootstrapBlobUrl] — both revoked together in stop()
    let runningName = null
    const connMeta = new Map()      // conn -> {conn,src,dst}, cached from onConnect for onClose
    const pendingPauses = new Map() // conn -> {direction, resolve, reject}; at most one per
                                     // conn, since per-conn serialization allows only one
                                     // in-flight onReceive (and so pause) at a time.

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
            handlers.onLog?.('log', msg.args)
        } else if (msg.kind === 'ctxlog') {
            // meta can be missing if this conn's onConnect predates the running script, or
            // if connMeta was already cleared on 'onClose' while an onReceive's ctx.log
            // call was still queued behind it.
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
        start(name, source) {
            runtime.stop()
            const scriptBlobUrl = URL.createObjectURL(new Blob([buildScriptSource(name, source)], { type: 'text/javascript' }))
            const bootstrapBlobUrl = URL.createObjectURL(new Blob([buildWorkerSource(scriptBlobUrl)], { type: 'text/javascript' }))
            blobUrls = [scriptBlobUrl, bootstrapBlobUrl]
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
        //  - onReceive: [direction, offset, length] — direction converted to string.
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
