// Runs one user framer script's frame(state, chunk) function in a Worker over a
// pre-fetched list of raw chunks — both directions merged into one chronological
// sequence (combined mode; see doc/design/framer-cross-direction-correlation.md) —
// producing frame-index batches to persist. No RPC bridge: a framer script is a pure
// function over bytes already in hand, so the only back-and-forth is a batch/ack cycle —
// the caller awaits each batch's persistence before the Worker computes the next one.
//
// Script contract: a plain top-level function frame(state, chunk), sync or async — always
// awaited (so a script that needs framer.fs.*/kv.* below can just await them inline).
// chunk is {offset, length, direction, data} — one raw chunk, in true chronological (stid)
// order across *both* directions, so chunk.direction ('c2s'/'s2c') now varies call to call
// within one run rather than being fixed for it; a script correlating the two keeps
// per-direction sub-state (e.g. state.c2s/state.s2c) itself. state and the returned
// {frames, state} are plain JSON-serializable values, never bytes/base64. Each returned
// frame is {ranges: [{offset, length}], meta?} — direction is not part of that shape; runScript below
// tags each with whichever chunk's frame() call produced it. No frame function defined,
// or one that throws, rejects runFramer's returned promise.
//
// A global `framer` object exposes the same transform framework tamper scripts get, under
// framer.transform.*/encode.*/decode.*/number.* (mirroring tamper.*'s shape, sans the
// `tamper` prefix). Unlike tamper's version, these are always plain synchronous — never a
// Promise — because runScript (unlike tamper's live event dispatch) only starts once
// explicitly told to via the 'run' message, so it can simply await the module import
// finishing first; a framer script's own top level, outside frame(), has no such
// guarantee and shouldn't reference framer.* there. framer.log(...args) — a plain
// postMessage, no OPERATIONS/FORMAT dependency — is surfaced to runFramer's caller via
// the optional onLog callback below. framer.hpack.decode(bytes, table) — decode-only
// HPACK (hpackDecode.js), the odd one out here: unlike transform/encode/decode/number,
// it's not part of the shared tamper/framer/dissector transform framework — HPACK's
// per-direction dynamic table state doesn't fit dissector scripts (which carry no
// cross-frame state at all), so it's exposed to framer scripts only. See
// hpackDecode.js's own header comment for the table-threading contract.
// framer.fs.*/framer.kv.* (coreApiClient.js) — the odd ones out the other way: real
// network calls, so unlike every surface above these always return a Promise and must be
// awaited. See core/CLAUDE.md for core.fs/core.kv themselves and coreApiClient.js's own
// header for the method list.

import { buildTransformApiSource, buildNumberApiSource, HEX_DEFAULTS, BASE64_DEFAULTS } from './transformWorkerApi.js'

const BATCH_FRAMES = 500  // flush a batch after this many frames accumulate
const BATCH_BYTES = 2 * 1024 * 1024 // ...or this many bytes processed, whichever first

// Absolute URLs, so BOOTSTRAP's dynamic import() can resolve their own relative imports
// (transforms/*, vendor/*) from inside a Blob-URL worker, where a relative specifier
// wouldn't resolve.
const TRANSFORMS_URL = new URL('./transforms.js', import.meta.url).href
const FORMAT_URL = new URL('./format.js', import.meta.url).href
const HPACK_URL = new URL('./hpackDecode.js', import.meta.url).href
const CORE_API_URL = new URL('./coreApiClient.js', import.meta.url).href

// Absolute origin, for the same relative-URL-resolution reason as the module URLs above —
// baked into BOOTSTRAP as string literals and handed to createFsApi/createKvApi.
const FS_BASE_URL = new URL('/api/core/fs', location.href).href
const KV_BASE_URL = new URL('/api/core/kv', location.href).href

// framer.transform.<category>'s function bodies call OPERATIONS directly — always plain
// sync, since runScript never calls frame() before modulesReady has resolved.
const FRAMER_TRANSFORM_API_SOURCE = buildTransformApiSource(
    opId => `(bytes, params) => OPERATIONS[${JSON.stringify(opId)}].run(bytes, params)`,
)

// framer.number.decode<Type>/encode<Type> — real numbers/bigints, not decimal text; each
// type's own shape is inlined so no runtime lookup back into NUMBER_TYPES is needed.
const FRAMER_NUMBER_API_SOURCE = buildNumberApiSource((type, kind) => {
    const typeJson = JSON.stringify(type)
    return kind === 'decode'
        ? `(bytes) => decodeNumberValue(bytes, ${typeJson})`
        : `(value) => encodeNumberValue(value, ${typeJson})`
})

const BOOTSTRAP = `
(function () {
    let pendingAck = null
    let OPERATIONS = null
    let FORMAT = null
    let decodeNumberValue = null
    let encodeNumberValue = null
    // Set at the top of each loop iteration below, before calling frame() — lets
    // framer.log tag its own postMessage with whichever chunk's call it was made
    // from, since a script's log call has no other way to say which direction it's
    // about (combined mode's chunks span both).
    let currentDirection = null

    const HEX_DEFAULTS = ${JSON.stringify(HEX_DEFAULTS)}
    const BASE64_DEFAULTS = ${JSON.stringify(BASE64_DEFAULTS)}

    let hpackMod = null

    const modulesReady = (async () => {
        const [transformsMod, formatMod, hpackModule, coreApiMod] = await Promise.all([
            import(${JSON.stringify(TRANSFORMS_URL)}),
            import(${JSON.stringify(FORMAT_URL)}),
            import(${JSON.stringify(HPACK_URL)}),
            import(${JSON.stringify(CORE_API_URL)}),
        ])
        await transformsMod.warmupWhirlpool()
        OPERATIONS = transformsMod.OPERATIONS
        FORMAT = formatMod
        decodeNumberValue = transformsMod.decodeNumberValue
        encodeNumberValue = transformsMod.encodeNumberValue
        hpackMod = hpackModule
        self.framer = {
            transform: ${FRAMER_TRANSFORM_API_SOURCE},
            encode: {
                hex:     (bytes, params) => new TextDecoder().decode(OPERATIONS['hex-encode'].run(bytes, { ...HEX_DEFAULTS, ...params })),
                base64:  (bytes, params) => new TextDecoder().decode(OPERATIONS['base64-encode'].run(bytes, { ...BASE64_DEFAULTS, ...params })),
                hexdump: (bytes, baseOffset) => FORMAT.fmtAsHexdump(bytes, baseOffset ?? 0),
            },
            decode: {
                hex:     (text, params) => OPERATIONS['hex-decode'].run(new TextEncoder().encode(text), { ...HEX_DEFAULTS, ...params }),
                base64:  (text, params) => OPERATIONS['base64-decode'].run(new TextEncoder().encode(text), { ...BASE64_DEFAULTS, ...params }),
                hexdump: (text) => FORMAT.parseHexdump(text),
            },
            number: ${FRAMER_NUMBER_API_SOURCE},
            // Decode-only HPACK (RFC 7541): decode(bytes, table) turns one complete,
            // already-reassembled HEADERS/CONTINUATION header block into { headers,
            // table } — table is the previous call's returned table, or
            // undefined/null for a direction's first block. Threading it back in on
            // the next call (via the script's own persisted state, same as a carry
            // buffer) is the script's job — this function carries no state of its own.
            hpack: { decode: (bytes, table) => hpackMod.decodeHeaderBlock(bytes, table) },
            log: (...args) => postMessage({ kind: 'log', args, direction: currentDirection }),
            fs: coreApiMod.createFsApi(${JSON.stringify(FS_BASE_URL)}),
            kv: coreApiMod.createKvApi(${JSON.stringify(KV_BASE_URL)}),
        }
    })()

    function postBatchAndWait(frames, state, processedOffset) {
        return new Promise((resolve, reject) => {
            pendingAck = { resolve, reject }
            postMessage({ kind: 'batch', frames, state, processedOffset })
        })
    }

    async function runScript(initialState, initialProcessedOffset, chunks) {
        if (typeof frame !== 'function') {
            throw new Error('framer script must define a top-level function named "frame"')
        }
        await modulesReady

        let state = initialState
        let pending = []
        let pendingBytes = 0
        // Per-direction, seeded from the caller's own current progress rather than 0:
        // a batch flushed after only one direction's chunks have been touched so far
        // this run must still report the OTHER direction's already-correct offset, not
        // rewind it to 0.
        let processedOffset = { c2s: initialProcessedOffset.c2s, s2c: initialProcessedOffset.s2c }

        for (const chunk of chunks) {
            // Numeric (0/1), matching frames.direction's own wire convention (and what
            // catchUpFramer's onLog(direction, args) contract expects) rather than
            // chunk.direction's script-facing 'c2s'/'s2c' string. Shared by the frame
            // tagging below and framer.log's own postMessage (via currentDirection).
            const dirNum = chunk.direction === 'c2s' ? 0 : 1
            currentDirection = dirNum
            const result = (await frame(state, chunk)) || {}
            if ('state' in result) state = result.state
            // direction isn't part of a script's own {ranges: [{offset, length}], meta?}
            // return shape — tagged here from whichever chunk produced it.
            for (const f of result.frames || []) pending.push({ ...f, direction: dirNum })
            pendingBytes += chunk.length
            processedOffset = { ...processedOffset, [chunk.direction]: chunk.offset + chunk.length }

            if (pending.length >= ${BATCH_FRAMES} || pendingBytes >= ${BATCH_BYTES}) {
                await postBatchAndWait(pending, state, processedOffset)
                pending = []
                pendingBytes = 0
            }
        }
        // Flush a final batch even if empty, so a run that only advances state (no new
        // frames in its last stretch) still persists that state/progress.
        if (chunks.length > 0) {
            await postBatchAndWait(pending, state, processedOffset)
        }
    }

    self.onmessage = (e) => {
        const msg = e.data
        if (msg.kind === 'run') {
            runScript(msg.initialState, msg.initialProcessedOffset, msg.chunks)
                .then(() => postMessage({ kind: 'done' }))
                .catch(err => postMessage({ kind: 'error', message: (err && (err.stack || err.message)) || String(err) }))
        } else if (msg.kind === 'continue') {
            pendingAck?.resolve()
            pendingAck = null
        }
    }

    self.addEventListener('error', (e) => { postMessage({ kind: 'error', message: e.message }); e.preventDefault() })
    self.addEventListener('unhandledrejection', (e) => { postMessage({ kind: 'error', message: (e.reason && e.reason.message) || String(e.reason) }); e.preventDefault() })
})();
`

function sanitizeScriptSourceUrl(name) {
    const base = String(name ?? '').replace(/[\r\n]/g, ' ').trim() || 'script'
    return base.endsWith('.js') ? base : `${base}.js`
}

// Deliberately not wrapped in an IIFE: the framer contract looks `frame` up by name
// (BOOTSTRAP's typeof frame / frame(...)), and an IIFE would trap the declaration in its
// own local scope instead of the global one BOOTSTRAP looks it up in.
function buildScriptSource(name, source) {
    return `${source}\n//# sourceURL=${sanitizeScriptSourceUrl(name)}\n`
}

function buildWorkerSource(scriptBlobUrl) {
    return `${BOOTSTRAP}
try {
    importScripts(${JSON.stringify(scriptBlobUrl)})
} catch (err) {
    postMessage({ kind: 'error', message: (err && (err.stack || err.message)) || String(err) })
}
//# sourceURL=frame-bootstrap.js
`
}

// Runs the script's frame function over chunks (in true chronological order, spanning
// both directions), starting from initialState. initialProcessedOffset is {c2s, s2c} —
// the caller's own current progress for each direction, seeded into the offset each
// batch reports so a batch that hasn't yet touched one direction still reports that
// direction's already-correct value rather than 0 (see runScript's own comment).
// onBatch(batch) is called with { frames, state, processedOffset } — frames now each
// carry their own numeric direction (tagged from whichever chunk produced them) and
// processedOffset is {c2s, s2c} — after every BATCH_FRAMES frames or BATCH_BYTES bytes,
// whichever comes first, and once more at the end (even if empty) so a final state-only
// advance still persists; it must return a Promise, and the Worker waits for it before
// computing the next batch.
//
// Rejects and stops the Worker immediately, computing nothing further, if the script
// throws, never defines frame, or an onBatch call rejects (e.g. a 409 indicating someone
// else already advanced this key). onLog (optional) is called with (direction, args) for
// a script's own framer.log(...) calls, in call order, whenever it uses that — direction
// is whichever chunk's frame() call was executing at the time, numeric (0/1). Best-effort,
// doesn't affect the run either way.
export function runFramer(scriptName, scriptSource, initialState, initialProcessedOffset, chunks, onBatch, onLog) {
    return new Promise((resolve, reject) => {
        const scriptBlobUrl = URL.createObjectURL(new Blob([buildScriptSource(scriptName, scriptSource)], { type: 'text/javascript' }))
        const bootstrapBlobUrl = URL.createObjectURL(new Blob([buildWorkerSource(scriptBlobUrl)], { type: 'text/javascript' }))
        const worker = new Worker(bootstrapBlobUrl)

        function cleanup() {
            worker.terminate()
            URL.revokeObjectURL(scriptBlobUrl)
            URL.revokeObjectURL(bootstrapBlobUrl)
        }

        worker.onmessage = (e) => {
            const msg = e.data
            if (msg.kind === 'batch') {
                Promise.resolve(onBatch({ frames: msg.frames, state: msg.state, processedOffset: msg.processedOffset }))
                    .then(() => worker.postMessage({ kind: 'continue' }))
                    .catch(err => { cleanup(); reject(err) })
            } else if (msg.kind === 'done') {
                cleanup()
                resolve()
            } else if (msg.kind === 'error') {
                cleanup()
                reject(new Error(msg.message))
            } else if (msg.kind === 'log') {
                onLog?.(msg.direction, msg.args)
            }
        }
        worker.onerror = (e) => {
            cleanup()
            reject(new Error(e.message || String(e)))
            e.preventDefault()
        }

        worker.postMessage({ kind: 'run', initialState, initialProcessedOffset, chunks })
    })
}
