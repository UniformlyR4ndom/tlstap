// Runs one user dissector script's dissect(bytes, frame) function in a Worker, once per
// call, producing a field-node tree for the UI. No RPC bridge and no batch/ack cycle: a
// dissector script is a pure, synchronous function over bytes already in hand (unlike
// frameRuntime.js, there's no stream to walk) — the Worker interface really is just
// "post bytes+frame in, get a result back", per doc/design/packet-dissector.md's
// "Execution model".
//
// Script contract: a plain top-level function dissect(bytes, frame), sync or async —
// always awaited (so a script that needs dissector.fs.*/kv.* below can just await them
// inline), returning FieldNode[] — top-level siblings, not one wrapping root (see the
// design doc's "Field node schema"). frame is {offset, length, direction, kind, ...}, the
// same shape a framer script tags its frames with. No dissect function defined, one that
// throws, or one that doesn't return an array all reject runDissector's returned promise.
//
// A global `dissector` object exposes the same transform framework framer/tamper scripts
// get, under dissector.transform.*/encode.*/decode.*/number.* (mirroring framer.*'s
// shape and always-synchronous convention — see frameRuntime.js's own header comment for
// why), plus dissector.fs.*/kv.* (coreApiClient.js) — real network calls, so unlike the
// transform surface above these always return a Promise and must be awaited; see
// core/CLAUDE.md for core.fs/core.kv themselves and coreApiClient.js's own header for the
// method list. Named `dissector`, not `dissect`, so it can't collide with the script's own
// top-level `function dissect(...)` declaration. Lets a script that needs to, say,
// decompress a sub-payload before reporting it as a node's `content` do so
// (dissector.transform.compression.zlibDecompress(bytes)) and base64-encode the result
// itself (dissector.encode.base64(...)) without a second formatting implementation.

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

// dissector.transform.<category>'s function bodies call OPERATIONS directly — always
// plain sync, since runScript never calls dissect() before modulesReady has resolved.
const DISSECTOR_TRANSFORM_API_SOURCE = buildTransformApiSource(
    opId => `(bytes, params) => OPERATIONS[${JSON.stringify(opId)}].run(bytes, params)`,
)

// dissector.number.decode<Type>/encode<Type> — real numbers/bigints, not decimal text;
// each type's own shape is inlined so no runtime lookup back into NUMBER_TYPES is needed.
const DISSECTOR_NUMBER_API_SOURCE = buildNumberApiSource((type, kind) => {
    const typeJson = JSON.stringify(type)
    return kind === 'decode'
        ? `(bytes) => decodeNumberValue(bytes, ${typeJson})`
        : `(value) => encodeNumberValue(value, ${typeJson})`
})

const BOOTSTRAP = `
(function () {
    let OPERATIONS = null
    let FORMAT = null
    let decodeNumberValue = null
    let encodeNumberValue = null

    const HEX_DEFAULTS = ${JSON.stringify(HEX_DEFAULTS)}
    const BASE64_DEFAULTS = ${JSON.stringify(BASE64_DEFAULTS)}

    const modulesReady = (async () => {
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
        self.dissector = {
            transform: ${DISSECTOR_TRANSFORM_API_SOURCE},
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
            number: ${DISSECTOR_NUMBER_API_SOURCE},
            fs: coreApiMod.createFsApi(${JSON.stringify(FS_BASE_URL)}),
            kv: coreApiMod.createKvApi(${JSON.stringify(KV_BASE_URL)}),
        }
    })()

    async function runScript(bytes, frame) {
        if (typeof dissect !== 'function') {
            throw new Error('dissector script must define a top-level function named "dissect"')
        }
        await modulesReady
        const nodes = await dissect(bytes, frame)
        if (!Array.isArray(nodes)) {
            throw new Error('dissector script\\'s "dissect" function must return an array of field nodes')
        }
        return nodes
    }

    self.onmessage = (e) => {
        const msg = e.data
        if (msg.kind === 'run') {
            runScript(msg.bytes, msg.frame)
                .then(nodes => postMessage({ kind: 'result', nodes }))
                .catch(err => postMessage({ kind: 'error', message: (err && (err.stack || err.message)) || String(err) }))
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

// Deliberately not wrapped in an IIFE: the dissector contract looks `dissect` up by name
// (BOOTSTRAP's typeof dissect / dissect(...)), and an IIFE would trap the declaration in
// its own local scope instead of the global one BOOTSTRAP looks it up in.
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
//# sourceURL=dissect-bootstrap.js
`
}

// Runs the script's dissect function once over bytes/frame, resolving with the returned
// FieldNode[]. A fresh Worker per call (no reuse across frames) — dissection is
// on-demand per selected frame, not a running process, so there's no state that would
// benefit from surviving between calls; revisit if per-click Worker startup cost turns
// out to matter in practice.
//
// Rejects if the script throws, never defines dissect, or dissect doesn't return an
// array.
export function runDissector(scriptName, scriptSource, bytes, frame) {
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
            if (msg.kind === 'result') {
                cleanup()
                resolve(msg.nodes)
            } else if (msg.kind === 'error') {
                cleanup()
                reject(new Error(msg.message))
            }
        }
        worker.onerror = (e) => {
            cleanup()
            reject(new Error(e.message || String(e)))
            e.preventDefault()
        }

        worker.postMessage({ kind: 'run', bytes, frame })
    })
}
