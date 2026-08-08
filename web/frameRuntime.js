// Runs one user framer script's frame(state, chunk) function in a Worker over a
// pre-fetched list of raw chunks, producing frame-index batches to persist. No RPC
// bridge: a framer script is a pure function over bytes already in hand, so the only
// back-and-forth is a batch/ack cycle — the caller awaits each batch's persistence
// before the Worker computes the next one.
//
// Script contract: a plain top-level function frame(state, chunk). chunk is
// {offset, length, direction, data} — one raw chunk, in stream order for one direction
// ('c2s'/'s2c', fixed for the run but carried on every chunk). state and the returned
// {frames, state} are plain JSON-serializable values, never bytes/base64. Each returned
// frame is {offset, length, meta?}. No frame function defined, or one that throws,
// rejects runFramer's returned promise.

const BATCH_FRAMES = 500  // flush a batch after this many frames accumulate
const BATCH_BYTES = 2 * 1024 * 1024 // ...or this many bytes processed, whichever first

const BOOTSTRAP = `
(function () {
    let pendingAck = null

    function postBatchAndWait(frames, state, processedOffset) {
        return new Promise((resolve, reject) => {
            pendingAck = { resolve, reject }
            postMessage({ kind: 'batch', frames, state, processedOffset })
        })
    }

    async function runScript(initialState, chunks) {
        if (typeof frame !== 'function') {
            throw new Error('framer script must define a top-level function named "frame"')
        }

        let state = initialState
        let pending = []
        let pendingBytes = 0
        let processedOffset = 0

        for (const chunk of chunks) {
            const result = frame(state, chunk) || {}
            if ('state' in result) state = result.state
            for (const f of result.frames || []) pending.push(f)
            pendingBytes += chunk.length
            processedOffset = chunk.offset + chunk.length

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
            runScript(msg.initialState, msg.chunks)
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

// Runs the script's frame function over chunks (in order), starting from initialState.
// onBatch(batch) is called with { frames, state, processedOffset } after every
// BATCH_FRAMES frames or BATCH_BYTES bytes, whichever comes first, and once more at the
// end (even if empty) so a final state-only advance still persists; it must return a
// Promise, and the Worker waits for it before computing the next batch.
//
// Rejects and stops the Worker immediately, computing nothing further, if the script
// throws, never defines frame, or an onBatch call rejects (e.g. a 409 indicating someone
// else already advanced this key).
export function runFramer(scriptName, scriptSource, initialState, chunks, onBatch) {
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
            }
        }
        worker.onerror = (e) => {
            cleanup()
            reject(new Error(e.message || String(e)))
            e.preventDefault()
        }

        worker.postMessage({ kind: 'run', initialState, chunks })
    })
}
