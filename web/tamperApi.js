const BASE = '/api/i/tamper'

function wsUrl(path) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${location.host}${path}`
}

// Opens the single tamper control connection. handlers: { onOpen, onClose, onError,
// onStreamCreated, onStreamTerminated, onHeld, onStreamList, onScriptUpdated }, all
// optional.
//
// Returns { setAutoIntercept(enabled), setMode(conn, intercepting), listStreams(),
// release(conn, direction, opts, editedBytes?), dropConnection(conn, direction),
// close() }, each command returning a Promise.
//
// release's opts: { action: 'forward'|'drop', releaseChunks, edited, prefixLength,
// bounds } — mirrors the server's combined edit+release command directly (see
// intercept/tamper/protocol.go's inboundMsg doc comment). editedBytes is required iff
// opts.edited is true.
//
// Replies are matched by their "type", not by "the next message in": the server can
// interleave a push event (held/stream-created/stream-terminated) with the ok/error/
// stream-list reply to whatever command was just sent, since pushes originate from a
// different goroutine than command replies (see intercept/tamper/api.go). "ok"/"error"
// resolve or reject the in-flight command; "stream-list" both updates onStreamList and
// resolves it, since every stream-list is inherently a reply to list-streams — the
// server never pushes it unsolicited.
//
// Only one command is ever in flight to the server at a time — sendCommand below queues
// the rest rather than clobbering an outstanding one (a real bug this replaced: a naive
// "one pending slot" implementation lets a second call silently overwrite the first
// call's {resolve,reject} before its reply arrives, abandoning that promise forever).
// list-streams is the one call site (TamperView.js's resync(), invoked from every push
// event — in particular onHeld, which fires once per physical chunk a connection
// receives) that isn't naturally rate-limited by real outstanding decisions, so it's
// coalesced: at most one list-streams in flight plus at most one more already queued
// behind it, with every extra resync() call in between just attaching its
// resolve/reject to that single queued entry instead of enqueueing a new one. Every
// other command (release/dropConnection/setMode/setAutoIntercept) corresponds to a
// distinct, non-redundant decision — those are never merged, and the FIFO for them is
// bounded by how many such decisions are genuinely outstanding across all connections
// (further capped, for release, by scriptRuntime.js's own per-connection
// serialization — at most one ctx.release() in flight per connection at a time), not by
// per-chunk arrival frequency.
export function openTamperControl(handlers = {}) {
    const ws = new WebSocket(wsUrl(`${BASE}/control`))
    let pending = null   // { type, waiters: [{resolve,reject}, ...] } — the in-flight command
    const queue = []     // not-yet-sent commands: { payload, type, waiters, binaryFollowup? }

    function settleWaiters(waiters, fn, value) {
        for (const w of waiters) fn === 'resolve' ? w.resolve(value) : w.reject(value)
    }

    // Sends the next queued command, if the connection is idle and something's waiting.
    // The binary followup (release's edited-bytes frame) is sent in the same tick,
    // immediately after its JSON command, regardless of how long that command sat
    // queued — the wire protocol requires them adjacent, and queueing delay must never
    // let some other command's frame land in between.
    function pump() {
        if (pending || queue.length === 0) return
        const next = queue.shift()
        pending = { type: next.type, waiters: next.waiters }
        ws.send(JSON.stringify(next.payload))
        if (next.binaryFollowup) ws.send(next.binaryFollowup)
    }

    function settle(fn, value) {
        if (!pending) return
        const p = pending
        pending = null
        settleWaiters(p.waiters, fn, value)
        pump()
    }

    ws.onopen = () => handlers.onOpen?.()
    ws.onclose = () => {
        handlers.onClose?.()
        settle('reject', new Error('control connection closed'))
        // Anything still queued has no chance of ever being sent now — reject it too,
        // rather than leaving those promises unsettled forever.
        for (const q of queue.splice(0)) settleWaiters(q.waiters, 'reject', new Error('control connection closed'))
    }
    ws.onerror = () => handlers.onError?.(new Error('WebSocket error'))
    ws.onmessage = event => {
        const msg = JSON.parse(event.data)
        switch (msg.type) {
            case 'ok':
                settle('resolve', msg)
                break
            case 'error':
                if (pending) settle('reject', new Error(msg.message))
                else handlers.onError?.(new Error(msg.message))
                break
            case 'stream-created':
                handlers.onStreamCreated?.(msg)
                break
            case 'stream-terminated':
                handlers.onStreamTerminated?.(msg)
                break
            case 'held':
                handlers.onHeld?.(msg)
                break
            case 'stream-list':
                handlers.onStreamList?.(msg.streams)
                settle('resolve', msg)
                break
            case 'script-updated':
                handlers.onScriptUpdated?.(msg.name)
                break
        }
    }

    function sendCommand(payload, binaryFollowup) {
        if (payload.type === 'list-streams') {
            const last = queue[queue.length - 1]
            if (last && last.type === 'list-streams') {
                return new Promise((resolve, reject) => { last.waiters.push({ resolve, reject }) })
            }
        }
        const promise = new Promise((resolve, reject) => {
            queue.push({ payload, type: payload.type, waiters: [{ resolve, reject }], binaryFollowup })
        })
        pump()
        return promise
    }

    return {
        setAutoIntercept(enabled) {
            return sendCommand({ type: 'set-auto-intercept', enabled })
        },
        setMode(conn, intercepting) {
            return sendCommand({ type: 'set-mode', conn, intercepting })
        },
        listStreams() {
            return sendCommand({ type: 'list-streams' })
        },
        release(conn, direction, opts, editedBytes) {
            const { action, releaseChunks = 0, edited = false, prefixLength = 0, bounds = [] } = opts
            return sendCommand({
                type: 'release', conn, direction, action,
                release_chunks: releaseChunks, edited,
                prefix_length: prefixLength, bounds,
            }, edited ? editedBytes : undefined)
        },
        dropConnection(conn, direction) {
            return sendCommand({ type: 'drop-connection', conn, direction })
        },
        // Fire-and-forget: the server never replies on success (see
        // intercept/tamper/protocol.go's cmdScriptLog), so this deliberately bypasses
        // sendCommand's one-in-flight pending-promise tracking rather than leaving a
        // promise that would never resolve. Silently dropped if the socket isn't open
        // (e.g. a log line racing connection teardown) — script logging is best-effort,
        // same as the browser's own in-memory log panel.
        scriptLog(level, text) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'script-log', level, text }))
            }
        },
        close() { ws.close() },
    }
}

// Reads one direction's currently-held buffer via a short-lived /watch connection: open,
// send "peek", collect the reply, close. Unlike the old per-chunk-id "peek", the server
// always replies with exactly one "pending" + binary pair (or a single "error" for an
// invalid direction) — a direction with nothing held is a normal zero-length reply, not
// an error. offset/length optionally slice the buffer; omit both for the whole thing.
//
// This connection is also registered server-side as a live-mirror watcher for as long as
// it's open (intercept/tamper/api.go's handleWatch) — mirroring fires on receipt of every
// chunk, regardless of hold/intercept state, so a chunk arriving on this stream while our
// own peek reply is still in flight interleaves its own unsolicited header+binary pair
// with ours on the very same socket. A mirror-frame header has no "type" field (unlike
// "pending"/"peek-done"/"error"), so text messages are already distinguishable — but
// since the server's writeJSON/writeBinary each independently acquire its per-connection
// writeMu (see watcher.writeJSON/writeBinary), not as one atomic pair, another goroutine's
// write can land between a header and its own binary payload; a single "last header seen"
// flag isn't enough if two unrelated pairs' headers both arrive before either's binary.
// awaiting is a FIFO of headers in arrival order (our own "pending" metadata, or null for
// a mirror frame) — every binary frame that arrives pairs with whichever header is at the
// front of that queue, which is always correct regardless of how many pairs interleave,
// since binaries arrive in the same relative order their own headers did.
export function peekBuffer(conn, direction, offset, length) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl(`${BASE}/watch?conn=${conn}`))
        ws.binaryType = 'arraybuffer'
        const awaiting = []
        let gotReply = false

        ws.onopen = () => ws.send(JSON.stringify({ type: 'peek', direction, offset, length }))
        ws.onerror = () => reject(new Error('WebSocket error'))
        ws.onmessage = event => {
            if (typeof event.data === 'string') {
                const msg = JSON.parse(event.data)
                if (msg.type === 'pending') {
                    awaiting.push(msg)
                } else if (msg.type === 'peek-done') {
                    ws.close()
                    if (!gotReply) reject(new Error('no reply received for peek'))
                } else if (msg.type === 'error') {
                    ws.close()
                    reject(new Error(msg.message))
                } else {
                    // Unsolicited live-mirror frame header — queue a marker so its binary
                    // payload, whenever it arrives relative to our own reply, is discarded
                    // rather than misread as ours.
                    awaiting.push(null)
                }
            } else {
                const meta = awaiting.shift()
                if (meta == null) return // a mirror frame's payload (or a stray extra binary) — not ours
                gotReply = true
                ws.close()
                resolve({
                    direction: meta.direction,
                    time: meta.time,
                    offset: meta.offset,
                    length: meta.length,
                    totalLength: meta.total_length,
                    bounds: meta.bounds ?? [],
                    data: new Uint8Array(event.data),
                })
            }
        }
    })
}

// Reports whether a script log file is configured server-side (see the tamper
// interceptor's "log-file" config arg), and its display filename — static for the
// server's whole run, so a plain one-shot GET is enough (no push event to track).
export async function getLogFileInfo() {
    const res = await checkOk(await fetch(`${BASE}/log-file`))
    return res.json()
}

// ── Script storage REST API (see intercept/tamper/scripts.go) ─────────────────────
// Content is a raw body (always UTF-8 JS text), not JSON/base64-wrapped.

async function checkOk(res) {
    if (!res.ok) {
        let message = res.statusText
        try {
            const body = await res.json()
            if (body.error) message = body.error
        } catch {}
        throw new Error(message)
    }
    return res
}

export async function listScripts() {
    const res = await checkOk(await fetch(`${BASE}/scripts`))
    return res.json()
}

export async function getScript(name) {
    const res = await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`))
    return res.text()
}

export async function putScript(name, content) {
    await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/javascript' },
        body: content,
    }))
}

export async function deleteScript(name) {
    await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' }))
}

// ── Filesystem REST API (see intercept/tamper/fs.go) ───────────────────────────────
// Content is a raw body (arbitrary binary), not JSON/base64-wrapped. path is always
// slash-separated, even for a nested subdirectory — segments are percent-encoded
// individually (not the path as a whole) so slashes survive as separators, matching the
// server's {path...} wildcard route.

function encodeFsPath(path) {
    return path.split('/').filter(s => s !== '').map(encodeURIComponent).join('/')
}

export async function listFs(path = '') {
    const enc = encodeFsPath(path)
    const res = await checkOk(await fetch(`${BASE}/fs/list${enc ? '/' + enc : ''}`))
    return res.json()
}

export async function readFs(path) {
    const res = await checkOk(await fetch(`${BASE}/fs/file/${encodeFsPath(path)}`))
    return new Uint8Array(await res.arrayBuffer())
}

export async function writeFs(path, bytes) {
    await checkOk(await fetch(`${BASE}/fs/file/${encodeFsPath(path)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: bytes,
    }))
}

// POST, not PUT: appending isn't idempotent (repeat = appended twice), unlike write/PUT
// above — see intercept/tamper/fs.go's handleFsAppend doc comment. Creates the file
// (and missing parent directories) if it doesn't exist yet, same as writeFs.
export async function appendFs(path, bytes) {
    await checkOk(await fetch(`${BASE}/fs/file/${encodeFsPath(path)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: bytes,
    }))
}
