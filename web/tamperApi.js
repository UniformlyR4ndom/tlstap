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
// bounds } — mirrors the server's combined edit+release command directly. editedBytes
// is required iff opts.edited is true.
//
// Replies are matched by their "type", not by "the next message in": the server can
// interleave a push event (held/stream-created/stream-terminated) with the ok/error/
// stream-list reply to whatever command was just sent. "ok"/"error" resolve or reject
// the in-flight command; "stream-list" both updates onStreamList and resolves it, since
// every stream-list is inherently a reply to list-streams — the server never pushes it
// unsolicited.
//
// Only one command is ever in flight to the server at a time — sendCommand below queues
// the rest rather than clobbering an outstanding one. list-streams is coalesced (at most
// one in flight plus one queued, with extra calls attaching to the queued one) since it
// can be issued redundantly at high frequency, unlike every other command
// (release/dropConnection/setMode/setAutoIntercept), each of which corresponds to a
// distinct, non-redundant decision and is never merged.
export function openTamperControl(handlers = {}) {
    const ws = new WebSocket(wsUrl(`${BASE}/control`))
    let pending = null   // { type, waiters: [{resolve,reject}, ...] } — the in-flight command
    const queue = []     // not-yet-sent commands: { payload, type, waiters, binaryFollowup? }

    function settleWaiters(waiters, fn, value) {
        for (const w of waiters) fn === 'resolve' ? w.resolve(value) : w.reject(value)
    }

    // Sends the next queued command, if the connection is idle and something's waiting.
    // A binary followup (release's edited-bytes frame) is sent immediately after its
    // JSON command, in the same tick — the wire protocol requires them adjacent.
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
        // Fire-and-forget: the server never replies on success, so this deliberately
        // bypasses sendCommand's one-in-flight pending-promise tracking rather than
        // leaving a promise that would never resolve. Silently dropped if the socket
        // isn't open (e.g. a log line racing connection teardown) — script logging
        // here is best-effort.
        scriptLog(level, text) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'script-log', level, text }))
            }
        },
        close() { ws.close() },
    }
}

// Reads one direction's currently-held buffer via a short-lived /watch connection: open,
// send "peek", collect the reply, close. The server always replies with exactly one
// "pending" + binary pair (or a single "error" for an invalid direction) — a direction
// with nothing held is a normal zero-length reply, not an error. offset/length
// optionally slice the buffer; omit both for the whole thing.
//
// This connection is also registered server-side as a live-mirror watcher for as long
// as it's open — mirroring fires on receipt of every chunk regardless of hold/intercept
// state, so a chunk arriving here while our own peek reply is still in flight
// interleaves its own unsolicited header+binary pair with ours on the same socket. A
// mirror-frame header has no "type" field, so text messages are already distinguishable,
// but header and binary writes aren't atomic server-side, so another write can land
// between a header and its own binary payload — a single "last header seen" flag isn't
// enough if two pairs' headers both arrive before either's binary. `awaiting` is a FIFO
// of headers in arrival order (our own "pending" metadata, or null for a mirror frame);
// each binary frame pairs with whichever header is at the front, which is always correct
// since binaries arrive in the same relative order as their headers.
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

// Reports whether a script log file is configured server-side (the tamper
// interceptor's "log-file" config arg), and its display filename — static for the
// server's whole run, so a one-shot GET needs no push event to track.
export async function getLogFileInfo() {
    const res = await checkOk(await fetch(`${BASE}/log-file`))
    return res.json()
}

// ── Script storage REST API ────────────────────────────────────────────────────────
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

// ── Filesystem REST API ─────────────────────────────────────────────────────────────
// Content is a raw body (arbitrary binary), not JSON/base64-wrapped. path is always
// slash-separated, even for a nested subdirectory — segments are percent-encoded
// individually (not the path as a whole) so slashes survive as separators, matching how
// the server parses the path.

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

// POST, not PUT: appending isn't idempotent (repeat = appended twice), unlike PUT
// above. Creates the file (and missing parent directories) if it doesn't exist yet.
export async function appendFs(path, bytes) {
    await checkOk(await fetch(`${BASE}/fs/file/${encodeFsPath(path)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: bytes,
    }))
}
