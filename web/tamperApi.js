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
// resolve or reject the one in-flight command promise (this wrapper only ever allows
// one at a time); "stream-list" both updates onStreamList and resolves a pending
// promise, since every stream-list is inherently a reply to list-streams — the server
// never pushes it unsolicited.
export function openTamperControl(handlers = {}) {
    const ws = new WebSocket(wsUrl(`${BASE}/control`))
    let pending = null // { resolve, reject }

    function settle(fn, value) {
        if (!pending) return
        const p = pending
        pending = null
        fn === 'resolve' ? p.resolve(value) : p.reject(value)
    }

    ws.onopen = () => handlers.onOpen?.()
    ws.onclose = () => {
        handlers.onClose?.()
        settle('reject', new Error('control connection closed'))
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

    function sendCommand(payload) {
        return new Promise((resolve, reject) => {
            pending = { resolve, reject }
            ws.send(JSON.stringify(payload))
        })
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
            const p = sendCommand({
                type: 'release', conn, direction, action,
                release_chunks: releaseChunks, edited,
                prefix_length: prefixLength, bounds,
            })
            if (edited) ws.send(editedBytes)
            return p
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
export function peekBuffer(conn, direction, offset, length) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl(`${BASE}/watch?conn=${conn}`))
        ws.binaryType = 'arraybuffer'
        let pendingMeta = null

        ws.onopen = () => ws.send(JSON.stringify({ type: 'peek', direction, offset, length }))
        ws.onerror = () => reject(new Error('WebSocket error'))
        ws.onmessage = event => {
            if (typeof event.data === 'string') {
                const msg = JSON.parse(event.data)
                if (msg.type === 'pending') {
                    pendingMeta = msg
                } else if (msg.type === 'peek-done') {
                    ws.close()
                    if (!pendingMeta) reject(new Error('no reply received for peek'))
                } else if (msg.type === 'error') {
                    ws.close()
                    reject(new Error(msg.message))
                }
            } else {
                const meta = pendingMeta
                pendingMeta = null
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
