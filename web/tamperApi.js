const BASE = '/api/i/tamper'

function wsUrl(path) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${location.host}${path}`
}

// Opens the single tamper control connection. handlers: { onOpen, onClose, onError,
// onStreamCreated, onStreamTerminated, onHeld, onStreamList }, all optional.
//
// Returns { setAutoIntercept(enabled), setMode(conn, intercepting), listStreams(),
// resolve(conn, id, action, editedBytes?), close() }, each command returning a Promise.
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
        resolve(conn, id, action, editedBytes) {
            const edited = editedBytes != null
            const p = sendCommand({ type: 'resolve', conn, id, action, edited })
            if (edited) ws.send(editedBytes)
            return p
        },
        close() { ws.close() },
    }
}

// Reads one currently-held chunk's bytes via a short-lived /watch connection: open,
// send "peek", collect the reply, close. Rejects if the chunk isn't currently pending.
export function peekChunk(conn, id) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl(`${BASE}/watch?conn=${conn}`))
        ws.binaryType = 'arraybuffer'
        let pendingMeta = null

        ws.onopen = () => ws.send(JSON.stringify({ type: 'peek', id }))
        ws.onerror = () => reject(new Error('WebSocket error'))
        ws.onmessage = event => {
            if (typeof event.data === 'string') {
                const msg = JSON.parse(event.data)
                if (msg.type === 'pending') {
                    pendingMeta = msg
                } else if (msg.type === 'peek-done') {
                    ws.close()
                    if (!pendingMeta) reject(new Error('chunk not found or no longer pending'))
                } else if (msg.type === 'error') {
                    ws.close()
                    reject(new Error(msg.message))
                }
            } else {
                const meta = pendingMeta
                pendingMeta = null
                ws.close()
                resolve({
                    id: meta.id,
                    direction: meta.direction,
                    time: meta.time,
                    offset: meta.offset,
                    length: meta.length,
                    totalLength: meta.total_length,
                    data: new Uint8Array(event.data),
                })
            }
        }
    })
}
