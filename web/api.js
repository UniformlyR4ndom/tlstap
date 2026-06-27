const BASE = '/api/i/dbdump'

function wsUrl(path) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${location.host}${path}`
}

async function post(path, body) {
    const r = await fetch(BASE + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    })
    if (!r.ok) throw new Error(await r.text())
    return r.json()
}

export async function getSessions() {
    const r = await fetch(BASE + '/sessions')
    if (!r.ok) throw new Error(await r.text())
    return r.json()
}

export function getStreams(sessionId) {
    return post('/streams', { session: sessionId })
}

export function getChunkList(sessionId, streamId) {
    return post('/chunklist', { session: sessionId, stream: streamId })
}

export function getChunkStid(sessionId, streamId, direction, id) {
    return post('/chunk-stid', { session: sessionId, stream: streamId, direction, id })
}

export function getByteStid(sessionId, streamId, direction, offset) {
    return post('/byte-stid', { session: sessionId, stream: streamId, direction, offset })
}

export function searchText(req) {
    return post('/search-text', req)
}

// Opens a persistent WebSocket for chunk streaming.
// Returns { fetch(streamId, direction, start, limit) → Promise<chunk[]>, close() }.
// The server processes requests sequentially; only one fetch should be in
// flight at a time per connection.
export function openStidStream() {
    const ws = new WebSocket(wsUrl(`${BASE}/stid-stream`))
    ws.binaryType = 'arraybuffer'

    let isOpen = false
    let openResolve, openReject
    const ready = new Promise((res, rej) => { openResolve = res; openReject = rej })

    let pendingMeta    = null
    let currentChunks  = []
    let currentResolve = null
    let currentReject  = null

    function fail(err) {
        if (!isOpen) openReject(err)
        if (currentReject) {
            currentReject(err)
            currentResolve = null
            currentReject  = null
        }
    }

    ws.onopen    = ()  => { isOpen = true; openResolve() }
    ws.onerror   = ()  => fail(new Error('WebSocket error'))
    ws.onclose   = e   => { if (!e.wasClean) fail(new Error('WebSocket connection lost')) }
    ws.onmessage = event => {
        if (typeof event.data === 'string') {
            const msg = JSON.parse(event.data)
            if (msg.done) {
                const chunks = currentChunks
                currentChunks  = []
                currentResolve?.(chunks)
                currentResolve = null
                currentReject  = null
            } else if (msg.error) {
                currentReject?.(new Error(msg.error))
                currentResolve = null
                currentReject  = null
            } else {
                pendingMeta = msg
            }
        } else if (pendingMeta) {
            currentChunks.push({
                stid:      pendingMeta.stid,
                chunkId:   pendingMeta['chunk-id'],
                direction: pendingMeta.direction,
                time:      pendingMeta.time,
                offset:    pendingMeta.offset,
                data:      new Uint8Array(event.data),
            })
            pendingMeta = null
        }
    }

    return {
        fetch(sessionId, streamId, start, n) {
            return ready.then(() => new Promise((resolve, reject) => {
                currentResolve = resolve
                currentReject  = reject
                currentChunks  = []
                ws.send(JSON.stringify({ session: sessionId, stream: streamId, start, n }))
            }))
        },
        close() { ws.close() },
    }
}

export function openSgidStream() {
    const ws = new WebSocket(wsUrl(`${BASE}/sgid-stream`))
    ws.binaryType = 'arraybuffer'

    let isOpen = false
    let openResolve, openReject
    const ready = new Promise((res, rej) => { openResolve = res; openReject = rej })

    let pendingMeta    = null
    let currentChunks  = []
    let currentResolve = null
    let currentReject  = null

    function fail(err) {
        if (!isOpen) openReject(err)
        if (currentReject) {
            currentReject(err)
            currentResolve = null
            currentReject  = null
        }
    }

    ws.onopen    = ()  => { isOpen = true; openResolve() }
    ws.onerror   = ()  => fail(new Error('WebSocket error'))
    ws.onclose   = e   => { if (!e.wasClean) fail(new Error('WebSocket connection lost')) }
    ws.onmessage = event => {
        if (typeof event.data === 'string') {
            const msg = JSON.parse(event.data)
            if (msg.done) {
                const chunks = currentChunks
                currentChunks  = []
                currentResolve?.(chunks)
                currentResolve = null
                currentReject  = null
            } else if (msg.error) {
                currentReject?.(new Error(msg.error))
                currentResolve = null
                currentReject  = null
            } else {
                pendingMeta = msg
            }
        } else if (pendingMeta) {
            currentChunks.push({
                sgid:      pendingMeta.sgid,
                chunkId:   pendingMeta['chunk-id'],
                stream:    pendingMeta.stream,
                direction: pendingMeta.direction,
                time:      pendingMeta.time,
                offset:    pendingMeta.offset,
                data:      new Uint8Array(event.data),
            })
            pendingMeta = null
        }
    }

    return {
        fetch(session, start, n) {
            return ready.then(() => new Promise((resolve, reject) => {
                currentResolve = resolve
                currentReject  = reject
                currentChunks  = []
                ws.send(JSON.stringify({ session, start, n }))
            }))
        },
        close() { ws.close() },
    }
}

