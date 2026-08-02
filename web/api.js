const BASE = '/api/i/dbdump'

function wsUrl(path) {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${location.host}${path}`
}

async function okJson(r) {
    if (!r.ok) throw new Error(await r.text())
    return r.json()
}

function post(path, body) {
    return fetch(BASE + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    }).then(okJson)
}

export function getSessions() {
    return fetch(BASE + '/sessions').then(okJson)
}

export function getStreams(sessionId) {
    return post('/streams', { session: sessionId })
}

export function getChunkList(sessionId, streamId) {
    return post('/chunklist', { session: sessionId, stream: streamId })
}

// `session`/`stream` are both optional and independent; see intercept/dbdump/CLAUDE.md's
// `/latest` entry for exactly which response fields each one unlocks.
export function getLatest({ session, stream } = {}) {
    const body = {}
    if (session != null) body.session = session
    if (stream != null) body.stream = stream
    return post('/latest', body)
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

// Opens a persistent WebSocket for chunk streaming, at `path`, using `buildChunk(meta,
// data)` to turn each arriving metadata/binary pair into a chunk object. Returns
// { send(payload) → Promise<chunk[]>, close() }. The server processes requests
// sequentially; only one send should be in flight at a time per connection.
function openChunkStream(path, buildChunk) {
    const ws = new WebSocket(wsUrl(`${BASE}${path}`))
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
            currentChunks.push(buildChunk(pendingMeta, event.data))
            pendingMeta = null
        }
    }

    return {
        send(payload) {
            return ready.then(() => new Promise((resolve, reject) => {
                currentResolve = resolve
                currentReject  = reject
                currentChunks  = []
                ws.send(JSON.stringify(payload))
            }))
        },
        close() { ws.close() },
    }
}

export function openStidStream() {
    const stream = openChunkStream('/stid-stream', (meta, data) => ({
        stid:      meta.stid,
        chunkId:   meta['chunk-id'],
        direction: meta.direction,
        time:      meta.time,
        offset:    meta.offset,
        data:      new Uint8Array(data),
    }))
    return {
        fetch(sessionId, streamId, start, n) {
            return stream.send({ session: sessionId, stream: streamId, start, n })
        },
        close: stream.close,
    }
}

export function openSgidStream() {
    const stream = openChunkStream('/sgid-stream', (meta, data) => ({
        sgid:      meta.sgid,
        chunkId:   meta['chunk-id'],
        stream:    meta.stream,
        direction: meta.direction,
        time:      meta.time,
        offset:    meta.offset,
        data:      new Uint8Array(data),
    }))
    return {
        fetch(session, start, n) {
            return stream.send({ session, start, n })
        },
        close: stream.close,
    }
}

