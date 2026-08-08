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

// `session`/`stream` are both optional and independent — each unlocks its own subset
// of response fields.
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

// Resolves fromOffset to its containing chunk's stid for direction, then fetches every
// later chunk (either direction) from that point via openStidStream, filtered down to
// just direction, in stid (i.e. chronological) order. toOffset is optional — omit for
// "everything up to the current end"; when given, only chunks up to (and possibly
// slightly past, if toOffset lands mid-chunk — callers needing an exact byte boundary
// trim the result themselves) the chunk containing that offset are fetched.
export async function fetchDirectionChunks(sessionId, streamId, direction, fromOffset, toOffset) {
    const { stid: startStid } = await getByteStid(sessionId, streamId, direction, fromOffset)
    let n = 0 // 0 = unlimited
    if (toOffset != null) {
        const { stid: endStid } = await getByteStid(sessionId, streamId, direction, toOffset)
        n = endStid - startStid + 1
    }

    const ws = openStidStream()
    try {
        const chunks = await ws.fetch(sessionId, streamId, startStid, n)
        return chunks.filter(c => c.direction === direction)
    } finally {
        ws.close()
    }
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

// Splits one /segments binary frame back into per-segment views using each metadata
// entry's own (non-cumulative) length, walked in array order — no separate blob-offset
// field needed on the wire. Returns zero-copy views into buffer, not copies.
function splitSegments(metas, buffer) {
    let pos = 0
    return metas.map(m => {
        const data = new Uint8Array(buffer, pos, m.length)
        pos += m.length
        return { stid: m.stid, segmentId: m.segmentId, direction: m.direction, time: m.time, offset: m.offset, length: m.length, data }
    })
}

// Opens a persistent WebSocket for /segments: one request gets exactly one response
// (metadata text frame + binary frame), not a per-item stream like openStidStream/
// openSgidStream above — see intercept/dbdump/CLAUDE.md's "WebSocket /segments protocol"
// and doc/design/hexview-segment-buffer.md for the full design. Returns
// { fetchForward(session, stream, afterStid, maxSegments, maxBytes),
//   fetchBackward(session, stream, beforeStid, maxSegments, maxBytes), close() }, each
// resolving to { segments: [{stid, segmentId, direction, time, offset, length, data}, ...],
// reachedEnd }. Deliberately two distinctly-named fetch methods rather than one taking a
// direction parameter — a generic "direction" would collide with the unrelated
// per-segment client→server/server→client direction each entry above already carries.
export function openSegmentsStream() {
    const ws = new WebSocket(wsUrl(`${BASE}/segments`))
    ws.binaryType = 'arraybuffer'

    let isOpen = false
    let openResolve, openReject
    const ready = new Promise((res, rej) => { openResolve = res; openReject = rej })

    let pendingMeta     = null // {segments, reachedEnd} awaiting its binary frame
    let currentResolve  = null
    let currentReject   = null

    function fail(err) {
        if (!isOpen) openReject(err)
        if (currentReject) {
            currentReject(err)
            currentResolve = null
            currentReject  = null
        }
    }

    ws.onopen  = ()  => { isOpen = true; openResolve() }
    ws.onerror = ()  => fail(new Error('WebSocket error'))
    ws.onclose = e   => { if (!e.wasClean) fail(new Error('WebSocket connection lost')) }
    ws.onmessage = event => {
        if (typeof event.data === 'string') {
            const msg = JSON.parse(event.data)
            if (msg.error) {
                currentReject?.(new Error(msg.error))
                currentResolve = null
                currentReject  = null
            } else {
                pendingMeta = msg
            }
        } else if (pendingMeta) {
            const segments  = splitSegments(pendingMeta.segments, event.data)
            const reachedEnd = pendingMeta.reachedEnd
            pendingMeta = null
            currentResolve?.({ segments, reachedEnd })
            currentResolve = null
            currentReject  = null
        }
    }

    function send(payload) {
        return ready.then(() => new Promise((resolve, reject) => {
            currentResolve = resolve
            currentReject  = reject
            ws.send(JSON.stringify(payload))
        }))
    }

    return {
        fetchForward(session, stream, afterStid, maxSegments, maxBytes) {
            return send({ session, stream, afterStid, maxSegments, maxBytes })
        },
        fetchBackward(session, stream, beforeStid, maxSegments, maxBytes) {
            return send({ session, stream, beforeStid, maxSegments, maxBytes })
        },
        close() { ws.close() },
    }
}

