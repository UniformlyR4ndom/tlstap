import { encodeByteRangesRequest, decodeByteRangesResponse } from './byteRangesCore.js'

// createDbDumpApi(basePath) binds every method below to one dbdump interceptor instance's
// own base path (e.g. "/proxy-name/api/i/dbdump") — a process may run more than one dbdump
// instance (one per proxy); see cli/CLAUDE.md's "REST API" section and the GET
// /api/instances discovery endpoint App.js uses to find them.
export function createDbDumpApi(basePath) {
    function wsUrl(path) {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
        return `${proto}//${location.host}${path}`
    }

    // Every endpoint here errors as JSON ({"error": "..."} via the Go side's writeError) —
    // extracts that message rather than surfacing the raw response body (which callers
    // that display it directly, e.g. TrafficView.js's Goto error banner, would otherwise
    // show verbatim as a JSON blob). Falls back to statusText for the rare non-JSON case
    // (a network-level failure page, say), matching every other API client's own
    // checkOk-shaped helper in this codebase (coreApiClient.js, tamperApi.js, ...).
    async function errorMessage(r) {
        let message = r.statusText
        try {
            const body = await r.json()
            if (body.error) message = body.error
        } catch { /* not JSON; keep statusText */ }
        return message
    }

    async function okJson(r) {
        if (!r.ok) throw new Error(await errorMessage(r))
        return r.json()
    }

    function post(path, body) {
        return fetch(basePath + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        }).then(okJson)
    }

    // Opens a persistent WebSocket for chunk streaming, at `path`, using `buildChunk(meta,
    // data)` to turn each arriving metadata/binary pair into a chunk object. Returns
    // { send(payload) → Promise<chunk[]>, close() }. The server processes requests
    // sequentially; only one send should be in flight at a time per connection.
    function openChunkStream(path, buildChunk) {
        const ws = new WebSocket(wsUrl(`${basePath}${path}`))
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

    function openStidStream() {
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

    function openSgidStream() {
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

    // Resolves fromOffset to its containing chunk's stid for direction, then fetches every
    // later chunk (either direction) from that point via openStidStream, filtered down to
    // just direction, in stid (i.e. chronological) order. toOffset is optional — omit for
    // "everything up to the current end"; when given, only chunks up to (and possibly
    // slightly past, if toOffset lands mid-chunk — callers needing an exact byte boundary
    // trim the result themselves) the chunk containing that offset are fetched.
    async function fetchDirectionChunks(sessionId, streamId, direction, fromOffset, toOffset) {
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

    function getByteStid(sessionId, streamId, direction, offset) {
        return post('/byte-stid', { session: sessionId, stream: streamId, direction, offset })
    }

    // TODO: remove openSegmentsStream/splitSegments below — superseded by fetchByteRanges +
    // listChunksTimeline/listChunksTimelineBackward above. Nothing calls this anymore
    // (chunkSegments.js/frameSegments.js are both off it); left in place pending manual
    // end-to-end browser verification of the replacement, see doc/design/
    // hexview-segment-buffer.md's "Migration plan" step 6.

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
    function openSegmentsStream() {
        const ws = new WebSocket(wsUrl(`${basePath}/segments`))
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

    return {
        getSessions() {
            return fetch(basePath + '/sessions').then(okJson)
        },

        getStreams(sessionId) {
            return post('/streams', { session: sessionId })
        },

        getChunkList(sessionId, streamId) {
            return post('/chunklist', { session: sessionId, stream: streamId })
        },

        // `session`/`stream` are both optional and independent — each unlocks its own
        // subset of response fields.
        getLatest({ session, stream } = {}) {
            const body = {}
            if (session != null) body.session = session
            if (stream != null) body.stream = stream
            return post('/latest', body)
        },

        getChunkStid(sessionId, streamId, direction, id) {
            return post('/chunk-stid', { session: sessionId, stream: streamId, direction, id })
        },

        getByteStid,

        fetchDirectionChunks,

        searchText(req) {
            return post('/search-text', req)
        },

        openStidStream,
        openSgidStream,

        // Opens the framer-jobs relay connection (intercept/dbdump/CLAUDE.md's "dbdump
        // Interceptor" section) — lets this tab receive framer-run requests pushed from
        // tapctl's POST /framer-jobs/run and report results back over the same socket.
        // handlers: { onOpen, onClose, onError, onJob(job) }, all optional — onJob receives
        // {job_id, session, stream, script}. Returns { respond(jobId, ok, error?), close() }.
        // Only one tab is tracked server-side at a time; opening a second connection
        // replaces (and disconnects) whichever was previously registered.
        openFramerJobs(handlers = {}) {
            const ws = new WebSocket(wsUrl(`${basePath}/framer-jobs`))
            ws.onopen = () => handlers.onOpen?.()
            ws.onclose = () => handlers.onClose?.()
            ws.onerror = () => handlers.onError?.(new Error('WebSocket error'))
            ws.onmessage = event => {
                const msg = JSON.parse(event.data)
                if (msg.kind === 'job') handlers.onJob?.(msg)
            }
            return {
                respond(jobId, ok, error) {
                    ws.send(JSON.stringify({ kind: 'result', job_id: jobId, ok, error }))
                },
                close() { ws.close() },
            }
        },

        // Opens the dissector-jobs relay connection (intercept/dbdump/CLAUDE.md's "Framer
        // jobs" section covers the shared relay mechanics; this is the dissector-script
        // sibling of openFramerJobs above) — lets this tab receive dissector-run requests
        // pushed from tapctl's POST /dissector-jobs/run and report results back. handlers:
        // { onOpen, onClose, onError, onJob(job) }, all optional — onJob receives {job_id,
        // session, stream, direction, framer_script, framer_script_version, frame_id,
        // dissect_script}. Returns { respond(jobId, ok, extra), close() } — extra is
        // merged into the result message (e.g. {nodes} on success, {error} on failure),
        // since unlike a framer job's plain ok/error a dissector job's success payload
        // actually carries data (dissection output is never persisted anywhere to go
        // inspect afterward). Only one tab is tracked server-side at a time, same as
        // openFramerJobs.
        openDissectorJobs(handlers = {}) {
            const ws = new WebSocket(wsUrl(`${basePath}/dissector-jobs`))
            ws.onopen = () => handlers.onOpen?.()
            ws.onclose = () => handlers.onClose?.()
            ws.onerror = () => handlers.onError?.(new Error('WebSocket error'))
            ws.onmessage = event => {
                const msg = JSON.parse(event.data)
                if (msg.kind === 'job') handlers.onJob?.(msg)
            }
            return {
                respond(jobId, ok, extra = {}) {
                    ws.send(JSON.stringify({ kind: 'result', job_id: jobId, ok, ...extra }))
                },
                close() { ws.close() },
            }
        },

        // fetchByteRanges resolves ranges ([{offset, direction, length}]) to a same-length,
        // same-order Uint8Array[] via POST /byte-ranges — see intercept/dbdump/CLAUDE.md's
        // "POST /byte-ranges" section for the full wire format. Each result may be shorter
        // than requested (never longer, never an error on its own — see that section for what
        // a short read means). Throws on a whole-request validation failure (400) or an
        // unknown session/stream (404). An empty ranges list is a harmless no-op (no request
        // sent).
        async fetchByteRanges(sessionId, streamId, ranges) {
            if (ranges.length === 0) return []
            const res = await fetch(`${basePath}/byte-ranges?session=${sessionId}&stream=${streamId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: encodeByteRangesRequest(ranges),
            })
            if (!res.ok) throw new Error(await errorMessage(res))
            return decodeByteRangesResponse(await res.arrayBuffer(), ranges.length)
        },

        // listChunksTimeline/listChunksTimelineBackward — POST /chunks/timeline's client
        // wrapper, mirroring dbdumpFramerApi.js's listFramesTimeline/listFramesTimelineBackward
        // minus any script key (chunks have none — just session/stream). n <= 0 means
        // unlimited. No server-side budget selection, unlike the old /segments — callers
        // apply their own (frameSegmentsCore.js's selectByBudget), same as frame mode already
        // does.
        listChunksTimeline(sessionId, streamId, start, n) {
            return post('/chunks/timeline', { session: sessionId, stream: streamId, start, n })
        },

        listChunksTimelineBackward(sessionId, streamId, beforeStid, n) {
            return post('/chunks/timeline', { session: sessionId, stream: streamId, beforeStid, n })
        },

        openSegmentsStream,
    }
}
