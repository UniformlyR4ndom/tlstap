// Catches a stream's persisted frame index up to date against a given framer script:
// fetches whatever raw chunk data hasn't been framed yet — merged across *both*
// directions, in true chronological (stid) order (combined mode; see
// doc/design/framer-cross-direction-correlation.md) — runs it through the script in a
// single Worker instance, and persists each computed batch. Idempotent and safe to call
// repeatedly; a call with nothing new to frame resolves immediately having
// fetched/computed nothing.
import { runFramer } from './frameRuntime.js'
import { DIRNUM_C2S, DIRNUM_S2C, dirToStr } from './direction.js'

export async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
}

// The downstream (client-facing) TLS session's negotiated parameters, or null for a
// plain-mode proxy or a detecttls connection that hasn't upgraded (yet) — mirrors
// proxy.ConnInfo.TLS's own nil convention. tls_version is the presence check (matches
// the backend's own NULL-guard column — see dbdump's ConnectionUpgraded). Shared by
// TrafficView.js's manual Run and framerJobsListener.js's remote-triggered one — both
// need it to build catchUpFramer's tlsInfo argument from a /streams row.
export function streamTlsInfo(stream) {
    return stream.tls_version != null
        ? { sni: stream.sni, alpn: stream.alpn, version: stream.tls_version, cipherSuite: stream.cipher_suite }
        : null
}

// createFramerRun(dbdumpApi, framerApi) binds catchUpFramer to one dbdump instance's own
// createDbDumpApi(...)/createDbDumpFramerApi(...) objects.
export function createFramerRun(dbdumpApi, framerApi) {
    const { getChunkList, getByteStid, openStidStream } = dbdumpApi
    const { getFrameProgress, appendFrames } = framerApi

    // Plain scalar ids, not whole session/stream objects, so a caller with only loose id
    // fields never needs to synthesize one just to call this. scriptSource is the script's
    // current content — never fetched here, so a script mid-edit can be run without saving
    // first. scriptVersion is derived from scriptSource via sha256Hex, kept internal so
    // every caller computes it identically. streamEnd is the stream's own `end` field
    // (0 while ongoing — same convention TrafficView.js's isClosed(stream) and
    // chunkSegments already use for this exact value) — once nonzero, catchUpFramer
    // delivers one final synthetic frame(state, {closed: true, ...}) call per direction
    // (see below) so a script can flush anything whose length is implicit in connection
    // close (e.g. an HTTP/1 response with neither Content-Length nor chunked
    // Transfer-Encoding). onLog (optional) is called with (direction, args) for every
    // framer.log(...) call the script makes during this run — direction is whichever
    // chunk's frame() call was executing at the time (numeric), passed straight through
    // from runFramer's own onLog, which already carries it per call now that one run spans
    // both directions. tlsInfo is the stream's downstream TLS state (TrafficView.js's
    // streamTlsInfo(stream)) — null for a plain-mode proxy or a not-yet-upgraded detecttls
    // connection, else {sni, alpn, version, cipherSuite} — attached to every chunk the same
    // way direction already is (constant for the whole run, e.g. to let one script branch
    // on ALPN between HTTP/1.1 and h2 framing).
    async function catchUpFramer(sessionId, streamId, scriptName, scriptSource, streamEnd, tlsInfo, onLog) {
        const scriptVersion = await sha256Hex(scriptSource)
        const key = { session: sessionId, stream: streamId, script: scriptName, scriptVersion }
        const streamClosed = !!streamEnd

        const { processedOffset, state, closed } = await getFrameProgress(key)
        if (closed.c2s && closed.s2c) return // fully done for both directions, including both close signals

        const lengths = await getChunkList(sessionId, streamId)
        const totalLength = { c2s: Math.max(0, lengths.length0), s2c: Math.max(0, lengths.length1) }
        const hasNewBacklog = processedOffset.c2s < totalLength.c2s || processedOffset.s2c < totalLength.s2c
        if (!streamClosed && !hasNewBacklog) return // already caught up, not closed yet

        // rawChunks (merged, both directions) backs chunkAtOffset's per-direction stid/time
        // lookups below; `chunks` (further down) is only ever *unprocessed* data actually fed
        // to frame(). A direction that has never captured any bytes at all is left out of the
        // fetch trigger entirely (getByteStid 404s if a direction has zero chunks ever) —
        // its rawByDir entry just stays empty, same "accepted edge case if a frame ever tries
        // to resolve against it" situation chunkAtOffset already documented pre-combined-mode.
        const dirsWithHistory = []
        if (totalLength.c2s > 0) dirsWithHistory.push({ dirNum: DIRNUM_C2S, dirStr: 'c2s' })
        if (totalLength.s2c > 0) dirsWithHistory.push({ dirNum: DIRNUM_S2C, dirStr: 's2c' })

        let rawChunks = []
        if (dirsWithHistory.length > 0) {
            // Each direction's own starting stid is a floor lookup (offset <= N) — for a
            // direction with no new backlog (processedOffset already at totalLength), this
            // resolves to its own last real chunk, exactly what's needed to still attribute a
            // frame the script emits from that direction's synthetic close chunk. The merged
            // fetch then starts from whichever direction's starting point is earliest and
            // pulls everything (both directions) from there to the true end in one go — no
            // separate per-direction fetch, reusing /stid-stream's existing unfiltered merge
            // (see the design doc's "Open, not yet decided" note, resolved in favor of this
            // over a new endpoint).
            const stids = await Promise.all(dirsWithHistory.map(d => getByteStid(sessionId, streamId, d.dirNum, processedOffset[d.dirStr])))
            const startStid = Math.min(...stids.map(s => s.stid))

            const ws = openStidStream()
            try {
                rawChunks = await ws.fetch(sessionId, streamId, startStid, 0)
            } finally {
                ws.close()
            }
        }

        const rawByDir = {
            c2s: rawChunks.filter(c => c.direction === DIRNUM_C2S),
            s2c: rawChunks.filter(c => c.direction === DIRNUM_S2C),
        }

        const chunks = rawChunks
            .filter(c => c.offset >= processedOffset[dirToStr(c.direction)])
            .map(c => ({ offset: c.offset, length: c.data.length, direction: dirToStr(c.direction), data: c.data, tls: tlsInfo }))
        if (streamClosed) {
            if (!closed.c2s) chunks.push({ offset: totalLength.c2s, length: 0, direction: 'c2s', data: new Uint8Array(0), closed: true, tls: tlsInfo })
            if (!closed.s2c) chunks.push({ offset: totalLength.s2c, length: 0, direction: 's2c', data: new Uint8Array(0), closed: true, tls: tlsInfo })
        }
        if (chunks.length === 0) return // shouldn't happen given the checks above, but nothing to do either way

        // Tags each frame with the stid and time of whichever raw chunk (in ITS OWN
        // direction's sequence) contains its last byte — i.e. the chunk containing
        // max(range.offset + range.length) across the frame's own ranges array, since a
        // frame's ranges are all within one direction and offset is monotonic with arrival
        // time there. stid is the true-wire-order key
        // listFramesTimeline sorts by; time is a frame's only timestamp, since frames aren't
        // captured, they're computed. This is deliberately independent of the order frame()
        // actually returned the frame in (that's what frames.seq is for instead, assigned
        // server-side in appendFrames) — a script holding a frame in state and returning it
        // later still gets its true stid, not one reflecting the delayed return. Each
        // direction's own cursor only advances forward, since a script's own per-direction
        // parse position is always increasing even when emission is reordered across
        // directions (see doc/design/framer-cross-direction-correlation.md). A frame emitted
        // from a synthetic close chunk for a direction with zero bytes ever has no chunk to
        // resolve against here and throws — an accepted edge case, surfaced as an ordinary
        // framer-run error rather than guarded against, since it only arises from a script
        // emitting a frame that references no real data.
        const chunkIdx = { c2s: 0, s2c: 0 }
        function chunkAtOffset(dirStr, byteOffset) {
            const arr = rawByDir[dirStr]
            while (chunkIdx[dirStr] < arr.length - 1 && arr[chunkIdx[dirStr]].offset + arr[chunkIdx[dirStr]].data.length - 1 < byteOffset) {
                chunkIdx[dirStr]++
            }
            return arr[chunkIdx[dirStr]]
        }

        let expectedOffset = processedOffset
        let finalState = state
        await runFramer(scriptName, scriptSource, state, processedOffset, chunks, async batch => {
            const framesWithStid = batch.frames.map(f => {
                const maxByteOffset = Math.max(...f.ranges.map(r => r.offset + r.length - 1))
                const c = chunkAtOffset(dirToStr(f.direction), maxByteOffset)
                return { ...f, stid: c.stid, time: c.time }
            })
            await appendFrames(key, expectedOffset, framesWithStid, batch.processedOffset, batch.state, { c2s: false, s2c: false })
            expectedOffset = batch.processedOffset
            finalState = batch.state
        }, onLog)

        // Only reached once every batch above — including whichever one carried either
        // direction's synthetic close chunk — has already persisted successfully, so this
        // can't mark a key closed before the close signal itself was actually delivered and
        // saved. Both directions close together (one TCP connection, one stream.end), so this
        // is always a transition from {false, false} to {true, true} in one call.
        if (streamClosed) {
            await appendFrames(key, expectedOffset, [], expectedOffset, finalState, { c2s: true, s2c: true })
        }
    }

    return { catchUpFramer }
}
