// Catches a stream direction's persisted frame index up to date against a given framer
// script: fetches whatever raw chunk data hasn't been framed yet, runs it through the
// script in a Worker, and persists each computed batch. Idempotent and safe to call
// repeatedly; a call with nothing new to frame resolves immediately having
// fetched/computed nothing.
import { fetchDirectionChunks, getChunkList } from './api.js'
import { getFrameProgress, appendFrames } from './dbdumpFramerApi.js'
import { runFramer } from './frameRuntime.js'
import { DIRNUM_C2S, dirToStr } from './direction.js'

export async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
    return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
}

// Plain scalar ids, not whole session/stream objects, so a caller with only loose id
// fields never needs to synthesize one just to call this. scriptSource is the script's
// current content — never fetched here, so a script mid-edit can be run without saving
// first. scriptVersion is derived from scriptSource via sha256Hex, kept internal so
// every caller computes it identically. streamEnd is the stream's own `end` field
// (0 while ongoing — same convention TrafficView.js's isClosed(stream) and chunkSegments
// already use for this exact value) — once nonzero, catchUpFramer delivers one final
// synthetic frame(state, {closed: true, ...}) call for this direction (see below) so a
// script can flush anything whose length is implicit in connection close (e.g. an
// HTTP/1 response with neither Content-Length nor chunked Transfer-Encoding). onLog
// (optional) is called with (direction, args) for every framer.log(...) call the script
// makes during this run — direction is this call's own fixed direction, passed through
// since runFramer's onLog only sees args. tlsInfo is the stream's downstream TLS state
// (TrafficView.js's streamTlsInfo(stream)) — null for a plain-mode proxy or a
// not-yet-upgraded detecttls connection, else {sni, alpn, version, cipherSuite} —
// attached to every chunk the same way direction already is (constant for the whole
// run, e.g. to let one script branch on ALPN between HTTP/1.1 and h2 framing).
export async function catchUpFramer(sessionId, streamId, direction, scriptName, scriptSource, streamEnd, tlsInfo, onLog) {
    const scriptVersion = await sha256Hex(scriptSource)
    const key = { session: sessionId, stream: streamId, direction, script: scriptName, scriptVersion }
    const streamClosed = !!streamEnd

    const { processedOffset, state, closed } = await getFrameProgress(key)
    if (closed) return // fully done, including the close signal — nothing can ever change again for this key

    const lengths = await getChunkList(sessionId, streamId)
    const totalLength = Math.max(0, direction === DIRNUM_C2S ? lengths.length0 : lengths.length1)
    if (!streamClosed && processedOffset >= totalLength) return // already caught up, not closed yet

    // rawChunks backs chunkAtOffset's stid/time lookups below; `chunks` (further down) is
    // only ever *unprocessed* data actually fed to frame(). The two diverge in exactly
    // one case: no new backlog to process, but the direction just closed — a frame the
    // script emits on the synthetic close chunk may still need a real chunk's stid/time
    // to attribute to, so the stream's last chunk is fetched for that alone (it's not
    // reprocessed; already handled in an earlier run).
    let rawChunks = []
    if (processedOffset < totalLength) {
        rawChunks = await fetchDirectionChunks(sessionId, streamId, direction, processedOffset)
    } else if (streamClosed && totalLength > 0) {
        // fetchDirectionChunks(..., totalLength) still resolves to the stream's last
        // real chunk even though totalLength itself lands one past its end — byte-stid
        // resolution is a floor lookup (offset <= N), not interval containment.
        rawChunks = await fetchDirectionChunks(sessionId, streamId, direction, totalLength)
    }

    // direction is fixed for the whole run (this key is scoped to one direction), but
    // carried per-chunk anyway, so a script branching per direction can read it straight
    // off the chunk it's given.
    const dirStr = dirToStr(direction)
    const chunks = rawChunks
        .filter(c => c.offset >= processedOffset)
        .map(c => ({ offset: c.offset, length: c.data.length, direction: dirStr, data: c.data, tls: tlsInfo }))
    if (streamClosed) chunks.push({ offset: totalLength, length: 0, direction: dirStr, data: new Uint8Array(0), closed: true, tls: tlsInfo })
    if (chunks.length === 0) return // shouldn't happen given the checks above, but nothing to do either way

    // Tags each frame with the stid and time of whichever raw chunk contains its last
    // byte — stid is the cross-direction ordering key the merged frame timeline sorts
    // by; time is a frame's only timestamp, since frames aren't captured, they're
    // computed. chunkIdx only advances forward, since frames are always processed in
    // increasing offset order. A frame emitted from the synthetic close chunk when
    // totalLength is 0 (direction closed having captured no bytes at all) has no chunk
    // to resolve against here and throws — an accepted edge case, surfaced as an
    // ordinary framer-run error rather than guarded against, since it only arises from a
    // script emitting a frame that references no real data.
    let chunkIdx = 0
    function chunkAtOffset(byteOffset) {
        while (chunkIdx < rawChunks.length - 1 && rawChunks[chunkIdx].offset + rawChunks[chunkIdx].data.length - 1 < byteOffset) {
            chunkIdx++
        }
        return rawChunks[chunkIdx]
    }

    let expectedOffset = processedOffset
    let finalState = state
    await runFramer(scriptName, scriptSource, state, chunks, async batch => {
        const framesWithStid = batch.frames.map(f => {
            const c = chunkAtOffset(f.offset + f.length - 1)
            return { ...f, stid: c.stid, time: c.time }
        })
        await appendFrames(key, expectedOffset, framesWithStid, batch.processedOffset, batch.state, false)
        expectedOffset = batch.processedOffset
        finalState = batch.state
    }, args => onLog?.(direction, args))

    // Only reached once every batch above — including whichever one carried the
    // synthetic close chunk — has already persisted successfully, so this can't mark a
    // key closed before the close signal itself was actually delivered and saved.
    if (streamClosed) {
        await appendFrames(key, expectedOffset, [], expectedOffset, finalState, true)
    }
}
