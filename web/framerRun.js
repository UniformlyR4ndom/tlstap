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
// every caller computes it identically. onLog (optional) is called with (direction, args)
// for every framer.log(...) call the script makes during this run — direction is this
// call's own fixed direction, passed through since runFramer's onLog only sees args.
export async function catchUpFramer(sessionId, streamId, direction, scriptName, scriptSource, onLog) {
    const scriptVersion = await sha256Hex(scriptSource)
    const key = { session: sessionId, stream: streamId, direction, script: scriptName, scriptVersion }

    const { processedOffset, state } = await getFrameProgress(key)

    const lengths = await getChunkList(sessionId, streamId)
    const totalLength = direction === DIRNUM_C2S ? lengths.length0 : lengths.length1
    if (totalLength <= 0 || processedOffset >= totalLength) return // already caught up (or no data at all yet)

    const rawChunks = await fetchDirectionChunks(sessionId, streamId, direction, processedOffset)
    if (rawChunks.length === 0) return // shouldn't happen given the check above, but nothing to do either way

    // direction is fixed for the whole run (this key is scoped to one direction), but
    // carried per-chunk anyway, so a script branching per direction can read it straight
    // off the chunk it's given.
    const dirStr = dirToStr(direction)
    const chunks = rawChunks.map(c => ({ offset: c.offset, length: c.data.length, direction: dirStr, data: c.data }))

    // Tags each frame with the stid and time of whichever raw chunk contains its last
    // byte — stid is the cross-direction ordering key the merged frame timeline sorts
    // by; time is a frame's only timestamp, since frames aren't captured, they're
    // computed. chunkIdx only advances forward, since frames are always processed in
    // increasing offset order.
    let chunkIdx = 0
    function chunkAtOffset(byteOffset) {
        while (chunkIdx < rawChunks.length - 1 && rawChunks[chunkIdx].offset + rawChunks[chunkIdx].data.length - 1 < byteOffset) {
            chunkIdx++
        }
        return rawChunks[chunkIdx]
    }

    let expectedOffset = processedOffset
    await runFramer(scriptName, scriptSource, state, chunks, async batch => {
        const framesWithStid = batch.frames.map(f => {
            const c = chunkAtOffset(f.offset + f.length - 1)
            return { ...f, stid: c.stid, time: c.time }
        })
        await appendFrames(key, expectedOffset, framesWithStid, batch.processedOffset, batch.state)
        expectedOffset = batch.processedOffset
    }, args => onLog?.(direction, args))
}
