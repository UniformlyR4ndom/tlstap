import { selectByBudget, computeReachedEnd } from './frameSegmentsCore.js'

// Chunk-mode adapter for useByteBuffer.js — maps its generic openConnection/fillForward/
// fillBackward contract onto POST /chunks/timeline (metadata) + POST /byte-ranges
// (bytes), replacing the old single-WS /segments (see intercept/dbdump/CLAUDE.md).
// Candidate selection now happens client-side via selectByBudget — the exact same
// function frame mode already uses (frameSegmentsCore.js) — rather than a second,
// server-side copy of the same "checked only between whole items" budget discipline.
// Every returned SegmentWindow is still always fully loaded: a chunk row's data is
// written as one complete, immutable blob, so requesting exactly a listed chunk's own
// (offset, length) from /byte-ranges can never come back short. resumeWindow/excludeIds
// are dropped entirely from fillForward/fillBackward's destructured params — dead for
// chunk mode, since chunks never tie on stid the way frames can and are always fully
// loaded already; byteBufferCore.js's fillToTarget still passes them (for contract
// uniformity with the frame adapter), they're just ignored here.
//
// fillForward/fillBackward below take their network calls via `handle` (built by
// openConnection) rather than a module-level api.js import, so they stay plain,
// dbdump-instance-agnostic exports — directly unit-testable with a fake handle
// (chunkSegments.test.js) with no dbdump instance/api.js involved at all.
// createChunkSegmentsAdapter(dbdumpApi) is what a caller (TrafficView.js) actually uses,
// binding openConnection to one dbdump instance's own createDbDumpApi(...) object.

// entity is unused — the returned handle is entity-agnostic; session/stream are sent per
// call instead. Kept as a parameter anyway to match the adapter contract's documented
// openConnection(entity) signature.
export function createChunkSegmentsAdapter(dbdumpApi) {
    return {
        openConnection(entity) {
            const { listChunksTimeline, listChunksTimelineBackward, fetchByteRanges } = dbdumpApi
            return { listChunksTimeline, listChunksTimelineBackward, fetchByteRanges }
        },
        fillForward,
        fillBackward,
    }
}

async function fetchWindows(handle, entity, candidates) {
    if (candidates.length === 0) return []
    const ranges = candidates.map(c => ({ offset: c.offset, direction: c.direction, length: c.length }))
    const bytesList = await handle.fetchByteRanges(entity.session, entity.id, ranges)
    return candidates.map((c, j) => ({
        segment:     { stid: c.stid, id: c.id, direction: c.direction, offset: c.offset, length: c.length, time: c.time },
        loadedStart: c.offset,
        loadedEnd:   c.offset + c.length,
        bytes:       bytesList[j],
    }))
}

export async function fillForward(handle, entity, { afterStid, maxBytes, maxSegments }) {
    const requestN = maxSegments + 1
    // /chunks/timeline's start is inclusive, unlike useByteBuffer.js's exclusive
    // afterStid convention — +1 bridges the two. No resumeWindow-aware inclusive-requery
    // exception needed here (unlike frameSegments.js), since chunks never tie.
    const chunks = await handle.listChunksTimeline(entity.session, entity.id, afterStid + 1, requestN)
    const { included } = selectByBudget(chunks, maxSegments, maxBytes, 1)
    const reachedEnd = computeReachedEnd(chunks, requestN, included)
    return { windows: await fetchWindows(handle, entity, included), reachedEnd }
}

export async function fillBackward(handle, entity, { beforeStid, maxBytes, maxSegments }) {
    const requestN = maxSegments + 1
    const chunks = await handle.listChunksTimelineBackward(entity.session, entity.id, beforeStid, requestN)
    // chunks comes back ascending (smallest stid first); reverse to nearest-to-
    // beforeStid-first (largest stid first) for selection, same convention frame mode's
    // fillBackward uses.
    const { included } = selectByBudget(chunks.slice().reverse(), maxSegments, maxBytes, -1)
    const reachedEnd = computeReachedEnd(chunks, requestN, included)
    const windows = await fetchWindows(handle, entity, included)
    windows.reverse() // included was nearest-first (descending); flip back to ascending
    return { windows, reachedEnd }
}
