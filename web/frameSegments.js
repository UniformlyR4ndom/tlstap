import { listFramesTimeline, listFramesTimelineBackward } from './dbdumpFramerApi.js'
import { fetchByteRanges } from './api.js'
import { isWindowFull } from './byteBufferCore.js'
import { mergeUint8Arrays } from './format.js'
import {
    selectByBudget, wantRangeFor, buildFrameWindow, virtualRangeToReal,
    extendRange, mergeExtendedWindow, computeReachedEnd, excludeAlreadyLoaded,
} from './frameSegmentsCore.js'

// Frame-mode adapter for useByteBuffer.js — see doc/design/hexview-segment-buffer.md's
// "Frame-mode adapter" section, and frameSegmentsCore.js's module comment for the virtual-
// addressing convention (a frame's own 0-based concatenation of ranges, independent of
// real stream position) and the pure selection/range math built on it. Metadata (ranges,
// length, no bytes) comes from /frames/timeline via dbdumpFramerApi.js, already cheap
// regardless of how huge a frame is; bytes come from POST /byte-ranges (api.js's
// fetchByteRanges) — a frame's virtual want-range is mapped to its own real
// (offset, length) sub-spans via virtualRangeToReal (one or more per frame, batched
// together across every included frame into a single request), with no stid resolution
// or covering-chunk over-fetch needed (unlike the old /segments-backed version): a range
// fetch can name an arbitrary byte span itself now, not just whole raw chunks.
//
// entity: the synthetic frame-mode object TrafficView.js builds —
// {id, session, streamId, script, scriptVersion, end}.

export function openConnection() {
    return { listFramesTimeline, listFramesTimelineBackward, fetchByteRanges }
}

function timelineKey(entity) {
    return { session: entity.session, stream: entity.streamId, script: entity.script, scriptVersion: entity.scriptVersion }
}

// A frame's own virtual want-range (see frameSegmentsCore.js's module comment) may span
// more than one of its real ranges, needing more than one /byte-ranges request entry —
// concatMerge collapses a frame's own slice of the flat response back into one virtual
// bytes buffer, skipping mergeUint8Arrays' copy for the common single-entry case.
function concatMerge(parts) {
    return parts.length === 1 ? parts[0] : mergeUint8Arrays(parts)
}

// Fetches bytes for every entry of included (one /byte-ranges call covering all of them
// at once — no dedup/overlap-awareness needed or wanted, see intercept/dbdump/CLAUDE.md's
// "POST /byte-ranges" section) and builds their SegmentWindows. Each frame's virtual
// want-range is mapped to its own real (offset, length) sub-spans via virtualRangeToReal —
// one frame may contribute more than one entry to the single flat batched request.
async function fetchFrameWindows(handle, entity, included, openRange) {
    if (included.length === 0) return []
    const wants = included.map(f => wantRangeFor(f, included, openRange))
    const perFrameEntries = included.map((f, j) => virtualRangeToReal(f.ranges, f.direction, wants[j].wantStart, wants[j].wantEnd))
    const bytesList = await handle.fetchByteRanges(entity.session, entity.streamId, perFrameEntries.flat())
    let cursor = 0
    return included.map((f, j) => {
        const n = perFrameEntries[j].length
        const bytes = concatMerge(bytesList.slice(cursor, cursor + n))
        cursor += n
        return buildFrameWindow(f, wants[j].wantStart, wants[j].wantEnd, bytes)
    })
}

async function extendResumeWindow(handle, entity, resumeWindow, maxBytes, dir) {
    const { wantStart, wantEnd } = extendRange(resumeWindow, maxBytes, dir)
    const entries = virtualRangeToReal(resumeWindow.segment.ranges, resumeWindow.segment.direction, wantStart, wantEnd)
    const bytesList = await handle.fetchByteRanges(entity.session, entity.streamId, entries)
    const bytes = concatMerge(bytesList)
    return { windows: [mergeExtendedWindow(resumeWindow, dir, wantStart, wantEnd, bytes)], reachedEnd: false }
}

export async function fillForward(handle, entity, { afterStid, resumeWindow, excludeIds, maxBytes, maxSegments }) {
    if (resumeWindow && !isWindowFull(resumeWindow)) return extendResumeWindow(handle, entity, resumeWindow, maxBytes, 1)

    const requestN = maxSegments + 1
    // Inclusive of afterStid (not "+1") whenever resumeWindow is given: a stid can hold
    // more than one frame (a tied group — e.g. two messages completing on the same raw
    // chunk), and once resumeWindow's own segment has finished loading, boundary/afterStid
    // is exactly its stid — an exclusive cursor would then permanently skip a still-unread
    // sibling at that same stid, since this stid is never revisited once passed. No
    // resumeWindow at all means a genuinely fresh boundary with nothing loaded there yet,
    // so the original exclusive "+1" still applies. excludeIds (every id already consumed
    // at this exact stid, not just resumeWindow's own — see excludeAlreadyLoaded) turns the
    // inclusive result back into "only what's genuinely new".
    const rawFrames = await handle.listFramesTimeline(timelineKey(entity), resumeWindow ? afterStid : afterStid + 1, requestN)
    const frames = excludeAlreadyLoaded(rawFrames, afterStid, excludeIds)

    // Already ascending = nearest-to-afterStid-first for a forward walk.
    const { included, openRange } = selectByBudget(frames, maxSegments, maxBytes, 1)
    const reachedEnd = computeReachedEnd(frames, requestN, included, rawFrames.length)
    if (included.length === 0) return { windows: [], reachedEnd }

    const windows = await fetchFrameWindows(handle, entity, included, openRange)
    return { windows, reachedEnd } // included was already ascending; no reorder needed
}

export async function fillBackward(handle, entity, { beforeStid, resumeWindow, excludeIds, maxBytes, maxSegments }) {
    if (resumeWindow && !isWindowFull(resumeWindow)) return extendResumeWindow(handle, entity, resumeWindow, maxBytes, -1)

    const requestN = maxSegments + 1
    // listFramesTimelineBackward is exclusive of beforeStid already (stid < beforeStid);
    // "+1" makes it inclusive of beforeStid whenever resumeWindow is given, mirroring
    // fillForward's adjustment above for the same tied-stid-group reason.
    const rawFrames = await handle.listFramesTimelineBackward(timelineKey(entity), resumeWindow ? beforeStid + 1 : beforeStid, requestN)
    const frames = excludeAlreadyLoaded(rawFrames, beforeStid, excludeIds)

    // frames comes back ascending (smallest stid first); reverse to nearest-to-
    // beforeStid-first (largest stid first) for selection.
    const nearestFirst = frames.slice().reverse()
    const { included, openRange } = selectByBudget(nearestFirst, maxSegments, maxBytes, -1)
    const reachedEnd = computeReachedEnd(frames, requestN, included, rawFrames.length)
    if (included.length === 0) return { windows: [], reachedEnd }

    const windows = await fetchFrameWindows(handle, entity, included, openRange)
    windows.reverse() // included was nearest-first (descending); flip back to ascending
    return { windows, reachedEnd }
}
