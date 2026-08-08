import { getByteStid, openSegmentsStream } from './api.js'
import { listFramesTimeline, listFramesTimelineBackward } from './dbdumpFramerApi.js'
import {
    selectByBudget, wantRangeFor, rangesByDirection, buildFrameWindow,
    extendRange, mergeExtendedWindow, computeReachedEnd,
} from './frameSegmentsCore.js'

// Frame-mode adapter for useByteBuffer.js — see doc/design/hexview-segment-buffer.md's
// "Frame-mode adapter" section, and frameSegmentsCore.js for the pure selection/range
// math this wraps with the real network calls. Metadata (offset/length, no bytes) comes
// from /frames/timeline via dbdumpFramerApi.js, already cheap regardless of how huge a
// frame is; bytes come from the same /segments endpoint chunk mode uses (this module has
// no special access to it — a frame's bytes are always sliced out of the underlying raw
// chunks), via the offset→stid resolution api.js's fetchDirectionChunks does today.
//
// entity: the synthetic frame-mode object TrafficView.js builds —
// {id, session, streamId, script, scriptVersion, end}. Not yet wired into any view; see
// the design doc's "Migration plan".

export function openConnection() {
    return openSegmentsStream()
}

function timelineKey(entity) {
    return { session: entity.session, stream: entity.streamId, script: entity.script, scriptVersion: entity.scriptVersion }
}

// Slices [offset, offset+length) out of a set of possibly-overlapping raw chunks (a
// frame's own bytes can span more than one underlying chunk). Deliberately duplicated
// from TrafficView.js's identical function rather than shared, for now — TrafficView.js
// still owns the production (unmigrated) frame view and this module must not touch it;
// once that view is cut over to useByteBuffer.js, TrafficView.js's copy is deleted and
// this becomes the only one (see the design doc's "Migration plan").
function sliceFrameBytes(chunks, offset, length) {
    const out = new Uint8Array(length)
    const end = offset + length
    for (const c of chunks) {
        const cEnd = c.offset + c.data.length
        if (cEnd <= offset || c.offset >= end) continue
        const srcStart  = Math.max(0, offset - c.offset)
        const srcEnd    = Math.min(c.data.length, end - c.offset)
        const destStart = Math.max(0, c.offset - offset)
        out.set(c.data.subarray(srcStart, srcEnd), destStart)
    }
    return out
}

// Fetches every underlying raw chunk covering [fromOffset, toOffset) for direction, via
// the shared /segments connection (handle) — the same offset→stid resolution
// api.js's fetchDirectionChunks does for /stid-stream, just backed by /segments instead.
// toOffset is resolved the same "possibly slightly past, if it lands mid-chunk" way
// fetchDirectionChunks already documents; callers always trim to the exact byte range
// they want via sliceFrameBytes afterward, so the harmless overshoot is never observed.
async function fetchDirectionRange(handle, session, streamId, direction, fromOffset, toOffset) {
    const { stid: startStid } = await getByteStid(session, streamId, direction, fromOffset)
    const { stid: endStid }   = await getByteStid(session, streamId, direction, toOffset)
    const maxSegments = endStid - startStid + 1
    const { segments } = await handle.fetchForward(session, streamId, startStid - 1, maxSegments, 0)
    return segments.filter(s => s.direction === direction).map(s => ({ offset: s.offset, data: s.data }))
}

// Fetches bytes for every entry of included (grouped by direction into one
// fetchDirectionRange call each, not one per frame — rangesByDirection is what computes
// the combined range) and builds their SegmentWindows.
async function fetchFrameWindows(handle, entity, included, openRange) {
    const ranges = rangesByDirection(included, openRange)

    const chunksByDirection = new Map()
    for (const direction of Object.keys(ranges)) {
        const { from, to } = ranges[direction]
        chunksByDirection.set(Number(direction), await fetchDirectionRange(handle, entity.session, entity.streamId, Number(direction), from, to))
    }

    return included.map(f => {
        const { wantStart, wantEnd } = wantRangeFor(f, included, openRange)
        const bytes = sliceFrameBytes(chunksByDirection.get(f.direction), wantStart, wantEnd - wantStart)
        return buildFrameWindow(f, wantStart, wantEnd, bytes)
    })
}

async function extendResumeWindow(handle, entity, resumeWindow, maxBytes, dir) {
    const { wantStart, wantEnd } = extendRange(resumeWindow, maxBytes, dir)
    const chunks   = await fetchDirectionRange(handle, entity.session, entity.streamId, resumeWindow.segment.direction, wantStart, wantEnd)
    const newBytes = sliceFrameBytes(chunks, wantStart, wantEnd - wantStart)
    const window   = mergeExtendedWindow(resumeWindow, dir, wantStart, wantEnd, newBytes)
    return { windows: [window], reachedEnd: false }
}

export async function fillForward(handle, entity, { afterStid, resumeWindow, maxBytes, maxSegments }) {
    if (resumeWindow) return extendResumeWindow(handle, entity, resumeWindow, maxBytes, 1)

    const requestN = maxSegments + 1
    const frames = await listFramesTimeline(timelineKey(entity), afterStid + 1, requestN)

    // Already ascending = nearest-to-afterStid-first for a forward walk.
    const { included, openRange } = selectByBudget(frames, maxSegments, maxBytes, 1)
    const reachedEnd = computeReachedEnd(frames, requestN, included)
    if (included.length === 0) return { windows: [], reachedEnd }

    const windows = await fetchFrameWindows(handle, entity, included, openRange)
    return { windows, reachedEnd } // included was already ascending; no reorder needed
}

export async function fillBackward(handle, entity, { beforeStid, resumeWindow, maxBytes, maxSegments }) {
    if (resumeWindow) return extendResumeWindow(handle, entity, resumeWindow, maxBytes, -1)

    const requestN = maxSegments + 1
    const frames = await listFramesTimelineBackward(timelineKey(entity), beforeStid, requestN)

    // frames comes back ascending (smallest stid first); reverse to nearest-to-
    // beforeStid-first (largest stid first) for selection.
    const nearestFirst = frames.slice().reverse()
    const { included, openRange } = selectByBudget(nearestFirst, maxSegments, maxBytes, -1)
    const reachedEnd = computeReachedEnd(frames, requestN, included)
    if (included.length === 0) return { windows: [], reachedEnd }

    const windows = await fetchFrameWindows(handle, entity, included, openRange)
    windows.reverse() // included was nearest-first (descending); flip back to ascending
    return { windows, reachedEnd }
}
