import { openSegmentsStream } from './api.js'

// Chunk-mode adapter for useByteBuffer.js — maps its generic openConnection/fillForward/
// fillBackward contract directly onto /segments (api.js's openSegmentsStream), see
// doc/design/hexview-segment-buffer.md's "Chunk-mode adapter" section. Every returned
// SegmentWindow is already fully loaded, since /segments always delivers a chunk's
// metadata and bytes together in one exchange — resumeWindow is accepted (for contract
// uniformity with the frame adapter, byteBufferCore.js's fillToTarget always passes the
// current edge whether or not it's fully loaded) but never read here: a chunk-mode window
// is always fully loaded already, and chunks never tie on `stid` the way frames can, so
// there's never anything for this adapter to do with it.

// entity is unused — a /segments connection is entity-agnostic; session/stream are sent
// per fetchForward/fetchBackward call instead. Kept as a parameter anyway to match the
// adapter contract's documented openConnection(entity) signature.
export function openConnection(entity) {
    return openSegmentsStream()
}

function toSegmentWindow(s) {
    return {
        segment: { stid: s.stid, id: s.segmentId, direction: s.direction, offset: s.offset, length: s.length, time: s.time },
        loadedStart: s.offset,
        loadedEnd:   s.offset + s.length,
        bytes:       s.data,
    }
}

export async function fillForward(handle, entity, { afterStid, maxBytes, maxSegments }) {
    const { segments, reachedEnd } = await handle.fetchForward(entity.session, entity.id, afterStid, maxSegments, maxBytes)
    return { windows: segments.map(toSegmentWindow), reachedEnd }
}

export async function fillBackward(handle, entity, { beforeStid, maxBytes, maxSegments }) {
    const { segments, reachedEnd } = await handle.fetchBackward(entity.session, entity.id, beforeStid, maxSegments, maxBytes)
    return { windows: segments.map(toSegmentWindow), reachedEnd }
}
