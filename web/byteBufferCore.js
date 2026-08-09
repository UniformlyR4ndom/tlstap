import { fmtRelTime } from './format.js'

// Pure, framework-free core of the byte-budgeted segment buffer described in
// doc/design/hexview-segment-buffer.md — split out from useByteBuffer.js specifically so
// it stays unit-testable with Node's plain test runner (no preact/hooks import here),
// the same reason format.js/transforms/*.js are kept UI-framework-free.
//
// A "segment" is either a raw chunk or a framer-script frame — {stid, id, direction,
// offset, length, time, meta?}, metadata only. A "SegmentWindow" is a segment plus
// however much of its own byte range is currently loaded: {segment, loadedStart,
// loadedEnd, bytes}, where bytes covers [loadedStart, loadedEnd) ⊆ [segment.offset,
// segment.offset + segment.length). For chunks this is always the whole segment; for
// frames it may be a sub-range, extended incrementally as the buffer scrolls deeper into
// a large one — this is the mechanism that bounds memory for an arbitrarily huge frame.

export const MAX_BUFFERED_BYTES    = 256 * 1024
export const MAX_BUFFERED_SEGMENTS = 4096

export const FILL_TARGET_BYTES = MAX_BUFFERED_BYTES / 2
// Exported for a future caller centering a jump-to-stid fetch window on its own resolved
// id — the same role BATCH plays for useChunkBuffer.js's callers today.
export const FILL_TARGET_SEGMENTS = MAX_BUFFERED_SEGMENTS / 2

// Per-adapter-call quantum: the amount asked for in any single fillForward/fillBackward
// call, well under FILL_TARGET_* so a fill toward target happens as several small,
// cancellable round trips rather than one that could itself be unbounded (the actual fix
// for the "huge single frame" problem this design exists for).
const WINDOW_STEP  = FILL_TARGET_BYTES / 4
const SEGMENT_STEP = FILL_TARGET_SEGMENTS / 4

export function windowBytes(w)   { return w.loadedEnd - w.loadedStart }
function windowHexRows(w)        { return Math.ceil(windowBytes(w) / 16) }
function windowRows(w)           { return 1 + windowHexRows(w) } // +1 header row
export function totalBytes(windows) { return windows.reduce((s, w) => s + windowBytes(w), 0) }
export function isWindowFull(w)  { return w.loadedEnd >= w.segment.offset + w.segment.length }

// Flattens buffered SegmentWindows into HexDump's row shape — one implementation shared
// by chunk mode and frame mode, replacing today's two separate buildRows/frameBuildRows.
// relTime is always computable now (segment.time is unconditionally present for both
// entity types — see doc/design/hexview-segment-buffer.md's "frames.time" note), so
// ChunkHeader's current relTime-may-be-absent special case for frame rows can go away
// once this is wired in. `continued: true` marks a header whose window no longer starts
// at the segment's own offset (front-trimmed while still partially resident) — exact
// visual treatment is a HexDump.js concern for the migration step, not decided here.
export function buildRows(windows, streamStart) {
    const rows = []
    for (const w of windows) {
        const { segment, loadedStart, bytes } = w
        rows.push({
            type:      'header',
            direction: segment.direction,
            stid:      segment.stid,
            chunkId:   segment.id,
            relTime:   fmtRelTime(segment.time, streamStart),
            size:      segment.length,
            continued: loadedStart > segment.offset,
        })
        const localBase = loadedStart - segment.offset
        for (let off = 0; off < bytes.length; off += 16) {
            rows.push({
                type:        'hex',
                direction:   segment.direction,
                bytes:       bytes.slice(off, off + 16),
                offset:      loadedStart + off,
                localOffset: localBase + off,
            })
        }
    }
    return rows
}

// Trims windows from the front (dir=1) or back (dir=-1) until within maxBytes/
// maxSegments. Segment *count* can only shrink by dropping whole windows (a partial trim
// never changes it), so that cap is enforced first; the byte cap is then enforced by
// dropping further whole windows, and — the key difference from useChunkBuffer.js's
// header-boundary-aligned eviction — by row-aligned (16-byte) *partial* trimming of the
// single boundary window once dropping it whole would overshoot. This is what lets
// eviction cut mid-segment instead of only at a header, fixing the tied-stid-group
// eviction gap the old chunk-count model had. Returns { windows, removedRows } —
// removedRows is exact (not estimated), for HexDump's scrollAdjust.
export function evict(windows, dir, maxBytes, maxSegments) {
    const out = windows.slice()
    let removedRows = 0

    function dropOne() {
        const w = dir === 1 ? out.shift() : out.pop()
        removedRows += windowRows(w)
    }

    while (out.length > maxSegments) dropOne()

    let bytes = totalBytes(out)
    while (bytes > maxBytes && out.length > 0) {
        const idx = dir === 1 ? 0 : out.length - 1
        const w = out[idx]
        const wBytes = windowBytes(w)
        const excess = bytes - maxBytes
        if (excess >= wBytes) {
            dropOne()
            bytes -= wBytes
            continue
        }
        const trimBytes = Math.min(Math.ceil(excess / 16) * 16, wBytes)
        if (trimBytes >= wBytes) {
            dropOne()
            bytes -= wBytes
            continue
        }
        const trimmedRows = trimBytes / 16
        removedRows += trimmedRows
        bytes -= trimBytes
        out[idx] = dir === 1
            ? { ...w, loadedStart: w.loadedStart + trimBytes, bytes: w.bytes.subarray(trimBytes) }
            : { ...w, loadedEnd:   w.loadedEnd   - trimBytes, bytes: w.bytes.subarray(0, w.bytes.length - trimBytes) }
        break
    }

    return { windows: out, removedRows }
}

// Every already-loaded segment id sharing stid, scanning inward from the buffer's edge —
// dir=1 walks backward from the tail, dir=-1 forward from the head. A tied-stid group is
// always contiguous at whichever end is currently being extended (segments are appended/
// prepended in stid order), so this stops at the first entry belonging to a different
// stid rather than scanning the whole array. Used to tell an adapter every id it has
// already consumed at the current boundary stid — not just the most recently finished
// one — since a tied group can (and here, routinely does) have more than two members and
// each fillForward/fillBackward round resolves only one more of them.
export function idsAtStid(windows, dir, stid) {
    const ids = []
    if (dir === 1) {
        for (let i = windows.length - 1; i >= 0 && windows[i].segment.stid === stid; i--) ids.push(windows[i].segment.id)
    } else {
        for (let i = 0; i < windows.length && windows[i].segment.stid === stid; i++) ids.push(windows[i].segment.id)
    }
    return ids
}

// The index into `windows` whose row-span contains `rowIndex`, as `buildRows` would
// flatten them (each window contributes `windowRows(w)` consecutive rows, in order) — or
// -1 if `rowIndex` is out of range. Used to find "the segment the viewport is currently
// showing" from a scroll-derived row index, for jumpToNextSegment/jumpToPrevSegment
// (useByteBuffer.js).
export function windowIndexAtRow(windows, rowIndex) {
    let row = 0
    for (let i = 0; i < windows.length; i++) {
        const span = windowRows(windows[i])
        if (rowIndex < row + span) return i
        row += span
    }
    return -1
}

// The row index of windows[index]'s own header row — the inverse companion to
// windowIndexAtRow, used once a target segment's index is known to compute where to
// scroll to.
export function rowIndexOfWindow(windows, index) {
    let row = 0
    for (let i = 0; i < index; i++) row += windowRows(windows[i])
    return row
}

// Repeatedly calls fill (fillForward or fillBackward) in WINDOW_STEP/SEGMENT_STEP-sized
// quanta, mutating windows in place — appended at the tail for dir=1, prepended at the
// head for dir=-1 — until targetBytes or targetSegments of *new* data has been added, the
// adapter reports reachedEnd, or a quantum makes no progress (defensive: never loops
// forever on a misbehaving adapter). generationRef/gen abort a stale in-flight fill
// between quanta, the same staleness guard useChunkBuffer.js applies after every await.
// initialResumeWindow is the buffer's current edge window when it isn't fully loaded yet
// (a still-growing huge frame); null when starting fresh (reload, or the edge was
// already complete). Returns { addedBytes, addedSegments, addedRows, reachedEnd }.
export async function fillToTarget(fill, handle, entity, windows, dir, boundaryStid, initialResumeWindow, targetBytes, targetSegments, generationRef, gen) {
    let addedBytes = 0, addedSegments = 0, addedRows = 0, reachedEnd = false
    let resumeWindow = initialResumeWindow
    let boundary = boundaryStid

    while (addedBytes < targetBytes && addedSegments < targetSegments) {
        const remainingBytes    = targetBytes - addedBytes
        const remainingSegments = targetSegments - addedSegments
        const req = {
            resumeWindow,
            // Every id already loaded at exactly `boundary` — a tied-stid-aware adapter
            // needs the whole set, not just resumeWindow's own id, once more than one
            // sibling at that stid has been consumed across successive rounds.
            excludeIds:  resumeWindow ? idsAtStid(windows, dir, boundary) : [],
            maxBytes:    Math.min(WINDOW_STEP, remainingBytes),
            maxSegments: Math.min(SEGMENT_STEP, remainingSegments),
        }
        req[dir === 1 ? 'afterStid' : 'beforeStid'] = boundary

        const result = await fill(handle, entity, req)
        if (generationRef.current !== gen) return { addedBytes, addedSegments, addedRows, reachedEnd: false, aborted: true }

        const got = result.windows
        reachedEnd = result.reachedEnd
        if (got.length === 0) break

        let rest = got
        let progressed = false
        // got[0] only replaces resumeWindow if it's genuinely a continuation of the same
        // segment (matched by stid+id) — resumeWindow is now carried forward even once
        // fully loaded (see below), so a same-stid got[0] that's actually a *different*
        // segment (a tied sibling) must fall through to the "new segment" branch instead.
        if (resumeWindow && got[0].segment.stid === resumeWindow.segment.stid && got[0].segment.id === resumeWindow.segment.id) {
            const replaced  = got[0]
            const byteDelta = windowBytes(replaced) - windowBytes(resumeWindow)
            const rowDelta  = windowHexRows(replaced) - windowHexRows(resumeWindow)
            if (byteDelta > 0) progressed = true
            addedBytes += byteDelta
            addedRows  += rowDelta
            if (dir === 1) windows[windows.length - 1] = replaced
            else            windows[0] = replaced
            rest = got.slice(1)
        }

        if (rest.length > 0) {
            progressed = true
            if (dir === 1) { for (const w of rest) windows.push(w) }
            else            { windows.unshift(...rest) }
            for (const w of rest) {
                addedBytes    += windowBytes(w)
                addedSegments += 1
                addedRows     += windowRows(w)
            }
        }

        const edge = dir === 1 ? windows[windows.length - 1] : windows[0]
        boundary     = edge.segment.stid
        // Passed on even once edge is fully loaded, unlike before (previously nulled
        // here) — a stid can hold more than one segment (a tied group, e.g. two frames
        // completing on the same raw chunk), and an adapter needs to see the just-finished
        // one to requery inclusively of its own stid rather than skipping past a sibling
        // left over there. isWindowFull(edge) is still what tells an adapter whether to
        // extend it (frameSegments.js) or treat it as closed and requery (chunk mode
        // ignores resumeWindow either way, per its own doc comment).
        resumeWindow = edge

        if (!progressed || reachedEnd) break
    }
    return { addedBytes, addedSegments, addedRows, reachedEnd }
}
