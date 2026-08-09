import { mergeUint8Arrays } from './format.js'

// Pure, framework/network-free core of frameSegments.js's adapter logic — split out
// specifically so it stays unit-testable with Node's plain test runner (frameSegments.js
// itself calls listFramesTimeline/getByteStid, live network calls not easily mocked via
// plain ES module imports). See doc/design/hexview-segment-buffer.md's "Frame-mode
// adapter" section.

// Drops every frame at exactly `stid` whose id is in excludeIds — used after a metadata
// fetch made *inclusive* of a boundary stid already partly consumed (see frameSegments.js),
// to turn the raw result back into "only what's genuinely new". excludeIds must list every
// id already consumed at that stid, not just the most recent one: a tied group can have
// more than two members, and each fillForward/fillBackward round resolves only one more —
// filtering by a single id would let an already-consumed earlier sibling reappear as
// "new" on the very next round (it doesn't get excluded by the id that round's exclusion
// happens to carry), producing an infinite reload/duplicate loop instead of converging.
export function excludeAlreadyLoaded(frames, stid, excludeIds) {
    if (!excludeIds || excludeIds.length === 0) return frames
    const ids = new Set(excludeIds)
    return frames.filter(f => !(f.stid === stid && ids.has(f.id)))
}

// The sub-range of a too-big-to-load-whole frame f to fetch on its first touch.
// Forward (dir=1, opened while scrolling *into* it from its start): anchor at f.offset,
// so later forward extension grows loadedEnd — exactly mergeExtendedWindow's forward
// case. Backward (dir=-1, opened while scrolling *into* it from its end): anchor at
// f.offset+f.length, so later backward extension shrinks loadedStart instead — the
// mirror image, matching where the buffer's already-visible content sits relative to it.
export function initialWindowRange(dir, f, maxBytes) {
    return dir === 1
        ? { wantStart: f.offset, wantEnd: f.offset + maxBytes }
        : { wantStart: f.offset + f.length - maxBytes, wantEnd: f.offset + f.length }
}

// True only if there is genuinely nothing left to fetch in this direction: the metadata
// listing itself ran dry (rawCount < requestN) *and* selectByBudget consumed every
// candidate it was given (frames — after any already-loaded-tied-sibling filtering the
// caller applied, see frameSegments.js). The latter half matters because selectByBudget
// can stop short of the full frames list purely on budget (byte cap, segment cap, or the
// oversized-single-candidate case) — that leftover metadata still describes real,
// not-yet-fetched segments, so reporting "reached end" on metadata exhaustion alone would
// strand them: the caller latches reachedEnd into a ref that permanently gates further
// fetches in that direction.
//
// rawCount defaults to frames.length (frames itself is the raw fetch) for a caller with
// nothing to filter out; frameSegments.js passes its actual raw fetch count explicitly,
// since filtering out an already-loaded tied sibling can shrink frames below requestN even
// when the server's own page was full (and so may have more beyond it) — comparing the
// *filtered* count against requestN there would misreport reachedEnd early.
export function computeReachedEnd(frames, requestN, included, rawCount = frames.length) {
    return rawCount < requestN && included.length === frames.length
}

// Decides which of candidatesNearestFirst (frame metadata, ordered nearest-to-the-
// current-boundary first) to open this round, respecting maxSegments/maxBytes. Mirrors
// the Go /segments endpoint's own "checked only between whole items" budget discipline,
// with one addition frames need and chunks don't: if the very first candidate alone
// exceeds maxBytes, it's still included, but only partially — openRange (via
// initialWindowRange) describes exactly which sub-range to load. Whenever openRange is
// set, included has exactly one entry — the loop breaks immediately after producing it,
// so a byte-fetch step never has to reason about a partial entry mixed in with whole ones.
export function selectByBudget(candidatesNearestFirst, maxSegments, maxBytes, dir) {
    const included = []
    let bytes = 0
    let openRange = null
    for (const f of candidatesNearestFirst) {
        if (included.length >= maxSegments) break
        if (included.length === 0 && f.length > maxBytes) {
            included.push(f)
            openRange = initialWindowRange(dir, f, maxBytes)
            break
        }
        if (included.length > 0 && bytes + f.length > maxBytes) break
        included.push(f)
        bytes += f.length
        if (bytes >= maxBytes) break
    }
    return { included, openRange }
}

// The exact byte range needed for one entry of included — openRange (if set) always
// applies to included[0] (see selectByBudget); every other entry wants its full
// [offset, offset+length).
export function wantRangeFor(f, included, openRange) {
    return openRange && f === included[0] ? openRange : { wantStart: f.offset, wantEnd: f.offset + f.length }
}

// The combined [from, to) byte range needed per direction to cover every entry of
// included — one fetch per direction is enough, not one per frame. Returns a plain
// object (not a Map) keyed by direction number, for straightforward assert.deepEqual in
// tests.
export function rangesByDirection(included, openRange) {
    const ranges = {}
    for (const f of included) {
        const { wantStart, wantEnd } = wantRangeFor(f, included, openRange)
        const r = ranges[f.direction]
        if (!r) ranges[f.direction] = { from: wantStart, to: wantEnd }
        else { r.from = Math.min(r.from, wantStart); r.to = Math.max(r.to, wantEnd) }
    }
    return ranges
}

export function buildFrameWindow(f, wantStart, wantEnd, bytes) {
    return {
        segment:     { stid: f.stid, id: f.id, direction: f.direction, offset: f.offset, length: f.length, time: f.time, meta: f.meta },
        loadedStart: wantStart,
        loadedEnd:   wantEnd,
        bytes,
    }
}

// The byte range to newly fetch this round to extend resumeWindow further, in direction
// dir (1 = grow loadedEnd forward, -1 = shrink loadedStart backward).
export function extendRange(resumeWindow, maxBytes, dir) {
    const { segment, loadedStart, loadedEnd } = resumeWindow
    return dir === 1
        ? { wantStart: loadedEnd, wantEnd: Math.min(segment.offset + segment.length, loadedEnd + maxBytes) }
        : { wantStart: Math.max(segment.offset, loadedStart - maxBytes), wantEnd: loadedStart }
}

// Merges newly-fetched bytes into resumeWindow, on the correct side for dir. No metadata
// is consulted to extend an already-open segment, so reachedEnd is always false here —
// the real answer comes once this segment is fully loaded and a subsequent call actually
// lists new frame metadata.
export function mergeExtendedWindow(resumeWindow, dir, wantStart, wantEnd, newBytes) {
    const { segment, loadedStart, loadedEnd, bytes: existing } = resumeWindow
    const bytes = dir === 1 ? mergeUint8Arrays([existing, newBytes]) : mergeUint8Arrays([newBytes, existing])
    return {
        segment,
        loadedStart: dir === 1 ? loadedStart : wantStart,
        loadedEnd:   dir === 1 ? wantEnd     : loadedEnd,
        bytes,
    }
}
