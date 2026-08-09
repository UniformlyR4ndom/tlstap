import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
    initialWindowRange, selectByBudget, computeReachedEnd, wantRangeFor, rangesByDirection,
    buildFrameWindow, extendRange, mergeExtendedWindow, excludeAlreadyLoaded,
} from './frameSegmentsCore.js'
import { fillToTarget, idsAtStid } from './byteBufferCore.js'

function frame(stid, id, direction, offset, length, time) {
    return { stid, id, direction, offset, length, time, meta: null }
}

// ── initialWindowRange ──────────────────────────────────────────────────────────────

test('initialWindowRange: forward anchors at the segment start', () => {
    const f = frame(1, 0, 0, 100, 1000, 0)
    assert.deepEqual(initialWindowRange(1, f, 300), { wantStart: 100, wantEnd: 400 })
})

test('initialWindowRange: backward anchors at the segment end', () => {
    const f = frame(1, 0, 0, 100, 1000, 0)
    assert.deepEqual(initialWindowRange(-1, f, 300), { wantStart: 800, wantEnd: 1100 })
})

// ── selectByBudget ───────────────────────────────────────────────────────────────────

test('selectByBudget: accumulates whole frames until the byte budget would be exceeded', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0), frame(2, 0, 0, 10, 10, 0), frame(3, 0, 0, 20, 10, 0)]
    const { included, openRange } = selectByBudget(frames, 100, 15, 1)
    assert.deepEqual(included.map(f => f.stid), [1]) // second frame would push 10+10=20 > 15
    assert.equal(openRange, null)
})

test('selectByBudget: stops at the segment cap regardless of remaining byte budget', () => {
    const frames = [frame(1, 0, 0, 0, 1, 0), frame(2, 0, 0, 1, 1, 0), frame(3, 0, 0, 2, 1, 0)]
    const { included } = selectByBudget(frames, 2, 1000, 1)
    assert.deepEqual(included.map(f => f.stid), [1, 2])
})

test('selectByBudget: a first candidate alone exceeding maxBytes is still included, partially, and nothing further is added', () => {
    const huge = frame(1, 0, 0, 0, 1000, 0)
    const next = frame(2, 0, 0, 1000, 10, 0)
    const { included, openRange } = selectByBudget([huge, next], 100, 300, 1)
    assert.deepEqual(included.map(f => f.stid), [1])
    assert.deepEqual(openRange, { wantStart: 0, wantEnd: 300 })
})

test('selectByBudget: a mid-batch oversized frame is deferred to the next round, not truncated', () => {
    const small = frame(1, 0, 0, 0, 10, 0)
    const huge  = frame(2, 0, 0, 10, 1000, 0)
    const { included, openRange } = selectByBudget([small, huge], 100, 300, 1)
    assert.deepEqual(included.map(f => f.stid), [1])
    assert.equal(openRange, null, 'huge was never even attempted this round')
})

test('selectByBudget: an exact-fit frame is included whole, not truncated', () => {
    const f = frame(1, 0, 0, 0, 300, 0)
    const { included, openRange } = selectByBudget([f], 100, 300, 1)
    assert.deepEqual(included.map(fr => fr.stid), [1])
    assert.equal(openRange, null)
})

test('selectByBudget: backward direction anchors a first-and-oversized candidate at its end', () => {
    const huge = frame(1, 0, 0, 0, 1000, 0)
    const { included, openRange } = selectByBudget([huge], 100, 300, -1)
    assert.deepEqual(included.map(f => f.stid), [1])
    assert.deepEqual(openRange, { wantStart: 700, wantEnd: 1000 })
})

test('selectByBudget: no candidates at all yields an empty selection', () => {
    const { included, openRange } = selectByBudget([], 100, 300, 1)
    assert.deepEqual(included, [])
    assert.equal(openRange, null)
})

// ── computeReachedEnd ────────────────────────────────────────────────────────────────

test('computeReachedEnd: true when metadata is exhausted and everything fetched was included', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0)]
    assert.equal(computeReachedEnd(frames, 5, frames), true)
})

test('computeReachedEnd: false when the metadata listing itself has more beyond this page', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0)]
    assert.equal(computeReachedEnd(frames, 1, frames), false) // frames.length === requestN
})

test('computeReachedEnd: false when selectByBudget left candidates unconsumed, even though metadata is exhausted', () => {
    // Reproduces the real scenario: a small frame fits the round's budget, a later oversized
    // one doesn't and is deferred (see selectByBudget's "deferred to the next round" test
    // above) — listFramesTimeline had nothing more beyond this page (frames.length <
    // requestN), but there's still real, not-yet-fetched data left over from *this* page.
    const small = frame(1, 0, 0, 0, 10, 0)
    const huge  = frame(2, 0, 0, 10, 1000, 0)
    const frames = [small, huge]
    const { included } = selectByBudget(frames, 100, 300, 1)
    assert.equal(computeReachedEnd(frames, 3, included), false)
})

test('computeReachedEnd: rawCount defaults to frames.length when omitted', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0)]
    assert.equal(computeReachedEnd(frames, 1, frames), false) // same as passing rawCount=1 explicitly
})

test('computeReachedEnd: a full raw page means more may follow, even if filtering an already-loaded tied sibling left frames short of requestN', () => {
    // frameSegments.js filters out an already-loaded (stid, id) before this is called —
    // that filtering can shrink frames below requestN even when the server's own page was
    // full (rawCount === requestN), which must not be misread as "nothing left".
    const frames = [frame(2, 1, 0, 10, 10, 0)] // one usable frame after filtering
    assert.equal(computeReachedEnd(frames, 2, frames, 2), false)
})

// ── wantRangeFor / rangesByDirection ────────────────────────────────────────────────

test('wantRangeFor: a whole (non-truncated) frame wants its full offset/length', () => {
    const f = frame(1, 0, 0, 50, 20, 0)
    assert.deepEqual(wantRangeFor(f, [f], null), { wantStart: 50, wantEnd: 70 })
})

test('wantRangeFor: only included[0] can ever be affected by openRange', () => {
    const f0 = frame(1, 0, 0, 0, 1000, 0)
    const f1 = frame(2, 0, 0, 1000, 10, 0)
    const openRange = { wantStart: 0, wantEnd: 300 }
    assert.deepEqual(wantRangeFor(f0, [f0, f1], openRange), openRange)
    assert.deepEqual(wantRangeFor(f1, [f0, f1], openRange), { wantStart: 1000, wantEnd: 1010 })
})

test('rangesByDirection: unions per-direction ranges across multiple frames, one entry per direction actually present', () => {
    const f0 = frame(1, 0, 0, 0, 10, 0)   // direction 0: [0, 10)
    const f1 = frame(2, 0, 1, 5, 10, 0)   // direction 1: [5, 15)
    const f2 = frame(3, 0, 0, 20, 10, 0)  // direction 0: [20, 30) — extends direction 0's range
    const ranges = rangesByDirection([f0, f1, f2], null)
    assert.deepEqual(ranges, { 0: { from: 0, to: 30 }, 1: { from: 5, to: 15 } })
})

test('rangesByDirection: an openRange on included[0] contributes its truncated range, not the frame\'s full one', () => {
    const huge = frame(1, 0, 0, 0, 1000, 0)
    const openRange = { wantStart: 0, wantEnd: 300 }
    const ranges = rangesByDirection([huge], openRange)
    assert.deepEqual(ranges, { 0: { from: 0, to: 300 } })
})

// ── buildFrameWindow ─────────────────────────────────────────────────────────────────

test('buildFrameWindow: carries the segment\'s true offset/length regardless of the loaded sub-range', () => {
    const f = frame(1, 2, 0, 100, 1000, 5000)
    const bytes = new Uint8Array(50)
    const w = buildFrameWindow(f, 100, 150, bytes)
    assert.deepEqual(w.segment, { stid: 1, id: 2, direction: 0, offset: 100, length: 1000, time: 5000, meta: null })
    assert.equal(w.loadedStart, 100)
    assert.equal(w.loadedEnd, 150)
    assert.equal(w.bytes, bytes)
})

// ── extendRange / mergeExtendedWindow ───────────────────────────────────────────────

test('extendRange: forward grows loadedEnd, clamped to the segment\'s true end', () => {
    const rw = { segment: { offset: 0, length: 1000 }, loadedStart: 0, loadedEnd: 300 }
    assert.deepEqual(extendRange(rw, 500, 1), { wantStart: 300, wantEnd: 800 })
    assert.deepEqual(extendRange(rw, 5000, 1), { wantStart: 300, wantEnd: 1000 }, 'clamped, not overshooting the segment')
})

test('extendRange: backward shrinks loadedStart, clamped to the segment\'s true start', () => {
    const rw = { segment: { offset: 0, length: 1000 }, loadedStart: 700, loadedEnd: 1000 }
    assert.deepEqual(extendRange(rw, 500, -1), { wantStart: 200, wantEnd: 700 })
    assert.deepEqual(extendRange(rw, 5000, -1), { wantStart: 0, wantEnd: 700 }, 'clamped, not undershooting the segment')
})

test('mergeExtendedWindow: forward appends new bytes after existing, growing loadedEnd only', () => {
    const rw = { segment: { offset: 0, length: 1000 }, loadedStart: 0, loadedEnd: 3, bytes: new Uint8Array([1, 2, 3]) }
    const w = mergeExtendedWindow(rw, 1, 3, 6, new Uint8Array([4, 5, 6]))
    assert.equal(w.loadedStart, 0)
    assert.equal(w.loadedEnd, 6)
    assert.deepEqual(Array.from(w.bytes), [1, 2, 3, 4, 5, 6])
})

test('mergeExtendedWindow: backward prepends new bytes before existing, shrinking loadedStart only', () => {
    const rw = { segment: { offset: 0, length: 1000 }, loadedStart: 700, loadedEnd: 1000, bytes: new Uint8Array([7, 8]) }
    const w = mergeExtendedWindow(rw, -1, 500, 700, new Uint8Array([5, 6]))
    assert.equal(w.loadedStart, 500)
    assert.equal(w.loadedEnd, 1000)
    assert.deepEqual(Array.from(w.bytes), [5, 6, 7, 8])
})

// ── excludeAlreadyLoaded ─────────────────────────────────────────────────────────────

test('excludeAlreadyLoaded: drops every listed id at the given stid, keeping everything else', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0), frame(1, 1, 0, 10, 10, 0), frame(3, 0, 1, 0, 10, 0)]
    const kept = excludeAlreadyLoaded(frames, 1, [0, 1])
    assert.deepEqual(kept.map(f => `${f.stid}:${f.id}`), ['3:0'])
})

test('excludeAlreadyLoaded: a single already-consumed id still leaves an unconsumed sibling at the same stid', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0), frame(1, 1, 0, 10, 10, 0)]
    const kept = excludeAlreadyLoaded(frames, 1, [0])
    assert.deepEqual(kept.map(f => f.id), [1])
})

test('excludeAlreadyLoaded: an empty or missing excludeIds is a no-op', () => {
    const frames = [frame(1, 0, 0, 0, 10, 0)]
    assert.deepEqual(excludeAlreadyLoaded(frames, 1, []), frames)
    assert.deepEqual(excludeAlreadyLoaded(frames, 1, undefined), frames)
})

// ── integration: byteBufferCore's fillToTarget + frame-mode's pure adapter logic ────
//
// Reproduces the real bug end to end (2026-08-08): two tied-stid groups, each an
// oversized frame (needing incremental resumeWindow loading) followed by a small sibling.
// A fake fillForward wired straight to the real selectByBudget/computeReachedEnd/
// excludeAlreadyLoaded — the same pieces frameSegments.js's real fillForward calls —
// proves the combination neither drops nor duplicates a frame across many quanta.

function fakeFrameFillForward(allFrames) {
    return async (handle, entity, { afterStid, resumeWindow, excludeIds, maxBytes, maxSegments }) => {
        if (resumeWindow && resumeWindow.loadedEnd < resumeWindow.segment.offset + resumeWindow.segment.length) {
            const seg = resumeWindow.segment
            const loadedEnd = Math.min(seg.offset + seg.length, resumeWindow.loadedEnd + maxBytes)
            return { windows: [{ segment: seg, loadedStart: resumeWindow.loadedStart, loadedEnd, bytes: new Uint8Array(loadedEnd - resumeWindow.loadedStart) }], reachedEnd: false }
        }

        const requestN = maxSegments + 1
        const query = resumeWindow ? afterStid : afterStid + 1
        const rawFrames = allFrames.filter(f => f.stid >= query).slice(0, requestN)
        const frames = excludeAlreadyLoaded(rawFrames, afterStid, excludeIds)

        const { included, openRange } = selectByBudget(frames, maxSegments, maxBytes, 1)
        const reachedEnd = computeReachedEnd(frames, requestN, included, rawFrames.length)
        const windows = included.map(f => {
            const { wantStart, wantEnd } = wantRangeFor(f, included, openRange)
            return { segment: f, loadedStart: wantStart, loadedEnd: wantEnd, bytes: new Uint8Array(wantEnd - wantStart) }
        })
        return { windows, reachedEnd }
    }
}

test('integration: two tied-stid groups (each oversized-then-small) load exactly once each, no duplicates, no drops', async () => {
    const frame1c = frame(1, 0, 0, 0, 65541)
    const frame2c = frame(1, 1, 0, 65541, 39)
    const frame1s = frame(3, 0, 1, 0, 65541)
    const frame2s = frame(3, 1, 1, 65541, 39)
    const fill = fakeFrameFillForward([frame1c, frame2c, frame1s, frame2s])

    const windows = []
    const generationRef = { current: 1 }
    const result = await fillToTarget(fill, null, {}, windows, 1, -1, null, 1e7, 1e4, generationRef, 1)

    assert.equal(result.reachedEnd, true)
    assert.deepEqual(
        windows.map(w => `${w.segment.stid}:${w.segment.id}`),
        ['1:0', '1:1', '3:0', '3:1'],
        'every frame appears exactly once, in ascending order',
    )
    assert.equal(windows[0].loadedEnd - windows[0].loadedStart, 65541, 'the first oversized frame ended up fully loaded')
    assert.equal(windows[2].loadedEnd - windows[2].loadedStart, 65541, 'the second oversized frame ended up fully loaded too')
})

// ── idsAtStid ────────────────────────────────────────────────────────────────────────

test('idsAtStid: forward collects every id tied to the tail, stopping at the first different stid', () => {
    const windows = [
        { segment: { stid: 1, id: 0 } },
        { segment: { stid: 3, id: 0 } },
        { segment: { stid: 3, id: 1 } },
    ]
    assert.deepEqual(idsAtStid(windows, 1, 3), [1, 0])
})

test('idsAtStid: backward collects every id tied to the head, stopping at the first different stid', () => {
    const windows = [
        { segment: { stid: 1, id: 0 } },
        { segment: { stid: 1, id: 1 } },
        { segment: { stid: 3, id: 0 } },
    ]
    assert.deepEqual(idsAtStid(windows, -1, 1), [0, 1])
})

test('idsAtStid: an empty windows array yields no ids', () => {
    assert.deepEqual(idsAtStid([], 1, 5), [])
})
