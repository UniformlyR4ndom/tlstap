import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRows, evict, fillToTarget } from './byteBufferCore.js'

// ── fixtures ─────────────────────────────────────────────────────────────────────────

function seg(stid, id, direction, offset, length, time) {
    return { stid, id, direction, offset, length, time }
}

function win(segment, loadedStart, loadedEnd) {
    return { segment, loadedStart, loadedEnd, bytes: new Uint8Array(loadedEnd - loadedStart) }
}

function fullWin(segment) {
    return win(segment, segment.offset, segment.offset + segment.length)
}

// Records every request it was called with; returns canned pages in sequence, then an
// empty/reachedEnd page if called more times than provided (defensive against a runaway
// loop actually reaching the fake's end).
function fakeFill(pages) {
    const calls = []
    let i = 0
    const fn = async (handle, entity, req) => {
        calls.push(req)
        return pages[i++] ?? { windows: [], reachedEnd: true }
    }
    fn.calls = calls
    return fn
}

// ── buildRows ────────────────────────────────────────────────────────────────────────

test('buildRows: a fully-loaded window produces one header + hex rows with local offsets from 0', () => {
    const s = seg(1, 0, 0, 0, 20, 1000)
    const w = fullWin(s)
    const rows = buildRows([w], 0)

    assert.equal(rows.length, 3) // 1 header + ceil(20/16)=2 hex rows
    assert.deepEqual(rows[0], {
        type: 'header', direction: 0, stid: 1, chunkId: 0, relTime: '+1.000s', size: 20, continued: false,
    })
    assert.equal(rows[1].type, 'hex')
    assert.equal(rows[1].offset, 0)
    assert.equal(rows[1].localOffset, 0)
    assert.equal(rows[1].bytes.length, 16)
    assert.equal(rows[2].offset, 16)
    assert.equal(rows[2].localOffset, 16)
    assert.equal(rows[2].bytes.length, 4)
})

test('buildRows: a front-trimmed (continued) window keeps its header and offsets by true segment position', () => {
    const s = seg(5, 2, 1, 100, 1000, 2000) // a large frame, offset=100, length=1000
    const w = win(s, 200, 232) // trimmed from its own start; 32 bytes currently loaded
    const rows = buildRows([w], 0)

    assert.equal(rows[0].continued, true)
    assert.equal(rows[0].size, 1000) // true segment length, not just what's loaded
    assert.equal(rows.length, 3) // header + ceil(32/16)=2 hex rows
    assert.equal(rows[1].offset, 200)
    assert.equal(rows[1].localOffset, 100) // 200 - segment.offset(100)
    assert.equal(rows[2].localOffset, 116)
})

test('buildRows: multiple windows concatenate in order', () => {
    const w1 = fullWin(seg(1, 0, 0, 0, 16, 0))
    const w2 = fullWin(seg(2, 0, 1, 0, 16, 0))
    const rows = buildRows([w1, w2], 0)
    assert.equal(rows.length, 4)
    assert.equal(rows[0].stid, 1)
    assert.equal(rows[2].stid, 2)
})

// ── evict ────────────────────────────────────────────────────────────────────────────

test('evict: segment cap alone drops whole windows from the front', () => {
    const windows = [0, 1, 2, 3, 4].map(j => fullWin(seg(j, 0, 0, j * 16, 16, 0)))
    const { windows: out, removedRows } = evict(windows, 1, Infinity, 2)
    assert.equal(out.length, 2)
    assert.deepEqual(out.map(w => w.segment.stid), [3, 4])
    assert.equal(removedRows, 6) // 3 dropped windows * (1 header + 1 hex row)
})

test('evict: segment cap alone drops whole windows from the back', () => {
    const windows = [0, 1, 2, 3, 4].map(j => fullWin(seg(j, 0, 0, j * 16, 16, 0)))
    const { windows: out, removedRows } = evict(windows, -1, Infinity, 2)
    assert.equal(out.length, 2)
    assert.deepEqual(out.map(w => w.segment.stid), [0, 1])
    assert.equal(removedRows, 6)
})

test('evict: byte cap partially trims the boundary window, row-aligned', () => {
    const w = fullWin(seg(1, 0, 0, 0, 64, 0))
    const { windows: out, removedRows } = evict([w], 1, 32, Infinity)
    assert.equal(out.length, 1)
    assert.equal(out[0].loadedStart, 32)
    assert.equal(out[0].loadedEnd, 64)
    assert.equal(out[0].bytes.length, 32)
    assert.equal(removedRows, 2) // 32 bytes / 16
})

test('evict: byte cap drops a whole window then partially trims the next', () => {
    const w0 = fullWin(seg(1, 0, 0, 0, 32, 0))  // covers stream bytes [0, 32)
    const w1 = fullWin(seg(2, 0, 0, 32, 32, 0)) // covers stream bytes [32, 64)
    const { windows: out, removedRows } = evict([w0, w1], 1, 16, Infinity)
    assert.equal(out.length, 1)
    assert.equal(out[0].segment.stid, 2)
    assert.equal(out[0].loadedStart, 48) // trimmed its own front 16 bytes: 32 + 16
    assert.equal(out[0].loadedEnd, 64)   // unchanged — trimming is always from the front here
    assert.equal(out[0].bytes.length, 16)
    // w0 fully dropped (1 header + 2 hex rows = 3) + 16 bytes trimmed off w1 (1 row) = 4
    assert.equal(removedRows, 4)
})

test('evict: never leaves a zero-byte window behind (drops instead of trimming to empty)', () => {
    const w = fullWin(seg(1, 0, 0, 0, 16, 0))
    const { windows: out, removedRows } = evict([w], 1, 0, Infinity)
    assert.equal(out.length, 0)
    assert.equal(removedRows, 2) // 1 header + 1 hex row
})

// ── fillToTarget ─────────────────────────────────────────────────────────────────────

test('fillToTarget: fills forward across multiple quanta with no resumeWindow', async () => {
    const w1 = fullWin(seg(1, 0, 0, 0, 8, 0))
    const w2 = fullWin(seg(2, 0, 0, 8, 8, 0))
    const w3 = fullWin(seg(3, 0, 0, 16, 8, 0))
    const fill = fakeFill([
        { windows: [w1, w2], reachedEnd: false },
        { windows: [w3], reachedEnd: true },
    ])
    const windows = []
    const genRef = { current: 1 }
    const result = await fillToTarget(fill, null, {}, windows, 1, -1, null, 20, 100, genRef, 1)

    assert.equal(result.addedBytes, 24)
    assert.equal(result.addedSegments, 3)
    assert.equal(result.reachedEnd, true)
    assert.deepEqual(windows.map(w => w.segment.stid), [1, 2, 3])

    assert.equal(fill.calls.length, 2)
    assert.equal(fill.calls[0].afterStid, -1)
    assert.equal(fill.calls[0].resumeWindow, null)
    assert.equal(fill.calls[1].afterStid, 2) // boundary advanced to w2's stid (fully-loaded edge)
})

test('fillToTarget: extends a still-open segment (resumeWindow) across quanta instead of opening a new one', async () => {
    const s = seg(9, 0, 0, 0, 100, 0) // a 100-byte frame, loaded incrementally
    const fill = fakeFill([
        { windows: [win(s, 0, 40)], reachedEnd: false },
        { windows: [win(s, 0, 80)], reachedEnd: false },
        { windows: [win(s, 0, 100)], reachedEnd: true },
    ])
    const windows = []
    const genRef = { current: 1 }
    const result = await fillToTarget(fill, null, {}, windows, 1, -1, null, 100, 100, genRef, 1)

    assert.equal(result.addedBytes, 100)
    assert.equal(result.reachedEnd, true)
    assert.equal(windows.length, 1, 'the segment is extended in place, never duplicated')
    assert.equal(windows[0].loadedEnd, 100)

    // addedRows: opening at 40 bytes = 1 header + ceil(40/16)=3 hex = 4; then hex-row-only
    // deltas for the two extensions: ceil(80/16)-ceil(40/16) = 5-3 = 2, ceil(100/16)-ceil(80/16) = 7-5 = 2.
    assert.equal(result.addedRows, 4 + 2 + 2)

    // Calls 2 and 3 must carry the previous call's own result forward as resumeWindow —
    // not the original null, and not some fixed reference — so the adapter always knows
    // exactly where the still-open segment's loaded window currently ends.
    assert.equal(fill.calls[0].resumeWindow, null)
    assert.equal(fill.calls[1].resumeWindow.loadedEnd, 40)
    assert.equal(fill.calls[2].resumeWindow.loadedEnd, 80)
})

test('fillToTarget: backward fill preserves ascending stid order when prepending multiple new segments', async () => {
    const wLow  = fullWin(seg(1, 0, 0, 0, 8, 0))
    const wMid  = fullWin(seg(2, 0, 0, 8, 8, 0))
    const wHigh = fullWin(seg(3, 0, 0, 16, 8, 0))
    const fill = fakeFill([{ windows: [wLow, wMid, wHigh], reachedEnd: true }])
    const windows = []
    const genRef = { current: 1 }
    await fillToTarget(fill, null, {}, windows, -1, 1000, null, 1000, 1000, genRef, 1)

    assert.deepEqual(windows.map(w => w.segment.stid), [1, 2, 3], 'must not come out reversed')
})

test('fillToTarget: aborts once the generation changes mid-fill, without merging the stale result', async () => {
    const w1 = fullWin(seg(1, 0, 0, 0, 8, 0))
    const w2 = fullWin(seg(2, 0, 0, 8, 8, 0))
    const genRef = { current: 1 }
    const pages = fakeFill([
        { windows: [w1], reachedEnd: false },
        { windows: [w2], reachedEnd: true },
    ])
    // A concurrent reload (e.g. the entity changed) bumps the generation right after the
    // 2nd call's response arrives, before fillToTarget gets to merge it in.
    const fill = async (h, e, r) => {
        const res = await pages(h, e, r)
        if (pages.calls.length === 2) genRef.current = 2
        return res
    }

    const windows = []
    const result = await fillToTarget(fill, null, {}, windows, 1, -1, null, 1000, 1000, genRef, 1)

    assert.equal(result.aborted, true)
    assert.deepEqual(windows.map(w => w.segment.stid), [1], 'the second page must never have been merged in')
})

test('fillToTarget: stops as soon as the adapter reports reachedEnd, even short of target', async () => {
    const w1 = fullWin(seg(1, 0, 0, 0, 8, 0))
    const fill = fakeFill([{ windows: [w1], reachedEnd: true }])
    const windows = []
    const genRef = { current: 1 }
    const result = await fillToTarget(fill, null, {}, windows, 1, -1, null, 1000, 1000, genRef, 1)

    assert.equal(fill.calls.length, 1)
    assert.equal(result.addedBytes, 8)
    assert.equal(result.reachedEnd, true)
})

test('fillToTarget: an empty page stops the loop', async () => {
    const fill = fakeFill([{ windows: [], reachedEnd: false }])
    const windows = []
    const genRef = { current: 1 }
    const result = await fillToTarget(fill, null, {}, windows, 1, -1, null, 1000, 1000, genRef, 1)

    assert.equal(fill.calls.length, 1)
    assert.equal(result.addedBytes, 0)
    assert.equal(windows.length, 0)
})

test('fillToTarget: a no-progress quantum breaks the loop instead of spinning forever', async () => {
    const s = seg(9, 0, 0, 0, 100, 0)
    const stagnant = win(s, 0, 40)
    // Every call "extends" the resumeWindow to the exact same 40 bytes — zero progress.
    const fill = fakeFill(Array(10).fill({ windows: [win(s, 0, 40)], reachedEnd: false }))
    const windows = [win(s, 0, 40)]
    const genRef = { current: 1 }
    const result = await fillToTarget(fill, null, {}, windows, 1, 9, stagnant, 1000, 1000, genRef, 1)

    assert.equal(fill.calls.length, 1, 'must give up after the first no-progress quantum, not loop')
    assert.equal(result.addedBytes, 0)
})

test('fillToTarget: per-quantum maxBytes/maxSegments are clamped to the remaining target', async () => {
    const w1 = fullWin(seg(1, 0, 0, 0, 8, 0))
    const fill = fakeFill([{ windows: [w1], reachedEnd: true }])
    const windows = []
    const genRef = { current: 1 }
    await fillToTarget(fill, null, {}, windows, 1, -1, null, 10, 3, genRef, 1)

    assert.equal(fill.calls[0].maxBytes, 10) // remaining(10) < WINDOW_STEP
    assert.equal(fill.calls[0].maxSegments, 3) // remaining(3) < SEGMENT_STEP
})
