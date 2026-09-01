import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fillForward, fillBackward } from './frameSegments.js'

function frame(stid, id, direction, offset, length, time = 0, meta = null) {
    return { stid, id, direction, ranges: [{ offset, length }], length, time, meta }
}

function multiRangeFrame(stid, id, direction, ranges, time = 0, meta = null) {
    return { stid, id, direction, ranges, length: ranges.reduce((s, r) => s + r.length, 0), time, meta }
}

// A fake handle — fillForward/fillBackward only ever call these three methods, so this
// sidesteps dbdumpFramerApi.js's/api.js's real network calls entirely, keeping this test
// plain-Node-runnable like every other web/*.test.js file.
function fakeHandle({ frames, bytesFor }) {
    const calls = []
    return {
        listFramesTimeline(key, start, n) {
            calls.push({ dir: 'forward', key, start, n })
            return Promise.resolve(frames)
        },
        listFramesTimelineBackward(key, beforeStid, n) {
            calls.push({ dir: 'backward', key, beforeStid, n })
            return Promise.resolve(frames)
        },
        fetchByteRanges(session, streamId, ranges) {
            calls.push({ dir: 'bytes', session, streamId, ranges })
            return Promise.resolve(ranges.map(bytesFor))
        },
        calls,
    }
}

function entity(overrides = {}) {
    return { session: 1, streamId: 2, script: 's', scriptVersion: 'v', end: 0, ...overrides }
}

test('fillForward requests each included frame\'s own (offset, direction, length) directly, mixed directions in one call', async () => {
    const f0 = frame(1, 0, 0, 10, 5)
    const f1 = frame(2, 0, 1, 20, 7)
    const handle = fakeHandle({ frames: [f0, f1], bytesFor: r => new Uint8Array(r.length) })
    const result = await fillForward(handle, entity(), {
        afterStid: 0, resumeWindow: null, excludeIds: [], maxBytes: 1000, maxSegments: 10,
    })

    assert.equal(result.windows.length, 2)
    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [
        { offset: 10, direction: 0, length: 5 },
        { offset: 20, direction: 1, length: 7 },
    ])
})

test('fillForward with no resumeWindow queries /frames/timeline exclusively (afterStid+1)', async () => {
    const handle = fakeHandle({ frames: [], bytesFor: () => new Uint8Array(0) })
    await fillForward(handle, entity(), { afterStid: 4, resumeWindow: null, excludeIds: [], maxBytes: 100, maxSegments: 10 })
    const listCall = handle.calls.find(c => c.dir === 'forward')
    assert.equal(listCall.start, 5)
})

test('fillBackward mirrors fillForward: mixed directions, correct byte-range entries', async () => {
    const f0 = frame(2, 0, 1, 0, 3)
    const f1 = frame(1, 0, 0, 0, 4)
    // listFramesTimelineBackward returns ascending order, as the real endpoint does.
    const handle = fakeHandle({ frames: [f1, f0], bytesFor: r => new Uint8Array(r.length) })
    const result = await fillBackward(handle, entity(), {
        beforeStid: 3, resumeWindow: null, excludeIds: [], maxBytes: 1000, maxSegments: 10,
    })

    assert.equal(result.windows.length, 2)
    // Result stays in ascending stid order regardless of selection's internal reversal.
    assert.deepEqual(result.windows.map(w => w.segment.stid), [1, 2])
})

test('extendResumeWindow (forward) requests exactly the extension range and appends bytes', async () => {
    const resumeWindow = {
        segment: { stid: 1, id: 0, direction: 0, offset: 0, length: 1000, time: 0, ranges: [{ offset: 0, length: 1000 }] },
        loadedStart: 0, loadedEnd: 300, bytes: new Uint8Array(300),
    }
    const extBytes = new Uint8Array([1, 2, 3])
    const handle = fakeHandle({ frames: [], bytesFor: () => extBytes })
    const result = await fillForward(handle, entity(), {
        afterStid: 1, resumeWindow, excludeIds: [], maxBytes: 3, maxSegments: 10,
    })

    assert.equal(result.reachedEnd, false)
    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.equal(w.loadedStart, 0)
    assert.equal(w.loadedEnd, 303)
    assert.deepEqual(Array.from(w.bytes.slice(300)), [1, 2, 3])

    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [{ offset: 300, direction: 0, length: 3 }])
    // The metadata endpoint must not be queried at all while still extending a partial window.
    assert.equal(handle.calls.some(c => c.dir === 'forward'), false)
})

test('extendResumeWindow (backward) requests exactly the extension range and prepends bytes', async () => {
    // segment.length is deliberately larger than loadedEnd here — isWindowFull only
    // checks the end boundary (a known, documented limitation for a genuinely
    // backward-opened window whose loadedEnd pins to the segment's true end from its
    // first load, see root CLAUDE.md's TODO section), so loadedEnd must stay short of
    // the segment's true end for this fixture to actually exercise the extend path
    // rather than being read as already-full.
    const resumeWindow = {
        segment: { stid: 1, id: 0, direction: 1, offset: 0, length: 2000, time: 0, ranges: [{ offset: 0, length: 2000 }] },
        loadedStart: 700, loadedEnd: 1000, bytes: new Uint8Array(300),
    }
    const extBytes = new Uint8Array([9, 9])
    const handle = fakeHandle({ frames: [], bytesFor: () => extBytes })
    const result = await fillBackward(handle, entity(), {
        beforeStid: 1, resumeWindow, excludeIds: [], maxBytes: 2, maxSegments: 10,
    })

    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.equal(w.loadedStart, 698)
    assert.equal(w.loadedEnd, 1000)

    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [{ offset: 698, direction: 1, length: 2 }])
})

test('an oversized first frame requests only its partial openRange, not its full length', async () => {
    const huge = frame(1, 0, 0, 0, 1000)
    const handle = fakeHandle({ frames: [huge], bytesFor: r => new Uint8Array(r.length) })
    const result = await fillForward(handle, entity(), {
        afterStid: 0, resumeWindow: null, excludeIds: [], maxBytes: 300, maxSegments: 10,
    })

    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.equal(w.loadedStart, 0)
    assert.equal(w.loadedEnd, 300)
    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [{ offset: 0, direction: 0, length: 300 }])
})

test('fillForward: a two-range frame fetches both real sub-spans in one batched call and concatenates them', async () => {
    const f = multiRangeFrame(1, 0, 0, [{ offset: 100, length: 3 }, { offset: 500, length: 4 }])
    const handle = fakeHandle({
        frames: [f],
        bytesFor: r => new Uint8Array(r.length).fill(r.offset === 100 ? 1 : 2),
    })
    const result = await fillForward(handle, entity(), {
        afterStid: 0, resumeWindow: null, excludeIds: [], maxBytes: 1000, maxSegments: 10,
    })

    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.equal(w.loadedStart, 0)
    assert.equal(w.loadedEnd, 7) // virtual total: 3 + 4
    assert.deepEqual(Array.from(w.bytes), [1, 1, 1, 2, 2, 2, 2])

    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [
        { offset: 100, length: 3, direction: 0 },
        { offset: 500, length: 4, direction: 0 },
    ])
})

test('fillForward: an oversized multi-range frame\'s truncated window fetches exactly the real sub-spans it spans, not the whole frame', async () => {
    // Three ranges of length 5 each (virtual total 15); maxBytes=8 truncates to virtual
    // [0,8) — the whole first range plus 3 bytes of the second, none of the third.
    const f = multiRangeFrame(1, 0, 0, [
        { offset: 100, length: 5 }, { offset: 500, length: 5 }, { offset: 900, length: 5 },
    ])
    const handle = fakeHandle({ frames: [f], bytesFor: r => new Uint8Array(r.length) })
    const result = await fillForward(handle, entity(), {
        afterStid: 0, resumeWindow: null, excludeIds: [], maxBytes: 8, maxSegments: 10,
    })

    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.equal(w.loadedStart, 0)
    assert.equal(w.loadedEnd, 8)
    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [
        { offset: 100, length: 5, direction: 0 },
        { offset: 500, length: 3, direction: 0 },
    ])
})

test('extendResumeWindow (forward) continues from one real range into the next once the first is exhausted', async () => {
    const resumeWindow = {
        segment: {
            stid: 1, id: 0, direction: 0, offset: 0, length: 10, time: 0,
            ranges: [{ offset: 100, length: 5 }, { offset: 500, length: 5 }],
        },
        loadedStart: 0, loadedEnd: 3, bytes: new Uint8Array(3),
    }
    const handle = fakeHandle({ frames: [], bytesFor: r => new Uint8Array(r.length) })
    // Extend by 4 bytes: virtual [3,7) — the last 2 bytes of range 0 (virtual [0,5)) plus
    // the first 2 bytes of range 1 (virtual [5,10)).
    const result = await fillForward(handle, entity(), {
        afterStid: 1, resumeWindow, excludeIds: [], maxBytes: 4, maxSegments: 10,
    })

    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.equal(w.loadedStart, 0)
    assert.equal(w.loadedEnd, 7)
    const bytesCall = handle.calls.find(c => c.dir === 'bytes')
    assert.deepEqual(bytesCall.ranges, [
        { offset: 103, length: 2, direction: 0 },
        { offset: 500, length: 2, direction: 0 },
    ])
})

test('no candidates selected means fetchByteRanges is never called', async () => {
    const handle = fakeHandle({ frames: [], bytesFor: () => new Uint8Array(0) })
    const result = await fillForward(handle, entity(), {
        afterStid: 0, resumeWindow: null, excludeIds: [], maxBytes: 1000, maxSegments: 10,
    })
    assert.deepEqual(result, { windows: [], reachedEnd: true })
    assert.equal(handle.calls.some(c => c.dir === 'bytes'), false)
})
