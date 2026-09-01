import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fillForward, fillBackward } from './chunkSegments.js'

// A fake handle — fillForward/fillBackward only ever call these three methods, so this
// sidesteps api.js's real listChunksTimeline/listChunksTimelineBackward/fetchByteRanges
// (browser-only, needs a live fetch()) entirely, keeping this test plain-Node-runnable
// like every other web/*.test.js file.
function fakeHandle({ chunks, bytesFor }) {
    const calls = []
    return {
        listChunksTimeline(session, stream, start, n) {
            calls.push({ dir: 'forward', session, stream, start, n })
            return Promise.resolve(chunks)
        },
        listChunksTimelineBackward(session, stream, beforeStid, n) {
            calls.push({ dir: 'backward', session, stream, beforeStid, n })
            return Promise.resolve(chunks)
        },
        fetchByteRanges(session, stream, ranges) {
            calls.push({ dir: 'bytes', session, stream, ranges })
            return Promise.resolve(ranges.map(bytesFor))
        },
        calls,
    }
}

test('fillForward maps chunks to fully-loaded SegmentWindows and passes request fields through', async () => {
    const chunk = { id: 2, direction: 1, stid: 5, time: 999, offset: 30, length: 3 }
    const data = new Uint8Array([1, 2, 3])
    const handle = fakeHandle({ chunks: [chunk], bytesFor: () => data })
    const entity = { session: 7, id: 3 }
    const result = await fillForward(handle, entity, { afterStid: 4, maxBytes: 100, maxSegments: 10 })

    assert.equal(result.reachedEnd, true)
    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.deepEqual(w.segment, { stid: 5, id: 2, direction: 1, offset: 30, length: 3, time: 999 })
    assert.equal(w.loadedStart, 30)
    assert.equal(w.loadedEnd, 33)
    assert.equal(w.bytes, data) // same array, no copy

    // afterStid+1 = 5 is the inclusive `start` /chunks/timeline expects.
    assert.deepEqual(handle.calls[0], { dir: 'forward', session: 7, stream: 3, start: 5, n: 11 })
    assert.deepEqual(handle.calls[1], { dir: 'bytes', session: 7, stream: 3, ranges: [{ offset: 30, direction: 1, length: 3 }] })
})

test('fillBackward mirrors fillForward, mapping beforeStid through unchanged', async () => {
    const handle = fakeHandle({ chunks: [], bytesFor: () => new Uint8Array(0) })
    const entity = { session: 1, id: 1 }
    const result = await fillBackward(handle, entity, { beforeStid: 20, maxBytes: 50, maxSegments: 5 })

    // Zero candidates, strictly fewer than the requestN lookahead -> genuinely reached end.
    assert.deepEqual(result, { windows: [], reachedEnd: true })
    assert.deepEqual(handle.calls[0], { dir: 'backward', session: 1, stream: 1, beforeStid: 20, n: 6 })
})

test('a window built from a chunk is always fully loaded', async () => {
    const chunk = { id: 1, direction: 0, stid: 1, time: 0, offset: 0, length: 64 }
    const data = new Uint8Array(64)
    const handle = fakeHandle({ chunks: [chunk], bytesFor: () => data })
    const { windows } = await fillForward(handle, { session: 1, id: 1 }, { afterStid: -1, maxBytes: 1000, maxSegments: 10 })
    const w = windows[0]
    assert.equal(w.loadedEnd, w.segment.offset + w.segment.length, 'isWindowFull() must hold for every chunk-mode window')
})

test('multiple chunks in one response map in order', async () => {
    const c0 = { id: 0, direction: 0, stid: 1, time: 0, offset: 0, length: 2 }
    const c1 = { id: 0, direction: 1, stid: 2, time: 0, offset: 0, length: 2 }
    const handle = fakeHandle({ chunks: [c0, c1], bytesFor: r => new Uint8Array(r.length) })
    const { windows } = await fillForward(handle, { session: 1, id: 1 }, { afterStid: -1, maxBytes: 1000, maxSegments: 10 })
    assert.deepEqual(windows.map(w => w.segment.stid), [1, 2])
})

test('an oversized single chunk is still included and fetched whole, not truncated to maxBytes', async () => {
    const chunk = { id: 0, direction: 0, stid: 1, time: 0, offset: 0, length: 1000 }
    const data = new Uint8Array(1000)
    const handle = fakeHandle({ chunks: [chunk], bytesFor: () => data })
    const { windows } = await fillForward(handle, { session: 1, id: 1 }, { afterStid: -1, maxBytes: 300, maxSegments: 10 })

    assert.equal(windows.length, 1)
    assert.equal(windows[0].loadedEnd - windows[0].loadedStart, 1000, 'fetched whole — chunk mode has no partial-load concept')
    assert.deepEqual(handle.calls[1].ranges, [{ offset: 0, direction: 0, length: 1000 }])
})

test('resumeWindow/excludeIds passed by fillToTarget are accepted but ignored', async () => {
    const chunk = { id: 0, direction: 0, stid: 1, time: 0, offset: 0, length: 4 }
    const handle = fakeHandle({ chunks: [chunk], bytesFor: r => new Uint8Array(r.length) })
    // Should not throw despite the extra, unused fields.
    const result = await fillForward(handle, { session: 1, id: 1 }, {
        afterStid: -1, maxBytes: 1000, maxSegments: 10, resumeWindow: { some: 'stale' }, excludeIds: [0, 1],
    })
    assert.equal(result.windows.length, 1)
})
