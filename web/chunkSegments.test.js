import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fillForward, fillBackward } from './chunkSegments.js'

// A fake connection handle — fillForward/fillBackward only ever call these two methods,
// so this sidesteps openConnection()'s real openSegmentsStream() (browser-only, needs a
// live WebSocket/location) entirely, keeping this test plain-Node-runnable like every
// other web/*.test.js file.
function fakeHandle(response) {
    const calls = []
    return {
        fetchForward(session, stream, afterStid, maxSegments, maxBytes) {
            calls.push({ dir: 'forward', session, stream, afterStid, maxSegments, maxBytes })
            return Promise.resolve(response)
        },
        fetchBackward(session, stream, beforeStid, maxSegments, maxBytes) {
            calls.push({ dir: 'backward', session, stream, beforeStid, maxSegments, maxBytes })
            return Promise.resolve(response)
        },
        calls,
    }
}

test('fillForward maps segments to fully-loaded SegmentWindows and passes request fields through', async () => {
    const data = new Uint8Array([1, 2, 3])
    const handle = fakeHandle({
        segments: [{ stid: 5, segmentId: 2, direction: 1, time: 999, offset: 30, length: 3, data }],
        reachedEnd: true,
    })
    const entity = { session: 7, id: 3 }
    const result = await fillForward(handle, entity, { afterStid: 4, resumeWindow: null, maxBytes: 100, maxSegments: 10 })

    assert.equal(result.reachedEnd, true)
    assert.equal(result.windows.length, 1)
    const w = result.windows[0]
    assert.deepEqual(w.segment, { stid: 5, id: 2, direction: 1, offset: 30, length: 3, time: 999 })
    assert.equal(w.loadedStart, 30)
    assert.equal(w.loadedEnd, 33)
    assert.equal(w.bytes, data) // same array, no copy

    assert.deepEqual(handle.calls[0], { dir: 'forward', session: 7, stream: 3, afterStid: 4, maxSegments: 10, maxBytes: 100 })
})

test('fillBackward mirrors fillForward, mapping beforeStid through', async () => {
    const handle = fakeHandle({ segments: [], reachedEnd: false })
    const entity = { session: 1, id: 1 }
    const result = await fillBackward(handle, entity, { beforeStid: 20, maxBytes: 50, maxSegments: 5 })

    assert.deepEqual(result, { windows: [], reachedEnd: false })
    assert.deepEqual(handle.calls[0], { dir: 'backward', session: 1, stream: 1, beforeStid: 20, maxSegments: 5, maxBytes: 50 })
})

test('a window built from a segment is always fully loaded', async () => {
    const data = new Uint8Array(64)
    const handle = fakeHandle({
        segments: [{ stid: 1, segmentId: 0, direction: 0, time: 0, offset: 0, length: 64, data }],
        reachedEnd: true,
    })
    const { windows } = await fillForward(handle, { session: 1, id: 1 }, { afterStid: -1, maxBytes: 1000, maxSegments: 10 })
    const w = windows[0]
    assert.equal(w.loadedEnd, w.segment.offset + w.segment.length, 'isWindowFull() must hold for every chunk-mode window')
})

test('multiple segments in one response map in order', async () => {
    const s0 = { stid: 1, segmentId: 0, direction: 0, time: 0, offset: 0, length: 2, data: new Uint8Array([1, 2]) }
    const s1 = { stid: 2, segmentId: 0, direction: 1, time: 0, offset: 0, length: 2, data: new Uint8Array([3, 4]) }
    const handle = fakeHandle({ segments: [s0, s1], reachedEnd: false })
    const { windows } = await fillForward(handle, { session: 1, id: 1 }, { afterStid: -1, maxBytes: 1000, maxSegments: 10 })
    assert.deepEqual(windows.map(w => w.segment.stid), [1, 2])
})
