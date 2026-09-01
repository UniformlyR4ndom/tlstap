import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DIRNUM_C2S, DIRNUM_S2C } from './direction.js'
import { encodeByteRangesRequest, decodeByteRangesResponse } from './byteRangesCore.js'

test('encodeByteRangesRequest: produces exactly length*16 bytes', () => {
    const buf = encodeByteRangesRequest([
        { offset: 0, direction: DIRNUM_C2S, length: 1 },
        { offset: 10, direction: DIRNUM_S2C, length: 2 },
    ])
    assert.equal(buf.byteLength, 32)
})

test('encodeByteRangesRequest: entries land at the right byte offsets, direction as sign', () => {
    const buf = encodeByteRangesRequest([
        { offset: 5, direction: DIRNUM_C2S, length: 100 },
        { offset: 0, direction: DIRNUM_S2C, length: 128 * 1024 * 1024 },
    ])
    const view = new DataView(buf)
    assert.equal(view.getBigInt64(0, false), 5n)
    assert.equal(view.getBigInt64(8, false), -100n) // c2s -> negative
    assert.equal(view.getBigInt64(16, false), 0n)
    assert.equal(view.getBigInt64(24, false), BigInt(128 * 1024 * 1024)) // s2c -> positive
})

test('encodeByteRangesRequest: an empty range list produces a zero-length buffer', () => {
    assert.equal(encodeByteRangesRequest([]).byteLength, 0)
})

test('decodeByteRangesResponse: parses mixed lengths in order, including zero-length entries', () => {
    const payload1 = new Uint8Array([1, 2, 3])
    const payload3 = new Uint8Array([9])
    const buf = new ArrayBuffer(8 + 3 + 8 + 0 + 8 + 1)
    const view = new DataView(buf)
    let pos = 0
    view.setBigInt64(pos, 3n, false); pos += 8
    new Uint8Array(buf, pos, 3).set(payload1); pos += 3
    view.setBigInt64(pos, 0n, false); pos += 8
    view.setBigInt64(pos, 1n, false); pos += 8
    new Uint8Array(buf, pos, 1).set(payload3); pos += 1

    const entries = decodeByteRangesResponse(buf, 3)
    assert.equal(entries.length, 3)
    assert.deepEqual(Array.from(entries[0]), [1, 2, 3])
    assert.deepEqual(Array.from(entries[1]), [])
    assert.deepEqual(Array.from(entries[2]), [9])
})

test('decodeByteRangesResponse: consecutive zero-length entries parse correctly', () => {
    const buf = new ArrayBuffer(24)
    const view = new DataView(buf)
    view.setBigInt64(0, 0n, false)
    view.setBigInt64(8, 0n, false)
    view.setBigInt64(16, 0n, false)
    const entries = decodeByteRangesResponse(buf, 3)
    assert.equal(entries.length, 3)
    for (const e of entries) assert.equal(e.length, 0)
})

test('decodeByteRangesResponse: returned views share the underlying buffer, no copy', () => {
    const buf = new ArrayBuffer(8 + 4)
    const view = new DataView(buf)
    view.setBigInt64(0, 4n, false)
    new Uint8Array(buf, 8, 4).set([1, 2, 3, 4])

    const [entry] = decodeByteRangesResponse(buf, 1)
    entry[0] = 99
    assert.equal(new Uint8Array(buf, 8, 4)[0], 99, 'mutating the view should mutate the shared buffer')
})

test('round trip: encode a request, decode a hand-built matching response', () => {
    const ranges = [
        { offset: 0, direction: DIRNUM_C2S, length: 5 },
        { offset: 100, direction: DIRNUM_S2C, length: 3 },
    ]
    encodeByteRangesRequest(ranges) // just confirms this doesn't throw for the shapes below

    const buf = new ArrayBuffer(8 + 2 + 8 + 3)
    const view = new DataView(buf)
    let pos = 0
    view.setBigInt64(pos, 2n, false); pos += 8 // short read: only 2 of 5 requested bytes available
    new Uint8Array(buf, pos, 2).set([1, 2]); pos += 2
    view.setBigInt64(pos, 3n, false); pos += 8
    new Uint8Array(buf, pos, 3).set([7, 8, 9]); pos += 3

    const entries = decodeByteRangesResponse(buf, 2)
    assert.deepEqual(Array.from(entries[0]), [1, 2], 'a short read is not an error, just fewer bytes')
    assert.deepEqual(Array.from(entries[1]), [7, 8, 9])
})
