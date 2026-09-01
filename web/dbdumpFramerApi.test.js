import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeState, decodeState, encodeMeta, decodeMeta, decodeFrame } from './dbdumpFramerApi.js'

test('encodeState/decodeState round-trips a plain value', () => {
    const value = { n: 1, s: 'hi', nested: { arr: [1, 2, 3] } }
    assert.deepEqual(decodeState(encodeState(value)), value)
})

test('encodeState/decodeState round-trips a nested Uint8Array', () => {
    const value = { carry: new Uint8Array([26, 3, 1, 0, 80, 255]) }
    const decoded = decodeState(encodeState(value))
    assert.ok(decoded.carry instanceof Uint8Array)
    assert.deepEqual(Array.from(decoded.carry), [26, 3, 1, 0, 80, 255])
})

test('encodeState/decodeState round-trips multiple Uint8Arrays at different depths', () => {
    const value = { a: new Uint8Array([1, 2]), nested: { b: new Uint8Array([3, 4, 5]) } }
    const decoded = decodeState(encodeState(value))
    assert.deepEqual(Array.from(decoded.a), [1, 2])
    assert.deepEqual(Array.from(decoded.nested.b), [3, 4, 5])
})

test('encodeState/decodeState round-trips an empty Uint8Array', () => {
    const value = { carry: new Uint8Array(0) }
    const decoded = decodeState(encodeState(value))
    assert.ok(decoded.carry instanceof Uint8Array)
    assert.equal(decoded.carry.length, 0)
})

test('encodeState/decodeState treats null/undefined as null', () => {
    assert.equal(encodeState(null), null)
    assert.equal(encodeState(undefined), null)
    assert.equal(decodeState(null), null)
    assert.equal(decodeState(undefined), null)
})

test('encodeMeta/decodeMeta round-trips a nested Uint8Array', () => {
    const value = { preview: new Uint8Array([0xde, 0xad, 0xbe, 0xef]) }
    const decoded = decodeMeta(encodeMeta(value))
    assert.ok(decoded.preview instanceof Uint8Array)
    assert.deepEqual(Array.from(decoded.preview), [0xde, 0xad, 0xbe, 0xef])
})

test('encodeMeta/decodeMeta round-trips a plain value without the bytes tag', () => {
    const value = { type: 22, typeName: 'handshake' }
    assert.deepEqual(decodeMeta(encodeMeta(value)), value)
})

// decodeFrame's length field — see its own doc comment in dbdumpFramerApi.js: a
// permanent, always-well-defined sum(ranges[].length), not a shim (unlike the retired
// `offset` field this used to also derive from ranges[0]).

test('decodeFrame: single-range frame — length is that one range\'s own length', () => {
    const wire = { id: 1, ranges: [{ offset: 10, length: 5 }], meta: null, direction: 0, stid: 2, time: 100, seq: 0, virtual_offset: 0 }
    const f = decodeFrame(wire)
    assert.equal(f.length, 5)
    assert.deepEqual(f.ranges, [{ offset: 10, length: 5 }])
    assert.equal(f.id, 1)
    assert.equal(f.stid, 2)
    assert.equal(f.time, 100)
    assert.equal(f.seq, 0)
    assert.equal(f.virtualOffset, 0)
    assert.equal(f.offset, undefined, 'offset is retired — consumers address a frame by its ranges/length now')
})

// virtual_offset is passed through as-is, unlike offset/length above — not itself
// shimmed/derived, and not necessarily equal to offset (a direction's running total is
// independent of any one frame's own real byte position).
test('decodeFrame: virtual_offset passes through unchanged as virtualOffset', () => {
    const wire = { id: 3, ranges: [{ offset: 100, length: 5 }], meta: null, direction: 1, stid: 4, time: 100, seq: 2, virtual_offset: 42 }
    const f = decodeFrame(wire)
    assert.equal(f.virtualOffset, 42)
})

test('decodeFrame: multi-range frame — length is the sum across all ranges', () => {
    const wire = { id: 1, ranges: [{ offset: 10, length: 5 }, { offset: 20, length: 3 }], meta: null, direction: 0, stid: 2, time: 100, seq: 0 }
    const f = decodeFrame(wire)
    assert.equal(f.length, 8)
    assert.deepEqual(f.ranges, wire.ranges)
})
