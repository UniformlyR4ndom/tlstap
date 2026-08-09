import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encodeState, decodeState, encodeMeta, decodeMeta } from './dbdumpFramerApi.js'

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
