import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DIRNUM_C2S, DIRNUM_S2C, encodeSignedLength, decodeSignedLength } from './direction.js'

test('encodeSignedLength/decodeSignedLength round-trip both directions', () => {
    for (const direction of [DIRNUM_C2S, DIRNUM_S2C]) {
        for (const magnitude of [1, 5000, 128 * 1024 * 1024]) {
            const signedLength = encodeSignedLength(direction, magnitude)
            assert.deepEqual(decodeSignedLength(signedLength), { direction, magnitude })
        }
    }
})

test('encodeSignedLength: c2s is negative, s2c is positive', () => {
    assert.equal(encodeSignedLength(DIRNUM_C2S, 42), -42)
    assert.equal(encodeSignedLength(DIRNUM_S2C, 42), 42)
})

test('decodeSignedLength: negative decodes to c2s, positive decodes to s2c', () => {
    assert.deepEqual(decodeSignedLength(-7), { direction: DIRNUM_C2S, magnitude: 7 })
    assert.deepEqual(decodeSignedLength(7), { direction: DIRNUM_S2C, magnitude: 7 })
})
