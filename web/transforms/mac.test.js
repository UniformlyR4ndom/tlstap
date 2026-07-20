import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './mac.js'

const enc = new TextEncoder()

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function repeatHex(byte, n) {
    return byte.toString(16).padStart(2, '0').repeat(n)
}

function run(op, bytes, params) {
    return OPERATIONS[op].run(bytes, params)
}

// RFC 2202 (HMAC-MD5/SHA1) and RFC 4231 (HMAC-SHA224/256/384/512) Test Case 1 — each algorithm's
// own key length exactly matches that RFC's table (16 bytes of 0x0b for MD5, 20 for the rest;
// they are *not* interchangeable — an earlier draft of this file mixed up the two key lengths and
// silently got the wrong HMAC-MD5 value, since HMAC's key handling depends on the block size).
// Independently cross-checked against Node's crypto.createHmac before use.
test('known vectors: RFC 2202/4231 Test Case 1 ("Hi There")', () => {
    const data = enc.encode('Hi There')
    assert.equal(toHex(run('hmac-md5', data, { key: repeatHex(0x0b, 16) })), '9294727a3638bb1c13f48ef8158bfc9d')
    assert.equal(toHex(run('hmac-sha1', data, { key: repeatHex(0x0b, 20) })), 'b617318655057264e28bc0b6fb378c8ef146be00')
    assert.equal(toHex(run('hmac-sha224', data, { key: repeatHex(0x0b, 20) })), '896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22')
    assert.equal(toHex(run('hmac-sha256', data, { key: repeatHex(0x0b, 20) })), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
    assert.equal(toHex(run('hmac-sha384', data, { key: repeatHex(0x0b, 20) })), 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6')
    assert.equal(toHex(run('hmac-sha512', data, { key: repeatHex(0x0b, 20) })), '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854')
})

// RFC 2202/4231 Test Case 2 — same key/message across all six algorithms, cross-checked against
// Node's crypto.createHmac.
test('known vectors: RFC 2202/4231 Test Case 2 (key="Jefe")', () => {
    const key = toHex(enc.encode('Jefe'))
    const data = enc.encode('what do ya want for nothing?')
    const expected = {
        'hmac-md5': '750c783e6ab0b503eaa86e310a5db738',
        'hmac-sha1': 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79',
        'hmac-sha224': 'a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44',
        'hmac-sha256': '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
        'hmac-sha384': 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649',
        'hmac-sha512': '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
    }
    for (const [op, hex] of Object.entries(expected)) {
        assert.equal(toHex(run(op, data, { key })), hex, op)
    }
})

test('key affects output (different keys produce different MACs on identical input)', () => {
    const data = enc.encode('same message')
    for (const op of Object.keys(OPERATIONS)) {
        const a = run(op, data, { key: repeatHex(0x01, 16) })
        const b = run(op, data, { key: repeatHex(0x02, 16) })
        assert.notEqual(toHex(a), toHex(b), op)
    }
})

test('message affects output (different messages produce different MACs under the same key)', () => {
    const key = repeatHex(0x01, 16)
    for (const op of Object.keys(OPERATIONS)) {
        const a = run(op, enc.encode('message one'), { key })
        const b = run(op, enc.encode('message two'), { key })
        assert.notEqual(toHex(a), toHex(b), op)
    }
})

test('empty message with a real key still produces a valid MAC', () => {
    const key = repeatHex(0x01, 16)
    for (const op of Object.keys(OPERATIONS)) {
        const mac = run(op, new Uint8Array(0), { key })
        assert.ok(mac.length > 0, op)
    }
})

test('rejects an empty key', () => {
    const data = enc.encode('x')
    for (const op of Object.keys(OPERATIONS)) {
        assert.throws(() => run(op, data, { key: '' }), op)
    }
})

test('accepts an optional "0x"/"0X" prefix on the key, ignored the same way as encryption.js\'s parseHexBytes', () => {
    const data = enc.encode('0x-prefix consistency check')
    const bareKey = repeatHex(0xab, 16)
    for (const op of Object.keys(OPERATIONS)) {
        const bare = run(op, data, { key: bareKey })
        const prefixed = run(op, data, { key: '0X' + bareKey })
        assert.deepEqual(prefixed, bare, op)
    }
})

test('shared hex parsing: rejects odd-length hex and invalid hex characters, and tolerates embedded whitespace (exercised once via HMAC-SHA256 rather than repeated per algorithm)', () => {
    const data = enc.encode('x')
    assert.throws(() => run('hmac-sha256', data, { key: repeatHex(0x01, 16) + '0' }))
    assert.throws(() => run('hmac-sha256', data, { key: 'zz'.repeat(16) }))
    const bare = run('hmac-sha256', data, { key: 'aabbccdd' })
    const spaced = run('hmac-sha256', data, { key: 'aa bb cc dd' })
    assert.deepEqual(spaced, bare)
})

test('fixed output length per algorithm regardless of input length', () => {
    const expectedLengths = { 'hmac-md5': 16, 'hmac-sha1': 20, 'hmac-sha224': 28, 'hmac-sha256': 32, 'hmac-sha384': 48, 'hmac-sha512': 64 }
    const key = repeatHex(0x01, 16)
    for (const [op, len] of Object.entries(expectedLengths)) {
        assert.equal(run(op, enc.encode('short'), { key }).length, len)
        assert.equal(run(op, enc.encode('a much longer input '.repeat(20)), { key }).length, len)
    }
})
