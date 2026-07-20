import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './encryption.js'

const enc = new TextEncoder()

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(hex) {
    const out = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16)
    return out
}

function run(op, bytes, params) {
    return OPERATIONS[op].run(bytes, params)
}

function assertRoundTrip(encOp, decOp, params, message) {
    const ct = run(encOp, message, params)
    const pt = run(decOp, ct, params)
    assert.deepEqual(pt, message, `${encOp} ${JSON.stringify(params)} (message length ${message.length})`)
}

function repeatHex(byte, n) {
    return byte.toString(16).padStart(2, '0').repeat(n)
}

function rangeHex(start, n) {
    return Array.from({ length: n }, (_, i) => (start + i).toString(16).padStart(2, '0')).join('')
}

// --- AES ---
// Every vector below (CBC/CTR/GCM, 128/192/256-bit keys, with and without AAD) was cross-checked
// against Node's own crypto.createCipheriv/getAuthTag (a different implementation from the
// vendored @noble/ciphers under test) before use. GCM's expected hex is ciphertext with Node's
// separately-reported auth tag appended, matching this module's own tag-append convention.
const AES_PT = enc.encode('AES known-vector test plaintext!')
const AES_IV = rangeHex(0x10, 16)
const AES_NONCE = rangeHex(0x20, 12)
const AES_AAD = toHex(enc.encode('extra-authenticated-data'))
const aesKey = n => rangeHex(1, n)

test('aes: known CBC vectors (128/192/256), cross-checked against Node crypto', () => {
    const expected = {
        16: 'b50cfb90d02f2baf1cff2acdcafc86f60c36abc083c458a9a3461005eb4b5f9347b46035f1d2366ad05e94713c159457',
        24: 'ac38c23c37d709c3308d26164939147ef6635a349c35a54fe9df4fc594572391c1a585380f3b259ce1cc14dd14de9b98',
        32: '7d4f4c18abce647760fb6a4dbbef5b48efc08c647d1a9602038b5831ec415e58f93b21c9086ea25a23e22fa37de4ed46',
    }
    for (const [len, hex] of Object.entries(expected)) {
        const ct = run('aes-encrypt', AES_PT, { mode: 'cbc', key: aesKey(Number(len)), iv: AES_IV, padding: 'pkcs7' })
        assert.equal(toHex(ct), hex, `${len}-byte key`)
    }
})

test('aes: known CTR vectors (128/192/256), cross-checked against Node crypto', () => {
    const expected = {
        16: '27f155bcd98b52c667adfd54b09ab1c7c4ba09bcee891502493e16b8470b4889',
        24: '45f7afcf8409b1c334522f7e57e087a9d0efd9260169dd00fe04862030126089',
        32: '49a5a70a72eff1e4b655fa3b9df874e71b392bc6b5b46b20d9eac661ffe23069',
    }
    for (const [len, hex] of Object.entries(expected)) {
        const ct = run('aes-encrypt', AES_PT, { mode: 'ctr', key: aesKey(Number(len)), iv: AES_IV })
        assert.equal(toHex(ct), hex, `${len}-byte key`)
    }
})

test('aes: known GCM vectors (128/192/256, no AAD), cross-checked against Node crypto', () => {
    const expected = {
        16: 'c2b64e37ab5c79f5b3c45b888d6829b227cd8257b909422d22929b82bae6bce61fd11bd36491eb07b75de537c372e878',
        24: 'b3b3ee89ca0ec352992d352cb2f6fd0177b71bd6bf28e935ba2c2e08fb83be5b9dc82feec2e74b84d2043d28bcc31cfb',
        32: '36b6e9439e35beb0768f71fc246db6ce71e1bed4a1e612d7e5a95006e749a82e4be492f0aeb2fadbd67116bdd7a2ac1b',
    }
    for (const [len, hex] of Object.entries(expected)) {
        const ct = run('aes-encrypt', AES_PT, { mode: 'gcm', key: aesKey(Number(len)), nonce: AES_NONCE, aad: '' })
        assert.equal(toHex(ct), hex, `${len}-byte key`)
    }
})

test('aes: known GCM vector with AAD (128-bit), cross-checked against Node crypto', () => {
    const ct = run('aes-encrypt', AES_PT, { mode: 'gcm', key: aesKey(16), nonce: AES_NONCE, aad: AES_AAD })
    assert.equal(toHex(ct), 'c2b64e37ab5c79f5b3c45b888d6829b227cd8257b909422d22929b82bae6bce6f90aa574c84602ef575c59f6d551f1fe')
})

test('aes: round-trips for every mode across all three key sizes', () => {
    for (const len of [16, 24, 32]) {
        const key = aesKey(len)
        for (const params of [
            { mode: 'cbc', key, iv: AES_IV, padding: 'pkcs7' },
            { mode: 'ctr', key, iv: AES_IV },
            { mode: 'gcm', key, nonce: AES_NONCE, aad: AES_AAD },
            { mode: 'ecb', key, padding: 'pkcs7' },
            { mode: 'cfb', key, iv: AES_IV },
            { mode: 'ofb', key, iv: AES_IV },
        ]) {
            const ct = run('aes-encrypt', AES_PT, params)
            const pt = run('aes-decrypt', ct, params)
            assert.deepEqual(pt, AES_PT, JSON.stringify(params))
        }
    }
})

test('aes: exhaustive round-trip matrix — every mode, both padding schemes where applicable, all three key sizes, empty and non-empty input', () => {
    const aligned = enc.encode('Exactly16Bytes!!') // block-aligned, needed for the "no padding" case
    for (const len of [16, 24, 32]) {
        const key = aesKey(len)
        for (const mode of ['ctr', 'cfb', 'ofb']) {
            for (const msg of [new Uint8Array(0), AES_PT]) {
                assertRoundTrip('aes-encrypt', 'aes-decrypt', { mode, key, iv: AES_IV }, msg)
            }
        }
        for (const msg of [new Uint8Array(0), AES_PT]) {
            assertRoundTrip('aes-encrypt', 'aes-decrypt', { mode: 'gcm', key, nonce: AES_NONCE, aad: AES_AAD }, msg)
        }
        for (const mode of ['cbc', 'ecb']) {
            for (const msg of [new Uint8Array(0), AES_PT]) {
                assertRoundTrip('aes-encrypt', 'aes-decrypt', { mode, key, iv: AES_IV, padding: 'pkcs7' }, msg)
            }
            for (const msg of [new Uint8Array(0), aligned]) {
                assertRoundTrip('aes-encrypt', 'aes-decrypt', { mode, key, iv: AES_IV, padding: 'none' }, msg)
            }
        }
    }
})

test('aes: known ECB/CFB/OFB vectors (128/192/256), cross-checked against Node crypto', () => {
    const expectedEcb = {
        16: '663e66674e492d99e9ac2ae8ebb7322e50c13ef537fead619fdc181f0326e05a6cc00a66d2ad83ffd76e9a2bcad89a01',
        24: '987109e9c8bf6854d9fb8b7a250023d01906107bae9313c5208b876c1b7c36b86fb166e30398f8678a61b860dfd3c86b',
        32: '7f68809fb667803118e1b472bc8752dcbd800d875210a3322457da958f16e0cdd45d7c5aa26bca9d6b1d5ddbf68f9ef6',
    }
    const expectedCfb = {
        16: '27f155bcd98b52c667adfd54b09ab1c729144318bf1f0952c2073c6c7334fbce',
        24: '45f7afcf8409b1c334522f7e57e087a91904e1989ae1fa4a7247743e31294441',
        32: '49a5a70a72eff1e4b655fa3b9df874e78ca7e15c6b15c786b310b0e5c3d28259',
    }
    const expectedOfb = {
        16: '27f155bcd98b52c667adfd54b09ab1c715664aa8aeec3b65b3dbe0718a404811',
        24: '45f7afcf8409b1c334522f7e57e087a98c4e8f96f20b03779ddff2dca287cc6f',
        32: '49a5a70a72eff1e4b655fa3b9df874e7837cd557266a9821f76400193833d76f',
    }
    for (const [len, hex] of Object.entries(expectedEcb)) {
        assert.equal(toHex(run('aes-encrypt', AES_PT, { mode: 'ecb', key: aesKey(Number(len)), padding: 'pkcs7' })), hex, `ECB ${len}-byte key`)
    }
    for (const [len, hex] of Object.entries(expectedCfb)) {
        assert.equal(toHex(run('aes-encrypt', AES_PT, { mode: 'cfb', key: aesKey(Number(len)), iv: AES_IV })), hex, `CFB ${len}-byte key`)
    }
    for (const [len, hex] of Object.entries(expectedOfb)) {
        assert.equal(toHex(run('aes-encrypt', AES_PT, { mode: 'ofb', key: aesKey(Number(len)), iv: AES_IV })), hex, `OFB ${len}-byte key`)
    }
})

test('aes: ECB requires no IV, and ECB/CFB/OFB all differ from each other and from CBC on identical input', () => {
    const key = aesKey(16)
    const ecbCt = run('aes-encrypt', AES_PT, { mode: 'ecb', key, padding: 'pkcs7' }) // no `iv` param at all
    const cbcCt = run('aes-encrypt', AES_PT, { mode: 'cbc', key, iv: AES_IV, padding: 'pkcs7' })
    const cfbCt = run('aes-encrypt', AES_PT, { mode: 'cfb', key, iv: AES_IV })
    const ofbCt = run('aes-encrypt', AES_PT, { mode: 'ofb', key, iv: AES_IV })
    const hexes = [ecbCt, cbcCt, cfbCt, ofbCt].map(toHex)
    assert.equal(new Set(hexes).size, 4, 'all four modes must produce distinct ciphertext')
})

test('aes: field visibility (showIf) matches expectations for every mode', () => {
    const params = OPERATIONS['aes-encrypt'].params
    const visible = mode => params.filter(p => !p.showIf || p.showIf({ mode })).map(p => p.key).sort()
    assert.deepEqual(visible('cbc'), ['iv', 'key', 'mode', 'padding'].sort())
    assert.deepEqual(visible('ctr'), ['iv', 'key', 'mode'].sort())
    assert.deepEqual(visible('ecb'), ['key', 'mode', 'padding'].sort())
    assert.deepEqual(visible('cfb'), ['iv', 'key', 'mode'].sort())
    assert.deepEqual(visible('ofb'), ['iv', 'key', 'mode'].sort())
    assert.deepEqual(visible('gcm'), ['aad', 'key', 'mode', 'nonce'].sort())
})

test('aes: CBC with "no padding" round-trips block-aligned input and rejects non-aligned input', () => {
    const key = aesKey(16)
    const aligned = enc.encode('Exactly16Bytes!!')
    const ct = run('aes-encrypt', aligned, { mode: 'cbc', key, iv: AES_IV, padding: 'none' })
    assert.equal(ct.length, aligned.length)
    assert.deepEqual(run('aes-decrypt', ct, { mode: 'cbc', key, iv: AES_IV, padding: 'none' }), aligned)
    const nonAligned = enc.encode('Not16BytesLong') // 14 bytes
    assert.throws(() => run('aes-encrypt', nonAligned, { mode: 'cbc', key, iv: AES_IV, padding: 'none' }))
})

test('aes: GCM rejects a tampered ciphertext/tag', () => {
    const key = aesKey(16)
    const ct = run('aes-encrypt', AES_PT, { mode: 'gcm', key, nonce: AES_NONCE, aad: '' })
    ct[0] ^= 0xff
    assert.throws(() => run('aes-decrypt', ct, { mode: 'gcm', key, nonce: AES_NONCE, aad: '' }), /authentication failed/)
})

test('aes: GCM rejects a mismatched AAD on decrypt', () => {
    const key = aesKey(16)
    const ct = run('aes-encrypt', AES_PT, { mode: 'gcm', key, nonce: AES_NONCE, aad: AES_AAD })
    assert.throws(() => run('aes-decrypt', ct, { mode: 'gcm', key, nonce: AES_NONCE, aad: '' }), /authentication failed/)
})

test('aes: CBC and CTR produce different ciphertext for identical input (guards against an ignored mode param)', () => {
    const key = aesKey(16)
    const cbcCt = run('aes-encrypt', AES_PT, { mode: 'cbc', key, iv: AES_IV, padding: 'pkcs7' })
    const ctrCt = run('aes-encrypt', AES_PT, { mode: 'ctr', key, iv: AES_IV })
    assert.notEqual(toHex(cbcCt), toHex(ctrCt))
})

test('aes: rejects an invalid key length', () => {
    assert.throws(() => run('aes-encrypt', AES_PT, { mode: 'cbc', key: rangeHex(1, 15), iv: AES_IV, padding: 'pkcs7' }))
})

// --- DES ---
test('des: classic textbook single-block vector (CBC with a zero IV reduces to ECB on one block)', () => {
    // Key/plaintext/ciphertext are the widely-published DES test vector (e.g. Applied
    // Cryptography, Schneier). CBC-with-zero-IV on a single block is mathematically identical to
    // plain ECB of that block, since XOR with an all-zero IV is a no-op.
    const key = '133457799bbcdff1'
    const zeroIv = repeatHex(0, 8)
    const pt = fromHex('0123456789abcdef')
    const ct = run('des-encrypt', pt, { mode: 'cbc', key, iv: zeroIv, padding: 'none' })
    assert.equal(toHex(ct), '85e813540f0ab405')
})

test('des: CBC/CTR round-trip and differ from each other', () => {
    const key = rangeHex(1, 8)
    const iv = rangeHex(0x10, 8)
    const pt = enc.encode('DES round-trip test message, longer than one block.')
    const cbcCt = run('des-encrypt', pt, { mode: 'cbc', key, iv, padding: 'pkcs7' })
    const ctrCt = run('des-encrypt', pt, { mode: 'ctr', key, iv })
    assert.deepEqual(run('des-decrypt', cbcCt, { mode: 'cbc', key, iv, padding: 'pkcs7' }), pt)
    assert.deepEqual(run('des-decrypt', ctrCt, { mode: 'ctr', key, iv }), pt)
    assert.equal(ctrCt.length, pt.length) // CTR is unpadded, stream-like
    assert.notEqual(toHex(cbcCt), toHex(ctrCt))
})

test('des: rejects a key that is not 8 bytes', () => {
    assert.throws(() => run('des-encrypt', enc.encode('x'), { mode: 'cbc', key: rangeHex(1, 7), iv: rangeHex(1, 8), padding: 'pkcs7' }))
})

test('des: ECB/CFB/OFB round-trip, ECB needs no IV, and all differ from CBC (no independent oracle for single DES beyond the classic vector above, so round-trip only)', () => {
    const key = rangeHex(1, 8)
    const iv = rangeHex(0x10, 8)
    const pt = enc.encode('DES round-trip test message, longer than one block.')
    const ecbCt = run('des-encrypt', pt, { mode: 'ecb', key, padding: 'pkcs7' })
    const cfbCt = run('des-encrypt', pt, { mode: 'cfb', key, iv })
    const ofbCt = run('des-encrypt', pt, { mode: 'ofb', key, iv })
    assert.deepEqual(run('des-decrypt', ecbCt, { mode: 'ecb', key, padding: 'pkcs7' }), pt)
    assert.deepEqual(run('des-decrypt', cfbCt, { mode: 'cfb', key, iv }), pt)
    assert.deepEqual(run('des-decrypt', ofbCt, { mode: 'ofb', key, iv }), pt)
    assert.equal(cfbCt.length, pt.length) // CFB/OFB are unpadded, stream-like
    assert.equal(ofbCt.length, pt.length)
    const hexes = [ecbCt, cfbCt, ofbCt].map(toHex)
    assert.equal(new Set(hexes).size, 3, 'ECB/CFB/OFB must produce distinct ciphertext')
})

test('des: exhaustive round-trip matrix — every mode, both padding schemes where applicable, empty and non-empty input', () => {
    const key = rangeHex(1, 8)
    const iv = rangeHex(0x10, 8)
    const normal = enc.encode('DES round-trip test message, longer than one block.')
    const aligned = enc.encode('Aligned8') // exactly 8 bytes, needed for the "no padding" case
    for (const mode of ['ctr', 'cfb', 'ofb']) {
        for (const msg of [new Uint8Array(0), normal]) {
            assertRoundTrip('des-encrypt', 'des-decrypt', { mode, key, iv }, msg)
        }
    }
    for (const mode of ['cbc', 'ecb']) {
        for (const msg of [new Uint8Array(0), normal]) {
            assertRoundTrip('des-encrypt', 'des-decrypt', { mode, key, iv, padding: 'pkcs7' }, msg)
        }
        for (const msg of [new Uint8Array(0), aligned]) {
            assertRoundTrip('des-encrypt', 'des-decrypt', { mode, key, iv, padding: 'none' }, msg)
        }
    }
})

test('des/3des: field visibility (showIf) hides IV only for ECB, padding only for CBC/ECB', () => {
    const params = OPERATIONS['des-encrypt'].params
    const visible = mode => params.filter(p => !p.showIf || p.showIf({ mode })).map(p => p.key).sort()
    assert.deepEqual(visible('cbc'), ['iv', 'key', 'mode', 'padding'].sort())
    assert.deepEqual(visible('ctr'), ['iv', 'key', 'mode'].sort())
    assert.deepEqual(visible('ecb'), ['key', 'mode', 'padding'].sort())
    assert.deepEqual(visible('cfb'), ['iv', 'key', 'mode'].sort())
    assert.deepEqual(visible('ofb'), ['iv', 'key', 'mode'].sort())
})

// --- 3DES ---
test('3des: known vectors for 16-byte (2-key EDE2) and 24-byte (3-key EDE3) keys, cross-checked against Node crypto (des-ede-cbc / des-ede3-cbc)', () => {
    const iv = repeatHex(0xef, 8)
    const pt = enc.encode('This is a longer DES/3DES test message.')
    const ct16 = run('3des-encrypt', pt, { mode: 'cbc', key: repeatHex(0xab, 16), iv, padding: 'pkcs7' })
    assert.equal(toHex(ct16), '9abf153992aa556432adced66dee3b211eaada9e54b36762e6774a975fccb0e7af7499e386e9c021')
    const ct24 = run('3des-encrypt', pt, { mode: 'cbc', key: repeatHex(0xcd, 24), iv, padding: 'pkcs7' })
    assert.equal(toHex(ct24), 'c6133e7625752e886ff87bb57cbff8ed7639d40a70e9b7076a7748fbd090de7a307136d129acb0a4')
})

test('3des: CBC/CTR round-trip with both key sizes', () => {
    const iv = rangeHex(0x20, 8)
    const pt = enc.encode('3DES round-trip test message, longer than one block.')
    for (const key of [rangeHex(1, 16), rangeHex(1, 24)]) {
        for (const params of [{ mode: 'cbc', key, iv, padding: 'pkcs7' }, { mode: 'ctr', key, iv }]) {
            const ct = run('3des-encrypt', pt, params)
            assert.deepEqual(run('3des-decrypt', ct, params), pt)
        }
    }
})

test('3des: rejects the degenerate 8-byte key length even though crypto-js itself accepts it', () => {
    assert.throws(() => run('3des-encrypt', enc.encode('x'), { mode: 'cbc', key: rangeHex(1, 8), iv: rangeHex(1, 8), padding: 'pkcs7' }))
})

test('3des: known ECB/CFB/OFB vectors (24-byte key), cross-checked against Node crypto (des-ede3-ecb/cfb/ofb)', () => {
    const key = rangeHex(1, 24)
    const iv = rangeHex(0x10, 8)
    const pt = enc.encode('This is a longer DES/3DES test message.')
    assert.equal(toHex(run('3des-encrypt', pt, { mode: 'ecb', key, padding: 'pkcs7' })),
        '9edfc320a46f549bc7ea66fb0288fe23a2073a886d5d40e2c29339c0c2deccc915a0328843a59700')
    assert.equal(toHex(run('3des-encrypt', pt, { mode: 'cfb', key, iv })),
        'e8d590e486e5d538944d92237cabfd3ba1aea343ec9fffbcc2ba86c910a8fb168006a6427802a7')
    assert.equal(toHex(run('3des-encrypt', pt, { mode: 'ofb', key, iv })),
        'e8d590e486e5d538ab294be563b57bcb82efa21598f16b1533bb8bcb0123db4bbc10b51e84a6c3')
})

test('3des: exhaustive round-trip matrix — every mode, both padding schemes where applicable, both key sizes, empty and non-empty input', () => {
    const iv = rangeHex(0x20, 8)
    const normal = enc.encode('3DES round-trip test message, longer than one block.')
    const aligned = enc.encode('Aligned8') // exactly 8 bytes, needed for the "no padding" case
    for (const key of [rangeHex(1, 16), rangeHex(1, 24)]) {
        for (const mode of ['ctr', 'cfb', 'ofb']) {
            for (const msg of [new Uint8Array(0), normal]) {
                assertRoundTrip('3des-encrypt', '3des-decrypt', { mode, key, iv }, msg)
            }
        }
        for (const mode of ['cbc', 'ecb']) {
            for (const msg of [new Uint8Array(0), normal]) {
                assertRoundTrip('3des-encrypt', '3des-decrypt', { mode, key, iv, padding: 'pkcs7' }, msg)
            }
            for (const msg of [new Uint8Array(0), aligned]) {
                assertRoundTrip('3des-encrypt', '3des-decrypt', { mode, key, iv, padding: 'none' }, msg)
            }
        }
    }
})

// --- RC4 ---
test('rc4: RFC 6229 40-bit-key keystream vector', () => {
    // Encrypting all-zero bytes exposes the raw keystream directly.
    const ct = run('rc4-encrypt', new Uint8Array(16), { key: '0102030405' })
    assert.equal(toHex(ct), 'b2396305f03dc027ccc3524a0a1118a8')
})

test('rc4: classic "Secret"/"Attack at dawn" vector', () => {
    const ct = run('rc4-encrypt', enc.encode('Attack at dawn'), { key: toHex(enc.encode('Secret')) })
    assert.equal(toHex(ct), '45a01f645fc35b383552544b9bf5')
})

test('rc4: round-trips and rejects an empty key', () => {
    const key = toHex(enc.encode('any length key works'))
    const pt = enc.encode('RC4 round-trip test.')
    const ct = run('rc4-encrypt', pt, { key })
    assert.deepEqual(run('rc4-decrypt', ct, { key }), pt)
    assert.throws(() => run('rc4-encrypt', pt, { key: '' }))
})

// --- Salsa20 ---
// Cross-checked against an independent from-spec Python implementation of the Salsa20 core
// (quarter-round + column/row rounds, both the 32-byte and 16-byte key expansion constants) —
// the same discipline hash.js's hand-rolled MD2/MD4 used, since noble-ciphers is the only JS
// implementation involved otherwise.
test('salsa20: known keystream vectors for both key sizes, spanning more than one 64-byte block', () => {
    const nonce = rangeHex(0, 8)
    const zeros = new Uint8Array(80)
    const ks32 = run('salsa20-encrypt', zeros, { key: rangeHex(0, 32), nonce })
    assert.equal(toHex(ks32), '2ead0f5f185729ced672b3a928e454f72fdb44a87b9cd8d219e4ec14aef9c6b' +
        'c77bf057f5659d7753848f8d3fe769ca5fdd8057d46326990e5f136e2fcb7bb' + '7ca13a2b59d9047b8dbeb93ec4b78ce1a5')
    const ks16 = run('salsa20-encrypt', zeros, { key: rangeHex(0, 16), nonce })
    assert.equal(toHex(ks16), '36ed2247b82ba6ab8c31bf24fdf5f993a709b8edbd9f82b580fc007d93ba9a9' +
        'a73f229cc31054bcd8044c96439fa4923804839dac47447fc4bdc2f53ba298a' + 'b219877b0c04b6379f978b7af388d582c0')
})

test('salsa20: round-trips and rejects an invalid key length', () => {
    const nonce = rangeHex(0x30, 8)
    const pt = enc.encode('Salsa20 round-trip test message.')
    const ct = run('salsa20-encrypt', pt, { key: rangeHex(1, 32), nonce })
    assert.deepEqual(run('salsa20-decrypt', ct, { key: rangeHex(1, 32), nonce }), pt)
    assert.throws(() => run('salsa20-encrypt', pt, { key: rangeHex(1, 20), nonce }))
})

// --- ChaCha20 ---
test('chacha20: known vector, cross-checked against Node crypto\'s bare "chacha20" cipher (16-byte IV = 4-byte zero counter || 12-byte nonce, matching RFC 8439\'s initial-counter-0 convention)', () => {
    const key = repeatHex(0x11, 32)
    const nonce = repeatHex(0x22, 12)
    const pt = enc.encode('Hello ChaCha20 test message!!!!')
    const ct = run('chacha20-encrypt', pt, { key, nonce })
    assert.equal(toHex(ct), '9078ff5f0738925b1cd4ac3a3d0a56d2b005c302078db3fe825feeba390458')
})

test('chacha20: round-trips and rejects an invalid key/nonce length', () => {
    const key = rangeHex(1, 32)
    const nonce = rangeHex(1, 12)
    const pt = enc.encode('ChaCha20 round-trip test message.')
    const ct = run('chacha20-encrypt', pt, { key, nonce })
    assert.deepEqual(run('chacha20-decrypt', ct, { key, nonce }), pt)
    assert.throws(() => run('chacha20-encrypt', pt, { key: rangeHex(1, 16), nonce })) // ChaCha20 requires a 32-byte key
    assert.throws(() => run('chacha20-encrypt', pt, { key, nonce: rangeHex(1, 8) })) // and a 12-byte nonce (RFC 8439), not the original 8-byte one
})

// --- XOR ---
test('xor: hand-verified vector and self-inverse property', () => {
    const key = toHex(enc.encode('key'))
    const pt = enc.encode('XOR')
    // 0x58^0x6b=0x33, 0x4f^0x65=0x2a, 0x52^0x79=0x2b
    const ct = run('xor-encrypt', pt, { key })
    assert.equal(toHex(ct), '332a2b')
    assert.deepEqual(run('xor-decrypt', ct, { key }), pt)
})

test('xor: repeating key covers input longer than the key, and rejects an empty key', () => {
    const key = toHex(enc.encode('ab'))
    const pt = enc.encode('abcdefgh')
    const ct = run('xor-encrypt', pt, { key })
    // Repeats "ab" across the whole input: byte i is XORed with key[i % 2].
    const expected = new Uint8Array(pt.length)
    const keyBytes = enc.encode('ab')
    for (let i = 0; i < pt.length; i++) expected[i] = pt[i] ^ keyBytes[i % 2]
    assert.deepEqual(ct, expected)
    assert.throws(() => run('xor-encrypt', pt, { key: '' }))
})

test('rc4/salsa20/chacha20/xor: round-trip including empty input (and Salsa20 with both key sizes via the actual ops, not just raw keystream)', () => {
    const messages = [new Uint8Array(0), enc.encode('Stream cipher round-trip test.')]
    const rc4Key = toHex(enc.encode('any length key works'))
    for (const msg of messages) assertRoundTrip('rc4-encrypt', 'rc4-decrypt', { key: rc4Key }, msg)

    const salsaNonce = rangeHex(0x30, 8)
    for (const key of [rangeHex(1, 16), rangeHex(1, 32)]) {
        for (const msg of messages) assertRoundTrip('salsa20-encrypt', 'salsa20-decrypt', { key, nonce: salsaNonce }, msg)
    }

    const chachaKey = rangeHex(1, 32)
    const chachaNonce = rangeHex(1, 12)
    for (const msg of messages) assertRoundTrip('chacha20-encrypt', 'chacha20-decrypt', { key: chachaKey, nonce: chachaNonce }, msg)

    const xorKey = toHex(enc.encode('key'))
    for (const msg of messages) assertRoundTrip('xor-encrypt', 'xor-decrypt', { key: xorKey }, msg)
})

// --- Shared hex-parsing validation (parseHexBytes), exercised once via AES rather than repeated
// per algorithm ---
test('shared hex parsing: rejects odd-length hex and invalid hex characters', () => {
    const iv = AES_IV
    assert.throws(() => run('aes-encrypt', AES_PT, { mode: 'cbc', key: rangeHex(1, 16) + '0', iv, padding: 'pkcs7' }))
    assert.throws(() => run('aes-encrypt', AES_PT, { mode: 'cbc', key: 'zz'.repeat(16), iv, padding: 'pkcs7' }))
})

test('shared hex parsing: an optional leading "0x"/"0X" is stripped and ignored, consistent with checksum.js\'s parseUintField', () => {
    const bareKey = aesKey(16)
    const bareIv = AES_IV
    const ctBare = run('aes-encrypt', AES_PT, { mode: 'cbc', key: bareKey, iv: bareIv, padding: 'pkcs7' })
    const ctPrefixed = run('aes-encrypt', AES_PT, { mode: 'cbc', key: '0x' + bareKey, iv: '0X' + bareIv, padding: 'pkcs7' })
    assert.deepEqual(ctPrefixed, ctBare)
})
