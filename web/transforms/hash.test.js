import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './hash.js'

const textEncoder = new TextEncoder()

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

// `await` on a plain (non-Promise) value is a no-op, so this works uniformly for both the
// synchronous ops and whirlpool (async, since it's WASM-backed) — same pattern TransformPanel's
// handleGo() uses for the step pipeline.
async function runHex(op, text) {
    return toHex(await OPERATIONS[op].run(textEncoder.encode(text)))
}

// RFC 1319 Appendix A test suite.
test('md2: RFC 1319 test vectors', async () => {
    assert.equal(await runHex('md2', ''), '8350e5a3e24c153df2275c9f80692773')
    assert.equal(await runHex('md2', 'a'), '32ec01ec4a6dac72c0ab96fb34c0b5d1')
    assert.equal(await runHex('md2', 'abc'), 'da853b0d3f88d99b30283a69e6ded6bb')
    assert.equal(await runHex('md2', 'message digest'), 'ab4f496bfb2a530b219ff33031fe06b0')
    assert.equal(await runHex('md2', 'abcdefghijklmnopqrstuvwxyz'), '4e8ddff3650292ab5a4108c3aa47940b')
})

// RFC 1320 Appendix A.5 test suite.
test('md4: RFC 1320 test vectors', async () => {
    assert.equal(await runHex('md4', ''), '31d6cfe0d16ae931b73c59d7e0c089c0')
    assert.equal(await runHex('md4', 'a'), 'bde52cb31de33e46245e05fbdbd6fb24')
    assert.equal(await runHex('md4', 'abc'), 'a448017aaf21d8525fc10ae87aa6729d')
    assert.equal(await runHex('md4', 'message digest'), 'd9130a8164549fe818874806e1c7014b')
    assert.equal(await runHex('md4', 'abcdefghijklmnopqrstuvwxyz'), 'd79e1c308aa5bbcdeea8ed63df412da9')
})

test('ntlm: empty input matches MD4 of empty UTF-16LE (well-known empty NTLM hash)', async () => {
    assert.equal(await runHex('ntlm', ''), '31d6cfe0d16ae931b73c59d7e0c089c0')
})

test('ntlm: well-known "password" test vector', async () => {
    assert.equal(await runHex('ntlm', 'password'), '8846f7eaee8fb117ad06bdd830b7586c')
})

test('ntlm: differs from md4 of the raw (non-UTF-16LE) bytes', async () => {
    assert.notEqual(await runHex('ntlm', 'password'), await runHex('md4', 'password'))
})

// FIPS PUB 180/181 and RFC 1321 standard "abc" vectors, cross-checked against Node's own
// crypto.createHash for md5/sha1/sha224/sha256/sha384/sha512 (a different implementation from
// the vendored crypto-js under test). Whirlpool's vectors are the canonical NESSIE/ISO ones,
// cross-checked against the vendored hash-wasm's own output before use (a WASM-compiled
// implementation, independent from any JS reimplementation risk).
for (const [op, empty, abc] of [
    ['md5', 'd41d8cd98f00b204e9800998ecf8427e', '900150983cd24fb0d6963f7d28e17f72'],
    ['sha1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'a9993e364706816aba3e25717850c26c9cd0d89d'],
    ['sha224', 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f', '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'],
    ['sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
    ['sha384', '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'],
    ['sha512', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'],
    ['whirlpool', '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3', '4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5'],
]) {
    test(`${op}: known test vectors (empty string and "abc")`, async () => {
        assert.equal(await runHex(op, ''), empty)
        assert.equal(await runHex(op, 'abc'), abc)
    })
}

test('all hash ops produce a fixed-length digest regardless of input length', async () => {
    const expectedLengths = { md2: 16, md4: 16, ntlm: 16, md5: 16, sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64, whirlpool: 64 }
    for (const [op, len] of Object.entries(expectedLengths)) {
        assert.equal((await OPERATIONS[op].run(textEncoder.encode('short'))).length, len)
        assert.equal((await OPERATIONS[op].run(textEncoder.encode('a much longer input '.repeat(20)))).length, len)
    }
})
