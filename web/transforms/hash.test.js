import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './hash.js'

const textEncoder = new TextEncoder()

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

// `await` on a plain (non-Promise) value is a no-op, so this works uniformly regardless of
// whether an op is synchronous or not. Every op here is sync except whirlpool on its very first
// call in this process (it lazily warms up a WASM hasher, then is sync from then on too — see
// hash.js's header comment) — same pattern TransformPanel's handleGo() relies on for its step
// pipeline.
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

// FIPS PUB 180/181 and RFC 1321 standard vectors, cross-checked against Node's own
// crypto.createHash for md5/sha1/sha224/sha256/sha384/sha512 (a different implementation from
// the vendored crypto-js under test). Whirlpool's vectors are the canonical NESSIE/ISO ones,
// cross-checked against the vendored hash-wasm's own output before use (a WASM-compiled
// implementation, independent from any JS reimplementation risk). MD5 gets the same
// "message digest"/alphabet vectors as MD2/MD4 above, since all three share the identical RFC
// 1319/1320/1321 test-string suite; SHA-1/224/256 get FIPS's classic three-block
// "abcdbcdecdefdefg..." vector, SHA-384/512 get their own two-block equivalent, and Whirlpool
// gets the same "message digest"/alphabet strings as MD5 for consistency, even though its
// reference is hash-wasm rather than an RFC.
const TWO_BLOCK_224_256 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
const LONG_384_512 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu'
const HASH_VECTORS = {
    md5: [
        ['', 'd41d8cd98f00b204e9800998ecf8427e'],
        ['abc', '900150983cd24fb0d6963f7d28e17f72'],
        ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
        ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
    ],
    sha1: [
        ['', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'],
        ['abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'],
        [TWO_BLOCK_224_256, '84983e441c3bd26ebaae4aa1f95129e5e54670f1'],
    ],
    sha224: [
        ['', 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f'],
        ['abc', '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'],
        [TWO_BLOCK_224_256, '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'],
    ],
    sha256: [
        ['', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
        ['abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'],
        [TWO_BLOCK_224_256, '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'],
    ],
    sha384: [
        ['', '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'],
        ['abc', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'],
        [LONG_384_512, '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039'],
    ],
    sha512: [
        ['', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'],
        ['abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'],
        [LONG_384_512, '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'],
    ],
    whirlpool: [
        ['', '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3'],
        ['abc', '4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5'],
        ['message digest', '378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e'],
        ['abcdefghijklmnopqrstuvwxyz', 'f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b'],
    ],
}
for (const [op, vectors] of Object.entries(HASH_VECTORS)) {
    test(`${op}: known test vectors`, async () => {
        for (const [input, expected] of vectors) {
            assert.equal(await runHex(op, input), expected, JSON.stringify(input))
        }
    })
}

test('all hash ops produce a fixed-length digest regardless of input length', async () => {
    const expectedLengths = { md2: 16, md4: 16, ntlm: 16, md5: 16, sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64, whirlpool: 64 }
    for (const [op, len] of Object.entries(expectedLengths)) {
        assert.equal((await OPERATIONS[op].run(textEncoder.encode('short'))).length, len)
        assert.equal((await OPERATIONS[op].run(textEncoder.encode('a much longer input '.repeat(20)))).length, len)
    }
})

test('different input produces a different digest for every hash op (guards against a constant/broken implementation)', async () => {
    for (const op of Object.keys(OPERATIONS)) {
        assert.notEqual(await runHex(op, 'input one'), await runHex(op, 'input two'), op)
    }
})
