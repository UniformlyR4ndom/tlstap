import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './compression.js'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

for (const format of ['gzip', 'deflate', 'zlib']) {
    test(`${format}: compress then decompress round-trips arbitrary text`, async () => {
        const input = textEncoder.encode('The quick brown fox jumps over the lazy dog. '.repeat(50))
        const compressed = await OPERATIONS[`${format}-compress`].run(input)
        assert.ok(compressed instanceof Uint8Array)
        const decompressed = await OPERATIONS[`${format}-decompress`].run(compressed)
        assert.deepEqual([...decompressed], [...input])
    })

    test(`${format}: compresses repetitive input to fewer bytes`, async () => {
        const input = textEncoder.encode('a'.repeat(10000))
        const compressed = await OPERATIONS[`${format}-compress`].run(input)
        assert.ok(compressed.length < input.length)
    })

    test(`${format}: round-trips empty input`, async () => {
        const compressed = await OPERATIONS[`${format}-compress`].run(new Uint8Array(0))
        const decompressed = await OPERATIONS[`${format}-decompress`].run(compressed)
        assert.equal(decompressed.length, 0)
    })

    test(`${format}: decompress rejects malformed input`, () => {
        assert.throws(
            () => OPERATIONS[`${format}-decompress`].run(new Uint8Array([1, 2, 3, 4, 5])),
            new RegExp(`invalid ${format} data`),
        )
    })
}

test('gzip, deflate, and zlib produce different (non-interchangeable) framing for the same input', async () => {
    const input = textEncoder.encode('same input, different container format')
    const gzipped = await OPERATIONS['gzip-compress'].run(input)
    const deflated = await OPERATIONS['deflate-compress'].run(input)
    const zlibbed = await OPERATIONS['zlib-compress'].run(input)
    assert.notDeepEqual([...gzipped], [...deflated])
    assert.notDeepEqual([...gzipped], [...zlibbed])
    assert.notDeepEqual([...deflated], [...zlibbed])
    assert.throws(() => OPERATIONS['deflate-decompress'].run(gzipped))
    assert.throws(() => OPERATIONS['gzip-decompress'].run(deflated))
    // Deflate and zlib are the most easily confused pair (zlib is raw DEFLATE plus a 2-byte
    // header and Adler-32 trailer), so cross-decoding them gets its own explicit check rather
    // than relying only on the gzip pair above.
    assert.throws(() => OPERATIONS['zlib-decompress'].run(deflated))
    assert.throws(() => OPERATIONS['deflate-decompress'].run(zlibbed))
})

test('known vector: gzip-decompress of a pre-calculated buffer matches the original text', async () => {
    // Pre-calculated via Node's zlib.gzipSync(Buffer.from('tlstap'), { mtime: 0 }) — a
    // different implementation than fflate's gzipSync under test, fixing the mtime field so
    // the vector is deterministic.
    const gzipped = Uint8Array.from([
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x2b, 0xc9, 0x29, 0x2e, 0x49, 0x2c, 0x00, 0x00, 0x1c, 0x90, 0x22, 0x7b, 0x06, 0x00, 0x00, 0x00,
    ])
    const decompressed = await OPERATIONS['gzip-decompress'].run(gzipped)
    assert.equal(textDecoder.decode(decompressed), 'tlstap')
})

test('known vector: zlib-decompress of a pre-calculated buffer matches the original text', async () => {
    // Pre-calculated via Node's zlib.deflateSync(Buffer.from('tlstap')) — Node's "deflate" is
    // actually the zlib-wrapped format (2-byte header + Adler-32 trailer around raw DEFLATE),
    // matching what zlib-compress/zlib-decompress use here; Node's raw-DEFLATE equivalent
    // (what this file's own deflate-compress/deflate-decompress use) is deflateRawSync/
    // inflateRawSync instead.
    const zlibbed = Uint8Array.from([
        0x78, 0x9c, 0x2b, 0xc9, 0x29, 0x2e, 0x49, 0x2c, 0x00, 0x00, 0x09, 0x34, 0x02, 0x99,
    ])
    const decompressed = await OPERATIONS['zlib-decompress'].run(zlibbed)
    assert.equal(textDecoder.decode(decompressed), 'tlstap')
})
