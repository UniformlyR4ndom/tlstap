import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './compression.js'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

for (const format of ['gzip', 'deflate']) {
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

    test(`${format}: decompress rejects malformed input`, async () => {
        await assert.rejects(
            () => OPERATIONS[`${format}-decompress`].run(new Uint8Array([1, 2, 3, 4, 5])),
            new RegExp(`invalid ${format} data`),
        )
    })
}

test('gzip and deflate produce different (non-interchangeable) framing for the same input', async () => {
    const input = textEncoder.encode('same input, different container format')
    const gzipped = await OPERATIONS['gzip-compress'].run(input)
    const deflated = await OPERATIONS['deflate-compress'].run(input)
    assert.notDeepEqual([...gzipped], [...deflated])
    await assert.rejects(() => OPERATIONS['deflate-decompress'].run(gzipped))
    await assert.rejects(() => OPERATIONS['gzip-decompress'].run(deflated))
})

test('known vector: gzip-decompress of a pre-calculated buffer matches the original text', async () => {
    // Pre-calculated via Node's zlib.gzipSync(Buffer.from('tlstap'), { mtime: 0 }) — a
    // different implementation entry point than the CompressionStream API under test, fixing
    // the mtime field so the vector is deterministic.
    const gzipped = Uint8Array.from([
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x2b, 0xc9, 0x29, 0x2e, 0x49, 0x2c, 0x00, 0x00, 0x1c, 0x90, 0x22, 0x7b, 0x06, 0x00, 0x00, 0x00,
    ])
    const decompressed = await OPERATIONS['gzip-decompress'].run(gzipped)
    assert.equal(textDecoder.decode(decompressed), 'tlstap')
})
