import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './zip.js'
import { zipSync, unzipSync } from '../vendor/fflate.module.js'

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

test('zip-compress then zip-decompress round-trips with the default filename', () => {
    const input = textEncoder.encode('hello, zip')
    const zipped = OPERATIONS['zip-compress'].run(input, { filename: 'data.bin' })
    assert.ok(zipped instanceof Uint8Array)
    const back = OPERATIONS['zip-decompress'].run(zipped, { entry: '' })
    assert.deepEqual([...back], [...input])
})

test('zip-compress uses the given filename as the single entry name', () => {
    const input = textEncoder.encode('content')
    const zipped = OPERATIONS['zip-compress'].run(input, { filename: 'notes.txt' })
    // Inspect the entry name via the vendored library directly, independent of
    // zip-decompress's own entry-selection logic (tested separately below).
    assert.deepEqual(Object.keys(unzipSync(zipped)), ['notes.txt'])
})

test('zip-decompress auto-extracts when the archive has exactly one entry', () => {
    const input = textEncoder.encode('single entry payload')
    const zipped = OPERATIONS['zip-compress'].run(input, { filename: 'only.bin' })
    const back = OPERATIONS['zip-decompress'].run(zipped, { entry: '' })
    assert.equal(textDecoder.decode(back), 'single entry payload')
})

test('zip-decompress selects a specific entry by name from a multi-entry archive', () => {
    const zipped = zipSync({
        'a.txt': textEncoder.encode('AAA'),
        'sub/b.bin': textEncoder.encode('BBB'),
    })
    const a = OPERATIONS['zip-decompress'].run(zipped, { entry: 'a.txt' })
    const b = OPERATIONS['zip-decompress'].run(zipped, { entry: 'sub/b.bin' })
    assert.equal(textDecoder.decode(a), 'AAA')
    assert.equal(textDecoder.decode(b), 'BBB')
})

test('zip-decompress throws a listing error for a multi-entry archive with no entry selected', () => {
    const zipped = zipSync({
        'a.txt': textEncoder.encode('AAA'),
        'b.txt': textEncoder.encode('BBB'),
    })
    assert.throws(
        () => OPERATIONS['zip-decompress'].run(zipped, { entry: '' }),
        /archive has multiple entries: a\.txt, b\.txt/,
    )
})

test('zip-decompress throws a helpful error for an unknown entry name', () => {
    const zipped = zipSync({ 'a.txt': textEncoder.encode('AAA') })
    assert.throws(
        () => OPERATIONS['zip-decompress'].run(zipped, { entry: 'missing.txt' }),
        /entry "missing\.txt" not found.*available: a\.txt/,
    )
})

test('zip-decompress rejects malformed input', () => {
    assert.throws(
        () => OPERATIONS['zip-decompress'].run(new Uint8Array([1, 2, 3, 4, 5]), { entry: '' }),
        /invalid zip data/,
    )
})
