import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fmtAsHexdump, parseHexdump, fmtAsBase64, parseBase64 } from './format.js'

test('parseHexdump round-trips fmtAsHexdump output for arbitrary bytes', () => {
    const bytes = new Uint8Array(37)
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7 + 3) & 0xff
    const dump = fmtAsHexdump(bytes, 0)
    assert.deepEqual([...parseHexdump(dump)], [...bytes])
})

test('parseHexdump round-trips a non-zero base offset', () => {
    const bytes = Uint8Array.from([0, 1, 2, 3, 255, 254, 16, 32])
    const dump = fmtAsHexdump(bytes, 0x1000)
    assert.deepEqual([...parseHexdump(dump)], [...bytes])
})

test('parseHexdump round-trips empty input', () => {
    assert.deepEqual([...parseHexdump(fmtAsHexdump(new Uint8Array(0), 0))], [])
    assert.deepEqual([...parseHexdump('')], [])
})

test('parseHexdump is lenient about extra/collapsed whitespace between hex groups', () => {
    const dump = '00000000  48 65 6c 6c 6f   20 77 6f 72 6c 64 21  |Hello world!|'
    assert.deepEqual([...parseHexdump(dump)], [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21])
})

test('parseHexdump rejects a line missing the |ascii| column', () => {
    assert.throws(() => parseHexdump('00000000  48 65 6c 6c 6f'), /invalid hexdump line/)
})

test('parseHexdump rejects an odd-length hex token', () => {
    assert.throws(() => parseHexdump('00000000  486 5  |Hh|'), /invalid hex byte/)
})

test('parseBase64 round-trips fmtAsBase64 output for arbitrary bytes', () => {
    const bytes = new Uint8Array(37)
    for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 11 + 5) & 0xff
    assert.deepEqual([...parseBase64(fmtAsBase64(bytes))], [...bytes])
})

test('parseBase64 round-trips empty input', () => {
    assert.deepEqual([...parseBase64(fmtAsBase64(new Uint8Array(0)))], [])
})
