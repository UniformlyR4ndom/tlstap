import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decodeInteger, decodeHeaderBlock, STATIC_TABLE, HUFFMAN_TABLE } from './hpackDecode.js'

function hex(...bytes) {
    return Uint8Array.from(bytes)
}

// ── Structural checks on HUFFMAN_TABLE itself — independent of any worked example, so a
// future accidental edit to the table fails here even if it happens to not be exercised
// by any of the string-decoding tests below. ──

test('HUFFMAN_TABLE has exactly 257 entries (256 octet values + EOS)', () => {
    assert.equal(HUFFMAN_TABLE.length, 257)
})

test('HUFFMAN_TABLE forms a complete prefix-free code (Kraft\'s inequality)', () => {
    // sum(2^-length) over every code must equal exactly 1 for a complete, valid Huffman
    // code — computed in a scaled integer domain (BigInt) to stay exact.
    const totalBits = 30 // longest code in the table
    let sum = 0n
    for (const [, length] of HUFFMAN_TABLE) sum += 1n << BigInt(totalBits - length)
    assert.equal(sum, 1n << BigInt(totalBits))
})

test('HUFFMAN_TABLE is prefix-free (no code is a prefix of another)', () => {
    const bitStrings = HUFFMAN_TABLE.map(([code, length]) => code.toString(2).padStart(length, '0')).sort()
    for (let i = 0; i < bitStrings.length - 1; i++) {
        assert.ok(!bitStrings[i + 1].startsWith(bitStrings[i]), `code ${bitStrings[i]} is a prefix of ${bitStrings[i + 1]}`)
    }
})

test('HUFFMAN_TABLE matches RFC 7541 Appendix B\'s own worked example (symbol 47 \'/\' = 0x18, 6 bits)', () => {
    assert.deepEqual(HUFFMAN_TABLE[47], [0x18, 6])
})

test('STATIC_TABLE has exactly 61 entries', () => {
    assert.equal(STATIC_TABLE.length, 61)
})

// ── RFC 7541 §5.1's own worked integer examples (C.1.1-C.1.3) ──

test('decodeInteger: 10 with a 5-bit prefix (RFC 7541 C.1.1)', () => {
    assert.deepEqual(decodeInteger(hex(0x0a), 0, 5), { value: 10, nextOffset: 1 })
})

test('decodeInteger: 1337 with a 5-bit prefix (RFC 7541 C.1.2)', () => {
    assert.deepEqual(decodeInteger(hex(0x1f, 0x9a, 0x0a), 0, 5), { value: 1337, nextOffset: 3 })
})

test('decodeInteger: 42 with an 8-bit prefix (RFC 7541 C.1.3)', () => {
    assert.deepEqual(decodeInteger(hex(0x2a), 0, 8), { value: 42, nextOffset: 1 })
})

// ── RFC 7541 C.3 — request examples without Huffman coding: dynamic table insertion and
// reuse (no eviction pressure, default 4096 max size). ──

test('decodeHeaderBlock: RFC 7541 C.3.1 (first request)', () => {
    const { headers, table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d),
        null,
    )
    assert.deepEqual(headers, [
        { name: ':method', value: 'GET' },
        { name: ':scheme', value: 'http' },
        { name: ':path', value: '/' },
        { name: ':authority', value: 'www.example.com' },
    ])
    assert.deepEqual(table.entries, [{ name: ':authority', value: 'www.example.com' }])
    assert.equal(table.size, 57)
})

test('decodeHeaderBlock: RFC 7541 C.3.2 (second request, reuses :authority from the dynamic table)', () => {
    const { table: table1 } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d),
        null,
    )
    const { headers, table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65),
        table1,
    )
    assert.deepEqual(headers, [
        { name: ':method', value: 'GET' },
        { name: ':scheme', value: 'http' },
        { name: ':path', value: '/' },
        { name: ':authority', value: 'www.example.com' },
        { name: 'cache-control', value: 'no-cache' },
    ])
    assert.deepEqual(table.entries, [
        { name: 'cache-control', value: 'no-cache' },
        { name: ':authority', value: 'www.example.com' },
    ])
    assert.equal(table.size, 110)
})

test('decodeHeaderBlock: RFC 7541 C.3.3 (third request, new literal name)', () => {
    let { table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d),
        null,
    )
    ;({ table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65),
        table,
    ))
    const { headers, table: table3 } = decodeHeaderBlock(
        hex(0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79,
            0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65),
        table,
    )
    assert.deepEqual(headers, [
        { name: ':method', value: 'GET' },
        { name: ':scheme', value: 'https' },
        { name: ':path', value: '/index.html' },
        { name: ':authority', value: 'www.example.com' },
        { name: 'custom-key', value: 'custom-value' },
    ])
    assert.deepEqual(table3.entries, [
        { name: 'custom-key', value: 'custom-value' },
        { name: 'cache-control', value: 'no-cache' },
        { name: ':authority', value: 'www.example.com' },
    ])
    assert.equal(table3.size, 164)
})

// ── RFC 7541 C.4 — same three requests, but with Huffman-coded literal values/names.
// Exercises decodeHuffmanString end-to-end against known plaintext, over the specific
// symbols appearing in these strings. ──

test('decodeHeaderBlock: RFC 7541 C.4.1 (first request, Huffman)', () => {
    const { headers, table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff),
        null,
    )
    assert.deepEqual(headers, [
        { name: ':method', value: 'GET' },
        { name: ':scheme', value: 'http' },
        { name: ':path', value: '/' },
        { name: ':authority', value: 'www.example.com' },
    ])
    assert.deepEqual(table.entries, [{ name: ':authority', value: 'www.example.com' }])
})

test('decodeHeaderBlock: RFC 7541 C.4.2 (second request, Huffman)', () => {
    const { table: table1 } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff),
        null,
    )
    const { headers } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf),
        table1,
    )
    assert.deepEqual(headers, [
        { name: ':method', value: 'GET' },
        { name: ':scheme', value: 'http' },
        { name: ':path', value: '/' },
        { name: ':authority', value: 'www.example.com' },
        { name: 'cache-control', value: 'no-cache' },
    ])
})

test('decodeHeaderBlock: RFC 7541 C.4.3 (third request, Huffman, new literal name)', () => {
    let { table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff),
        null,
    )
    ;({ table } = decodeHeaderBlock(
        hex(0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf),
        table,
    ))
    const { headers } = decodeHeaderBlock(
        hex(0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
            0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf),
        table,
    )
    assert.deepEqual(headers, [
        { name: ':method', value: 'GET' },
        { name: ':scheme', value: 'https' },
        { name: ':path', value: '/index.html' },
        { name: ':authority', value: 'www.example.com' },
        { name: 'custom-key', value: 'custom-value' },
    ])
})

// ── RFC 7541 C.5 — response examples with SETTINGS_HEADER_TABLE_SIZE set to 256, which
// forces real evictions (unlike C.3/C.4's default 4096). Covers insertEntry's eviction
// loop, including evicting the just-inserted entry itself when a later, larger one
// displaces older ones. ──

test('decodeHeaderBlock: RFC 7541 C.5.1-C.5.3 (responses, dynamic table eviction under a 256-octet cap)', () => {
    const shrunk = { entries: [], size: 0, maxSize: 256 }

    const r1 = decodeHeaderBlock(
        hex(0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
            0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33,
            0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20, 0x47, 0x4d, 0x54,
            0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d),
        shrunk,
    )
    assert.deepEqual(r1.headers, [
        { name: ':status', value: '302' },
        { name: 'cache-control', value: 'private' },
        { name: 'date', value: 'Mon, 21 Oct 2013 20:13:21 GMT' },
        { name: 'location', value: 'https://www.example.com' },
    ])
    assert.deepEqual(r1.table.entries.map(e => e.name), ['location', 'date', 'cache-control', ':status'])
    assert.equal(r1.table.size, 222)

    // :status: 302 (42 octets) is evicted to make room for :status: 307.
    const r2 = decodeHeaderBlock(hex(0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf), r1.table)
    assert.deepEqual(r2.headers, [
        { name: ':status', value: '307' },
        { name: 'cache-control', value: 'private' },
        { name: 'date', value: 'Mon, 21 Oct 2013 20:13:21 GMT' },
        { name: 'location', value: 'https://www.example.com' },
    ])
    assert.deepEqual(r2.table.entries.map(e => e.name), [':status', 'location', 'date', 'cache-control'])
    assert.equal(r2.table.size, 222)

    // Several more evictions: cache-control, then the old date value, then location and
    // :status:307 both get pushed out once set-cookie's own large entry is inserted.
    const r3 = decodeHeaderBlock(
        hex(0x88, 0xc1,
            0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33,
            0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x32, 0x20, 0x47, 0x4d, 0x54,
            0xc0,
            0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70,
            0x77, 0x38, 0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53, 0x44, 0x4a, 0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a, 0x58, 0x4f,
            0x51, 0x57, 0x45, 0x4f, 0x50, 0x49, 0x55, 0x41, 0x58, 0x51, 0x57, 0x45, 0x4f, 0x49, 0x55, 0x3b, 0x20, 0x6d,
            0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, 0x33, 0x36, 0x30, 0x30, 0x3b, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
            0x6f, 0x6e, 0x3d, 0x31),
        r2.table,
    )
    assert.deepEqual(r3.headers, [
        { name: ':status', value: '200' },
        { name: 'cache-control', value: 'private' },
        { name: 'date', value: 'Mon, 21 Oct 2013 20:13:22 GMT' },
        { name: 'location', value: 'https://www.example.com' },
        { name: 'content-encoding', value: 'gzip' },
        { name: 'set-cookie', value: 'foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1' },
    ])
    assert.deepEqual(r3.table.entries.map(e => e.name), ['set-cookie', 'content-encoding', 'date'])
    assert.equal(r3.table.size, 215)
})

// ── Malformed input: throws rather than a silent best-effort decode. ──

test('decodeHeaderBlock throws on a truncated integer', () => {
    assert.throws(() => decodeHeaderBlock(hex(0x7f), null), /hpack/) // continuation flagged but no more bytes
})

test('decodeHeaderBlock throws on an out-of-range indexed header field', () => {
    assert.throws(() => decodeHeaderBlock(hex(0xff, 0x00), null), /hpack.*index/) // 0xff,0x00 = index 127, well past both tables
})

test('decodeHeaderBlock throws on indexed header field index 0', () => {
    assert.throws(() => decodeHeaderBlock(hex(0x80), null), /hpack.*index 0/)
})

test('decodeHeaderBlock throws on an invalid Huffman-encoded string', () => {
    // 0x41 (:authority, literal, incremental indexing), 0x81 (Huffman flag + length 1),
    // then a single all-zero-bit byte, which is not a valid complete or padding-only code.
    assert.throws(() => decodeHeaderBlock(hex(0x41, 0x81, 0x00), null), /hpack/)
})
