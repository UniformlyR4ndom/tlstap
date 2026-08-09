import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS, decodeNumberValue, encodeNumberValue } from './numbers.js'

// Mirrors (but doesn't import) numbers.js's private NUMBER_TYPES table, so the test data is
// independent of the implementation it's checking.
const TYPES = [
    { id: 'i8',    bytes: 1, signed: true },
    { id: 'u8',    bytes: 1, signed: false },
    { id: 'i16be', bytes: 2, signed: true,  be: true },
    { id: 'i16le', bytes: 2, signed: true,  be: false },
    { id: 'u16be', bytes: 2, signed: false, be: true },
    { id: 'u16le', bytes: 2, signed: false, be: false },
    { id: 'i32be', bytes: 4, signed: true,  be: true },
    { id: 'i32le', bytes: 4, signed: true,  be: false },
    { id: 'u32be', bytes: 4, signed: false, be: true },
    { id: 'u32le', bytes: 4, signed: false, be: false },
    { id: 'i64be', bytes: 8, signed: true,  be: true,  big: true },
    { id: 'i64le', bytes: 8, signed: true,  be: false, big: true },
    { id: 'u64be', bytes: 8, signed: false, be: true,  big: true },
    { id: 'u64le', bytes: 8, signed: false, be: false, big: true },
]

function range(t) {
    if (t.big) {
        const bits = BigInt(t.bytes * 8)
        return t.signed ? [-(2n ** (bits - 1n)), 2n ** (bits - 1n) - 1n] : [0n, 2n ** bits - 1n]
    }
    const bits = t.bytes * 8
    return t.signed ? [-(2 ** (bits - 1)), 2 ** (bits - 1) - 1] : [0, 2 ** bits - 1]
}

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()

function decode(id, bytes) {
    return textDecoder.decode(OPERATIONS[`decnum-${id}`].run(Uint8Array.from(bytes)))
}

function encode(id, text) {
    return OPERATIONS[`encnum-${id}`].run(textEncoder.encode(text))
}

// Known byte vectors, independent of encode/decode round-tripping, so a bug that flips byte
// order (or sign handling) identically in both directions can't hide behind a passing round-trip.
test('known byte vectors', () => {
    assert.equal(decode('i16be', [0x00, 0x01]), '1')
    assert.equal(decode('i16le', [0x01, 0x00]), '1')
    assert.equal(decode('u16be', [0xff, 0xff]), '65535')
    assert.equal(decode('i16be', [0xff, 0xff]), '-1')
    assert.equal(decode('i16le', [0xff, 0xff]), '-1')

    assert.equal(decode('u32be', [0x00, 0x00, 0x01, 0x00]), '256')
    assert.equal(decode('u32le', [0x00, 0x01, 0x00, 0x00]), '256')
    assert.equal(decode('i32be', [0xff, 0xff, 0xff, 0xff]), '-1')

    assert.equal(decode('u64be', [0, 0, 0, 0, 0, 0, 0, 1]), '1')
    assert.equal(decode('u64le', [1, 0, 0, 0, 0, 0, 0, 0]), '1')
    assert.equal(decode('i64be', [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), '-1')

    assert.deepEqual([...encode('u16be', '256')], [0x01, 0x00])
    assert.deepEqual([...encode('u16le', '256')], [0x00, 0x01])
    assert.deepEqual([...encode('i32le', '-1')], [0xff, 0xff, 0xff, 0xff])
    assert.deepEqual([...encode('u64be', '1')], [0, 0, 0, 0, 0, 0, 0, 1])
})

for (const t of TYPES) {
    const [min, max] = range(t)

    test(`${t.id}: decode/encode round-trip at boundaries`, () => {
        const values = [min, max, t.big ? 0n : 0, t.big ? 1n : 1]
        if (t.signed) values.push(t.big ? -1n : -1)
        for (const v of values) {
            const text = String(v)
            const bytes = encode(t.id, text)
            assert.equal(bytes.length, t.bytes)
            assert.equal(decode(t.id, bytes), text)
        }
    })

    test(`${t.id}: decode requires exact byte width`, () => {
        assert.throws(() => OPERATIONS[`decnum-${t.id}`].run(new Uint8Array(t.bytes + 1)))
        if (t.bytes > 1) assert.throws(() => OPERATIONS[`decnum-${t.id}`].run(new Uint8Array(t.bytes - 1)))
    })

    test(`${t.id}: encode rejects out-of-range values`, () => {
        const belowMin = t.big ? min - 1n : min - 1
        const aboveMax = t.big ? max + 1n : max + 1
        assert.throws(() => encode(t.id, String(belowMin)))
        assert.throws(() => encode(t.id, String(aboveMax)))
    })

    test(`${t.id}: encode rejects non-integer text`, () => {
        for (const bad of ['abc', '1.5', '', ' ', '1e5', '0x10']) {
            assert.throws(() => encode(t.id, bad), `expected "${bad}" to be rejected`)
        }
    })

    if (t.bytes > 1) {
        test(`${t.id}: encoded byte order matches endianness`, () => {
            const value = t.big ? 1n : 1
            const bytes = encode(t.id, String(value))
            if (t.be) {
                assert.equal(bytes[bytes.length - 1], 1)
                assert.equal(bytes[0], 0)
            } else {
                assert.equal(bytes[0], 1)
                assert.equal(bytes[bytes.length - 1], 0)
            }
        })
    }
}

// Cross-check: for a given width/signedness, the be/le variants must encode the same integer
// as byte-reversed arrays of each other.
for (const width of [16, 32, 64]) {
    for (const sign of ['i', 'u']) {
        test(`${sign}${width}: be/le encodings are byte-reversed for the same value`, () => {
            const beId = `${sign}${width}be`
            const leId = `${sign}${width}le`
            const value = width === 64 ? '123456789012345' : '12345'
            const be = encode(beId, value)
            const le = encode(leId, value)
            assert.deepEqual([...be], [...le].reverse())
        })
    }
}

test('2^64 exact boundary exceeds every implemented type (including UInt64)', () => {
    const value = 2n ** 64n
    for (const t of TYPES) {
        assert.throws(() => encode(t.id, String(value)), `expected ${t.id} to reject 2^64`)
    }
})

test('-(2^64) exceeds every implemented signed type', () => {
    const negValue = -(2n ** 64n)
    for (const t of TYPES) {
        if (!t.signed) continue
        assert.throws(() => encode(t.id, String(negValue)), `expected ${t.id} to reject -(2^64)`)
    }
})

// Hard-coded pre-calculated vectors, one positive and one negative value per byte-range
// midpoint (0<x<2^8, 2^8<x<2^16, ..., 2^56<x<2^64). Bands 3/4 and 5/6/7/8 share a width because
// no 3-, 5-, 6-, or 7-byte type is implemented — those bands are still tested separately since
// they exercise different magnitude regions of the 32-bit/64-bit types. Every value is chosen
// in the lower half of its width's *unsigned* range (i.e. below 2^(width-1)) so the exact same
// magnitude is valid for both the signed and unsigned type of that width, and so its negation
// is a valid signed value too — this is what keeps one pos/neg pair meaningful for both
// signedness variants instead of needing separate magnitudes.
//
// Byte layouts were derived independently of numberEncode/numberDecode (the code under test)
// via Node's native DataView, then hard-coded below as plain literals:
//   width  8: 100  -> 0x64                              | -100 -> 0x9c
//   width 16: 30000  -> be 75 30 / le 30 75              | -30000  -> be 8a d0 / le d0 8a
//   width 32: 1000000    -> be 00 0f 42 40 / le 40 42 0f 00 | -1000000    -> be ff f0 bd c0 / le c0 bd f0 ff
//   width 32: 2000000000 -> be 77 35 94 00 / le 00 94 35 77 | -2000000000 -> be 88 ca 6c 00 / le 00 6c ca 88
//   width 64: 100000000000       -> be 00 00 00 17 48 76 e8 00 / le 00 e8 76 48 17 00 00 00
//             -100000000000      -> be ff ff ff e8 b7 89 18 00 / le 00 18 89 b7 e8 ff ff ff
//   width 64: 100000000000000    -> be 00 00 5a f3 10 7a 40 00 / le 00 40 7a 10 f3 5a 00 00
//             -100000000000000   -> be ff ff a5 0c ef 85 c0 00 / le 00 c0 85 ef 0c a5 ff ff
//   width 64: 50000000000000000  -> be 00 b1 a2 bc 2e c5 00 00 / le 00 00 c5 2e bc a2 b1 00
//             -50000000000000000 -> be ff 4e 5d 43 d1 3b 00 00 / le 00 00 3b d1 43 5d 4e ff
//   width 64: 5000000000000000000  -> be 45 63 91 82 44 f4 00 00 / le 00 00 f4 44 82 91 63 45
//             -5000000000000000000 -> be ba 9c 6e 7d bb 0c 00 00 / le 00 00 0c bb 7d 6e 9c ba
const BOUNDARY_VECTORS = [
    { band: '0 < x < 2^8', widthBits: 8,
        pos: { value: '100', bytes: [0x64] }, neg: { value: '-100', bytes: [0x9c] } },
    { band: '2^8 < x < 2^16', widthBits: 16,
        pos: { value: '30000', be: [0x75, 0x30], le: [0x30, 0x75] },
        neg: { value: '-30000', be: [0x8a, 0xd0], le: [0xd0, 0x8a] } },
    { band: '2^16 < x < 2^24', widthBits: 32,
        pos: { value: '1000000', be: [0x00, 0x0f, 0x42, 0x40], le: [0x40, 0x42, 0x0f, 0x00] },
        neg: { value: '-1000000', be: [0xff, 0xf0, 0xbd, 0xc0], le: [0xc0, 0xbd, 0xf0, 0xff] } },
    { band: '2^24 < x < 2^32', widthBits: 32,
        pos: { value: '2000000000', be: [0x77, 0x35, 0x94, 0x00], le: [0x00, 0x94, 0x35, 0x77] },
        neg: { value: '-2000000000', be: [0x88, 0xca, 0x6c, 0x00], le: [0x00, 0x6c, 0xca, 0x88] } },
    { band: '2^32 < x < 2^40', widthBits: 64,
        pos: { value: '100000000000', be: [0x00, 0x00, 0x00, 0x17, 0x48, 0x76, 0xe8, 0x00], le: [0x00, 0xe8, 0x76, 0x48, 0x17, 0x00, 0x00, 0x00] },
        neg: { value: '-100000000000', be: [0xff, 0xff, 0xff, 0xe8, 0xb7, 0x89, 0x18, 0x00], le: [0x00, 0x18, 0x89, 0xb7, 0xe8, 0xff, 0xff, 0xff] } },
    { band: '2^40 < x < 2^48', widthBits: 64,
        pos: { value: '100000000000000', be: [0x00, 0x00, 0x5a, 0xf3, 0x10, 0x7a, 0x40, 0x00], le: [0x00, 0x40, 0x7a, 0x10, 0xf3, 0x5a, 0x00, 0x00] },
        neg: { value: '-100000000000000', be: [0xff, 0xff, 0xa5, 0x0c, 0xef, 0x85, 0xc0, 0x00], le: [0x00, 0xc0, 0x85, 0xef, 0x0c, 0xa5, 0xff, 0xff] } },
    { band: '2^48 < x < 2^56', widthBits: 64,
        pos: { value: '50000000000000000', be: [0x00, 0xb1, 0xa2, 0xbc, 0x2e, 0xc5, 0x00, 0x00], le: [0x00, 0x00, 0xc5, 0x2e, 0xbc, 0xa2, 0xb1, 0x00] },
        neg: { value: '-50000000000000000', be: [0xff, 0x4e, 0x5d, 0x43, 0xd1, 0x3b, 0x00, 0x00], le: [0x00, 0x00, 0x3b, 0xd1, 0x43, 0x5d, 0x4e, 0xff] } },
    { band: '2^56 < x < 2^64', widthBits: 64,
        pos: { value: '5000000000000000000', be: [0x45, 0x63, 0x91, 0x82, 0x44, 0xf4, 0x00, 0x00], le: [0x00, 0x00, 0xf4, 0x44, 0x82, 0x91, 0x63, 0x45] },
        neg: { value: '-5000000000000000000', be: [0xba, 0x9c, 0x6e, 0x7d, 0xbb, 0x0c, 0x00, 0x00], le: [0x00, 0x00, 0x0c, 0xbb, 0x7d, 0x6e, 0x9c, 0xba] } },
]

// Type ids (and whether each is signed) for a given width; width 8 has no be/le variants.
function typesForWidth(widthBits) {
    if (widthBits === 8) return [{ id: 'i8', signed: true }, { id: 'u8', signed: false }]
    const n = widthBits
    return [
        { id: `i${n}be`, signed: true }, { id: `i${n}le`, signed: true },
        { id: `u${n}be`, signed: false }, { id: `u${n}le`, signed: false },
    ]
}

function expectedBytesFor(entry, widthBits) {
    if (widthBits === 8) return entry.bytes
    return entry.id.endsWith('be') ? entry.be : entry.le
}

// Runs all 3 required checks for one hard-coded (value, bytes) pair against one type id:
//   1) encode(value) then decode(...) returns the original value        (encode/decode round-trip)
//   2) decode(bytes) then encode(...) returns the original bytes        (decode/encode round-trip)
//   3) encode(value) and decode(bytes) each match the pre-calculated bytes/value exactly (accuracy)
function checkVector(id, value, bytes) {
    const encoded = encode(id, value)
    assert.deepEqual([...encoded], bytes, `encode(${id}, ${value}) should match the pre-calculated bytes`)
    assert.equal(decode(id, bytes), value, `decode(${id}, <pre-calculated bytes>) should match the pre-calculated value`)

    assert.equal(decode(id, encoded), value, `encode then decode should round-trip to ${value}`)
    assert.deepEqual([...encode(id, decode(id, bytes))], bytes, 'decode then encode should round-trip to the same bytes')
}

for (const vector of BOUNDARY_VECTORS) {
    for (const { id, signed } of typesForWidth(vector.widthBits)) {
        test(`byte boundary ${vector.band} (${id}): positive pre-calculated vector`, () => {
            checkVector(id, vector.pos.value, expectedBytesFor({ ...vector.pos, id }, vector.widthBits))
        })

        if (signed) {
            test(`byte boundary ${vector.band} (${id}): negative pre-calculated vector`, () => {
                checkVector(id, vector.neg.value, expectedBytesFor({ ...vector.neg, id }, vector.widthBits))
            })
        }
    }
}

// decodeNumberValue/encodeNumberValue: the pure number<->bytes core numberDecode/
// numberEncode above (and framer.number.*/tamper.number.* — see transformWorkerApi.js)
// build on, deliberately independent of OPERATIONS' decimal-text convention. Own minimal
// type literals here, not imported from numbers.js, same independence rationale as TYPES
// above.
const U16BE = { label: 'UInt16 (big endian)', bytes: 2, signed: false, get: 'getUint16', set: 'setUint16', le: false }
const I32LE = { label: 'Int32 (little endian)', bytes: 4, signed: true, get: 'getInt32', set: 'setInt32', le: true }
const U64BE = { label: 'UInt64 (big endian)', bytes: 8, signed: false, get: 'getBigUint64', set: 'setBigUint64', le: false, big: true }

test('decodeNumberValue/encodeNumberValue round-trip a plain number', () => {
    const bytes = encodeNumberValue(256, U16BE)
    assert.deepEqual([...bytes], [0x01, 0x00])
    assert.equal(decodeNumberValue(bytes, U16BE), 256)
})

test('decodeNumberValue/encodeNumberValue round-trip a negative number', () => {
    const bytes = encodeNumberValue(-1, I32LE)
    assert.deepEqual([...bytes], [0xff, 0xff, 0xff, 0xff])
    assert.equal(decodeNumberValue(bytes, I32LE), -1)
})

test('decodeNumberValue/encodeNumberValue round-trip a BigInt for a 64-bit type', () => {
    const bytes = encodeNumberValue(123456789012345n, U64BE)
    assert.equal(decodeNumberValue(bytes, U64BE), 123456789012345n)
})

test('decodeNumberValue rejects the wrong byte length', () => {
    assert.throws(() => decodeNumberValue(new Uint8Array(1), U16BE))
    assert.throws(() => decodeNumberValue(new Uint8Array(3), U16BE))
})

test('encodeNumberValue rejects an out-of-range value', () => {
    assert.throws(() => encodeNumberValue(65536, U16BE))
    assert.throws(() => encodeNumberValue(-1, U16BE))
})

test('encodeNumberValue rejects a plain number for a 64-bit (BigInt) type', () => {
    assert.throws(() => encodeNumberValue(1, U64BE))
})

test('encodeNumberValue rejects a BigInt for a non-64-bit type', () => {
    assert.throws(() => encodeNumberValue(1n, U16BE))
})
