import { test } from 'node:test'
import assert from 'node:assert/strict'
import { OPERATIONS } from './checksum.js'

const enc = new TextEncoder()

function toHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function run(op, text, params = {}) {
    return OPERATIONS[op].run(enc.encode(text), params)
}

// Reference "check" input from the CRC RevEng catalogue convention. Every expected value below
// was independently cross-checked before use: against Python's zlib.crc32/zlib.adler32 for the
// two variants zlib implements directly (CRC-32 "standard" and Adler-32), and against a
// from-scratch Python reimplementation of the same width/poly/init/refin/refout/xorout model for
// every other named variant (CRC-32C/BZIP2/MPEG-2, all CRC-16 variants) — see the outline in
// checksum.js's header comment.
const CHECK = '123456789'
const FOX = 'The quick brown fox jumps over the lazy dog'

test('crc16: known preset check-values for "123456789"', () => {
    const expected = { 'ccitt-false': '29b1', arc: 'bb3d', modbus: '4b37', xmodem: '31c3', kermit: '2189', usb: 'b4c8' }
    for (const [variant, hex] of Object.entries(expected)) {
        assert.equal(toHex(run('crc16', CHECK, { variant })), hex, variant)
    }
})

test('crc32: known preset check-values for "123456789"', () => {
    const expected = { crc32: 'cbf43926', crc32c: 'e3069283', bzip2: 'fc891918', mpeg2: '0376e6e7' }
    for (const [variant, hex] of Object.entries(expected)) {
        assert.equal(toHex(run('crc32', CHECK, { variant })), hex, variant)
    }
})

test('crc32: standard variant on a second known string (cross-checked against zlib.crc32)', () => {
    assert.equal(toHex(run('crc32', FOX, { variant: 'crc32' })), '414fa339')
})

test('crc32: CRC-32 and CRC-32C differ on identical input (guards against an ignored poly param)', () => {
    assert.notEqual(toHex(run('crc32', FOX, { variant: 'crc32' })), toHex(run('crc32', FOX, { variant: 'crc32c' })))
})

test('adler32: known check-values (cross-checked against zlib.adler32)', () => {
    assert.equal(toHex(run('adler32', CHECK)), '091e01de')
    assert.equal(toHex(run('adler32', FOX)), '5bdc0fda')
})

test('empty input', () => {
    assert.equal(toHex(run('crc32', '', { variant: 'crc32' })), '00000000')
    assert.equal(toHex(run('crc16', '', { variant: 'ccitt-false' })), 'ffff')
    assert.equal(toHex(run('adler32', '')), '00000001')
})

test('output byte length matches each checksum width, big-endian', () => {
    assert.equal(run('crc16', CHECK, { variant: 'modbus' }).length, 2)
    assert.equal(run('crc32', CHECK, { variant: 'crc32' }).length, 4)
    assert.equal(run('adler32', CHECK).length, 4)
    // Big-endian: CRC-32 0xCBF43926's most significant byte (0xCB) comes first.
    assert.equal(run('crc32', CHECK, { variant: 'crc32' })[0], 0xcb)
})

test('custom variant reproduces a named preset when given the same five parameters', () => {
    const preset = run('crc16', CHECK, { variant: 'modbus' })
    const custom = run('crc16', CHECK, {
        variant: 'custom', poly: '0x8005', init: '0xFFFF', refin: true, refout: true, xorout: '0x0000',
    })
    assert.deepEqual(custom, preset)
})

test('custom variant accepts 0x-hex, bare hex with no prefix, and plain-decimal parameter text interchangeably', () => {
    // 0x04C11DB7 == 79764919 decimal; mixing all three forms should still match the CRC-32 preset.
    const preset = run('crc32', CHECK, { variant: 'crc32' })
    const custom = run('crc32', CHECK, {
        variant: 'custom', poly: '79764919', init: '0xFFFFFFFF', refin: true, refout: true, xorout: '4294967295',
    })
    assert.deepEqual(custom, preset)
    // Bare hex with no "0x" prefix at all — only unambiguous when it contains a letter (a-f),
    // since a pure-digit string is still read as decimal (see next test).
    const bareHex = run('crc32', CHECK, {
        variant: 'custom', poly: '04c11db7', init: 'ffffffff', refin: true, refout: true, xorout: 'ffffffff',
    })
    assert.deepEqual(bareHex, preset)
})

test('custom variant treats a pure-digit bare string as decimal, not hex, preserving already-typed values\' meaning', () => {
    // "1217" must mean decimal 1217 (== hex 0x04C1), not hex 0x1217 (== decimal 4631) — silently
    // reinterpreting bare digit strings as hex would change what anyone's already-typed values mean.
    const decimalPoly = run('crc16', CHECK, {
        variant: 'custom', poly: '1217', init: '0x0000', refin: false, refout: false, xorout: '0x0000',
    })
    const hexPolySameDigits = run('crc16', CHECK, {
        variant: 'custom', poly: '0x1217', init: '0x0000', refin: false, refout: false, xorout: '0x0000',
    })
    assert.notEqual(toHex(decimalPoly), toHex(hexPolySameDigits))
    const hexPolyEquivalentValue = run('crc16', CHECK, {
        variant: 'custom', poly: '0x04c1', init: '0x0000', refin: false, refout: false, xorout: '0x0000',
    })
    assert.deepEqual(decimalPoly, hexPolyEquivalentValue)
})

test('custom variant rejects invalid parameter text', () => {
    assert.throws(() => run('crc32', CHECK, {
        variant: 'custom', poly: 'not-hex', init: '0xFFFFFFFF', refin: true, refout: true, xorout: '0xFFFFFFFF',
    }))
})

test('custom variant rejects a poly value wider than the checksum width', () => {
    assert.throws(() => run('crc16', CHECK, {
        variant: 'custom', poly: '0x10000', init: '0xFFFF', refin: false, refout: false, xorout: '0x0000',
    }))
})

test('unknown variant name is rejected', () => {
    assert.throws(() => run('crc16', CHECK, { variant: 'not-a-real-variant' }))
})
