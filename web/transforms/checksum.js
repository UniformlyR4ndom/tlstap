// CRC16 and CRC32 share one generic core implementing the Williams/Rocksoft CRC model: every
// named variant (see CRC16_PRESETS/CRC32_PRESETS below) is fully defined by five parameters
// (width, poly, init, refin, refout, xorout) over an otherwise identical bit loop — this is the
// same model the "reveng" CRC catalogue uses to define e.g. CRC-16/MODBUS vs. CRC-16/XMODEM
// (same poly, different init) or CRC-32 vs. CRC-32/BZIP2 (same poly/init, different
// refin/refout/xorout). Hand-rolled rather than vendored (unlike e.g. Whirlpool in hash.js):
// the algorithm is a short, unambiguous bit-shift-and-XOR loop, not something meaningfully
// error-prone enough to justify a dependency.
// Adler-32 (RFC 1950) is unrelated to the CRC model and hand-rolled separately below.
import { fmtUintHex, parseUintField } from '../format.js'

function reflect(value, bits) {
    let result = 0
    let v = value >>> 0
    for (let i = 0; i < bits; i++) {
        result = ((result << 1) | (v & 1)) >>> 0
        v >>>= 1
    }
    return result
}

function crcCompute(bytes, { width, poly, init, refin, refout, xorout }) {
    const mask = width === 32 ? 0xFFFFFFFF : (((1 << width) - 1) >>> 0)
    const topBit = (1 << (width - 1)) >>> 0
    let reg = init >>> 0
    for (let i = 0; i < bytes.length; i++) {
        const inByte = refin ? reflect(bytes[i], 8) : bytes[i]
        reg = (reg ^ ((inByte << (width - 8)) >>> 0)) >>> 0
        for (let bit = 0; bit < 8; bit++) {
            reg = (reg & topBit) ? (((reg << 1) >>> 0) ^ poly) >>> 0 : (reg << 1) >>> 0
            reg = (reg & mask) >>> 0
        }
    }
    if (refout) reg = reflect(reg, width)
    return ((reg ^ xorout) & mask) >>> 0
}

const ADLER_MOD = 65521

function adler32(bytes) {
    let a = 1, b = 0
    for (let i = 0; i < bytes.length; i++) {
        a = (a + bytes[i]) % ADLER_MOD
        b = (b + a) % ADLER_MOD
    }
    const out = new Uint8Array(4)
    new DataView(out.buffer).setUint32(0, ((b << 16) | a) >>> 0, false)
    return out
}

// Named variants, value/label pairs doubling as both the "variant" select's option list and the
// parameter source that select's onSet copies from (see makeCrcParams below).
const CRC16_PRESETS = [
    { value: 'ccitt-false', label: 'CCITT-FALSE', poly: 0x1021, init: 0xFFFF, refin: false, refout: false, xorout: 0x0000 },
    { value: 'arc',         label: 'ARC',         poly: 0x8005, init: 0x0000, refin: true,  refout: true,  xorout: 0x0000 },
    { value: 'modbus',      label: 'MODBUS',      poly: 0x8005, init: 0xFFFF, refin: true,  refout: true,  xorout: 0x0000 },
    { value: 'xmodem',      label: 'XMODEM',      poly: 0x1021, init: 0x0000, refin: false, refout: false, xorout: 0x0000 },
    { value: 'kermit',      label: 'KERMIT',      poly: 0x1021, init: 0x0000, refin: true,  refout: true,  xorout: 0x0000 },
    { value: 'usb',         label: 'USB',         poly: 0x8005, init: 0xFFFF, refin: true,  refout: true,  xorout: 0xFFFF },
]

const CRC32_PRESETS = [
    { value: 'crc32',  label: 'CRC-32',  poly: 0x04C11DB7, init: 0xFFFFFFFF, refin: true,  refout: true,  xorout: 0xFFFFFFFF },
    { value: 'crc32c', label: 'CRC-32C', poly: 0x1EDC6F41, init: 0xFFFFFFFF, refin: true,  refout: true,  xorout: 0xFFFFFFFF },
    { value: 'bzip2',  label: 'BZIP2',   poly: 0x04C11DB7, init: 0xFFFFFFFF, refin: false, refout: false, xorout: 0xFFFFFFFF },
    { value: 'mpeg2',  label: 'MPEG-2',  poly: 0x04C11DB7, init: 0xFFFFFFFF, refin: false, refout: false, xorout: 0x00000000 },
]

// Resolves a step's params down to the five crcCompute() fields: either a named preset's fixed
// values, or the Custom variant's own poly/init/refin/refout/xorout fields (parsed/validated).
function resolveCrcParams(params, presetsByValue, width) {
    if (params.variant === 'custom') {
        return {
            poly: parseUintField(params.poly, 'poly', width),
            init: parseUintField(params.init, 'init', width),
            refin: !!params.refin,
            refout: !!params.refout,
            xorout: parseUintField(params.xorout, 'xorout', width),
        }
    }
    const preset = presetsByValue[params.variant]
    if (!preset) throw new Error(`unknown CRC variant "${params.variant}"`)
    return preset
}

// The Custom fields (poly/init/refin/refout/xorout) are only shown once "Custom" is picked
// (TransformPanel.js's showIf support); selecting a named variant instead copies that preset's
// values into them via onSet, so they always reflect whatever's actually in effect and Custom
// starts from a sensible seed rather than blank. Both keep the same key names so resolveCrcParams
// can read them uniformly regardless of how they got there.
function makeCrcParams(width, presets) {
    const lookup = Object.fromEntries(presets.map(p => [p.value, p]))
    const defaultPreset = presets[0]
    return [
        {
            // inHeader: rendered next to the step's title instead of the body param area below it.
            key: 'variant', label: 'Variant', type: 'select', default: defaultPreset.value, inHeader: true,
            options: [...presets.map(p => ({ value: p.value, label: p.label })), { value: 'custom', label: 'Custom' }],
            onSet: (value) => {
                const preset = lookup[value]
                if (!preset) return {}
                return {
                    poly: fmtUintHex(preset.poly, width),
                    init: fmtUintHex(preset.init, width),
                    refin: preset.refin,
                    refout: preset.refout,
                    xorout: fmtUintHex(preset.xorout, width),
                }
            },
        },
        // row/rowLabel: params sharing a `row` key render on one labeled line — "XOR in" pairs
        // init with its reflect toggle, "XOR out" pairs xorout with its reflect toggle.
        { key: 'poly', label: 'Hex value', type: 'text', default: fmtUintHex(defaultPreset.poly, width), wide: true,
          row: 'poly', rowLabel: 'Polynomial', showIf: params => params.variant === 'custom' },
        { key: 'init', label: 'Hex value', type: 'text', default: fmtUintHex(defaultPreset.init, width), wide: true,
          row: 'xorin', rowLabel: 'XOR in', showIf: params => params.variant === 'custom' },
        { key: 'xorout', label: 'Hex value', type: 'text', default: fmtUintHex(defaultPreset.xorout, width), wide: true,
          row: 'xorout', rowLabel: 'XOR out', showIf: params => params.variant === 'custom' },
        { key: 'refin', label: 'Reflect in', type: 'boolean', default: defaultPreset.refin,
          row: 'xorin', showIf: params => params.variant === 'custom' },
        { key: 'refout', label: 'Reflect out', type: 'boolean', default: defaultPreset.refout,
          row: 'xorout', showIf: params => params.variant === 'custom' },
    ]
}

const CRC16_BY_VALUE = Object.fromEntries(CRC16_PRESETS.map(p => [p.value, p]))
const CRC32_BY_VALUE = Object.fromEntries(CRC32_PRESETS.map(p => [p.value, p]))

function crc16Run(bytes, params) {
    const resolved = resolveCrcParams(params, CRC16_BY_VALUE, 16)
    const value = crcCompute(bytes, { width: 16, ...resolved })
    const out = new Uint8Array(2)
    new DataView(out.buffer).setUint16(0, value, false)
    return out
}

function crc32Run(bytes, params) {
    const resolved = resolveCrcParams(params, CRC32_BY_VALUE, 32)
    const value = crcCompute(bytes, { width: 32, ...resolved })
    const out = new Uint8Array(4)
    new DataView(out.buffer).setUint32(0, value, false)
    return out
}

// Output is the checksum's raw big-endian bytes (e.g. CRC-32 0xCBF43926 -> CB F4 39 26), the
// same convention hash.js's digests use — no endianness param, same as none of the hash ops has one.
export const OPERATIONS = {
    crc16: { label: 'CRC16', params: makeCrcParams(16, CRC16_PRESETS), run: crc16Run },
    crc32: { label: 'CRC32', params: makeCrcParams(32, CRC32_PRESETS), run: crc32Run },
    adler32: { label: 'Adler32', run: adler32 },
}

export const CHECKSUM_ALGORITHMS = [
    { label: 'CRC16', op: 'crc16' }, { label: 'CRC32', op: 'crc32' }, { label: 'Adler32', op: 'adler32' },
]
