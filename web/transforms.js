import { fmtAsBase64 } from './format.js'

const BASEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function validateBase(base) {
    const b = Math.round(Number(base))
    if (!Number.isFinite(b) || b < 2 || b > 64) throw new Error('base must be between 2 and 64')
    return b
}

// Maps a hex separator param value to its literal character(s).
const HEX_SEPARATOR_CHARS = {
    x0: '0x', xesc: '\\x', comma: ',', semi: ';', colon: ':', space: ' ', newline: '\n',
}
const HEX_SEPARATOR_OPTIONS = [
    { value: 'x0',      label: '0x' },
    { value: 'xesc',    label: '\\x' },
    { value: 'comma',   label: ',' },
    { value: 'semi',    label: ';' },
    { value: 'colon',   label: ':' },
    { value: 'space',   label: 'Space' },
    { value: 'newline', label: '\\n' },
]
const HEX_PARAMS = [{ key: 'separator', label: 'Separator', type: 'select', options: HEX_SEPARATOR_OPTIONS, default: 'space' }]

function hexEncode(bytes, params) {
    const sep = params.separator
    const hexBytes = Array.from(bytes, b => b.toString(16).padStart(2, '0'))
    let text
    if (sep === 'x0') text = hexBytes.map(h => '0x' + h).join(' ')
    else if (sep === 'xesc') text = hexBytes.map(h => '\\x' + h).join('')
    else text = hexBytes.join(HEX_SEPARATOR_CHARS[sep])
    return new TextEncoder().encode(text)
}

function hexDecode(bytes, params) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    const sepChars = HEX_SEPARATOR_CHARS[params.separator]
    const withoutSeparator = sepChars ? text.split(sepChars).join('') : text
    const cleaned = withoutSeparator.replace(/\s+/g, '')
    if (cleaned.length % 2 !== 0) throw new Error('odd number of hex digits')
    if (!/^[0-9a-fA-F]*$/.test(cleaned)) throw new Error('invalid hex digit')
    const out = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < cleaned.length; i += 2) out[i / 2] = parseInt(cleaned.slice(i, i + 2), 16)
    return out
}

function base64Encode(bytes, params) {
    let text = fmtAsBase64(bytes)
    if (params.urlSafe) text = text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    return new TextEncoder().encode(text)
}

function base64Decode(bytes, params) {
    let text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim()
    if (params.urlSafe) {
        text = text.replace(/-/g, '+').replace(/_/g, '/')
        const pad = text.length % 4
        if (pad === 1) throw new Error('invalid base64url input length')
        if (pad > 0) text += '='.repeat(4 - pad)
    }
    let bin
    try {
        bin = atob(text)
    } catch {
        throw new Error('invalid base64 input')
    }
    return Uint8Array.from(bin, c => c.charCodeAt(0))
}

function octalEncode(bytes) {
    return new TextEncoder().encode(Array.from(bytes, b => b.toString(8).padStart(3, '0')).join(' '))
}

function octalDecode(bytes) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
    const tokens = text.trim().split(/\s+/).filter(t => t.length > 0)
    const out = new Uint8Array(tokens.length)
    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i]
        if (!/^[0-7]+$/.test(t)) throw new Error(`invalid octal digit in "${t}"`)
        const v = parseInt(t, 8)
        if (v > 255) throw new Error(`octal value out of byte range: "${t}"`)
        out[i] = v
    }
    return out
}

// Arbitrary-base encoding of the byte buffer as one big integer, base 2-64. Leading zero
// bytes are preserved as leading zero-symbol characters (same convention as Base58).
function baseNEncode(bytes, params) {
    const base = validateBase(params.base)
    if (bytes.length === 0) return new Uint8Array(0)
    const alphabet = BASEN_ALPHABET.slice(0, base)
    let leadingZeros = 0
    while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros++
    let num = 0n
    for (const b of bytes) num = (num << 8n) | BigInt(b)
    const digits = []
    while (num > 0n) {
        digits.push(Number(num % BigInt(base)))
        num /= BigInt(base)
    }
    digits.reverse()
    const encoded = alphabet[0].repeat(leadingZeros) + digits.map(d => alphabet[d]).join('')
    return new TextEncoder().encode(encoded)
}

function baseNDecode(bytes, params) {
    const base = validateBase(params.base)
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim()
    if (text.length === 0) return new Uint8Array(0)
    const alphabet = BASEN_ALPHABET.slice(0, base)
    let leadingZeros = 0
    while (leadingZeros < text.length && text[leadingZeros] === alphabet[0]) leadingZeros++
    let num = 0n
    for (const ch of text) {
        const idx = alphabet.indexOf(ch)
        if (idx === -1) throw new Error(`character "${ch}" is not valid in base ${base}`)
        num = num * BigInt(base) + BigInt(idx)
    }
    const bytesOut = []
    while (num > 0n) {
        bytesOut.push(Number(num & 0xFFn))
        num >>= 8n
    }
    bytesOut.reverse()
    return new Uint8Array([...Array(leadingZeros).fill(0), ...bytesOut])
}

const BASEN_PARAMS = [{ key: 'base', label: 'Base', type: 'number', min: 2, max: 64, default: 64 }]
const BASE64_PARAMS = [{ key: 'urlSafe', label: 'URL safe', type: 'boolean', default: false }]

// Fixed-width binary integer types. `get`/`set` name the DataView methods to use; the
// 1-byte types ignore the extra `le` argument DataView getters/setters are called with.
const NUMBER_TYPES = [
    { id: 'i8',    label: 'Int8',                    bytes: 1, signed: true,  get: 'getInt8',     set: 'setInt8' },
    { id: 'u8',    label: 'UInt8',                   bytes: 1, signed: false, get: 'getUint8',    set: 'setUint8' },
    { id: 'i16be', label: 'Int16 (big endian)',      bytes: 2, signed: true,  get: 'getInt16',    set: 'setInt16',    le: false },
    { id: 'i16le', label: 'Int16 (little endian)',   bytes: 2, signed: true,  get: 'getInt16',    set: 'setInt16',    le: true },
    { id: 'u16be', label: 'UInt16 (big endian)',     bytes: 2, signed: false, get: 'getUint16',   set: 'setUint16',   le: false },
    { id: 'u16le', label: 'UInt16 (little endian)',  bytes: 2, signed: false, get: 'getUint16',   set: 'setUint16',   le: true },
    { id: 'i32be', label: 'Int32 (big endian)',      bytes: 4, signed: true,  get: 'getInt32',    set: 'setInt32',    le: false },
    { id: 'i32le', label: 'Int32 (little endian)',   bytes: 4, signed: true,  get: 'getInt32',    set: 'setInt32',    le: true },
    { id: 'u32be', label: 'UInt32 (big endian)',     bytes: 4, signed: false, get: 'getUint32',   set: 'setUint32',   le: false },
    { id: 'u32le', label: 'UInt32 (little endian)',  bytes: 4, signed: false, get: 'getUint32',   set: 'setUint32',   le: true },
    { id: 'i64be', label: 'Int64 (big endian)',      bytes: 8, signed: true,  get: 'getBigInt64',  set: 'setBigInt64',  le: false, big: true },
    { id: 'i64le', label: 'Int64 (little endian)',   bytes: 8, signed: true,  get: 'getBigInt64',  set: 'setBigInt64',  le: true,  big: true },
    { id: 'u64be', label: 'UInt64 (big endian)',     bytes: 8, signed: false, get: 'getBigUint64', set: 'setBigUint64', le: false, big: true },
    { id: 'u64le', label: 'UInt64 (little endian)',  bytes: 8, signed: false, get: 'getBigUint64', set: 'setBigUint64', le: true,  big: true },
]

function numberRange(type) {
    if (type.big) {
        const bits = BigInt(type.bytes * 8)
        return type.signed ? { min: -(2n ** (bits - 1n)), max: 2n ** (bits - 1n) - 1n } : { min: 0n, max: 2n ** bits - 1n }
    }
    const bits = type.bytes * 8
    return type.signed ? { min: -(2 ** (bits - 1)), max: 2 ** (bits - 1) - 1 } : { min: 0, max: 2 ** bits - 1 }
}

// Decodes a fixed-width binary integer to its decimal text representation.
function numberDecode(bytes, type) {
    if (bytes.length !== type.bytes) {
        throw new Error(`expected exactly ${type.bytes} byte${type.bytes === 1 ? '' : 's'} for ${type.label}, got ${bytes.length}`)
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    const value = view[type.get](0, type.le)
    return new TextEncoder().encode(String(value))
}

// Encodes decimal text (e.g. "-123") into the fixed-width binary representation.
function numberEncode(bytes, type) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim()
    if (!/^-?\d+$/.test(text)) throw new Error(`"${text}" is not a valid integer`)
    const value = type.big ? BigInt(text) : Number(text)
    const { min, max } = numberRange(type)
    if (value < min || value > max) throw new Error(`value ${text} is out of range for ${type.label} (${min} to ${max})`)
    const out = new Uint8Array(type.bytes)
    new DataView(out.buffer)[type.set](0, value, type.le)
    return out
}

// Registry of implemented transform operations, keyed by the op id referenced from
// ALGORITHM_SECTIONS below. An algorithm catalog entry with no matching registry entry
// renders as "[TODO]" and can't be added as a step yet.
export const OPERATIONS = {
    'hex-encode':    { label: 'Hex',    params: HEX_PARAMS, run: hexEncode },
    'hex-decode':    { label: 'Hex',    params: HEX_PARAMS, run: hexDecode },
    'base64-encode': { label: 'Base64', params: BASE64_PARAMS, run: base64Encode },
    'base64-decode': { label: 'Base64', params: BASE64_PARAMS, run: base64Decode },
    'octal-encode':  { label: 'Octal',  run: octalEncode },
    'octal-decode':  { label: 'Octal',  run: octalDecode },
    'basen-encode':  { label: 'Base-N', params: BASEN_PARAMS, run: baseNEncode },
    'basen-decode':  { label: 'Base-N', params: BASEN_PARAMS, run: baseNDecode },
}
for (const t of NUMBER_TYPES) {
    OPERATIONS[`decnum-${t.id}`] = { label: t.label, run: bytes => numberDecode(bytes, t) }
    OPERATIONS[`encnum-${t.id}`] = { label: t.label, run: bytes => numberEncode(bytes, t) }
}

// Sections/subsections whose name starts with "Encode"/"Decode" get a label prefix (this
// covers both the Basic > Encode/Decode subsections and the flat "Encode Number"/"Decode
// Number" sections) — Encrypt/Decrypt and Compress/Uncompress are conceptually similar but
// weren't asked to be marked, so they're deliberately excluded by not matching the prefix.
function namePrefix(name) {
    if (name.startsWith('Encode')) return '[E] '
    if (name.startsWith('Decode')) return '[D] '
    return null
}

// Catalog of selectable algorithms, grouped by section. Sections whose algorithms run in
// either direction (Basic, Compression, Encryption) are split into two subsections. Entries
// with no corresponding OPERATIONS registration are shown as "[TODO]" and aren't selectable.
export const ALGORITHM_SECTIONS = [
    { name: 'Basic', subsections: [
        { name: 'Encode', algorithms: [
            { label: 'Hex', op: 'hex-encode' }, { label: 'Base64', op: 'base64-encode' },
            { label: 'Octal', op: 'octal-encode' }, { label: 'Base-N', op: 'basen-encode' },
        ]},
        { name: 'Decode', algorithms: [
            { label: 'Hex', op: 'hex-decode' }, { label: 'Base64', op: 'base64-decode' },
            { label: 'Octal', op: 'octal-decode' }, { label: 'Base-N', op: 'basen-decode' },
        ]},
    ]},
    { name: 'Encode Number', algorithms: NUMBER_TYPES.map(t => ({ label: t.label, op: `encnum-${t.id}` })) },
    { name: 'Decode Number', algorithms: NUMBER_TYPES.map(t => ({ label: t.label, op: `decnum-${t.id}` })) },
    { name: 'Compression', subsections: [
        { name: 'Compress',   algorithms: [] },
        { name: 'Uncompress', algorithms: [] },
    ]},
    { name: 'Checksum', algorithms: [
        { label: 'CRC16', op: 'crc16' }, { label: 'CRC32', op: 'crc32' }, { label: 'Adler32', op: 'adler32' },
    ]},
    { name: 'Encryption', subsections: [
        { name: 'Encrypt', algorithms: [] },
        { name: 'Decrypt', algorithms: [] },
    ]},
    { name: 'Hash', algorithms: [
        { label: 'MD5', op: 'md5' }, { label: 'MD2', op: 'md2' }, { label: 'MD4', op: 'md4' },
        { label: 'NTLM', op: 'ntlm' }, { label: 'SHA1', op: 'sha1' }, { label: 'SHA224', op: 'sha224' },
        { label: 'SHA256', op: 'sha256' }, { label: 'SHA384', op: 'sha384' }, { label: 'SHA512', op: 'sha512' },
        { label: 'Whirlpool', op: 'whirlpool' },
    ]},
].map(section => {
    if (section.subsections) {
        return { ...section, subsections: section.subsections.map(sub => ({ ...sub, algorithms: prefixAndSort(sub.name, sub.algorithms) })) }
    }
    return { ...section, algorithms: prefixAndSort(section.name, section.algorithms) }
})

function prefixAndSort(name, algorithms) {
    const prefix = namePrefix(name)
    const prefixed = prefix ? algorithms.map(a => ({ ...a, label: prefix + a.label })) : algorithms
    return [...prefixed].sort((a, b) => a.label.localeCompare(b.label))
}
