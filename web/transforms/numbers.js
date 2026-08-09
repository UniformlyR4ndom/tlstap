import { fmtAsRaw, parseRaw } from '../format.js'

// Fixed-width binary integer types. `get`/`set` name the DataView methods to use; the
// 1-byte types ignore the extra `le` argument DataView getters/setters are called with.
// Exported for transformWorkerApi.js's number namespace (framer.number.*/tamper.number.*
// — see that file), the one other consumer that needs the raw type table rather than
// going through OPERATIONS' decimal-text-in-bytes convention below.
export const NUMBER_TYPES = [
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

// Decodes a fixed-width binary integer to its actual number/bigint value (bigint for the
// 64-bit types, per DataView's own getBigInt64/getBigUint64). The pure bytes<->value core
// both numberDecode/numberEncode below (OPERATIONS' decimal-text convention) and
// transformWorkerApi.js's number namespace (framer.number.*/tamper.number.* — real
// numbers, no text round-trip) build on.
export function decodeNumberValue(bytes, type) {
    if (bytes.length !== type.bytes) {
        throw new Error(`expected exactly ${type.bytes} byte${type.bytes === 1 ? '' : 's'} for ${type.label}, got ${bytes.length}`)
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    return view[type.get](0, type.le)
}

// Encodes a number (or bigint, for the 64-bit types) into the fixed-width binary
// representation.
export function encodeNumberValue(value, type) {
    if (type.big && typeof value !== 'bigint') {
        throw new Error(`${type.label} requires a BigInt value (e.g. ${value}n)`)
    }
    if (!type.big && typeof value !== 'number') {
        throw new Error(`${type.label} requires a number value`)
    }
    const { min, max } = numberRange(type)
    if (value < min || value > max) throw new Error(`value ${value} is out of range for ${type.label} (${min} to ${max})`)
    const out = new Uint8Array(type.bytes)
    new DataView(out.buffer)[type.set](0, value, type.le)
    return out
}

// Decodes a fixed-width binary integer to its decimal text representation.
function numberDecode(bytes, type) {
    return parseRaw(String(decodeNumberValue(bytes, type)))
}

// Encodes decimal text (e.g. "-123") into the fixed-width binary representation.
function numberEncode(bytes, type) {
    const text = fmtAsRaw(bytes).trim()
    if (!/^-?\d+$/.test(text)) throw new Error(`"${text}" is not a valid integer`)
    return encodeNumberValue(type.big ? BigInt(text) : Number(text), type)
}

export const OPERATIONS = {}
for (const t of NUMBER_TYPES) {
    OPERATIONS[`decnum-${t.id}`] = { label: t.label, run: bytes => numberDecode(bytes, t) }
    OPERATIONS[`encnum-${t.id}`] = { label: t.label, run: bytes => numberEncode(bytes, t) }
}

export const ENCODE_ALGORITHMS = NUMBER_TYPES.map(t => ({ label: t.label, op: `encnum-${t.id}` }))
export const DECODE_ALGORITHMS = NUMBER_TYPES.map(t => ({ label: t.label, op: `decnum-${t.id}` }))
