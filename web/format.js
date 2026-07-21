export function fmtAsRaw(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

export function parseRaw(text) {
    return new TextEncoder().encode(text)
}

export function fmtAsBase64(bytes) {
    return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
}

export function fmtAsHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

export function fmtAsAscii(bytes) {
    return Array.from(bytes, b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('')
}

export function fmtAsHexdump(bytes, baseOffset) {
    const lines = []
    for (let i = 0; i < bytes.length; i += 16) {
        const slice = bytes.slice(i, i + 16)
        const off = (baseOffset + i).toString(16).padStart(8, '0')
        const hexParts = Array.from(slice, b => b.toString(16).padStart(2, '0'))
        const g1 = hexParts.slice(0, 8).join(' ').padEnd(23)
        const g2 = hexParts.slice(8).join(' ').padEnd(23)
        const asc = Array.from(slice, b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('')
        lines.push(`${off}  ${g1}  ${g2}  |${asc}|`)
    }
    return lines.join('\n')
}

// Inverse of fmtAsHexdump: parses an xxd-style "OOOOOOOO  hh hh … hh  hh hh … hh  |ascii|"
// dump back into bytes. Ignores the offset and |ascii| columns entirely (both are derived,
// lossy for non-printable bytes in the ascii case) and only reads the hex byte tokens
// between them; lenient about exact spacing so a manually-tweaked or partially-reflowed
// dump still parses, as long as each line keeps the "offset  hexbytes  |ascii|" shape.
export function parseHexdump(text) {
    const bytes = []
    for (const rawLine of text.split('\n')) {
        const line = rawLine.trim()
        if (!line) continue
        const m = line.match(/^[0-9a-fA-F]+\s+(.*?)\s*\|.*\|$/)
        if (!m) throw new Error(`invalid hexdump line: "${rawLine}"`)
        for (const tok of m[1].split(/\s+/).filter(Boolean)) {
            if (!/^[0-9a-fA-F]{2}$/.test(tok)) throw new Error(`invalid hex byte "${tok}" in line: "${rawLine}"`)
            bytes.push(parseInt(tok, 16))
        }
    }
    return new Uint8Array(bytes)
}

// Accepts an optional leading "0x"/"0X" prefix (stripped if present); the remainder must be a
// plain, contiguous run of hex-digit pairs. `validLengths` (optional array of acceptable byte
// counts) is enforced here for callers whose underlying library doesn't validate it itself.
export function parseHexBytes(text, label, validLengths) {
    let cleaned = String(text ?? '').replace(/\s+/g, '')
    if (/^0[xX]/.test(cleaned)) cleaned = cleaned.slice(2)
    if (cleaned.length === 0) throw new Error(`${label} must not be empty`)
    if (cleaned.length % 2 !== 0) throw new Error(`${label}: odd number of hex digits`)
    if (!/^[0-9a-fA-F]*$/.test(cleaned)) throw new Error(`${label}: invalid hex digit`)
    const bytes = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < cleaned.length; i += 2) bytes[i / 2] = parseInt(cleaned.slice(i, i + 2), 16)
    if (validLengths && !validLengths.includes(bytes.length)) {
        throw new Error(`${label} must be ${validLengths.join(' or ')} bytes, got ${bytes.length}`)
    }
    return bytes
}

// Unpacks a crypto-js WordArray-shaped object ({words: number[], sigBytes}) into a Uint8Array —
// crypto-js packs bytes big-endian, 4 per 32-bit word.
export function bytesFromWordArray(wordArray) {
    const { words, sigBytes } = wordArray
    const bytes = new Uint8Array(sigBytes)
    for (let i = 0; i < sigBytes; i++) {
        bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    }
    return bytes
}

// Formats an unsigned integer as a fixed-width, zero-padded "0x"-prefixed hex string
// (width in bits, e.g. fmtUintHex(0xFF, 16) -> "0x00FF").
export function fmtUintHex(n, width) {
    return '0x' + ((n >>> 0).toString(16).toUpperCase().padStart(width / 4, '0'))
}

// Accepts "0x"/"0X"-prefixed hex, plain decimal, or bare hex with no prefix at all (e.g.
// "c10fd7ae") — a pure-digit string (no a-f letters) is read as decimal so an already-typed
// value like "1021" doesn't silently become 0x1021; a string containing a-f is unambiguous
// and accepted as hex directly. Validates the parsed value fits in `width` bits.
export function parseUintField(text, label, width) {
    const s = String(text).trim()
    let value
    if (/^0[xX][0-9a-fA-F]+$/.test(s)) value = parseInt(s, 16)
    else if (/^[0-9]+$/.test(s)) value = parseInt(s, 10)
    else if (/^[0-9a-fA-F]+$/.test(s)) value = parseInt(s, 16)
    else throw new Error(`invalid ${label}: "${text}"`)
    const max = width === 32 ? 0xFFFFFFFF : (1 << width) - 1
    if (value > max) throw new Error(`${label} out of range for a ${width}-bit value: "${text}"`)
    return value >>> 0
}

// Rounds `value` to the nearest integer and validates it falls within [min, max].
export function parseIntInRange(value, min, max, label) {
    const n = Math.round(Number(value))
    if (!Number.isFinite(n) || n < min || n > max) throw new Error(`${label} must be between ${min} and ${max}`)
    return n
}

export function mergeUint8Arrays(arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const a of arrays) { out.set(a, off); off += a.length }
    return out
}
