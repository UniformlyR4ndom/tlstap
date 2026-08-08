export function fmtAsRaw(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
}

export function parseRaw(text) {
    return new TextEncoder().encode(text)
}

export function fmtAsBase64(bytes) {
    return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
}

export function parseBase64(text) {
    return Uint8Array.from(atob(text), c => c.charCodeAt(0))
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
        const asc = fmtAsAscii(slice)
        lines.push(`${off}  ${g1}  ${g2}  |${asc}|`)
    }
    return lines.join('\n')
}

// Inverse of fmtAsHexdump: reads only the hex byte tokens, ignoring the offset/ascii
// columns (both derived). Tolerant of loose spacing between tokens.
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

// Accepts an optional leading "0x"/"0X" prefix; the remainder must be a plain, contiguous
// run of hex-digit pairs. `validLengths` (optional) enforces an exact byte count if given.
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

// Accepts "0x"-prefixed hex, plain decimal, or bare hex (e.g. "c10fd7ae"). A pure-digit
// string is read as decimal (so "1021" doesn't silently become 0x1021); a string
// containing a-f is read as hex. Validates the result fits in `width` bits.
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

// Formats a byte count as a human-readable size. Negative n (e.g. a not-yet-known total)
// formats as '?'.
export function fmtByteSize(n) {
    if (n < 0)       return '?'
    if (n < 1024)    return `${n} B`
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / 1048576).toFixed(1)} MB`
}

// Formats start→end (ms epoch) as e.g. "12.34s". If end is falsy, measures against
// Date.now() and appends " (ongoing)".
export function fmtDuration(start, end) {
    const d = (end || Date.now()) - start
    let s
    if (d < 1000)       s = `${d}ms`
    else if (d < 60000) s = `${(d / 1000).toFixed(2)}s`
    else                s = `${Math.floor(d / 60000)}m ${Math.floor((d % 60000) / 1000)}s`
    return end ? s : `${s} (ongoing)`
}

// Formats a chunk timestamp relative to a stream/session start (both ms epoch), e.g. "+1.234s".
export function fmtRelTime(ms, base) {
    const d = ms - base
    return `+${Math.floor(d / 1000)}.${String(d % 1000).padStart(3, '0')}s`
}
