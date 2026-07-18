export function fmtAsRaw(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
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

export function mergeUint8Arrays(arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const a of arrays) { out.set(a, off); off += a.length }
    return out
}
