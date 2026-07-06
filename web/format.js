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

export function mergeUint8Arrays(arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const a of arrays) { out.set(a, off); off += a.length }
    return out
}
