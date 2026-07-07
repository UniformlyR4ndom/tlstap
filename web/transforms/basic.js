import { fmtAsBase64 } from '../format.js'

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

export const ENCODE_ALGORITHMS = [
    { label: 'Hex', op: 'hex-encode' }, { label: 'Base64', op: 'base64-encode' },
    { label: 'Octal', op: 'octal-encode' }, { label: 'Base-N', op: 'basen-encode' },
]

export const DECODE_ALGORITHMS = [
    { label: 'Hex', op: 'hex-decode' }, { label: 'Base64', op: 'base64-decode' },
    { label: 'Octal', op: 'octal-decode' }, { label: 'Base-N', op: 'basen-decode' },
]
