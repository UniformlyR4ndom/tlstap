// HMAC over each hash algorithm already in transforms/hash.js's SHA-1/SHA-2 family plus MD5 —
// the six that actually see real-world use as MACs (JWT HS256, AWS SigV4, webhook signatures,
// etc.). MD2/MD4/NTLM/Whirlpool are deliberately excluded: HMAC over the first three isn't a
// real, standardized, commonly-used construction (NTLM in particular has its own different
// MAC-like protocol uses, not "HMAC with NTLM plugged in"), and Whirlpool would need hand-rolling
// the generic HMAC construction ourselves (our vendored copy is a minimal hash-only WASM bundle
// with no HMAC helper) for a niche algorithm not judged worth it.
//
// All six come from the vendored crypto-js (already used by hash.js and, since the Encryption
// work, encryption.js too) — its own module now also includes the HMAC helpers; see
// ../vendor/crypto-js.module.js's header comment for the full rebuild recipe, including the
// import-order requirement (hmac.js before the hash files) that isn't obvious from crypto-js's
// own docs.
import { WordArray, HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512 } from '../vendor/crypto-js.module.js'

function bytesFromWordArray(wordArray) {
    const { words, sigBytes } = wordArray
    const bytes = new Uint8Array(sigBytes)
    for (let i = 0; i < sigBytes; i++) {
        bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    }
    return bytes
}

// Same hex-parsing convention as encryption.js's parseHexBytes (0x-prefix optional, bare hex
// accepted) — duplicated here rather than imported, matching this project's per-module-private-
// helper convention (hash.js and encryption.js each already keep their own separate copy of a
// near-identical bytesFromWordArray). No length constraint: HMAC is defined for any key length —
// RFC 2104 zero-pads short keys and hashes down long ones internally — so the only requirement is
// that a key was actually given.
function parseHexBytes(text, label) {
    let cleaned = String(text ?? '').replace(/\s+/g, '')
    if (/^0[xX]/.test(cleaned)) cleaned = cleaned.slice(2)
    if (cleaned.length === 0) throw new Error(`${label} must not be empty`)
    if (cleaned.length % 2 !== 0) throw new Error(`${label}: odd number of hex digits`)
    if (!/^[0-9a-fA-F]*$/.test(cleaned)) throw new Error(`${label}: invalid hex digit`)
    const bytes = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < cleaned.length; i += 2) bytes[i / 2] = parseInt(cleaned.slice(i, i + 2), 16)
    return bytes
}

const KEY_PARAM = [
    { key: 'key', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'key', rowLabel: 'Key' },
]

function hmac(hasher) {
    return (bytes, params) => bytesFromWordArray(hasher(WordArray.create(bytes), WordArray.create(parseHexBytes(params.key, 'Key'))))
}

export const OPERATIONS = {
    'hmac-md5': { label: 'HMAC-MD5', params: KEY_PARAM, run: hmac(HmacMD5) },
    'hmac-sha1': { label: 'HMAC-SHA1', params: KEY_PARAM, run: hmac(HmacSHA1) },
    'hmac-sha224': { label: 'HMAC-SHA224', params: KEY_PARAM, run: hmac(HmacSHA224) },
    'hmac-sha256': { label: 'HMAC-SHA256', params: KEY_PARAM, run: hmac(HmacSHA256) },
    'hmac-sha384': { label: 'HMAC-SHA384', params: KEY_PARAM, run: hmac(HmacSHA384) },
    'hmac-sha512': { label: 'HMAC-SHA512', params: KEY_PARAM, run: hmac(HmacSHA512) },
}

export const MAC_ALGORITHMS = [
    { label: 'HMAC-MD5', op: 'hmac-md5' }, { label: 'HMAC-SHA1', op: 'hmac-sha1' },
    { label: 'HMAC-SHA224', op: 'hmac-sha224' }, { label: 'HMAC-SHA256', op: 'hmac-sha256' },
    { label: 'HMAC-SHA384', op: 'hmac-sha384' }, { label: 'HMAC-SHA512', op: 'hmac-sha512' },
]
