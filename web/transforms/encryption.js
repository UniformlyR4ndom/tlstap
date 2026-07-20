// Library split, verified directly against each package's own source before use (not from
// memory) — see checksum.js's header comment for the same discipline applied there:
// - AES (CBC/CTR/GCM) and ChaCha20/Salsa20 come from the vendored @noble/ciphers (MIT, zero
//   runtime deps, audited) — see ../vendor/noble-ciphers/aes.js's header comment for why it's
//   vendored as plain files rather than an esbuild bundle.
// - DES/TripleDES/RC4 come from the vendored crypto-js (already used by hash.js) — its own
//   module now also includes the cipher-related pieces; see ../vendor/crypto-js.module.js's
//   header comment for the full rebuild recipe. crypto-js has no GCM/AEAD support at all, which
//   is exactly why AES doesn't use it.
// - XOR is hand-rolled: a repeating-key XOR has no meaningful "library" question, same reasoning
//   as CRC/Adler-32 in checksum.js.
import { cbc as aesCbc, ctr as aesCtr, ecb as aesEcb, cfb as aesCfb, gcm as aesGcm } from '../vendor/noble-ciphers/aes.js'
import { chacha20 } from '../vendor/noble-ciphers/chacha.js'
import { salsa20 } from '../vendor/noble-ciphers/salsa.js'
import { WordArray, CipherParams, ModeCBC, ModeCTR, ModeECB, ModeCFB, ModeOFB, PadPkcs7, PadNoPadding, DES, TripleDES, RC4 } from '../vendor/crypto-js.module.js'

function bytesFromWordArray(wordArray) {
    const { words, sigBytes } = wordArray
    const bytes = new Uint8Array(sigBytes)
    for (let i = 0; i < sigBytes; i++) {
        bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff
    }
    return bytes
}

// Key/IV/nonce/AAD fields are plain hex-digit-pair strings — byte strings, not single integer
// constants, so the Basic category's hex-decode convention fits better than checksum.js's
// 0x-or-decimal one for poly/init/xorout. An optional leading "0x"/"0X" is stripped and ignored
// if present (consistent with checksum.js's parseUintField also treating it as optional), but
// unlike that helper there's no decimal fallback to worry about here — these fields are always
// hex, so a bare "c10fd7ae" with no prefix at all is accepted directly too. `validLengths` (array
// of acceptable byte counts), when given, is enforced here; when omitted, the underlying library
// (noble-ciphers) does its own length validation with an equally clear error message, so there's
// no need to duplicate it for AES/Salsa20/ChaCha20 — only the crypto-js-backed ciphers
// (DES/TripleDES), which are far less strict internally, need it enforced here.
function parseHexBytes(text, label, validLengths) {
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

// AAD is the one optional hex field in this module (empty = no additional authenticated data,
// the overwhelmingly common case) — parseHexBytes() alone would reject empty input.
function parseOptionalHexBytes(text) {
    const cleaned = String(text ?? '').trim()
    return cleaned === '' ? new Uint8Array(0) : parseHexBytes(cleaned, 'AAD')
}

const MODE_OPTIONS_AES = [
    { value: 'cbc', label: 'CBC' },
    { value: 'ctr', label: 'CTR' },
    { value: 'gcm', label: 'GCM' },
    { value: 'ecb', label: 'ECB' },
    { value: 'cfb', label: 'CFB' },
    { value: 'ofb', label: 'OFB' },
]
const MODE_OPTIONS_BLOCK = [
    { value: 'cbc', label: 'CBC' },
    { value: 'ctr', label: 'CTR' },
    { value: 'ecb', label: 'ECB' },
    { value: 'cfb', label: 'CFB' },
    { value: 'ofb', label: 'OFB' },
]
// Modes needing an IV/counter block vs. not (ECB has none; GCM uses a separate `nonce` field).
const AES_MODES_WITH_IV = new Set(['cbc', 'ctr', 'cfb', 'ofb'])
// Modes that operate on whole blocks and therefore need a padding scheme; CTR/CFB/OFB/GCM are all
// stream-like constructions operating on exact input length, with nothing to pad.
const MODES_NEEDING_PADDING = new Set(['cbc', 'ecb'])
const PADDING_OPTIONS = [
    { value: 'pkcs7', label: 'PKCS7' },
    { value: 'none', label: 'No padding' },
]

// row/rowLabel/inHeader/wide/showIf are the generic param-model hooks built for checksum.js's
// CRC variant/Custom design — reused here unchanged; no TransformPanel.js changes were needed
// for this module at all.
const AES_PARAMS = [
    { key: 'mode', label: 'Mode', type: 'select', default: 'cbc', inHeader: true, options: MODE_OPTIONS_AES },
    { key: 'key', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'key', rowLabel: 'Key' },
    { key: 'iv', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'iv', rowLabel: 'IV',
      showIf: params => AES_MODES_WITH_IV.has(params.mode) },
    { key: 'nonce', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'nonce', rowLabel: 'Nonce',
      showIf: params => params.mode === 'gcm' },
    { key: 'padding', label: 'Padding', type: 'select', default: 'pkcs7', options: PADDING_OPTIONS,
      row: 'padding', rowLabel: 'Padding', showIf: params => MODES_NEEDING_PADDING.has(params.mode) },
    { key: 'aad', label: 'Hex bytes, optional', type: 'text', default: '', wide: true, row: 'aad', rowLabel: 'AAD',
      showIf: params => params.mode === 'gcm' },
]

const BLOCK_CIPHER_PARAMS = [
    { key: 'mode', label: 'Mode', type: 'select', default: 'cbc', inHeader: true, options: MODE_OPTIONS_BLOCK },
    { key: 'key', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'key', rowLabel: 'Key' },
    { key: 'iv', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'iv', rowLabel: 'IV',
      showIf: params => params.mode !== 'ecb' },
    { key: 'padding', label: 'Padding', type: 'select', default: 'pkcs7', options: PADDING_OPTIONS,
      row: 'padding', rowLabel: 'Padding', showIf: params => MODES_NEEDING_PADDING.has(params.mode) },
]

const KEY_ONLY_PARAMS = [
    { key: 'key', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'key', rowLabel: 'Key' },
]

const KEY_NONCE_PARAMS = [
    { key: 'key', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'key', rowLabel: 'Key' },
    { key: 'nonce', label: 'Hex bytes', type: 'text', default: '', wide: true, row: 'nonce', rowLabel: 'Nonce' },
]

// @noble/ciphers has no OFB export at all (only ctr/ecb/cbc/cfb/gcm/... — confirmed by grepping
// its source, not assumed) — hand-rolled here as the standard NIST SP 800-38A construction
// (keystream_0 = E(IV), keystream_i = E(keystream_{i-1}), ciphertext = plaintext XOR keystream),
// built entirely on noble's own already-audited ECB block encryption (`disablePadding: true`
// processes one exact 16-byte block at a time with no padding invention of our own) — no
// cryptographic design here, just orchestrating a trusted primitive in a well-known way, same
// spirit as the hand-rolled CRC/XOR ops. Self-inverse like CTR (the keystream depends only on
// key+IV, never on plaintext/ciphertext), so one function serves both directions. Cross-checked
// against Node's `aes-*-ofb` in encryption.test.js.
function aesOfbTransform(bytes, key, iv) {
    const blockSize = 16
    const numBlocks = Math.ceil(bytes.length / blockSize)
    const keystream = new Uint8Array(numBlocks * blockSize)
    let block = iv
    for (let i = 0; i < numBlocks; i++) {
        // Every noble-ciphers cipher instance is deliberately single-use (calling .encrypt()
        // twice on the same instance throws, as a guard against accidental key/nonce reuse) — so
        // a fresh instance is constructed per block rather than reusing one across the loop.
        block = aesEcb(key, { disablePadding: true }).encrypt(block)
        keystream.set(block, i * blockSize)
    }
    const out = new Uint8Array(bytes.length)
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ keystream[i]
    return out
}

function resolveAesCipher(params) {
    const key = parseHexBytes(params.key, 'Key')
    if (params.mode === 'cbc') {
        return aesCbc(key, parseHexBytes(params.iv, 'IV'), { disablePadding: params.padding === 'none' })
    }
    if (params.mode === 'ctr') {
        return aesCtr(key, parseHexBytes(params.iv, 'IV'))
    }
    if (params.mode === 'ecb') {
        return aesEcb(key, { disablePadding: params.padding === 'none' })
    }
    if (params.mode === 'cfb') {
        return aesCfb(key, parseHexBytes(params.iv, 'IV'))
    }
    if (params.mode === 'gcm') {
        return aesGcm(key, parseHexBytes(params.nonce, 'Nonce'), parseOptionalHexBytes(params.aad))
    }
    throw new Error(`unknown AES mode "${params.mode}"`)
}

function aesEncrypt(bytes, params) {
    if (params.mode === 'ofb') {
        return aesOfbTransform(bytes, parseHexBytes(params.key, 'Key'), parseHexBytes(params.iv, 'IV'))
    }
    return resolveAesCipher(params).encrypt(bytes)
}

function aesDecrypt(bytes, params) {
    if (params.mode === 'ofb') {
        return aesOfbTransform(bytes, parseHexBytes(params.key, 'Key'), parseHexBytes(params.iv, 'IV'))
    }
    try {
        return resolveAesCipher(params).decrypt(bytes)
    } catch (err) {
        if (params.mode === 'gcm' && /invalid ghash tag/.test(err.message)) {
            throw new Error('AES-GCM authentication failed: ciphertext/tag does not match the given key, nonce, or AAD')
        }
        throw err
    }
}

const BLOCK_CIPHER_MODE_MAP = { cbc: ModeCBC, ctr: ModeCTR, ecb: ModeECB, cfb: ModeCFB, ofb: ModeOFB }

// CTR/CFB/OFB are stream-like modes and must never be padded — crypto-js's
// BlockCipher._doFinalize applies cfg.padding unconditionally, it doesn't special-case any of
// them, so leaving the (hidden, CBC/ECB-only) padding param's leftover value in place would
// silently pad their output. ECB needs no IV at all (crypto-js's mode creator simply never reads
// `cfg.iv` when unset), so it's the one mode that skips parsing/requiring one.
function resolveBlockCipherConfig(params, keyValidLengths) {
    const key = WordArray.create(parseHexBytes(params.key, 'Key', keyValidLengths))
    const mode = BLOCK_CIPHER_MODE_MAP[params.mode]
    if (!mode) throw new Error(`unknown mode "${params.mode}"`)
    const padding = MODES_NEEDING_PADDING.has(params.mode) ? (params.padding === 'none' ? PadNoPadding : PadPkcs7) : PadNoPadding
    const cfg = { mode, padding }
    if (params.mode !== 'ecb') {
        cfg.iv = WordArray.create(parseHexBytes(params.iv, 'IV', [8]))
    }
    return { key, cfg }
}

function makeBlockCipherOps(algo, keyValidLengths) {
    return {
        encrypt(bytes, params) {
            const { key, cfg } = resolveBlockCipherConfig(params, keyValidLengths)
            return bytesFromWordArray(algo.encrypt(WordArray.create(bytes), key, cfg).ciphertext)
        },
        decrypt(bytes, params) {
            const { key, cfg } = resolveBlockCipherConfig(params, keyValidLengths)
            const wrapped = CipherParams.create({ ciphertext: WordArray.create(bytes) })
            return bytesFromWordArray(algo.decrypt(wrapped, key, cfg))
        },
    }
}

// DES requires an 8-byte key; TripleDES accepts 16 (2-key EDE2) or 24 (3-key EDE3) — the
// degenerate 8-byte "3DES" crypto-js itself still accepts is deliberately not offered here since
// it's never actually keyed with 3 distinct DES keys.
const desOps = makeBlockCipherOps(DES, [8])
const tripledesOps = makeBlockCipherOps(TripleDES, [16, 24])

function rc4Encrypt(bytes, params) {
    const key = WordArray.create(parseHexBytes(params.key, 'Key'))
    return bytesFromWordArray(RC4.encrypt(WordArray.create(bytes), key).ciphertext)
}

function rc4Decrypt(bytes, params) {
    const key = WordArray.create(parseHexBytes(params.key, 'Key'))
    return bytesFromWordArray(RC4.decrypt(CipherParams.create({ ciphertext: WordArray.create(bytes) }), key))
}

// Salsa20/ChaCha20 are XOR-keystream stream ciphers, hence self-inverse — encrypt and decrypt are
// literally the same function applied to plaintext or ciphertext respectively, matching noble's
// own single-call API (no separate .encrypt()/.decrypt() methods to call here).
function salsa20Transform(bytes, params) {
    return salsa20(parseHexBytes(params.key, 'Key'), parseHexBytes(params.nonce, 'Nonce'), bytes)
}

// RFC 8439 ChaCha20 specifically (32-byte key, 12-byte nonce, 4-byte counter) — not the original
// 8-byte-nonce DJB variant (noble's separate `chacha20orig` export).
function chacha20Transform(bytes, params) {
    return chacha20(parseHexBytes(params.key, 'Key'), parseHexBytes(params.nonce, 'Nonce'), bytes)
}

// Repeating-key XOR — also self-inverse, hand-rolled (see module header comment).
function xorTransform(bytes, params) {
    const key = parseHexBytes(params.key, 'Key')
    const out = new Uint8Array(bytes.length)
    for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length]
    return out
}

export const OPERATIONS = {
    'aes-encrypt': { label: 'AES', params: AES_PARAMS, run: aesEncrypt },
    'aes-decrypt': { label: 'AES', params: AES_PARAMS, run: aesDecrypt },
    'des-encrypt': { label: 'DES', params: BLOCK_CIPHER_PARAMS, run: desOps.encrypt },
    'des-decrypt': { label: 'DES', params: BLOCK_CIPHER_PARAMS, run: desOps.decrypt },
    '3des-encrypt': { label: '3DES', params: BLOCK_CIPHER_PARAMS, run: tripledesOps.encrypt },
    '3des-decrypt': { label: '3DES', params: BLOCK_CIPHER_PARAMS, run: tripledesOps.decrypt },
    'rc4-encrypt': { label: 'RC4', params: KEY_ONLY_PARAMS, run: rc4Encrypt },
    'rc4-decrypt': { label: 'RC4', params: KEY_ONLY_PARAMS, run: rc4Decrypt },
    'salsa20-encrypt': { label: 'Salsa20', params: KEY_NONCE_PARAMS, run: salsa20Transform },
    'salsa20-decrypt': { label: 'Salsa20', params: KEY_NONCE_PARAMS, run: salsa20Transform },
    'chacha20-encrypt': { label: 'ChaCha20', params: KEY_NONCE_PARAMS, run: chacha20Transform },
    'chacha20-decrypt': { label: 'ChaCha20', params: KEY_NONCE_PARAMS, run: chacha20Transform },
    'xor-encrypt': { label: 'XOR', params: KEY_ONLY_PARAMS, run: xorTransform },
    'xor-decrypt': { label: 'XOR', params: KEY_ONLY_PARAMS, run: xorTransform },
}

export const ENCRYPT_ALGORITHMS = [
    { label: 'AES', op: 'aes-encrypt' }, { label: 'DES', op: 'des-encrypt' }, { label: '3DES', op: '3des-encrypt' },
    { label: 'RC4', op: 'rc4-encrypt' }, { label: 'Salsa20', op: 'salsa20-encrypt' },
    { label: 'ChaCha20', op: 'chacha20-encrypt' }, { label: 'XOR', op: 'xor-encrypt' },
]

export const DECRYPT_ALGORITHMS = [
    { label: 'AES', op: 'aes-decrypt' }, { label: 'DES', op: 'des-decrypt' }, { label: '3DES', op: '3des-decrypt' },
    { label: 'RC4', op: 'rc4-decrypt' }, { label: 'Salsa20', op: 'salsa20-decrypt' },
    { label: 'ChaCha20', op: 'chacha20-decrypt' }, { label: 'XOR', op: 'xor-decrypt' },
]
