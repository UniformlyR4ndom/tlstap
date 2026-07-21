// SHA1/SHA224/SHA256/SHA384/SHA512/MD5 come from the vendored crypto-js (see
// ../vendor/crypto-js.module.js for why it needs bundling). MD2, MD4 and NTLM (which is just
// MD4 of a UTF-16LE-encoded input) have no such well-established library backing them, so
// they're hand-rolled here directly from their RFCs (1319, 1320) instead. Whirlpool (which
// crypto-js doesn't support either) comes from the vendored hash-wasm instead of being
// hand-rolled — see ../vendor/hash-wasm-whirlpool.module.js for why.
import { WordArray, MD5, SHA1, SHA224, SHA256, SHA384, SHA512 } from '../vendor/crypto-js.module.js'
import { createWhirlpool } from '../vendor/hash-wasm-whirlpool.module.js'
import { bytesFromWordArray, fmtAsRaw } from '../format.js'

function cryptoJsHash(hasher, bytes) {
    return bytesFromWordArray(hasher(WordArray.create(bytes)))
}

// createWhirlpool() (unlike hash-wasm's plain whirlpool() convenience function — see
// ../vendor/hash-wasm-whirlpool.module.js) returns a reusable IHasher whose init()/update()/
// digest() are synchronous once the WASM module has been compiled+instantiated. That
// compilation is the only actually-async part, so it's paid once (memoized here) rather than on
// every call: warmupWhirlpool() lets a caller (scriptRuntime.js's Worker bootstrap, for one —
// see its header comment) force that one-time cost up front, so every whirlpool() call from then
// on is genuinely synchronous instead of returning a Promise. Without an explicit warmup, the
// first call anywhere in this JS realm still pays it lazily and returns a Promise; every call
// after that (in that same realm) is sync.
let whirlpoolHasher = null
let whirlpoolHasherPromise = null

export function warmupWhirlpool() {
    if (!whirlpoolHasherPromise) {
        whirlpoolHasherPromise = createWhirlpool().then(h => { whirlpoolHasher = h; return h })
    }
    return whirlpoolHasherPromise
}

function whirlpoolDigest(bytes) {
    whirlpoolHasher.init()
    whirlpoolHasher.update(bytes)
    return whirlpoolHasher.digest('binary')
}

function whirlpool(bytes) {
    return whirlpoolHasher ? whirlpoolDigest(bytes) : warmupWhirlpool().then(() => whirlpoolDigest(bytes))
}

// Permutation of pi's digits, per RFC 1319 Appendix A.
const MD2_SBOX = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199, 115, 140,
    152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
    190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
    148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
    255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182,
    118, 252, 107, 226, 156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
    27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81, 175, 58,
    195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
    106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109,
    233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
    49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
]

// RFC 1319: pad with n bytes of value n (n = 16 - len%16; a full 16 bytes of value 16 when the
// message is already block-aligned), append a 16-byte checksum block, then run 18 rounds of
// S-box substitution over a 48-byte state per 16-byte block.
function md2(bytes) {
    const padValue = 16 - (bytes.length % 16)
    const padded = new Uint8Array(bytes.length + padValue)
    padded.set(bytes)
    padded.fill(padValue, bytes.length)

    const checksum = new Uint8Array(16)
    let last = 0
    for (let i = 0; i < padded.length; i += 16) {
        for (let j = 0; j < 16; j++) {
            const c = padded[i + j]
            checksum[j] ^= MD2_SBOX[c ^ last]
            last = checksum[j]
        }
    }

    const message = new Uint8Array(padded.length + 16)
    message.set(padded)
    message.set(checksum, padded.length)

    const state = new Uint8Array(48)
    for (let i = 0; i < message.length; i += 16) {
        for (let j = 0; j < 16; j++) {
            state[16 + j] = message[i + j]
            state[32 + j] = state[16 + j] ^ state[j]
        }
        let t = 0
        for (let round = 0; round < 18; round++) {
            for (let k = 0; k < 48; k++) {
                state[k] ^= MD2_SBOX[t]
                t = state[k]
            }
            t = (t + round) & 0xff
        }
    }

    return state.slice(0, 16)
}

function leftRotate32(x, s) {
    return ((x << s) | (x >>> (32 - s))) >>> 0
}

// RFC 1320 padding: 0x80, zero bytes up to 56 mod 64, then the message length in bits as a
// 64-bit little-endian integer (shared by MD4; MD5/SHA* padding is handled inside crypto-js).
function md4Pad(bytes) {
    const bitLen = BigInt(bytes.length) * 8n
    const padLen = ((56 - ((bytes.length + 1) % 64)) + 64) % 64
    const padded = new Uint8Array(bytes.length + 1 + padLen + 8)
    padded.set(bytes)
    padded[bytes.length] = 0x80
    new DataView(padded.buffer).setBigUint64(padded.length - 8, bitLen, true)
    return padded
}

// RFC 1320 round message-index/shift tables and function definitions.
function md4(bytes) {
    const padded = md4Pad(bytes)
    const view = new DataView(padded.buffer)

    const F = (x, y, z) => (x & y) | (~x & z)
    const G = (x, y, z) => (x & y) | (x & z) | (y & z)
    const H = (x, y, z) => x ^ y ^ z
    const S1 = [3, 7, 11, 19], S2 = [3, 5, 9, 13], S3 = [3, 9, 11, 15]

    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476

    for (let chunk = 0; chunk < padded.length; chunk += 64) {
        const M = []
        for (let i = 0; i < 16; i++) M.push(view.getUint32(chunk + i * 4, true))

        let a = a0, b = b0, c = c0, d = d0
        function op(fn, a, b, c, d, k, s, ac) {
            return leftRotate32((a + fn(b, c, d) + M[k] + ac) >>> 0, s)
        }

        const round1 = [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        for (const [k0, k1, k2, k3] of round1) {
            a = op(F, a, b, c, d, k0, S1[0], 0); d = op(F, d, a, b, c, k1, S1[1], 0)
            c = op(F, c, d, a, b, k2, S1[2], 0); b = op(F, b, c, d, a, k3, S1[3], 0)
        }
        const round2 = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]]
        for (const [k0, k1, k2, k3] of round2) {
            a = op(G, a, b, c, d, k0, S2[0], 0x5A827999); d = op(G, d, a, b, c, k1, S2[1], 0x5A827999)
            c = op(G, c, d, a, b, k2, S2[2], 0x5A827999); b = op(G, b, c, d, a, k3, S2[3], 0x5A827999)
        }
        const round3 = [[0, 8, 4, 12], [2, 10, 6, 14], [1, 9, 5, 13], [3, 11, 7, 15]]
        for (const [k0, k1, k2, k3] of round3) {
            a = op(H, a, b, c, d, k0, S3[0], 0x6ED9EBA1); d = op(H, d, a, b, c, k1, S3[1], 0x6ED9EBA1)
            c = op(H, c, d, a, b, k2, S3[2], 0x6ED9EBA1); b = op(H, b, c, d, a, k3, S3[3], 0x6ED9EBA1)
        }

        a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0
    }

    const out = new Uint8Array(16)
    const outView = new DataView(out.buffer)
    outView.setUint32(0, a0, true); outView.setUint32(4, b0, true)
    outView.setUint32(8, c0, true); outView.setUint32(12, d0, true)
    return out
}

// NTLM hash = MD4(UTF-16LE(password)). Input bytes are treated as UTF-8 text (consistent with
// SearchPanel.js's utf16le format) and re-encoded before hashing.
function ntlm(bytes) {
    const text = fmtAsRaw(bytes)
    const utf16le = new Uint8Array(text.length * 2)
    const view = new DataView(utf16le.buffer)
    for (let i = 0; i < text.length; i++) view.setUint16(i * 2, text.charCodeAt(i), true)
    return md4(utf16le)
}

export const OPERATIONS = {
    md2: { label: 'MD2', run: md2 },
    md4: { label: 'MD4', run: md4 },
    ntlm: { label: 'NTLM', run: ntlm },
    md5: { label: 'MD5', run: bytes => cryptoJsHash(MD5, bytes) },
    sha1: { label: 'SHA1', run: bytes => cryptoJsHash(SHA1, bytes) },
    sha224: { label: 'SHA224', run: bytes => cryptoJsHash(SHA224, bytes) },
    sha256: { label: 'SHA256', run: bytes => cryptoJsHash(SHA256, bytes) },
    sha384: { label: 'SHA384', run: bytes => cryptoJsHash(SHA384, bytes) },
    sha512: { label: 'SHA512', run: bytes => cryptoJsHash(SHA512, bytes) },
    whirlpool: { label: 'Whirlpool', run: whirlpool },
}

export const HASH_ALGORITHMS = [
    { label: 'MD2', op: 'md2' }, { label: 'MD4', op: 'md4' }, { label: 'MD5', op: 'md5' },
    { label: 'NTLM', op: 'ntlm' }, { label: 'SHA1', op: 'sha1' }, { label: 'SHA224', op: 'sha224' },
    { label: 'SHA256', op: 'sha256' }, { label: 'SHA384', op: 'sha384' }, { label: 'SHA512', op: 'sha512' },
    { label: 'Whirlpool', op: 'whirlpool' },
]
