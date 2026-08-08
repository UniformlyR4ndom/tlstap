// TLS record-layer framer — splits a stream into individual TLS records using the
// 5-byte header (type: 1 byte, legacy_record_version: 2 bytes, length: uint16
// big-endian) defined in RFC 8446 §5.1 (unchanged from RFC 5246 §6.2.1). Works
// unmodified before *and* after encryption starts — the header is never encrypted;
// only the fragment payload is, once a cipher suite is active, so this framer doesn't
// need to know or care about the handshake state at all.

const MAX_FRAGMENT_LENGTH = 16640 // 2^14 + 256, the largest a TLSCiphertext.fragment may be (5.1)
const HEADER_LEN = 5

const CONTENT_TYPES = {
    20: 'change_cipher_spec',
    21: 'alert',
    22: 'handshake',
    23: 'application_data',
    24: 'heartbeat',
}

function bytesToBase64(bytes) {
    return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
}

function base64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

function frame(state, chunk) {
    // `state.carry` holds whatever tail bytes didn't yet form a complete record last
    // time (undefined on the very first call for this direction).
    const carry = state && state.carry ? base64ToBytes(state.carry) : new Uint8Array(0)

    const buf = new Uint8Array(carry.length + chunk.data.length)
    buf.set(carry, 0)
    buf.set(chunk.data, carry.length)

    // chunk.offset is where chunk.data starts in the stream; carry's bytes came
    // immediately before that, so buf[0] sits at (chunk.offset - carry.length).
    const bufBaseOffset = chunk.offset - carry.length

    const frames = []
    let pos = 0
    while (buf.length - pos >= HEADER_LEN) {
        const type    = buf[pos]
        const verMaj  = buf[pos + 1]
        const verMin  = buf[pos + 2]
        const length  = (buf[pos + 3] << 8) | buf[pos + 4]

        if (length > MAX_FRAGMENT_LENGTH) {
            throw new Error(`implausible TLS record length ${length} at offset ${bufBaseOffset + pos} — probably misaligned, not a real record boundary`)
        }
        if (buf.length - pos < HEADER_LEN + length) break // record not fully arrived yet

        frames.push({
            offset: bufBaseOffset + pos,
            length: HEADER_LEN + length,
            meta: {
                type,
                typeName: CONTENT_TYPES[type] ?? `unknown(${type})`,
                version: `${verMaj}.${verMin}`,
                fragmentLength: length,
            },
        })
        pos += HEADER_LEN + length
    }

    return {
        frames,
        state: { carry: bytesToBase64(buf.subarray(pos)) },
    }
}
