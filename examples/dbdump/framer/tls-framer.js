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

function frame(state, chunk) {
    // Combined mode runs one script instance across both directions (see
    // doc/design/framer-cross-direction-correlation.md), so state carries two
    // independent sub-states — state.c2s/state.s2c — one per direction, since this
    // framer has no need to correlate the two; only the current call's own
    // chunk.direction sub-state is ever read or written.
    const sub = (state && state[chunk.direction]) || {}
    // sub.carry holds whatever tail bytes didn't yet form a complete record last time
    // (undefined on the very first call for this direction) — a plain Uint8Array;
    // dbdumpFramerApi.js base64-encodes it only when state actually crosses the wire.
    const carry = sub.carry || new Uint8Array(0)

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
        const length  = framer.number.decodeU16be(buf.subarray(pos + 3, pos + 5))

        if (length > MAX_FRAGMENT_LENGTH) {
            const headerHex = framer.encode.hex(buf.subarray(pos, pos + HEADER_LEN))
            throw new Error(`implausible TLS record length ${length} (header bytes ${headerHex}) at offset ${bufBaseOffset + pos} — probably misaligned, not a real record boundary`)
        }
        if (buf.length - pos < HEADER_LEN + length) break // record not fully arrived yet

        frames.push({
            ranges: [{ offset: bufBaseOffset + pos, length: HEADER_LEN + length }],
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
        // .slice(), not .subarray(): a view would keep the whole (possibly much larger)
        // accumulated buf alive in memory for as long as this carry is held.
        state: { ...state, [chunk.direction]: { carry: buf.slice(pos) } },
    }
}
