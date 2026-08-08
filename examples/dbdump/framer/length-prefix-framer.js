// Length-prefixed message framer — each message is a 4-byte big-endian uint32 payload
// length, followed by that many bytes of payload (the prefix itself is not part of the
// emitted frame). A common minimal application-framing convention; used here as
// test/bulkclient-cli's -length-prefix companion, e.g. for producing a single frame
// large enough to exercise the byte-budgeted segment buffer (see
// doc/design/hexview-segment-buffer.md).

const HEADER_LEN = 4
const MAX_MESSAGE_LENGTH = 256 * 1024 * 1024 // sanity cap against a misaligned stream

function bytesToBase64(bytes) {
    return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
}

function base64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

function frame(state, chunk) {
    // `state.carry` holds whatever tail bytes didn't yet form a complete message last
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
        const length = ((buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]) >>> 0

        if (length > MAX_MESSAGE_LENGTH) {
            throw new Error(`implausible message length ${length} at offset ${bufBaseOffset + pos} — probably misaligned, not a real message boundary`)
        }
        if (buf.length - pos < HEADER_LEN + length) break // message not fully arrived yet

        frames.push({
            offset: bufBaseOffset + pos + HEADER_LEN,
            length,
            meta: { declaredLength: length },
        })
        pos += HEADER_LEN + length
    }

    return {
        frames,
        state: { carry: bytesToBase64(buf.subarray(pos)) },
    }
}
