// Length-prefixed message framer — each message is a 4-byte big-endian uint32 payload
// length, followed by that many bytes of payload (the prefix itself is not part of the
// emitted frame). A common minimal application-framing convention; used here as
// test/bulkclient-cli's -length-prefix companion, e.g. for producing a single frame
// large enough to exercise the byte-budgeted segment buffer (see
// doc/design/hexview-segment-buffer.md).

const HEADER_LEN = 4
const MAX_MESSAGE_LENGTH = 256 * 1024 * 1024 // sanity cap against a misaligned stream

function frame(state, chunk) {
    // Combined mode runs one script instance across both directions (see
    // doc/design/framer-cross-direction-correlation.md), so state carries two
    // independent sub-states — state.c2s/state.s2c — one per direction; only the
    // current call's own chunk.direction sub-state is ever read or written.
    const sub = (state && state[chunk.direction]) || {}
    // sub.carry holds whatever tail bytes didn't yet form a complete message last
    // time (undefined on the very first call for this direction) — a plain Uint8Array;
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
        const length = framer.number.decodeU32be(buf.subarray(pos, pos + HEADER_LEN))
        
        if (length > MAX_MESSAGE_LENGTH) {
            const headerHex = framer.encode.hex(buf.subarray(pos, pos + HEADER_LEN))
            throw new Error(`implausible message length ${length} (header bytes ${headerHex}) at offset ${bufBaseOffset + pos} — probably misaligned, not a real message boundary`)
        }
        if (buf.length - pos < HEADER_LEN + length) break // message not fully arrived yet

        framer.log("emitting frame at offset: " + bufBaseOffset + pos + HEADER_LEN)
        frames.push({
            ranges: [{ offset: bufBaseOffset + pos + HEADER_LEN, length }],
            meta: { declaredLength: length },
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
