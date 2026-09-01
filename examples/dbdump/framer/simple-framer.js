// Simple length-prefixed framer template — covers a large class of length-prefixed
// protocols by editing the CONFIG constants below, without writing frame(state, chunk)
// from scratch. Copy this file, rename it, and adjust CONFIG for your protocol; the
// framing loop underneath doesn't need to change.
//
// The emitted frame always spans from where scanning started, i.e. it includes the
// header — trim a known header back out of the range yourself below if you'd rather the
// frame view show only the payload (see length-prefix-framer.js for that convention).

// ── CONFIG — edit these for your protocol ──
const LENGTH_OFFSET = 0            // byte offset of the length field, relative to frame start
const LENGTH_SIZE = 4              // byte width of the length field: 1, 2, 4, or 8
const LENGTH_ENDIANNESS = 'le'     // 'be' | 'le'
const LENGTH_ADJUST = LENGTH_SIZE  // added to the decoded length to get the frame's total size:
                                    // 0 if the length already counts the whole frame; the header's
                                    // size if it counts only the payload (as here, since this
                                    // example's header is just the length field itself)
const MAX_FRAME_SIZE = 16 * 1024 * 1024 // sanity cap: throw instead of buffering forever on a
                                         // garbage/misaligned length

// Derived, don't edit
const LENGTH_FIELD_END = LENGTH_OFFSET + LENGTH_SIZE // byte offset immediately after the length field

function frame(state, chunk) {
    // Combined mode runs one script instance across both directions (see
    // doc/design/framer-cross-direction-correlation.md), so state carries two
    // independent sub-states — state.c2s/state.s2c — one per direction; only the
    // current call's own chunk.direction sub-state is ever read or written.
    const sub = (state && state[chunk.direction]) || {}
    // sub.carry holds whatever tail bytes didn't yet form a complete frame last time
    const carry = sub.carry || new Uint8Array(0)

    const buf = new Uint8Array(carry.length + chunk.data.length)
    buf.set(carry, 0)
    buf.set(chunk.data, carry.length)

    // chunk.offset is where chunk.data starts in the stream; carry's bytes came
    // immediately before that, so buf[0] sits at (chunk.offset - carry.length).
    const bufBaseOffset = chunk.offset - carry.length

    // framer.* isn't available at script load time (only once frame() is actually
    // called — see web/CLAUDE.md's "Framer scripts" section), so this lookup has to
    // happen in here rather than alongside CONFIG above.
    const LENGTH_DECODERS = {
        1: framer.number.decodeU8,
        2: LENGTH_ENDIANNESS === 'le' ? framer.number.decodeU16le : framer.number.decodeU16be,
        4: LENGTH_ENDIANNESS === 'le' ? framer.number.decodeU32le : framer.number.decodeU32be,
        8: LENGTH_ENDIANNESS === 'le' ? framer.number.decodeU64le : framer.number.decodeU64be,
    }
    const decodeLength = LENGTH_DECODERS[LENGTH_SIZE]
    if (!decodeLength) throw new Error(`LENGTH_SIZE must be 1, 2, 4, or 8 (got ${LENGTH_SIZE})`)

    const frames = []
    let pos = 0
    while (buf.length - pos >= LENGTH_FIELD_END) {
        const rawLength = decodeLength(buf.subarray(pos + LENGTH_OFFSET, pos + LENGTH_FIELD_END))
        // rawLength is a BigInt when LENGTH_SIZE is 8 (decodeU64be/le), so the addition
        // has to happen in BigInt domain too, then convert back down.
        const totalFrameSize = LENGTH_SIZE === 8 ? Number(rawLength + BigInt(LENGTH_ADJUST)) : rawLength + LENGTH_ADJUST

        if (totalFrameSize > MAX_FRAME_SIZE || totalFrameSize < LENGTH_FIELD_END) {
            const headerHex = framer.encode.hex(buf.subarray(pos, pos + LENGTH_FIELD_END))
            throw new Error(`implausible frame length ${totalFrameSize} (header bytes ${headerHex}) at offset ${bufBaseOffset + pos} — probably misaligned, not a real frame boundary`)
        }
        if (buf.length - pos < totalFrameSize) break // frame not fully arrived yet

        frames.push({
            ranges: [{ offset: bufBaseOffset + pos, length: totalFrameSize }],
            meta: { declaredLength: LENGTH_SIZE === 8 ? Number(rawLength) : rawLength },
        })
        pos += totalFrameSize
    }

    return {
        frames,
        // .slice(), not .subarray(): a view would keep the whole (possibly much larger)
        // accumulated buf alive in memory for as long as this carry is held.
        state: { ...state, [chunk.direction]: { carry: buf.slice(pos) } },
    }
}
