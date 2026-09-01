// HTTP/2 frame-layer framer — splits a stream into individual HTTP/2 frames using the
// fixed 9-byte header (RFC 9113 §4.1: 24-bit length, 8-bit type, 8-bit flags, 31-bit
// stream id) that precedes every frame's payload. Framing itself needs nothing beyond
// that length field — HTTP/2 has no ambiguous or connection-close-delimited lengths the
// way HTTP/1 does — so the interesting part here is reassembling HEADERS/PUSH_PROMISE/
// CONTINUATION frames into complete field blocks and decoding them via framer.hpack
// (decode-only HPACK, see web/CLAUDE.md's "Framer scripts" section), attaching the
// result to whichever frame completes the block.
//
// The client's one-time, 24-byte connection preface (RFC 9113 §3.4) is detected and
// emitted as its own pseudo-frame on the c2s direction only; the server side has no such
// fixed byte sequence (just an ordinary — possibly empty — SETTINGS frame).

const HEADER_LEN = 9

const TYPE_HEADERS = 0x01
const TYPE_PUSH_PROMISE = 0x05
const TYPE_CONTINUATION = 0x09

const TYPE_NAMES = {
    0x00: 'DATA',
    0x01: 'HEADERS',
    0x02: 'PRIORITY',
    0x03: 'RST_STREAM',
    0x04: 'SETTINGS',
    0x05: 'PUSH_PROMISE',
    0x06: 'PING',
    0x07: 'GOAWAY',
    0x08: 'WINDOW_UPDATE',
    0x09: 'CONTINUATION',
}

// Flag bits shared by HEADERS/PUSH_PROMISE/CONTINUATION at the same positions wherever
// each applies — see extractFieldBlockFragment below for which fields exist on which type.
const FLAG_END_HEADERS = 0x04
const FLAG_PADDED = 0x08
const FLAG_PRIORITY = 0x20 // HEADERS only

// RFC 9113 §3.4 — the client connection preface, byte for byte: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".
const PREFACE = new Uint8Array([
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30,
    0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a,
])

// No 24-bit decoder exists among framer.number.*'s 8/16/32/64-bit types.
function decodeLength24(buf, pos) {
    return (buf[pos] << 16) | (buf[pos + 1] << 8) | buf[pos + 2]
}

// Field block fragment location within a HEADERS/PUSH_PROMISE frame's payload — RFC 9113
// §6.2/§6.6. Never called for CONTINUATION (§6.10), whose entire payload is fragment; it
// has no PADDED/PRIORITY fields of its own at all.
function extractFieldBlockFragment(type, flags, payload) {
    let pos = 0
    let padLen = 0
    if (flags & FLAG_PADDED) {
        padLen = payload[0]
        pos = 1
    }
    if (type === TYPE_HEADERS && (flags & FLAG_PRIORITY)) {
        pos += 5 // Exclusive(1 bit) + Stream Dependency(31 bit) + Weight(8 bit)
    }
    if (type === TYPE_PUSH_PROMISE) {
        pos += 4 // Reserved(1 bit) + Promised Stream ID(31 bit)
    }
    const end = payload.length - padLen
    if (end < pos) {
        throw new Error(`http2: PADDED length ${padLen} leaves no room for the field block fragment`)
    }
    return payload.subarray(pos, end)
}

function mergeFragments(fragments) {
    const total = fragments.reduce((n, f) => n + f.length, 0)
    const merged = new Uint8Array(total)
    let off = 0
    for (const f of fragments) {
        merged.set(f, off)
        off += f.length
    }
    return merged
}

function frame(state, chunk) {
    // Combined mode runs one script instance across both directions (see
    // doc/design/framer-cross-direction-correlation.md), so state carries two
    // independent sub-states — state.c2s/state.s2c — one per direction, since neither
    // the connection preface nor HPACK's dynamic table are shared across directions;
    // only the current call's own chunk.direction sub-state is ever read or written.
    const sub = (state && state[chunk.direction]) || {}
    const carry = sub.carry || new Uint8Array(0)
    let prefaceChecked = !!sub.prefaceChecked
    let hpackTable = sub.hpackTable
    let hpackDecodeDisabled = !!sub.hpackDecodeDisabled
    // headerBlock: null, or { streamId, fragments: [Uint8Array, ...] } — a field block
    // currently being reassembled across a HEADERS/PUSH_PROMISE frame and zero or more
    // CONTINUATION frames. At most one at a time per direction: RFC 9113 §6.2/§6.10
    // forbid any other frame (any type, any stream) appearing before the sequence's
    // END_HEADERS frame, so there's never a second one to track concurrently.
    let headerBlock = sub.headerBlock || null

    const buf = new Uint8Array(carry.length + chunk.data.length)
    buf.set(carry, 0)
    buf.set(chunk.data, carry.length)
    const bufBaseOffset = chunk.offset - carry.length

    const frames = []
    let pos = 0

    if (!prefaceChecked) {
        if (chunk.direction === 'c2s') {
            if (buf.length >= PREFACE.length) {
                prefaceChecked = true
                let matches = true
                for (let i = 0; i < PREFACE.length; i++) {
                    if (buf[i] !== PREFACE[i]) { matches = false; break }
                }
                if (matches) {
                    frames.push({ ranges: [{ offset: bufBaseOffset, length: PREFACE.length }], meta: { kind: 'http2-preface' } })
                    pos = PREFACE.length
                }
                // else: capture starts mid-connection (the real preface predates it) —
                // leave the buffer untouched and let the normal frame loop handle it.
            }
            // else: not enough data yet to decide — leave prefaceChecked false and try
            // again next call.
        } else {
            // The server side has no fixed preface byte sequence to look for (RFC 9113
            // §3.4) — just an ordinary (possibly empty) SETTINGS frame, handled by the
            // normal loop below.
            prefaceChecked = true
        }
    }

    while (buf.length - pos >= HEADER_LEN) {
        const length = decodeLength24(buf, pos)
        if (buf.length - pos < HEADER_LEN + length) break // frame not fully arrived yet

        const type = buf[pos + 3]
        const flags = buf[pos + 4]
        const streamId = framer.number.decodeU32be(buf.subarray(pos + 5, pos + 9)) & 0x7fffffff
        const payload = buf.subarray(pos + HEADER_LEN, pos + HEADER_LEN + length)
        const typeName = TYPE_NAMES[type] ?? `unknown(${type})`

        const meta = { kind: 'http2-frame', type, typeName, flags, streamId, payloadLength: length }

        if (type === TYPE_HEADERS || type === TYPE_PUSH_PROMISE || type === TYPE_CONTINUATION) {
            if (type === TYPE_CONTINUATION) {
                if (!headerBlock) {
                    throw new Error(`http2: CONTINUATION frame on stream ${streamId} without a preceding HEADERS/PUSH_PROMISE`)
                }
                if (streamId !== headerBlock.streamId) {
                    throw new Error(`http2: CONTINUATION frame on stream ${streamId}, expected stream ${headerBlock.streamId} (RFC 9113 §6.10)`)
                }
                // .slice(), not the subarray payload itself: fragments live in state,
                // possibly across many frame() calls — a view would keep the whole
                // (much larger, and eventually stale) buf alive for as long as it's held.
                headerBlock.fragments.push(payload.slice())
            } else {
                if (headerBlock) {
                    throw new Error(`http2: ${typeName} frame on stream ${streamId} while stream ${headerBlock.streamId}'s field block is still open (RFC 9113 §6.2/§6.6)`)
                }
                headerBlock = { streamId, fragments: [extractFieldBlockFragment(type, flags, payload).slice()] }
            }

            if (flags & FLAG_END_HEADERS) {
                if (!hpackDecodeDisabled) {
                    try {
                        const decoded = framer.hpack.decode(mergeFragments(headerBlock.fragments), hpackTable)
                        meta.headers = decoded.headers
                        hpackTable = decoded.table
                    } catch (e) {
                        // Not fatal to framing — very plausible on a capture that starts
                        // mid-connection, missing whatever the peer's dynamic table
                        // already held. Latched off rather than retried: once desynced,
                        // every later block would fail the same way.
                        framer.log(`HPACK decode failed, disabling header decoding for this direction: ${e.message}`)
                        hpackDecodeDisabled = true
                    }
                }
                headerBlock = null
            }
        } else if (headerBlock) {
            throw new Error(`http2: ${typeName} frame on stream ${streamId} while stream ${headerBlock.streamId}'s field block is still open (RFC 9113 §6.2/§6.10)`)
        }
        // chunk.closed is deliberately never consulted here — every HTTP/2 frame is
        // self-delimited by its own explicit length field, unlike (for example) an
        // HTTP/1 response relying on connection close.

        frames.push({ ranges: [{ offset: bufBaseOffset + pos, length: HEADER_LEN + length }], meta })
        pos += HEADER_LEN + length
    }

    return {
        frames,
        state: {
            ...state,
            [chunk.direction]: {
                // .slice(), not .subarray(): a view would keep the whole (possibly much
                // larger) accumulated buf alive in memory for as long as this carry is held.
                carry: buf.slice(pos), prefaceChecked, hpackTable, hpackDecodeDisabled, headerBlock,
            },
        },
    }
}
