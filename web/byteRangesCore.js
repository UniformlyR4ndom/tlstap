import { encodeSignedLength } from './direction.js'

// Pure wire-format encode/decode for /byte-ranges — split out from api.js specifically
// so it stays unit-testable with Node's plain test runner, the same reason
// byteBufferCore.js/frameSegmentsCore.js are kept framework-free. See
// intercept/dbdump/CLAUDE.md's "POST /byte-ranges" section for the full wire-format
// rationale (bounds, the sign-encodes-direction trick, why a short/zero read is valid,
// never an error).

// ranges: [{offset, direction, length}] -> ArrayBuffer, ranges.length * 16 bytes: one
// (offset int64 BE, signedLength int64 BE) entry per range, in order. No validation here
// — this is a pure wire encoder; api.js's fetchByteRanges is the one caller, always
// building ranges from already-valid candidate metadata.
export function encodeByteRangesRequest(ranges) {
    const buf = new ArrayBuffer(ranges.length * 16)
    const view = new DataView(buf)
    ranges.forEach((r, j) => {
        view.setBigInt64(j * 16, BigInt(r.offset), false)
        view.setBigInt64(j * 16 + 8, BigInt(encodeSignedLength(r.direction, r.length)), false)
    })
    return buf
}

// Parses count length-prefixed entries out of a /byte-ranges binary response into
// zero-copy Uint8Array views into buffer, in wire order (one per requested range). Each
// entry's length may be less than what was requested for it (a short/zero read is valid,
// signaled purely by this — see the CLAUDE.md section above) — this function just parses
// whatever length each entry actually declares.
export function decodeByteRangesResponse(buffer, count) {
    const view = new DataView(buffer)
    const out = []
    let pos = 0
    for (let j = 0; j < count; j++) {
        const length = Number(view.getBigInt64(pos, false))
        pos += 8
        out.push(new Uint8Array(buffer, pos, length))
        pos += length
    }
    return out
}
