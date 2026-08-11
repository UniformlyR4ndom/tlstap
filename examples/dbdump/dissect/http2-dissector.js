// HTTP/2 frame dissector — pairs with examples/dbdump/framer/http2-framer.js. Breaks one
// frame down into its RFC 9113 §4.1 fixed 9-byte header fields plus, per frame type, its
// own defined payload structure (§6.1-§6.9) — deliberately going further than
// tls-dissector.js's own "just the shared header" scope, since every HTTP/2 frame type
// turned out to be a small, fixed structure once actually checked, not a big lift. What
// stays genuinely out of scope: interpreting decoded header *content* as HTTP semantics,
// and anything HPACK-related — that's already done by the framer, which persists decoded
// headers into frame.meta.headers once a field block completes; this script only ever
// displays what's already there, never re-derives it (a dissector has no cross-frame
// state to rebuild a dynamic table from — see framer.hpack's own doc comment).

const HEADER_LEN = 9

const FLAG_END_STREAM = 0x01
const FLAG_END_HEADERS = 0x04
const FLAG_ACK = 0x01
const FLAG_PADDED = 0x08
const FLAG_PRIORITY = 0x20 // HEADERS only

const TYPE_DATA = 0x00
const TYPE_HEADERS = 0x01
const TYPE_PRIORITY = 0x02
const TYPE_RST_STREAM = 0x03
const TYPE_SETTINGS = 0x04
const TYPE_PUSH_PROMISE = 0x05
const TYPE_PING = 0x06
const TYPE_GOAWAY = 0x07
const TYPE_WINDOW_UPDATE = 0x08
const TYPE_CONTINUATION = 0x09

// [bit, name] pairs, in display order — RFC 9113 §6.1/§6.2/§6.5/§6.6/§6.7/§6.10. Types
// not listed here (PRIORITY, RST_STREAM, GOAWAY, WINDOW_UPDATE) define no flags at all.
const FLAG_DEFS = {
    [TYPE_DATA]: [[FLAG_PADDED, 'PADDED'], [FLAG_END_STREAM, 'END_STREAM']],
    [TYPE_HEADERS]: [[FLAG_PRIORITY, 'PRIORITY'], [FLAG_PADDED, 'PADDED'], [FLAG_END_HEADERS, 'END_HEADERS'], [FLAG_END_STREAM, 'END_STREAM']],
    [TYPE_SETTINGS]: [[FLAG_ACK, 'ACK']],
    [TYPE_PUSH_PROMISE]: [[FLAG_PADDED, 'PADDED'], [FLAG_END_HEADERS, 'END_HEADERS']],
    [TYPE_PING]: [[FLAG_ACK, 'ACK']],
    [TYPE_CONTINUATION]: [[FLAG_END_HEADERS, 'END_HEADERS']],
}

// RFC 9113 §7.
const ERROR_CODES = {
    0x00: 'NO_ERROR', 0x01: 'PROTOCOL_ERROR', 0x02: 'INTERNAL_ERROR',
    0x03: 'FLOW_CONTROL_ERROR', 0x04: 'SETTINGS_TIMEOUT', 0x05: 'STREAM_CLOSED',
    0x06: 'FRAME_SIZE_ERROR', 0x07: 'REFUSED_STREAM', 0x08: 'CANCEL',
    0x09: 'COMPRESSION_ERROR', 0x0a: 'CONNECT_ERROR', 0x0b: 'ENHANCE_YOUR_CALM',
    0x0c: 'INADEQUATE_SECURITY', 0x0d: 'HTTP_1_1_REQUIRED',
}

// RFC 9113 §6.5.2.
const SETTINGS_NAMES = {
    0x01: 'SETTINGS_HEADER_TABLE_SIZE', 0x02: 'SETTINGS_ENABLE_PUSH',
    0x03: 'SETTINGS_MAX_CONCURRENT_STREAMS', 0x04: 'SETTINGS_INITIAL_WINDOW_SIZE',
    0x05: 'SETTINGS_MAX_FRAME_SIZE', 0x06: 'SETTINGS_MAX_HEADER_LIST_SIZE',
}

function errorCodeLabel(code) {
    return `${ERROR_CODES[code] ?? `unknown(${code})`} (${code})`
}

function decodeFlags(type, flags) {
    const defs = FLAG_DEFS[type]
    if (!defs) {
        return [{ label: 'Value', content: `0x${flags.toString(16).padStart(2, '0')}` }]
    }
    return defs.map(([bit, name]) => ({ label: name, content: (flags & bit) !== 0 }))
}

// Field block fragment location within a HEADERS/PUSH_PROMISE payload — mirrors
// http2-framer.js's own extractFieldBlockFragment exactly. Returns [nodes, fragmentStart,
// fragmentEnd] so the caller can attach meta.headers (if any) to the fragment node.
function dissectFieldBlockLayout(type, flags, bytes, payloadOffset, payloadEnd) {
    const nodes = []
    let pos = payloadOffset
    let padLen = 0

    if (flags & FLAG_PADDED) {
        padLen = bytes[pos]
        nodes.push({ label: 'Pad Length', offset: pos, length: 1, 'display-hint': 'hex', sub: [{ label: 'Value', content: padLen }] })
        pos += 1
    }
    if (type === TYPE_HEADERS && (flags & FLAG_PRIORITY)) {
        nodes.push(...dissectPriorityFields(bytes, pos))
        pos += 5
    }
    if (type === TYPE_PUSH_PROMISE) {
        const promisedStreamId = dissector.number.decodeU32be(bytes.slice(pos, pos + 4)) & 0x7fffffff
        nodes.push({ label: 'Promised Stream ID', offset: pos, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: promisedStreamId }] })
        pos += 4
    }

    const fragmentStart = pos
    const fragmentEnd = payloadEnd - padLen
    return { nodes, fragmentStart, fragmentEnd: Math.max(fragmentEnd, fragmentStart) }
}

function dissectPriorityFields(bytes, offset) {
    const raw = dissector.number.decodeU32be(bytes.slice(offset, offset + 4))
    const exclusive = (raw & 0x80000000) !== 0
    const streamDependency = raw & 0x7fffffff
    const weight = bytes[offset + 4]
    return [
        { label: 'Exclusive', offset, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: exclusive }] },
        { label: 'Stream Dependency', offset, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: streamDependency }] },
        { label: 'Weight', offset: offset + 4, length: 1, 'display-hint': 'hex', sub: [{ label: 'Value', content: weight + 1 }] }, // §6.3: actual priority is the value + 1
    ]
}

function dissectPayloadStructure(type, flags, bytes, payloadOffset, payloadEnd, headers) {
    if (type === TYPE_HEADERS || type === TYPE_PUSH_PROMISE || type === TYPE_CONTINUATION) {
        const { nodes, fragmentStart, fragmentEnd } = type === TYPE_CONTINUATION
            ? { nodes: [], fragmentStart: payloadOffset, fragmentEnd: payloadEnd }
            : dissectFieldBlockLayout(type, flags, bytes, payloadOffset, payloadEnd)

        const fragmentNode = { label: 'Field Block Fragment', offset: fragmentStart, length: fragmentEnd - fragmentStart, 'display-hint': 'hexdump' }
        if (headers) {
            fragmentNode.sub = headers.map(h => ({ label: h.name, content: h.value }))
        }
        nodes.push(fragmentNode)

        if (fragmentEnd < payloadEnd) {
            nodes.push({ label: 'Padding', offset: fragmentEnd, length: payloadEnd - fragmentEnd, 'display-hint': 'hexdump' })
        }
        return nodes
    }

    if (type === TYPE_DATA) {
        const nodes = []
        let pos = payloadOffset
        let padLen = 0
        if (flags & FLAG_PADDED) {
            padLen = bytes[pos]
            nodes.push({ label: 'Pad Length', offset: pos, length: 1, 'display-hint': 'hex', sub: [{ label: 'Value', content: padLen }] })
            pos += 1
        }
        const dataEnd = Math.max(payloadEnd - padLen, pos)
        nodes.push({ label: 'Data', offset: pos, length: dataEnd - pos, 'display-hint': 'hexdump' })
        if (dataEnd < payloadEnd) {
            nodes.push({ label: 'Padding', offset: dataEnd, length: payloadEnd - dataEnd, 'display-hint': 'hexdump' })
        }
        return nodes
    }

    if (type === TYPE_PRIORITY) {
        return dissectPriorityFields(bytes, payloadOffset)
    }

    if (type === TYPE_RST_STREAM) {
        const code = dissector.number.decodeU32be(bytes.slice(payloadOffset, payloadOffset + 4))
        return [{ label: 'Error Code', offset: payloadOffset, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: errorCodeLabel(code) }] }]
    }

    if (type === TYPE_SETTINGS) {
        const nodes = []
        let pos = payloadOffset
        while (pos + 6 <= payloadEnd) {
            const id = dissector.number.decodeU16be(bytes.slice(pos, pos + 2))
            const value = dissector.number.decodeU32be(bytes.slice(pos + 2, pos + 6))
            const name = SETTINGS_NAMES[id] ?? `unknown(${id})`
            nodes.push({ label: name, offset: pos, length: 6, 'display-hint': 'hex', sub: [{ label: 'Value', content: value }] })
            pos += 6
        }
        return nodes
    }

    if (type === TYPE_GOAWAY) {
        const lastStreamId = dissector.number.decodeU32be(bytes.slice(payloadOffset, payloadOffset + 4)) & 0x7fffffff
        const code = dissector.number.decodeU32be(bytes.slice(payloadOffset + 4, payloadOffset + 8))
        const nodes = [
            { label: 'Last-Stream-ID', offset: payloadOffset, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: lastStreamId }] },
            { label: 'Error Code', offset: payloadOffset + 4, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: errorCodeLabel(code) }] },
        ]
        if (payloadEnd > payloadOffset + 8) {
            nodes.push({ label: 'Additional Debug Data', offset: payloadOffset + 8, length: payloadEnd - (payloadOffset + 8), 'display-hint': 'ascii' })
        }
        return nodes
    }

    if (type === TYPE_WINDOW_UPDATE) {
        const increment = dissector.number.decodeU32be(bytes.slice(payloadOffset, payloadOffset + 4)) & 0x7fffffff
        return [{ label: 'Window Size Increment', offset: payloadOffset, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: increment }] }]
    }

    if (type === TYPE_PING) {
        return [{ label: 'Opaque Data', offset: payloadOffset, length: payloadEnd - payloadOffset, 'display-hint': 'hexdump' }]
    }

    // Unknown frame type — nothing to structurally parse it against.
    return []
}

function dissect(bytes, frame) {
    if (frame.kind === 'http2-preface') {
        return [{ label: 'Connection Preface', offset: 0, length: bytes.length, 'display-hint': 'ascii' }]
    }

    if (bytes.length < HEADER_LEN) {
        return [{ label: 'Frame', content: `truncated (${bytes.length} byte(s) loaded, need at least ${HEADER_LEN})` }]
    }

    const meta = frame.meta ?? {}
    const nodes = [
        { label: 'Length', offset: 0, length: 3, 'display-hint': 'hex', sub: [{ label: 'Value', content: `${meta.payloadLength} byte(s)` }] },
        { label: 'Type', offset: 3, length: 1, 'display-hint': 'hex', sub: [{ label: 'Value', content: `${meta.typeName} (${meta.type})` }] },
        { label: 'Flags', offset: 4, length: 1, 'display-hint': 'hex', sub: decodeFlags(meta.type, meta.flags) },
        { label: 'Stream Identifier', offset: 5, length: 4, 'display-hint': 'hex', sub: [{ label: 'Value', content: meta.streamId }] },
    ]

    const payloadOffset = HEADER_LEN
    const availableLen = bytes.length - HEADER_LEN
    if (availableLen > 0) {
        if (availableLen < meta.payloadLength) {
            // Still loading (a large frame the client hasn't fully fetched yet — see
            // TrafficView.js's own note on this) — a plain hexdump rather than a
            // structural parse that needs bytes we don't have. Only really reachable for
            // DATA in practice, since every type this script parses structurally is
            // small (bounded by MAX_FRAME_SIZE) and DATA isn't parsed beyond Pad Length.
            nodes.push({ label: 'Payload', offset: payloadOffset, length: availableLen, 'display-hint': 'hexdump' })
        } else {
            nodes.push({
                label: 'Payload',
                offset: payloadOffset,
                length: availableLen,
                'display-hint': 'hexdump',
                sub: dissectPayloadStructure(meta.type, meta.flags, bytes, payloadOffset, payloadOffset + availableLen, meta.headers),
            })
        }
    }

    return nodes
}
