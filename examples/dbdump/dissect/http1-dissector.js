// HTTP/1 message dissector — pairs with examples/dbdump/framer/http1-framer.js. Start-line
// parts, headers, and chunked-encoding chunks/trailers are entirely metadata-driven: the
// framer already located them and handed them over via frame.meta, so this script never
// re-scans raw bytes for those — same division of labor http2-dissector.js's "framer
// decodes HPACK, dissector just displays frame.meta.headers" already established.
// Unlike HTTP/2's decoded (HPACK-compressed) headers, an HTTP/1 header line *is* a literal
// byte range on the wire, so each header node below is offset/length (clickable,
// highlighting "Name: Value\r\n" in the hex view), not a content-only value.
//
// Request/response *parameters* — query string, and body form fields (urlencoded/JSON/
// multipart) — are a deliberate exception: this script scans the body bytes itself rather
// than asking the framer to understand every possible body encoding. That's fine here
// specifically because it's presentation-only (doesn't affect message framing/boundaries)
// and needs no state across frame() calls, unlike chunked-encoding parsing which stays in
// the framer for exactly that reason.

const CR = 0x0d, LF = 0x0a, COLON = 0x3a

const UTF8 = new TextDecoder('utf-8')

function decodeText(bytes) {
    return UTF8.decode(bytes)
}

function findHeaderValue(headers, nameLower) {
    return headers.find(h => h.name.toLowerCase() === nameLower)?.value
}

// Splits a header value's main token from its ;name=value/;name="quoted value" params
// (RFC 9110 §5.6.6), e.g. 'multipart/form-data; boundary="abc def"' ->
// { mainValue: 'multipart/form-data', params: { boundary: 'abc def' } }. mainValue is
// lowercased (a bare token, safe to compare case-insensitively); param values keep their
// original case, quoted-pair escapes (\") unescaped.
function parseHeaderParams(value) {
    const semi = value.indexOf(';')
    const mainValue = (semi < 0 ? value : value.slice(0, semi)).trim().toLowerCase()
    const params = {}
    let rest = semi < 0 ? '' : value.slice(semi + 1)
    while (true) {
        rest = rest.replace(/^;?\s*/, '')
        if (rest.length === 0) break
        const eq = rest.indexOf('=')
        if (eq < 0) break
        const name = rest.slice(0, eq).trim().toLowerCase()
        rest = rest.slice(eq + 1)
        let val
        if (rest[0] === '"') {
            let j = 1
            while (j < rest.length && rest[j] !== '"') {
                if (rest[j] === '\\' && j + 1 < rest.length) j++
                j++
            }
            val = rest.slice(1, j).replace(/\\(.)/g, '$1')
            rest = rest.slice(j + 1)
        } else {
            const nextSemi = rest.indexOf(';')
            val = (nextSemi < 0 ? rest : rest.slice(0, nextSemi)).trim()
            rest = nextSemi < 0 ? '' : rest.slice(nextSemi)
        }
        params[name] = val
    }
    return { mainValue, params }
}

function findLineEnd(buf, from) {
    for (let i = from; i < buf.length - 1; i++) {
        if (buf[i] === CR && buf[i + 1] === LF) return i + 2
    }
    return -1
}

function findSubarray(buf, pattern, from) {
    outer: for (let i = from; i <= buf.length - pattern.length; i++) {
        for (let j = 0; j < pattern.length; j++) {
            if (buf[i + j] !== pattern[j]) continue outer
        }
        return i
    }
    return -1
}

// One-shot "Name: Value\r\n" scan (unlike the framer's incremental scanHeaderLines, the
// whole buffer is already in hand) used for a multipart part's own header block.
function parseHeaderBlock(buf, pos) {
    const headers = []
    while (true) {
        const lineEnd = findLineEnd(buf, pos)
        if (lineEnd < 0) throw new Error('unterminated part header block')
        if (lineEnd - pos === 2) return { headers, pos: lineEnd }
        const lineBytes = buf.subarray(pos, lineEnd - 2)
        const colon = lineBytes.indexOf(COLON)
        if (colon < 0) throw new Error('malformed part header line (no colon)')
        headers.push({ name: decodeText(lineBytes.subarray(0, colon)).trim(), value: decodeText(lineBytes.subarray(colon + 1)).trim() })
        pos = lineEnd
    }
}

// Reassembles a message's actual body content (independent of the wire encoding that
// carried it) as a slice/copy of bytes, plus baseOffset — the frame-relative offset of
// that content's first byte, or null when no single contiguous range in the frame
// corresponds to it (a chunked body's data is scattered between chunk-size lines/CRLFs).
// null for 'none'/'tunnel', which have no body content at all.
function reassembleBody(bytes, body) {
    if (body.kind === 'content-length' || body.kind === 'close-delimited') {
        return { bytes: bytes.subarray(body.offset, body.offset + body.length), baseOffset: body.offset }
    }
    if (body.kind === 'chunked') {
        const parts = body.chunks.map(c => bytes.subarray(c.dataOffset, c.dataOffset + c.dataLength))
        const total = parts.reduce((n, p) => n + p.length, 0)
        const out = new Uint8Array(total)
        let pos = 0
        for (const p of parts) { out.set(p, pos); pos += p.length }
        return { bytes: out, baseOffset: null }
    }
    return null
}

function formParamNodes(text) {
    const nodes = []
    for (const [key, value] of new URLSearchParams(text)) nodes.push({ label: key, content: value })
    return nodes
}

function queryParamNodes(target) {
    const q = target.indexOf('?')
    if (q < 0 || q === target.length - 1) return null
    return formParamNodes(target.slice(q + 1))
}

function jsonValueNode(label, value) {
    if (Array.isArray(value)) return { label, sub: value.map((v, i) => jsonValueNode(`[${i}]`, v)) }
    if (value !== null && typeof value === 'object') return { label, sub: Object.entries(value).map(([k, v]) => jsonValueNode(k, v)) }
    return { label, content: value === null ? 'null' : value }
}

// raw is a body's reassembled content bytes (baseOffset-relative to the frame); parses it
// as multipart/form-data (RFC 2046 §5.1) into one node per part: Name/Filename (from
// Content-Disposition), Content-Type if present, and Content as a real offset/length
// range (clickable/hexdump) — a part's own bytes are a literal, undecoded slice of raw.
function multipartNodes(raw, baseOffset, boundary) {
    const delim = new TextEncoder().encode(`--${boundary}`)
    let pos = findSubarray(raw, delim, 0)
    if (pos < 0) throw new Error('boundary not found in body')
    pos += delim.length

    const nodes = []
    let index = 0
    while (true) {
        if (raw[pos] === 0x2d && raw[pos + 1] === 0x2d) break // "--": final boundary
        if (raw[pos] === CR && raw[pos + 1] === LF) pos += 2

        const { headers, pos: afterHeaders } = parseHeaderBlock(raw, pos)
        const disposition = parseHeaderParams(findHeaderValue(headers, 'content-disposition') ?? '')
        const contentType = findHeaderValue(headers, 'content-type')

        const nextDelim = findSubarray(raw, delim, afterHeaders)
        if (nextDelim < 0) throw new Error('unterminated multipart part')
        let contentEnd = nextDelim
        if (raw[contentEnd - 2] === CR && raw[contentEnd - 1] === LF) contentEnd -= 2

        const sub = []
        if (disposition.params.name) sub.push({ label: 'Name', content: disposition.params.name })
        if (disposition.params.filename) sub.push({ label: 'Filename', content: disposition.params.filename })
        if (contentType !== undefined) sub.push({ label: 'Content-Type', content: contentType })
        sub.push({ label: 'Content', offset: baseOffset + afterHeaders, length: contentEnd - afterHeaders, 'display-hint': 'hexdump' })

        nodes.push({ label: disposition.params.name ? `Part (${disposition.params.name})` : `Part ${index}`, sub })

        pos = nextDelim + delim.length
        index++
    }
    return nodes
}

// Extra field nodes for a body's decoded parameters, based on Content-Type — [] when
// there's nothing to add (no Content-Type, empty/truncated/bodyless body, or a
// Content-Type this script doesn't know how to parse). A parse failure (malformed JSON,
// missing boundary, ...) is reported as its own node rather than thrown — this runs
// inside the dissect() call that builds the *whole* tree, and an uncaught throw here
// would blank the entire frame's output, not just the body.
function parsedBodyNodes(bytes, body, headers) {
    if (body.truncated) return []
    const ctValue = findHeaderValue(headers, 'content-type')
    if (ctValue === undefined) return []
    const ct = parseHeaderParams(ctValue)

    const reassembled = reassembleBody(bytes, body)
    if (!reassembled || reassembled.bytes.length === 0) return []

    try {
        if (ct.mainValue === 'application/x-www-form-urlencoded') {
            return [{ label: 'Form Parameters', sub: formParamNodes(decodeText(reassembled.bytes)) }]
        }
        if (ct.mainValue === 'application/json' || ct.mainValue.endsWith('+json')) {
            return [jsonValueNode('JSON', JSON.parse(decodeText(reassembled.bytes)))]
        }
        if (ct.mainValue === 'multipart/form-data') {
            if (!ct.params.boundary) throw new Error('Content-Type has no boundary parameter')
            if (reassembled.baseOffset == null) {
                return [{ label: 'Parts', content: '(multipart parsing not supported for chunked-encoded bodies)' }]
            }
            return [{ label: 'Parts', sub: multipartNodes(reassembled.bytes, reassembled.baseOffset, ct.params.boundary) }]
        }
    } catch (e) {
        return [{ label: 'Parameters', content: `(parse error: ${e.message})` }]
    }
    return []
}

function headerNodes(headers) {
    return headers.map(h => ({ label: h.name, offset: h.offset, length: h.length, 'display-hint': 'ascii' }))
}

function bodySub(bytes, body, headers) {
    const sub = [{ label: 'Kind', content: body.kind }]
    sub.push(...parsedBodyNodes(bytes, body, headers))
    if (body.truncated) sub.push({ label: 'Truncated', content: true })
    return sub
}

function chunkedBodyNode(bytes, body, headers) {
    const sub = body.chunks.map((c, i) => ({
        label: `Chunk ${i}`,
        sub: [
            { label: 'Chunk Size', offset: c.sizeOffset, length: c.sizeLength, 'display-hint': 'ascii', sub: [{ label: 'Value', content: c.dataLength }] },
            { label: 'Chunk Data', offset: c.dataOffset, length: c.dataLength, 'display-hint': 'hexdump' },
        ],
    }))
    sub.push(...parsedBodyNodes(bytes, body, headers))
    if (body.trailers.length > 0) {
        sub.push({ label: 'Trailers', sub: headerNodes(body.trailers) })
    }
    if (body.truncated) sub.push({ label: 'Truncated', content: true })
    return { label: 'Body', offset: body.offset, length: body.length, 'display-hint': 'hexdump', sub }
}

function bodyNode(bytes, body, headers) {
    if (body.kind === 'none') {
        return { label: 'Body', content: '(none)' }
    }
    if (body.kind === 'chunked') {
        return chunkedBodyNode(bytes, body, headers)
    }
    return { label: 'Body', offset: body.offset, length: body.length, 'display-hint': 'hexdump', sub: bodySub(bytes, body, headers) }
}

const RAW_REASONS = {
    tunnel: 'CONNECT tunnel payload (opaque, not HTTP)',
    'http09-response': 'HTTP/0.9 response (no length signal — not re-segmented)',
}

// RFC 6455 §5.2/§11.8. 3 (Continuation ... Reserved) covers 0x3-0x7, likewise for
// 0xB-0xF — those ranges have no individual meaning assigned, just "reserved".
const WS_OPCODE_NAMES = { 0: 'Continuation', 1: 'Text', 2: 'Binary', 8: 'Close', 9: 'Ping', 0xa: 'Pong' }
function wsOpcodeName(opcode) {
    return WS_OPCODE_NAMES[opcode] ?? `Reserved (0x${opcode.toString(16)})`
}

// RFC 6455 §7.4.1. 1005/1006/1015 are reserved for library-internal use and never
// actually appear on the wire, but labeling them if seen is harmless.
const WS_CLOSE_CODE_NAMES = {
    1000: 'Normal Closure', 1001: 'Going Away', 1002: 'Protocol Error', 1003: 'Unsupported Data',
    1005: 'No Status Rcvd', 1006: 'Abnormal Closure', 1007: 'Invalid Frame Payload Data',
    1008: 'Policy Violation', 1009: 'Message Too Big', 1010: 'Mandatory Extension',
    1011: 'Internal Server Error', 1015: 'TLS Handshake',
}
function wsCloseCodeName(code) {
    if (WS_CLOSE_CODE_NAMES[code]) return WS_CLOSE_CODE_NAMES[code]
    if (code >= 3000 && code <= 3999) return 'registered (IANA)'
    if (code >= 4000 && code <= 4999) return 'private use'
    return 'unknown'
}

// A stateless, single-frame, byte-for-byte XOR — unlike decompression, this can be shown
// as a display-only transform without losing the offset/length correspondence to the raw
// wire bytes (byte i of the unmasked view is still exactly byte i of the wire payload).
function unmaskPayload(payloadBytes, maskKeyHex) {
    const key = maskKeyHex.match(/../g).map(h => parseInt(h, 16))
    const out = new Uint8Array(payloadBytes.length)
    for (let i = 0; i < payloadBytes.length; i++) out[i] = payloadBytes[i] ^ key[i % 4]
    return out
}

// kind: 'websocket-frame' (websocketFrameNodes below) is a control frame or an
// unfragmented message (fin:true on its first — and only — frame); the framer reassembles
// an actually-fragmented message into kind: 'websocket-message' instead
// (websocketMessageNodes further below), one tlstap frame spanning every fragment's own
// wire span. permessage-deflate-compressed payloads (rsv1 set) aren't decompressed in
// either case — that needs cross-message state this stateless dissect() call doesn't have.
const SNIFF_JSON_PAYLOADS = true // best-effort JSON.parse on Text/Binary payloads; not backed by any Content-Type-equivalent signal, so a parse failure is silently ignored, not shown

function websocketFrameNodes(bytes, meta) {
    const raw = bytes.subarray(meta.payload.offset, meta.payload.offset + meta.payload.length)
    const unmasked = meta.masked ? unmaskPayload(raw, meta.maskKey) : raw

    const nodes = [
        { label: 'FIN', content: meta.fin },
        { label: 'RSV1 (permessage-deflate compression flag)', content: meta.rsv1 },
        { label: 'RSV2', content: meta.rsv2 },
        { label: 'RSV3', content: meta.rsv3 },
        { label: 'Opcode', content: `${wsOpcodeName(meta.opcode)} (${meta.opcode})` },
        { label: 'Masked', content: meta.masked },
    ]
    if (meta.masked) nodes.push({ label: 'Masking Key', content: meta.maskKey })

    const payloadSub = []
    if (meta.messageOpcode === 1 || meta.opcode === 9 || meta.opcode === 10) {
        payloadSub.push({ label: 'Text', content: decodeText(unmasked) })
    } else if (meta.opcode === 8 && unmasked.length >= 2) {
        const code = (unmasked[0] << 8) | unmasked[1]
        payloadSub.push({ label: 'Status Code', content: `${code} (${wsCloseCodeName(code)})` })
        if (unmasked.length > 2) payloadSub.push({ label: 'Reason', content: decodeText(unmasked.subarray(2)) })
    }
    if (SNIFF_JSON_PAYLOADS && (meta.messageOpcode === 1 || meta.messageOpcode === 2)) {
        try {
            payloadSub.push(jsonValueNode('JSON', JSON.parse(decodeText(unmasked))))
        } catch {
            // not JSON — a best-effort sniff, nothing to report on failure
        }
    }
    if (meta.truncated) payloadSub.push({ label: 'Truncated', content: true })
    nodes.push({ label: 'Payload', offset: meta.payload.offset, length: meta.payload.length, 'display-hint': 'hexdump', sub: payloadSub })

    return nodes
}

// A fragmented WebSocket message (kind: 'websocket-message', see http1-framer.js's
// advanceWebSocket): bytes is already the frame's own concatenation of every fragment's
// full wire span (frame.ranges), so each fragment's own payload sub-range
// (f.payloadOffset/payloadLength) is a real, clickable offset/length pair directly into
// it — same idea as websocketFrameNodes' single-frame Payload node, just located per
// fragment instead of at a fixed spot. The reassembled content itself has no single real
// offset/length of its own (its bytes are scattered across the frame, not contiguous —
// same reason reassembleBody's chunked case above returns baseOffset: null), so it's
// shown as a content-only node, mirroring that convention.
function websocketMessageNodes(bytes, meta) {
    const parts = meta.fragments.map(f => {
        const raw = bytes.subarray(f.payloadOffset, f.payloadOffset + f.payloadLength)
        return f.maskKey ? unmaskPayload(raw, f.maskKey) : raw
    })
    const total = parts.reduce((n, p) => n + p.length, 0)
    const unmasked = new Uint8Array(total)
    let pos = 0
    for (const p of parts) { unmasked.set(p, pos); pos += p.length }

    const nodes = [
        { label: 'Opcode', content: `${wsOpcodeName(meta.messageOpcode)} (${meta.messageOpcode})` },
        { label: 'Fragment Count', content: meta.fragments.length },
    ]

    const contentSub = []
    if (meta.messageOpcode === 1) contentSub.push({ label: 'Text', content: decodeText(unmasked) })
    if (SNIFF_JSON_PAYLOADS && (meta.messageOpcode === 1 || meta.messageOpcode === 2)) {
        try {
            contentSub.push(jsonValueNode('JSON', JSON.parse(decodeText(unmasked))))
        } catch {
            // not JSON — a best-effort sniff, nothing to report on failure
        }
    }
    nodes.push({ label: 'Reassembled Payload', content: `${unmasked.length} bytes`, sub: contentSub })

    nodes.push({
        label: 'Fragments',
        sub: meta.fragments.map((f, i) => {
            const sub = []
            if (f.maskKey) sub.push({ label: 'Masking Key', content: f.maskKey })
            sub.push({ label: 'Payload', offset: f.payloadOffset, length: f.payloadLength, 'display-hint': 'hexdump' })
            return { label: `Fragment ${i}`, sub }
        }),
    })
    if (meta.truncated) nodes.push({ label: 'Truncated', content: true })

    return nodes
}

function dissect(bytes, frame) {
    const meta = frame.meta
    if (!meta) {
        return [{ label: 'Message', content: '(no metadata — framer did not attach meta for this frame)' }]
    }
    if (meta.kind === 'raw') {
        return [
            { label: 'Reason', content: RAW_REASONS[meta.reason] ?? meta.reason },
            { label: 'Data', offset: 0, length: bytes.length, 'display-hint': 'hexdump' },
        ]
    }
    if (meta.kind === 'websocket-frame') {
        return websocketFrameNodes(bytes, meta)
    }
    if (meta.kind === 'websocket-message') {
        return websocketMessageNodes(bytes, meta)
    }

    const nodes = [
        {
            label: 'Start Line',
            offset: meta.startLine.offset,
            length: meta.startLine.length,
            'display-hint': 'ascii',
            sub: meta.kind === 'http-request'
                ? [
                    { label: 'Method', content: meta.method },
                    { label: 'Target', content: meta.target, sub: queryParamNodes(meta.target) },
                    { label: 'Version', content: meta.version },
                ]
                : [
                    { label: 'Version', content: meta.version },
                    { label: 'Status Code', content: meta.statusCode },
                    { label: 'Reason Phrase', content: meta.reasonPhrase },
                ],
        },
        { label: 'Headers', sub: headerNodes(meta.headers) },
        bodyNode(bytes, meta.body, meta.headers),
    ]

    return nodes
}
