// HTTP/1 message framer (RFC 9112), running in combined mode (see doc/design/http1-framer.md
// and doc/design/framer-cross-direction-correlation.md) to resolve message-length rules that
// need the *other* direction's stream. A 101 Switching Protocols response switches both
// directions to WebSocket framing (RFC 6455) for the rest of the connection.
//
// One frame = one complete HTTP message (start-line + headers + body); HTTP/1 has no
// independent-frame wire seam to split on, unlike HTTP/2's HEADERS/DATA. Chunked-encoding
// parsing happens here, never in the dissector. A WebSocket control frame (close/ping/
// pong) is its own tlstap frame, one wire frame each, since it's independently
// self-delimited and can legally interrupt a fragmented message (RFC 6455 §5.4) without
// being part of it. A WebSocket data message (Text/Binary, plus any continuation frames
// completing it) is reassembled into one tlstap frame spanning all of its fragments'
// wire spans — a multi-range frame when actually fragmented, a single-range one
// otherwise (the common case, unchanged from before this reassembly existed).

const CR = 0x0d, LF = 0x0a, COLON = 0x3a, SEMICOLON = 0x3b, SP = 0x20, HTAB = 0x09

const MAX_START_LINE = 8 * 1024          // sanity cap while scanning for a start-line's CRLF
const MAX_HEADER_BLOCK = 1024 * 1024     // sanity cap on a whole header (or trailer) block
const MAX_CHUNK_SIZE = 256 * 1024 * 1024 // sanity cap on one chunked-encoding chunk
const MAX_WS_PAYLOAD = 256 * 1024 * 1024 // sanity cap on one WebSocket frame's declared payload length

const WS_FIN = 0x80, WS_RSV1 = 0x40, WS_RSV2 = 0x20, WS_RSV3 = 0x10, WS_OPCODE_MASK = 0x0f
const WS_MASK_BIT = 0x80, WS_LEN_MASK = 0x7f
const WS_OP_CONTINUATION = 0x0, WS_OP_TEXT = 0x1, WS_OP_BINARY = 0x2

const HTTP_VERSION_RE = /^HTTP\/\d\.\d$/
const HTTP09_METHOD_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/ // RFC 9110 §5.6.2 token charset

const ASCII = new TextDecoder('latin1') // header field values are ISO-8859-1/obs-text per RFC 9110 §5.5

function findLineEnd(buf, from) {
    for (let i = from; i < buf.length - 1; i++) {
        if (buf[i] === CR && buf[i + 1] === LF) return i + 2
    }
    return -1
}

// Scans "Name: Value\r\n" lines into target until a blank line ends the block, returning
// { pos } right after it, or null if more data is needed. Shared by the header block and
// chunked trailers; blockStart bounds MAX_HEADER_BLOCK against a block with no terminator.
//
// A line starting with SP/HTAB is obsolete line folding (RFC 9112 §5.2 — its RWS
// requirement also means a blank line can never be misread as one), unfolded rather than
// rejected since this script never forwards what it parses. foldedHeader dedupes the log
// warning to once per folded header, not once per line.
function scanHeaderLines(buf, pos, target, bufBaseOffset, blockStart) {
    let foldedHeader = null
    while (true) {
        const lineEnd = findLineEnd(buf, pos)
        if (lineEnd < 0) {
            if (bufBaseOffset + pos - blockStart > MAX_HEADER_BLOCK) {
                throw new Error(`http1: header block exceeds ${MAX_HEADER_BLOCK} bytes starting at offset ${blockStart} — probably misaligned, not a real header block`)
            }
            return null
        }
        if (lineEnd - pos === 2) return { pos: lineEnd } // blank line: end of block

        if (buf[pos] === SP || buf[pos] === HTAB) {
            const cont = ASCII.decode(buf.subarray(pos, lineEnd - 2)).trim()
            const prev = target[target.length - 1]
            if (!prev) {
                framer.log(`http1: obsolete line folding with no preceding header field at offset ${bufBaseOffset + pos} — discarding line`)
                pos = lineEnd
                continue
            }
            if (foldedHeader !== prev) {
                framer.log(`http1: header "${prev.name}" uses obsolete line folding — unfolding`)
                foldedHeader = prev
            }
            if (cont.length > 0) prev.value += ' ' + cont
            prev.length = (bufBaseOffset + lineEnd) - prev.offset
            pos = lineEnd
            continue
        }
        foldedHeader = null

        const lineBytes = buf.subarray(pos, lineEnd - 2)
        const colon = lineBytes.indexOf(COLON)
        if (colon < 0) {
            throw new Error(`http1: malformed header line (no colon) at offset ${bufBaseOffset + pos}: "${ASCII.decode(lineBytes)}"`)
        }
        target.push({
            name: ASCII.decode(lineBytes.subarray(0, colon)).trim(),
            value: ASCII.decode(lineBytes.subarray(colon + 1)).trim(),
            offset: bufBaseOffset + pos,
            length: lineEnd - pos,
        })
        pos = lineEnd
    }
}

function combinedTransferEncoding(headers) {
    const values = headers.filter(h => h.name.toLowerCase() === 'transfer-encoding').map(h => h.value)
    return values.length === 0 ? undefined : values.join(', ')
}

function hasContentLength(headers) {
    return headers.some(h => h.name.toLowerCase() === 'content-length')
}

// RFC 9112 §6.3 rule 4: multiple differing values, or a single malformed value, is a
// framing error, not something to guess past.
function validatedContentLength(headers) {
    const values = headers.filter(h => h.name.toLowerCase() === 'content-length').map(h => h.value)
    if (values.length === 0) return null
    if (new Set(values).size > 1) {
        throw new Error(`http1: conflicting Content-Length values: ${values.join(', ')}`)
    }
    if (!/^\d+$/.test(values[0])) {
        throw new Error(`http1: invalid Content-Length value "${values[0]}"`)
    }
    return Number(values[0])
}

// "chunked" only counts as the transfer length mechanism when it's the *final* coding
// (RFC 9112 §6.3 rule 3) — chunk-extensions/other codings before it don't change that.
function isChunkedFinal(value) {
    const codings = value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
    return codings.length > 0 && codings[codings.length - 1] === 'chunked'
}

function newChunkedBody() {
    return { kind: 'chunked', chunks: [], trailers: [], phase: 'size', curChunk: null }
}

// A frame for a span given up on rather than parsed as HTTP (CONNECT tunnel payload, or an
// HTTP/0.9 response with no length signal) — one per chunk, so Frame view shows something
// instead of going silent.
function rawFrame(offset, length, reason) {
    return { ranges: [{ offset, length }], meta: { kind: 'raw', reason } }
}

// Builds one WebSocket frame's {ranges, meta} (RFC 6455 §5.2) for a control frame or an
// unfragmented Text/Binary message (fin:true on its very first — and only — frame).
// frameAbsoluteStart is the frame's own first byte, not the payload's; meta's offsets are
// relative to it. messageOpcode is opcode itself for Text/Binary, null for a control
// frame — never called for a continuation frame, which always goes through the
// accumulator below instead (see advanceWebSocket).
function wsFrameMeta(frameAbsoluteStart, fin, rsv1, rsv2, rsv3, opcode, messageOpcode, masked, maskKeyBytes, payloadAbsoluteStart, payloadAbsoluteEnd, truncated) {
    const meta = {
        kind: 'websocket-frame',
        fin, rsv1, rsv2, rsv3, opcode, masked,
        payload: { offset: payloadAbsoluteStart - frameAbsoluteStart, length: payloadAbsoluteEnd - payloadAbsoluteStart },
    }
    if (messageOpcode != null) meta.messageOpcode = messageOpcode
    if (masked) meta.maskKey = Array.from(maskKeyBytes, b => b.toString(16).padStart(2, '0')).join('')
    if (truncated) meta.truncated = true
    return { ranges: [{ offset: frameAbsoluteStart, length: payloadAbsoluteEnd - frameAbsoluteStart }], meta }
}

// Finalizes a fragmented message accumulated in pendingMessage (see advanceWebSocket)
// into one tlstap frame: ranges is each fragment's own full wire span, in order — the
// frame's own bytes (as dissect() receives them) are exactly this concatenation, with no
// gap for whatever control frame may have interrupted the sequence physically in between.
// meta.fragments locates each fragment's payload within that concatenation
// (payloadOffset, mirroring body.chunks' own frame-relative-offset convention) plus its
// own mask key (RFC 6455 gives every wire frame, fragments included, its own key, never
// one shared per message) — enough for a dissector to unmask and concatenate just the
// logical payload bytes, skipping each fragment's own header/mask bytes.
function finalizeMessage(pendingMessage, truncated) {
    const meta = { kind: 'websocket-message', messageOpcode: pendingMessage.messageOpcode, fragments: pendingMessage.fragments }
    if (truncated) meta.truncated = true
    return { ranges: pendingMessage.ranges, meta }
}

// Advances one direction's WebSocket frame stream as far as (carry + data) allows,
// returning { frames, wsState }. A control frame is always its own tlstap frame,
// regardless of whether a message is currently being accumulated below — it can legally
// interrupt a fragmented message (RFC 6455 §5.4) without being part of it. An unfragmented
// Text/Binary message (fin:true on its first frame) is likewise emitted immediately, same
// as before this function reassembled anything. A fragmented message's frames (fin:false
// Text/Binary, then one or more continuations) are instead accumulated in
// wsState.pendingMessage — {messageOpcode, ranges, fragments} — until the fin:true
// continuation completes it (or the connection closes mid-sequence, flushed as
// meta.truncated); this needs no new signal from the platform, just holding state across
// calls the same way any framer script's own state already can.
function advanceWebSocket(wsState, data, dataOffset, closed) {
    const carry = wsState.carry
    let pendingMessage = wsState.pendingMessage ?? null
    const buf = new Uint8Array(carry.length + data.length)
    buf.set(carry, 0)
    buf.set(data, carry.length)
    const bufBaseOffset = dataOffset - carry.length

    const frames = []
    // A connection closing with a partial message header, or mid-sequence with no further
    // fragment ever arriving, abandons whatever's accumulated so far rather than losing it
    // silently — this is the one case a fragmented message can end without its own
    // fin:true continuation ever completing it.
    function abandonPendingOnClose() {
        if (pendingMessage) frames.push(finalizeMessage(pendingMessage, true))
        pendingMessage = null
    }

    let pos = 0
    while (true) {
        if (buf.length - pos < 2) {
            if (closed) { abandonPendingOnClose(); pos = buf.length }
            break
        }
        const b0 = buf[pos], b1 = buf[pos + 1]
        const masked = (b1 & WS_MASK_BIT) !== 0
        const lenField = b1 & WS_LEN_MASK
        const hdrLen = 2 + (lenField === 126 ? 2 : lenField === 127 ? 8 : 0) + (masked ? 4 : 0)
        if (buf.length - pos < hdrLen) {
            if (closed) { abandonPendingOnClose(); pos = buf.length }
            break
        }

        let extPos = pos + 2
        let payloadLen
        if (lenField === 126) {
            payloadLen = (buf[extPos] << 8) | buf[extPos + 1]
            extPos += 2
        } else if (lenField === 127) {
            // 64-bit big-endian length — JS bitwise ops truncate to 32 bits, so build via
            // multiplication instead. MAX_WS_PAYLOAD rejects anything implausible below,
            // so precision beyond 2^53 is never actually relied on.
            let len = 0
            for (let i = 0; i < 8; i++) len = len * 256 + buf[extPos + i]
            payloadLen = len
            extPos += 8
        } else {
            payloadLen = lenField
        }
        if (payloadLen > MAX_WS_PAYLOAD) {
            throw new Error(`websocket: implausible frame payload length ${payloadLen} at offset ${bufBaseOffset + pos} — probably misaligned, not a real frame`)
        }

        let maskKey = null
        if (masked) {
            maskKey = buf.subarray(extPos, extPos + 4)
            extPos += 4
        }

        if (buf.length - extPos < payloadLen && !closed) break // wait for the rest of the payload

        const frameAbsStart = bufBaseOffset + pos
        const payloadAbsStart = bufBaseOffset + extPos
        const fin = (b0 & WS_FIN) !== 0, rsv1 = (b0 & WS_RSV1) !== 0, rsv2 = (b0 & WS_RSV2) !== 0, rsv3 = (b0 & WS_RSV3) !== 0
        const opcode = b0 & WS_OPCODE_MASK
        const truncated = buf.length - extPos < payloadLen // implies closed, given the check above
        const payloadAbsEnd = truncated ? bufBaseOffset + buf.length : payloadAbsStart + payloadLen
        const isControl = opcode !== WS_OP_CONTINUATION && opcode !== WS_OP_TEXT && opcode !== WS_OP_BINARY

        if (isControl || (opcode !== WS_OP_CONTINUATION && fin)) {
            frames.push(wsFrameMeta(frameAbsStart, fin, rsv1, rsv2, rsv3, opcode, isControl ? null : opcode, masked, maskKey, payloadAbsStart, payloadAbsEnd, truncated))
        } else {
            if (opcode === WS_OP_CONTINUATION && !pendingMessage) {
                throw new Error(`websocket: continuation frame at offset ${frameAbsStart} with no message in progress — probably misaligned, not a real frame`)
            }
            if (opcode !== WS_OP_CONTINUATION) pendingMessage = { messageOpcode: opcode, ranges: [], fragments: [] }
            const messageBytesSoFar = pendingMessage.ranges.reduce((n, r) => n + r.length, 0)
            pendingMessage.ranges.push({ offset: frameAbsStart, length: payloadAbsEnd - frameAbsStart })
            const fragment = { payloadOffset: messageBytesSoFar + (payloadAbsStart - frameAbsStart), payloadLength: payloadAbsEnd - payloadAbsStart }
            if (masked) fragment.maskKey = Array.from(maskKey, b => b.toString(16).padStart(2, '0')).join('')
            pendingMessage.fragments.push(fragment)
            if (fin || truncated) {
                frames.push(finalizeMessage(pendingMessage, truncated))
                pendingMessage = null
            }
        }

        if (truncated) { pos = buf.length; break }
        pos = extPos + payloadLen
    }

    return { frames, wsState: { carry: buf.slice(pos), pendingMessage } }
}

function classifyRequestBody(headers) {
    const te = combinedTransferEncoding(headers)
    if (te !== undefined) {
        if (hasContentLength(headers)) {
            framer.log('http1: request has both Content-Length and Transfer-Encoding headers — Transfer-Encoding governs per RFC 9112 §6.3 rule 3, but this combination is a known request-smuggling vector')
        }
        if (!isChunkedFinal(te)) {
            // RFC 9112 §6.3 rule 3: a request whose final coding isn't chunked has no
            // reliable length — a real server would reject it with 400 and close.
            throw new Error(`http1: request Transfer-Encoding present but "chunked" is not the final coding ("${te}")`)
        }
        return newChunkedBody()
    }
    const cl = validatedContentLength(headers)
    if (cl != null) return { kind: 'content-length', length: cl }
    return { kind: 'none' }
}

function classifyResponseBody(headers, statusCode, reqMethod) {
    // RFC 9112 §6.3 rules 1-2: CONNECT tunnel and HEAD/1xx/204/304 both ignore
    // Content-Length/Transfer-Encoding entirely, checked before either is consulted.
    if (reqMethod === 'CONNECT' && statusCode >= 200 && statusCode < 300) {
        return { kind: 'tunnel' }
    }
    if (reqMethod === 'HEAD' || statusCode < 200 || statusCode === 204 || statusCode === 304) {
        return { kind: 'none' }
    }
    const te = combinedTransferEncoding(headers)
    if (te !== undefined) {
        if (hasContentLength(headers)) {
            framer.log('http1: response has both Content-Length and Transfer-Encoding headers — Transfer-Encoding governs per RFC 9112 §6.3 rule 3, but this combination is a known request-smuggling vector')
        }
        if (isChunkedFinal(te)) return newChunkedBody()
        // Recoverable oddity, not a hard desync — fall back to close-delimited rather
        // than aborting framing.
        framer.log(`http1: response Transfer-Encoding present but "chunked" is not the final coding ("${te}") — falling back to close-delimited framing`)
        return { kind: 'close-delimited' }
    }
    const cl = validatedContentLength(headers)
    if (cl != null) return { kind: 'content-length', length: cl }
    return { kind: 'close-delimited' }
}

function parseStartLine(buf, start, lineEnd, dir, bufBaseOffset) {
    const line = ASCII.decode(buf.subarray(start, lineEnd - 2))
    const msgStartAbsolute = bufBaseOffset + start
    const common = { msgStartAbsolute, startLineAbsolute: msgStartAbsolute, startLineLen: lineEnd - start, headers: [] }

    if (dir === 'c2s') {
        const firstSpace = line.indexOf(' ')
        if (firstSpace < 0) {
            throw new Error(`http1: malformed request-line "${line}" at offset ${msgStartAbsolute}`)
        }
        const lastSpace = line.lastIndexOf(' ')
        if (lastSpace === firstSpace) {
            // Two tokens, no HTTP-version — the shape of an HTTP/0.9 simple-request
            // rather than a malformed HTTP/1.x request-line.
            const method = line.slice(0, firstSpace)
            const target = line.slice(firstSpace + 1)
            if (!HTTP09_METHOD_RE.test(method)) {
                throw new Error(`http1: malformed request-line "${line}" at offset ${msgStartAbsolute}`)
            }
            return { kind: 'http-request', http09: true, method, target, version: 'HTTP/0.9', ...common }
        }
        const method = line.slice(0, firstSpace)
        const target = line.slice(firstSpace + 1, lastSpace)
        const version = line.slice(lastSpace + 1)
        if (!HTTP_VERSION_RE.test(version)) {
            throw new Error(`http1: malformed request-line "${line}" at offset ${msgStartAbsolute} — bad HTTP-version "${version}"`)
        }
        return { kind: 'http-request', method, target, version, ...common }
    }

    const firstSpace = line.indexOf(' ')
    if (firstSpace < 0) {
        throw new Error(`http1: malformed status-line "${line}" at offset ${msgStartAbsolute}`)
    }
    const version = line.slice(0, firstSpace)
    if (!HTTP_VERSION_RE.test(version)) {
        throw new Error(`http1: malformed status-line "${line}" at offset ${msgStartAbsolute} — bad HTTP-version "${version}"`)
    }
    // RFC 9112 §4 requires the separating space (even with an empty reason-phrase) and a
    // 3-digit status-code; both are tolerated here (logged, not rejected), since this
    // script never forwards what it parses. Only a non-numeric status-code is unrecoverable.
    const secondSpace = line.indexOf(' ', firstSpace + 1)
    const statusText = secondSpace < 0 ? line.slice(firstSpace + 1) : line.slice(firstSpace + 1, secondSpace)
    if (!/^\d+$/.test(statusText)) {
        throw new Error(`http1: malformed status-line "${line}" at offset ${msgStartAbsolute} — non-numeric status-code "${statusText}"`)
    }
    if (secondSpace < 0) {
        framer.log(`http1: status-line missing the separating space before reason-phrase at offset ${msgStartAbsolute} — tolerating empty reason-phrase ("${line}")`)
    }
    if (statusText.length !== 3) {
        framer.log(`http1: status-line status-code "${statusText}" is not exactly 3 digits at offset ${msgStartAbsolute} — tolerating ("${line}")`)
    }
    const reasonPhrase = secondSpace < 0 ? '' : line.slice(secondSpace + 1)
    return { kind: 'http-response', statusCode: Number(statusText), reasonPhrase, version, ...common }
}

// Advances a chunked body's sub-state machine (size -> data -> data-crlf -> ... -> zero-size
// chunk -> trailers -> done) as far as buf allows. Returns { pos } once the trailers' blank
// line completes the body, { pos: buf.length, truncated: true } if closed mid-way (only
// fully-parsed chunks/trailers included), or null if more data is needed.
function tryConsumeChunkedBody(buf, pos, body, bufBaseOffset, closed) {
    while (true) {
        if (body.phase === 'size') {
            const lineEnd = findLineEnd(buf, pos)
            if (lineEnd < 0) return closed ? { pos: buf.length, truncated: true } : null
            const lineBytes = buf.subarray(pos, lineEnd - 2)
            const semi = lineBytes.indexOf(SEMICOLON) // chunk-extensions, if any, are ignored
            const sizeHex = ASCII.decode(semi >= 0 ? lineBytes.subarray(0, semi) : lineBytes).trim()
            if (!/^[0-9a-fA-F]+$/.test(sizeHex)) {
                throw new Error(`http1: malformed chunk-size line at offset ${bufBaseOffset + pos}: "${ASCII.decode(lineBytes)}"`)
            }
            const size = parseInt(sizeHex, 16)
            if (size > MAX_CHUNK_SIZE) {
                throw new Error(`http1: implausible chunk size ${size} at offset ${bufBaseOffset + pos} — probably misaligned, not a real chunk boundary`)
            }
            body.curChunk = { sizeOffset: bufBaseOffset + pos, sizeLength: lineEnd - pos, size, dataOffset: bufBaseOffset + lineEnd }
            pos = lineEnd
            body.phase = size === 0 ? 'trailers' : 'data'
            if (body.phase === 'trailers') body.trailersStart = bufBaseOffset + pos
            continue
        }
        if (body.phase === 'data') {
            const need = body.curChunk.size
            if (buf.length - pos < need) return closed ? { pos: buf.length, truncated: true } : null
            pos += need
            body.phase = 'data-crlf'
            continue
        }
        if (body.phase === 'data-crlf') {
            if (buf.length - pos < 2) return closed ? { pos: buf.length, truncated: true } : null
            if (buf[pos] !== CR || buf[pos + 1] !== LF) {
                throw new Error(`http1: chunk data not followed by CRLF at offset ${bufBaseOffset + pos} — declared chunk size probably wrong`)
            }
            body.chunks.push({ sizeOffset: body.curChunk.sizeOffset, sizeLength: body.curChunk.sizeLength, dataOffset: body.curChunk.dataOffset, dataLength: body.curChunk.size })
            body.curChunk = null
            pos += 2
            body.phase = 'size'
            continue
        }
        // 'trailers'
        const r = scanHeaderLines(buf, pos, body.trailers, bufBaseOffset, body.trailersStart)
        if (!r) return closed ? { pos: buf.length, truncated: true } : null
        return { pos: r.pos }
    }
}

// Converts msg's absolute offsets to frame-relative (see doc/design/packet-dissector.md's
// field-node schema) and builds the final {offset, length, meta}.
function finishMessage(msg, bodyEndAbsolute) {
    const base = msg.msgStartAbsolute
    const rel = f => ({ ...f, offset: f.offset - base })

    const meta = {
        kind: msg.kind,
        version: msg.version,
        startLine: { offset: msg.startLineAbsolute - base, length: msg.startLineLen },
        headers: msg.headers.map(rel),
        body: { kind: msg.body.kind, offset: msg.bodyStartAbsolute - base, length: bodyEndAbsolute - msg.bodyStartAbsolute },
    }
    if (msg.kind === 'http-request') {
        meta.method = msg.method
        meta.target = msg.target
    } else {
        meta.statusCode = msg.statusCode
        meta.reasonPhrase = msg.reasonPhrase
    }
    if (msg.http09) meta.http09 = true
    if (msg.body.truncated) meta.body.truncated = true
    if (msg.body.kind === 'chunked') {
        meta.body.chunks = msg.body.chunks.map(c => ({
            sizeOffset: c.sizeOffset - base, sizeLength: c.sizeLength,
            dataOffset: c.dataOffset - base, dataLength: c.dataLength,
        }))
        meta.body.trailers = msg.body.trailers.map(rel)
    }

    return { ranges: [{ offset: base, length: bodyEndAbsolute - base }], meta }
}

function frame(state, chunk) {
    state = state || {}
    // 101 Switching Protocols: switch to WebSocket framing (RFC 6455) instead of HTTP,
    // both directions. state.ws's carry has to persist correctly across every call once
    // this branch is entered, so it's threaded through here rather than the shared
    // write-back at the bottom of this function.
    if (state.upgraded) {
        const dir = chunk.direction
        const wsState = state.ws || {}
        const sub = wsState[dir] || { carry: new Uint8Array(0), pendingMessage: null }
        const { frames, wsState: newSub } = advanceWebSocket(sub, chunk.data, chunk.offset, chunk.closed)
        return { frames, state: { ...state, ws: { ...wsState, [dir]: newSub } } }
    }
    // CONNECT tunnel: opaque bytes, both directions (e.g. TLS for an HTTPS-through-proxy
    // connection) — one raw frame per chunk rather than silence, since (unlike the
    // upgrade case) there's no better home for this data.
    if (state.tunneled) {
        return { frames: chunk.data.length > 0 ? [rawFrame(chunk.offset, chunk.data.length, 'tunnel')] : [] }
    }

    const dir = chunk.direction
    // HTTP/0.9 response: no length signal at all, and a compliant connection never sends
    // a second request — s2c alone gives up (one raw frame per chunk). c2s keeps parsing:
    // a hedge against misdetecting a corrupted stream as 0.9, so a later genuine request
    // can still resync.
    if (dir === 's2c' && state.s2cUnframable) {
        return { frames: chunk.data.length > 0 ? [rawFrame(chunk.offset, chunk.data.length, 'http09-response')] : [] }
    }
    // pendingMethods: FIFO queue of request methods, pushed when a request's headers
    // complete, shifted when a response's do. Correct pairing relies on combined mode's
    // ordering guarantee (a response's bytes never precede its request's) plus RFC 9112
    // §9.7 (responses arrive in request order) — so the queue's front is always right.
    const pendingMethods = (state.pendingMethods || []).slice()
    const sub = state[dir] || { carry: new Uint8Array(0), phase: 'start-line', msg: null }

    const buf = new Uint8Array(sub.carry.length + chunk.data.length)
    buf.set(sub.carry, 0)
    buf.set(chunk.data, sub.carry.length)
    const bufBaseOffset = chunk.offset - sub.carry.length

    let pos = 0
    let phase = sub.phase
    let msg = sub.msg
    // upgraded/tunneled safely reset to false each call — both directions short-circuit
    // at the top once either is true, so a call that would overwrite it with false never
    // happens.
    let upgraded = false
    let wsStateOnUpgrade = { carry: new Uint8Array(0), pendingMessage: null }
    let tunneled = false
    // s2cUnframable can't follow that pattern: c2s keeps running (and rewriting state)
    // after it's set, so it must be carried forward explicitly or the next c2s call
    // would silently clear it.
    let s2cUnframable = !!state.s2cUnframable
    const frames = []

    while (true) {
        if (phase === 'start-line') {
            const lineEnd = findLineEnd(buf, pos)
            if (lineEnd < 0) {
                // A stray partial line at connection close is never a coherent message —
                // nothing to frame, just stop (not an error: the capture simply ends here).
                if (chunk.closed) { pos = buf.length; break }
                if (buf.length - pos > MAX_START_LINE) {
                    throw new Error(`http1: no CRLF found within ${MAX_START_LINE} bytes looking for a start-line at offset ${bufBaseOffset + pos} (${dir}) — probably not HTTP/1, or a misaligned capture`)
                }
                break
            }
            msg = parseStartLine(buf, pos, lineEnd, dir, bufBaseOffset)
            pos = lineEnd
            if (msg.http09) {
                framer.log(`http1: request-line "${msg.method} ${msg.target}" at offset ${msg.startLineAbsolute} looks like an HTTP/0.9 simple-request (no version, no headers) — framing this request only; its response has no length signal and won't be framed`)
                msg.bodyStartAbsolute = msg.startLineAbsolute + msg.startLineLen
                msg.body = { kind: 'none' }
                frames.push(finishMessage(msg, msg.bodyStartAbsolute))
                msg = null
                phase = 'start-line'
                s2cUnframable = true
                continue
            }
            phase = 'headers'
            continue
        }

        if (phase === 'headers') {
            const r = scanHeaderLines(buf, pos, msg.headers, bufBaseOffset, msg.startLineAbsolute + msg.startLineLen)
            if (!r) {
                // Same as the start-line case: headers cut short by connection close
                // describe no complete message worth keeping.
                if (chunk.closed) { msg = null; phase = 'start-line'; pos = buf.length; break }
                break
            }
            pos = r.pos
            msg.bodyStartAbsolute = bufBaseOffset + pos

            if (dir === 'c2s') {
                msg.body = classifyRequestBody(msg.headers)
                // Once s2c has given up (HTTP/0.9), nothing will ever shift this queue
                // again — skip growing it for the rest of the connection.
                if (!s2cUnframable) pendingMethods.push(msg.method)
            } else {
                // A 1xx response (e.g. 100 Continue) is interim, not a request's final
                // response — it must not consume a pendingMethods entry, or every later
                // response's lookup shifts by one until the queue happens to re-align.
                // The request stays queued until its final (>= 200) response.
                const reqMethod = msg.statusCode >= 200 ? pendingMethods.shift() : undefined
                msg.body = classifyResponseBody(msg.headers, msg.statusCode, reqMethod)
            }

            if (msg.body.kind === 'none' || msg.body.kind === 'tunnel') {
                frames.push(finishMessage(msg, msg.bodyStartAbsolute))
                const upgrades = dir === 's2c' && msg.statusCode === 101
                const startsTunnel = dir === 's2c' && msg.body.kind === 'tunnel'
                msg = null
                phase = 'start-line'
                if (upgrades) {
                    upgraded = true
                    // Bytes already past the 101 response in this same buffer may already
                    // be WebSocket frames — parse them now (empty carry: nothing was
                    // accumulated for this direction before the upgrade), not left in a
                    // carry buffer nothing will read again.
                    if (pos < buf.length) {
                        const r = advanceWebSocket({ carry: new Uint8Array(0), pendingMessage: null }, buf.subarray(pos), bufBaseOffset + pos, chunk.closed)
                        frames.push(...r.frames)
                        wsStateOnUpgrade = r.wsState
                    }
                    pos = buf.length
                    break
                }
                if (startsTunnel) {
                    tunneled = true
                    // Bytes already past the response headers in this same buffer are
                    // tunnel payload, not a new HTTP message — hand them off as one raw
                    // frame now, since state.tunneled short-circuits future calls before
                    // they'd ever read a leftover carry.
                    if (pos < buf.length) frames.push(rawFrame(bufBaseOffset + pos, buf.length - pos, 'tunnel'))
                    pos = buf.length
                    break
                }
                continue
            }
            phase = 'body'
            continue
        }

        // phase === 'body'
        const body = msg.body
        if (body.kind === 'content-length') {
            if (buf.length - pos < body.length) {
                if (!chunk.closed) break
                body.truncated = true
                pos = buf.length
            } else {
                pos += body.length
            }
        } else if (body.kind === 'chunked') {
            const r = tryConsumeChunkedBody(buf, pos, body, bufBaseOffset, chunk.closed)
            if (!r) break
            pos = r.pos
            if (r.truncated) body.truncated = true
        } else {
            // close-delimited: length is implicit in connection close — accumulate
            // until chunk.closed. ('tunnel' never reaches here — finished as soon as
            // it's classified, above.)
            if (!chunk.closed) break
            pos = buf.length
        }

        frames.push(finishMessage(msg, bufBaseOffset + pos))
        msg = null
        phase = 'start-line'
    }

    return {
        frames,
        state: {
            ...state,
            pendingMethods,
            upgraded,
            tunneled,
            s2cUnframable,
            ...(upgraded && { ws: { ...(state.ws || {}), [dir]: wsStateOnUpgrade } }),
            // .slice(), not .subarray(): a view would keep the whole (possibly much
            // larger) accumulated buf alive in memory for as long as this carry is held.
            [dir]: { carry: buf.slice(pos), phase, msg },
        },
    }
}
