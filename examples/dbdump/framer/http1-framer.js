// HTTP/1 message framer — splits a stream into individual HTTP/1.1 request/response
// messages (RFC 9112) using combined mode's shared state (see
// doc/design/framer-cross-direction-correlation.md) to resolve message-length rules that
// depend on the *other* direction's stream — most importantly, any response to a HEAD
// request has no body regardless of Content-Length (§6.3 rule 1). See
// doc/design/http1-framer.md for the full design this implements.
//
// One frame = one complete message (start-line + headers + body) — like tls-framer.js's
// one-frame-per-record, not split the way http2-framer.js splits HEADERS/DATA, since
// HTTP/1 has no independent-frame wire seam to split on. Chunked-encoding parsing
// happens here (never in the dissector), the same division of labor http2-framer.js's
// HPACK-in-the-framer already established.

const CR = 0x0d, LF = 0x0a, COLON = 0x3a, SEMICOLON = 0x3b

const MAX_START_LINE = 8 * 1024          // sanity cap while scanning for a start-line's CRLF
const MAX_HEADER_BLOCK = 1024 * 1024     // sanity cap on a whole header (or trailer) block
const MAX_CHUNK_SIZE = 256 * 1024 * 1024 // sanity cap on one chunked-encoding chunk

const HTTP_VERSION_RE = /^HTTP\/\d\.\d$/

const ASCII = new TextDecoder('latin1') // header field values are ISO-8859-1/obs-text per RFC 9110 §5.5

function findLineEnd(buf, from) {
    for (let i = from; i < buf.length - 1; i++) {
        if (buf[i] === CR && buf[i + 1] === LF) return i + 2
    }
    return -1
}

// Scans "Name: Value\r\n" lines into target (mutated in place) starting at pos, until a
// blank line (bare CRLF) terminates the block or more data is needed. Shared by the main
// header block and chunked-encoding trailers — syntactically identical. blockStart is the
// block's own absolute start offset, purely to bound MAX_HEADER_BLOCK against runaway
// buffering (a misapplied framer, or genuinely malformed input, never finding a blank
// line). Returns { pos } (the position right after the blank line) once done, or null if
// more data is needed.
function scanHeaderLines(buf, pos, target, bufBaseOffset, blockStart) {
    while (true) {
        const lineEnd = findLineEnd(buf, pos)
        if (lineEnd < 0) {
            if (bufBaseOffset + pos - blockStart > MAX_HEADER_BLOCK) {
                throw new Error(`http1: header block exceeds ${MAX_HEADER_BLOCK} bytes starting at offset ${blockStart} — probably misaligned, not a real header block`)
            }
            return null
        }
        if (lineEnd - pos === 2) return { pos: lineEnd } // blank line: end of block
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

function findHeaderValue(headers, nameLower) {
    return headers.find(h => h.name.toLowerCase() === nameLower)?.value
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

function classifyRequestBody(headers) {
    const te = findHeaderValue(headers, 'transfer-encoding')
    if (te !== undefined) {
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
    // Rule 2 (CONNECT tunnel) and rule 1 (HEAD/1xx/204/304) both ignore Content-Length/
    // Transfer-Encoding entirely, checked before either is even consulted.
    if (reqMethod === 'CONNECT' && statusCode >= 200 && statusCode < 300) {
        return { kind: 'tunnel' }
    }
    if (reqMethod === 'HEAD' || statusCode < 200 || statusCode === 204 || statusCode === 304) {
        return { kind: 'none' }
    }
    const te = findHeaderValue(headers, 'transfer-encoding')
    if (te !== undefined) {
        if (isChunkedFinal(te)) return newChunkedBody()
        // Recoverable oddity, not a hard desync (same spirit as http2-framer.js's HPACK-
        // failure latch): fall back to close-delimited rather than aborting framing.
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
        const lastSpace = line.lastIndexOf(' ')
        if (firstSpace < 0 || lastSpace === firstSpace) {
            throw new Error(`http1: malformed request-line "${line}" at offset ${msgStartAbsolute}`)
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
    const secondSpace = firstSpace < 0 ? -1 : line.indexOf(' ', firstSpace + 1)
    if (firstSpace < 0 || secondSpace < 0) {
        throw new Error(`http1: malformed status-line "${line}" at offset ${msgStartAbsolute}`)
    }
    const version = line.slice(0, firstSpace)
    const statusText = line.slice(firstSpace + 1, secondSpace)
    const reasonPhrase = line.slice(secondSpace + 1)
    if (!HTTP_VERSION_RE.test(version) || !/^\d{3}$/.test(statusText)) {
        throw new Error(`http1: malformed status-line "${line}" at offset ${msgStartAbsolute}`)
    }
    return { kind: 'http-response', statusCode: Number(statusText), reasonPhrase, version, ...common }
}

// Advances a chunked body's own sub-state machine (size -> data -> data-crlf -> size, ...,
// a zero-size chunk -> trailers -> done) as far as buf allows. Returns { pos } once the
// trailers' blank line completes the body, { pos: buf.length, truncated: true } if closed
// mid-way, or null if more data is needed (not closed). Whatever's already in body.chunks/
// body.trailers when truncated is exactly what was fully parsed before the connection
// closed — a chunk or trailer line cut short by the close isn't added.
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

// Converts msg's absolute offsets to frame-relative (per the dissector field-node schema
// — see doc/design/packet-dissector.md) and builds the final {offset, length, meta} frame.
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
    if (msg.body.truncated) meta.body.truncated = true
    if (msg.body.kind === 'chunked') {
        meta.body.chunks = msg.body.chunks.map(c => ({
            sizeOffset: c.sizeOffset - base, sizeLength: c.sizeLength,
            dataOffset: c.dataOffset - base, dataLength: c.dataLength,
        }))
        meta.body.trailers = msg.body.trailers.map(rel)
    }

    return { offset: base, length: bodyEndAbsolute - base, meta }
}

function frame(state, chunk) {
    state = state || {}
    // Once either a 101 response or a successful CONNECT tunnel is seen, the connection
    // has left HTTP entirely (both directions) — stop parsing for good, cheaply, rather
    // than attempting (and failing) to parse raw post-upgrade/tunneled bytes as HTTP.
    if (state.passthrough) return {}

    const dir = chunk.direction
    // pendingMethods: a FIFO queue of request methods, pushed on each request's headers
    // completing, shifted on each response's — correlation state shared across both
    // directions (see doc/design/framer-cross-direction-correlation.md). Correct pairing
    // relies on two guarantees established for combined mode: a response's bytes never
    // precede its request's, and responses arrive in the same order requests were sent
    // (RFC 9112 §9.7) — so the front of the queue is always the right request.
    const pendingMethods = (state.pendingMethods || []).slice()
    const sub = state[dir] || { carry: new Uint8Array(0), phase: 'start-line', msg: null }

    const buf = new Uint8Array(sub.carry.length + chunk.data.length)
    buf.set(sub.carry, 0)
    buf.set(chunk.data, sub.carry.length)
    const bufBaseOffset = chunk.offset - sub.carry.length

    let pos = 0
    let phase = sub.phase
    let msg = sub.msg
    let passthrough = false
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
            phase = 'headers'
            continue
        }

        if (phase === 'headers') {
            const r = scanHeaderLines(buf, pos, msg.headers, bufBaseOffset, msg.startLineAbsolute + msg.startLineLen)
            if (!r) {
                // Same reasoning as the start-line case: headers cut short by connection
                // close describe no complete message worth keeping.
                if (chunk.closed) { msg = null; phase = 'start-line'; pos = buf.length; break }
                break
            }
            pos = r.pos
            msg.bodyStartAbsolute = bufBaseOffset + pos

            if (dir === 'c2s') {
                msg.body = classifyRequestBody(msg.headers)
                pendingMethods.push(msg.method)
            } else {
                // A 1xx response (e.g. 100 Continue) is an interim status, not a
                // request's actual final response — it must not consume a
                // pendingMethods entry, or the real final response's own lookup (and
                // every later response's, until the queue happens to re-align) shifts
                // by one. The request stays queued until its final (>= 200) response.
                const reqMethod = msg.statusCode >= 200 ? pendingMethods.shift() : undefined
                msg.body = classifyResponseBody(msg.headers, msg.statusCode, reqMethod)
            }

            if (msg.body.kind === 'none') {
                frames.push(finishMessage(msg, msg.bodyStartAbsolute))
                const stopsHttp = dir === 's2c' && msg.statusCode === 101
                msg = null
                phase = 'start-line'
                if (stopsHttp) { passthrough = true; break }
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
            // close-delimited or tunnel: length is implicit in connection close — keep
            // accumulating until chunk.closed says there's nothing more coming.
            if (!chunk.closed) break
            pos = buf.length
        }

        frames.push(finishMessage(msg, bufBaseOffset + pos))
        const stopsHttp = dir === 's2c' && body.kind === 'tunnel'
        msg = null
        phase = 'start-line'
        if (stopsHttp) { passthrough = true; break }
    }

    return {
        frames,
        state: {
            ...state,
            pendingMethods,
            passthrough,
            // .slice(), not .subarray(): a view would keep the whole (possibly much
            // larger) accumulated buf alive in memory for as long as this carry is held.
            [dir]: { carry: buf.slice(pos), phase, msg },
        },
    }
}
