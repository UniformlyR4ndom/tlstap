// HTTP/1 message dissector — pairs with examples/dbdump/framer/http1-framer.js. Entirely
// metadata-driven: every field (start-line parts, headers, chunked-encoding chunks/
// trailers) was already located by the framer and handed over via frame.meta, so this
// script never re-scans raw bytes itself — same division of labor http2-dissector.js's
// "framer decodes HPACK, dissector just displays frame.meta.headers" already established.
// Unlike HTTP/2's decoded (HPACK-compressed) headers, an HTTP/1 header line *is* a literal
// byte range on the wire, so each header node below is offset/length (clickable,
// highlighting "Name: Value\r\n" in the hex view), not a content-only value.

function headerNodes(headers) {
    return headers.map(h => ({ label: h.name, offset: h.offset, length: h.length, 'display-hint': 'ascii' }))
}

function bodySub(body) {
    const sub = [{ label: 'Kind', content: body.kind }]
    if (body.truncated) sub.push({ label: 'Truncated', content: true })
    return sub
}

function chunkedBodyNode(body) {
    const sub = body.chunks.map((c, i) => ({
        label: `Chunk ${i}`,
        sub: [
            { label: 'Chunk Size', offset: c.sizeOffset, length: c.sizeLength, 'display-hint': 'ascii', sub: [{ label: 'Value', content: c.dataLength }] },
            { label: 'Chunk Data', offset: c.dataOffset, length: c.dataLength, 'display-hint': 'hexdump' },
        ],
    }))
    if (body.trailers.length > 0) {
        sub.push({ label: 'Trailers', sub: headerNodes(body.trailers) })
    }
    if (body.truncated) sub.push({ label: 'Truncated', content: true })
    return { label: 'Body', offset: body.offset, length: body.length, 'display-hint': 'hexdump', sub }
}

function bodyNode(body) {
    if (body.kind === 'none') {
        return { label: 'Body', content: '(none)' }
    }
    if (body.kind === 'chunked') {
        return chunkedBodyNode(body)
    }
    return { label: 'Body', offset: body.offset, length: body.length, 'display-hint': 'hexdump', sub: bodySub(body) }
}

function dissect(bytes, frame) {
    const meta = frame.meta
    if (!meta) {
        return [{ label: 'Message', content: '(no metadata — framer did not attach meta for this frame)' }]
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
                    { label: 'Target', content: meta.target },
                    { label: 'Version', content: meta.version },
                ]
                : [
                    { label: 'Version', content: meta.version },
                    { label: 'Status Code', content: meta.statusCode },
                    { label: 'Reason Phrase', content: meta.reasonPhrase },
                ],
        },
        { label: 'Headers', sub: headerNodes(meta.headers) },
        bodyNode(meta.body),
    ]

    return nodes
}
