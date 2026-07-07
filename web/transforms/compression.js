import { mergeUint8Arrays } from '../format.js'

// Drains a CompressionStream/DecompressionStream fully into one Uint8Array. Same
// write-then-read-until-done pattern as MarkersPanel.js's compress/decompress helpers, except
// the writer's write()/close() promises are explicitly swallowed: on malformed input, the
// stream can reject *both* the write side and the read side with the same underlying error,
// and the write-side rejection would otherwise go unhandled since nothing else awaits it — the
// read loop below is what surfaces the real error to the caller.
async function runStream(stream, bytes) {
    const writer = stream.writable.getWriter()
    const writeDone = writer.write(bytes).then(() => writer.close())
    writeDone.catch(() => {})
    const chunks = []
    const reader = stream.readable.getReader()
    for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        chunks.push(value)
    }
    return mergeUint8Arrays(chunks)
}

function compress(format, bytes) {
    return runStream(new CompressionStream(format), bytes)
}

async function decompress(format, bytes) {
    try {
        return await runStream(new DecompressionStream(format), bytes)
    } catch (err) {
        // Browsers/Node report malformed input differently (e.g. Node puts the useful text
        // in `cause.message` rather than `message`) — fall back through both.
        const detail = err.message || err.cause?.message || String(err)
        throw new Error(`invalid ${format} data: ${detail}`)
    }
}

// run() returns a Promise<Uint8Array> here rather than a plain Uint8Array — the only
// operations in the registry that do, since CompressionStream/DecompressionStream are
// inherently stream-based/async. TransformPanel's step pipeline awaits each step's result.
export const OPERATIONS = {
    'gzip-compress':      { label: 'Gzip',    run: bytes => compress('gzip', bytes) },
    'gzip-decompress':    { label: 'Gzip',    run: bytes => decompress('gzip', bytes) },
    'deflate-compress':   { label: 'Deflate', run: bytes => compress('deflate', bytes) },
    'deflate-decompress': { label: 'Deflate', run: bytes => decompress('deflate', bytes) },
}

export const COMPRESS_ALGORITHMS = [
    { label: 'Gzip', op: 'gzip-compress' },
    { label: 'Deflate', op: 'deflate-compress' },
]

export const UNCOMPRESS_ALGORITHMS = [
    { label: 'Gzip', op: 'gzip-decompress' },
    { label: 'Deflate', op: 'deflate-decompress' },
]
