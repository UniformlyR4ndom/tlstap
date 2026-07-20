import { gzipSync, gunzipSync, deflateSync, inflateSync } from '../vendor/fflate.module.js'

function decompress(fn, format, bytes) {
    try {
        return fn(bytes)
    } catch (err) {
        // fflate throws its own short message (e.g. "invalid gzip data", "unexpected EOF") —
        // rewrapped here for a consistent "invalid <format> data: ..." message regardless of
        // which of the two malformed-input errors it happened to be.
        throw new Error(`invalid ${format} data: ${err.message || String(err)}`)
    }
}

export const OPERATIONS = {
    'gzip-compress':      { label: 'Gzip',    run: bytes => gzipSync(bytes) },
    'gzip-decompress':    { label: 'Gzip',    run: bytes => decompress(gunzipSync, 'gzip', bytes) },
    'deflate-compress':   { label: 'Deflate', run: bytes => deflateSync(bytes) },
    'deflate-decompress': { label: 'Deflate', run: bytes => decompress(inflateSync, 'deflate', bytes) },
}

export const COMPRESS_ALGORITHMS = [
    { label: 'Gzip', op: 'gzip-compress' },
    { label: 'Deflate', op: 'deflate-compress' },
]

export const UNCOMPRESS_ALGORITHMS = [
    { label: 'Gzip', op: 'gzip-decompress' },
    { label: 'Deflate', op: 'deflate-decompress' },
]
