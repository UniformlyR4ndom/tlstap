// Imported by relative path rather than a bare 'fflate' specifier: unlike preact/htm (browser-
// only, resolved via the importmap), this module is also loaded directly by the Node test
// suite, which has no importmap support.
import { zipSync, unzipSync } from '../vendor/fflate.module.js'

const COMPRESS_PARAMS = [{ key: 'filename', label: 'Filename', type: 'text', default: 'data.bin' }]
const UNCOMPRESS_PARAMS = [{ key: 'entry', label: 'Entry', type: 'text', default: '' }]

function zipCompress(bytes, params) {
    const filename = params.filename || 'data.bin'
    return zipSync({ [filename]: bytes })
}

// A zip archive can hold multiple entries, but this pipeline is single-blob-in/single-blob-out.
// With `entry` left blank, a single-entry archive auto-extracts; anything else (zero or several
// entries) throws a listing of what's actually in the archive, since guessing which one the
// user wants would silently risk picking the wrong file.
function zipDecompress(bytes, params) {
    let entries
    try {
        entries = unzipSync(bytes)
    } catch (err) {
        throw new Error(`invalid zip data: ${err.message}`)
    }
    const names = Object.keys(entries)
    const requested = params.entry?.trim()
    if (requested) {
        if (!(requested in entries)) {
            throw new Error(`entry "${requested}" not found in archive (available: ${names.join(', ') || '<none>'})`)
        }
        return entries[requested]
    }
    if (names.length === 1) return entries[names[0]]
    if (names.length === 0) throw new Error('archive has no entries')
    throw new Error(`archive has multiple entries: ${names.join(', ')} — set "Entry" to pick one`)
}

export const OPERATIONS = {
    'zip-compress':   { label: 'Zip', params: COMPRESS_PARAMS, run: zipCompress },
    'zip-decompress': { label: 'Zip', params: UNCOMPRESS_PARAMS, run: zipDecompress },
}

export const COMPRESS_ALGORITHMS = [{ label: 'Zip', op: 'zip-compress' }]
export const UNCOMPRESS_ALGORITHMS = [{ label: 'Zip', op: 'zip-decompress' }]
