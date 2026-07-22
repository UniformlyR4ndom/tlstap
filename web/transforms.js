import * as basic from './transforms/basic.js'
import * as numbers from './transforms/numbers.js'
import * as compression from './transforms/compression.js'
import * as zip from './transforms/zip.js'
import * as hash from './transforms/hash.js'
import * as checksum from './transforms/checksum.js'
import * as encryption from './transforms/encryption.js'
import * as mac from './transforms/mac.js'

// Re-exported so a dynamic importer of this module can warm up Whirlpool's WASM hasher
// before first use.
export { warmupWhirlpool } from './transforms/hash.js'

// Grouped for a script-facing API surface (`tamper.transform.<category>.<function>`) —
// deliberately independent of ALGORITHM_SECTIONS below: the UI's Encode/Decode-style
// subsections, [TODO] fallback, and alphabetical menu ordering have no bearing on that API,
// which just needs "which op ids make up which flat category". Compression merges
// compression.js + zip.js into one bucket, same as ALGORITHM_SECTIONS' Compression section
// does. Category keys use user-facing naming (`numeric`, matching the "Numeric" section)
// rather than internal module filenames (`numbers.js`).
export const OPERATIONS_BY_CATEGORY = {
    basic: basic.OPERATIONS,
    numeric: numbers.OPERATIONS,
    compression: { ...compression.OPERATIONS, ...zip.OPERATIONS },
    checksum: checksum.OPERATIONS,
    encryption: encryption.OPERATIONS,
    mac: mac.OPERATIONS,
    hash: hash.OPERATIONS,
}

// Registry of implemented transform operations, keyed by the op id referenced from
// ALGORITHM_SECTIONS below. An algorithm catalog entry with no matching registry entry
// renders as "[TODO]" and can't be added as a step yet. Flattened from
// OPERATIONS_BY_CATEGORY rather than re-spreading each category module a second time,
// so adding a category only means updating one place.
export const OPERATIONS = Object.assign({}, ...Object.values(OPERATIONS_BY_CATEGORY))

// Sections/subsections whose name starts with "Encode"/"Decode" get a label prefix once an
// algorithm is added to the step chain (this covers the Basic > Encode/Decode and
// Numeric > Encode/Decode subsections uniformly); Encrypt/Decrypt and Compress/Uncompress
// don't match the prefix and are deliberately excluded. Exported so a consumer can apply it
// only to step labels, not to this module's own catalog entries.
export function sectionPrefix(name) {
    if (name.startsWith('Encode')) return '[E] '
    if (name.startsWith('Decode')) return '[D] '
    return null
}

// Sorting only needs the plain label: every entry in a given (sub)section would receive the
// same prefix (if any) once added as a step, so applying one never changes their relative
// order — no need to prefix before sorting.
function sortAlgorithms(algorithms) {
    return [...algorithms].sort((a, b) => a.label.localeCompare(b.label))
}

// Catalog of selectable algorithms, grouped by UI section. This grouping is purely a
// presentation concern and doesn't need to match how operations are grouped into category
// modules under transforms/. Sections whose algorithms run in either direction (Basic,
// Numeric, Compression, Encryption) are split into two subsections. Entries with no
// corresponding OPERATIONS registration are shown as "[TODO]" and aren't selectable.
export const ALGORITHM_SECTIONS = [
    { name: 'Basic', subsections: [
        { name: 'Encode', algorithms: basic.ENCODE_ALGORITHMS },
        { name: 'Decode', algorithms: basic.DECODE_ALGORITHMS },
    ]},
    { name: 'Numeric', subsections: [
        { name: 'Encode', algorithms: numbers.ENCODE_ALGORITHMS },
        { name: 'Decode', algorithms: numbers.DECODE_ALGORITHMS },
    ]},
    { name: 'Compression', subsections: [
        { name: 'Compress',   algorithms: [...compression.COMPRESS_ALGORITHMS, ...zip.COMPRESS_ALGORITHMS] },
        { name: 'Uncompress', algorithms: [...compression.UNCOMPRESS_ALGORITHMS, ...zip.UNCOMPRESS_ALGORITHMS] },
    ]},
    { name: 'Checksum', algorithms: checksum.CHECKSUM_ALGORITHMS },
    { name: 'Encryption', subsections: [
        { name: 'Encrypt', algorithms: encryption.ENCRYPT_ALGORITHMS },
        { name: 'Decrypt', algorithms: encryption.DECRYPT_ALGORITHMS },
    ]},
    { name: 'Hash', algorithms: hash.HASH_ALGORITHMS },
    { name: 'MAC', algorithms: mac.MAC_ALGORITHMS },
].map(section => {
    if (section.subsections) {
        return { ...section, subsections: section.subsections.map(sub => ({ ...sub, algorithms: sortAlgorithms(sub.algorithms) })) }
    }
    return { ...section, algorithms: sortAlgorithms(section.algorithms) }
})
