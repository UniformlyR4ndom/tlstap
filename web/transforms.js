import * as basic from './transforms/basic.js'
import * as numbers from './transforms/numbers.js'
import * as compression from './transforms/compression.js'
import * as zip from './transforms/zip.js'
import * as hash from './transforms/hash.js'

// Registry of implemented transform operations, keyed by the op id referenced from
// ALGORITHM_SECTIONS below. An algorithm catalog entry with no matching registry entry
// renders as "[TODO]" and can't be added as a step yet.
export const OPERATIONS = {
    ...basic.OPERATIONS,
    ...numbers.OPERATIONS,
    ...compression.OPERATIONS,
    ...zip.OPERATIONS,
    ...hash.OPERATIONS,
}

// Sections/subsections whose name starts with "Encode"/"Decode" get a label prefix once an
// algorithm is added to the step chain (this covers both the Basic > Encode/Decode
// subsections and the flat "Encode Number"/"Decode Number" sections) — Encrypt/Decrypt and
// Compress/Uncompress are conceptually similar but weren't asked to be marked, so they're
// deliberately excluded by not matching the prefix. Exported so TransformPanel.js can apply
// it only to step labels, not to this selection menu's catalog entries.
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
// modules under transforms/ (e.g. numbers.js feeds two separate top-level sections here).
// Sections whose algorithms run in either direction (Basic, Compression, Encryption) are
// split into two subsections. Entries with no corresponding OPERATIONS registration are
// shown as "[TODO]" and aren't selectable.
export const ALGORITHM_SECTIONS = [
    { name: 'Basic', subsections: [
        { name: 'Encode', algorithms: basic.ENCODE_ALGORITHMS },
        { name: 'Decode', algorithms: basic.DECODE_ALGORITHMS },
    ]},
    { name: 'Encode Number', algorithms: numbers.ENCODE_ALGORITHMS },
    { name: 'Decode Number', algorithms: numbers.DECODE_ALGORITHMS },
    { name: 'Compression', subsections: [
        { name: 'Compress',   algorithms: [...compression.COMPRESS_ALGORITHMS, ...zip.COMPRESS_ALGORITHMS] },
        { name: 'Uncompress', algorithms: [...compression.UNCOMPRESS_ALGORITHMS, ...zip.UNCOMPRESS_ALGORITHMS] },
    ]},
    { name: 'Checksum', algorithms: [
        { label: 'CRC16', op: 'crc16' }, { label: 'CRC32', op: 'crc32' }, { label: 'Adler32', op: 'adler32' },
    ]},
    { name: 'Encryption', subsections: [
        { name: 'Encrypt', algorithms: [] },
        { name: 'Decrypt', algorithms: [] },
    ]},
    { name: 'Hash', algorithms: hash.HASH_ALGORITHMS },
].map(section => {
    if (section.subsections) {
        return { ...section, subsections: section.subsections.map(sub => ({ ...sub, algorithms: sortAlgorithms(sub.algorithms) })) }
    }
    return { ...section, algorithms: sortAlgorithms(section.algorithms) }
})
