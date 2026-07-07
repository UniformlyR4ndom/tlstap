import * as basic from './transforms/basic.js'
import * as numbers from './transforms/numbers.js'
import * as compression from './transforms/compression.js'
import * as zip from './transforms/zip.js'

// Registry of implemented transform operations, keyed by the op id referenced from
// ALGORITHM_SECTIONS below. An algorithm catalog entry with no matching registry entry
// renders as "[TODO]" and can't be added as a step yet.
export const OPERATIONS = {
    ...basic.OPERATIONS,
    ...numbers.OPERATIONS,
    ...compression.OPERATIONS,
    ...zip.OPERATIONS,
}

// Sections/subsections whose name starts with "Encode"/"Decode" get a label prefix (this
// covers both the Basic > Encode/Decode subsections and the flat "Encode Number"/"Decode
// Number" sections) — Encrypt/Decrypt and Compress/Uncompress are conceptually similar but
// weren't asked to be marked, so they're deliberately excluded by not matching the prefix.
function namePrefix(name) {
    if (name.startsWith('Encode')) return '[E] '
    if (name.startsWith('Decode')) return '[D] '
    return null
}

function prefixAndSort(name, algorithms) {
    const prefix = namePrefix(name)
    const prefixed = prefix ? algorithms.map(a => ({ ...a, label: prefix + a.label })) : algorithms
    return [...prefixed].sort((a, b) => a.label.localeCompare(b.label))
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
    { name: 'Hash', algorithms: [
        { label: 'MD5', op: 'md5' }, { label: 'MD2', op: 'md2' }, { label: 'MD4', op: 'md4' },
        { label: 'NTLM', op: 'ntlm' }, { label: 'SHA1', op: 'sha1' }, { label: 'SHA224', op: 'sha224' },
        { label: 'SHA256', op: 'sha256' }, { label: 'SHA384', op: 'sha384' }, { label: 'SHA512', op: 'sha512' },
        { label: 'Whirlpool', op: 'whirlpool' },
    ]},
].map(section => {
    if (section.subsections) {
        return { ...section, subsections: section.subsections.map(sub => ({ ...sub, algorithms: prefixAndSort(sub.name, sub.algorithms) })) }
    }
    return { ...section, algorithms: prefixAndSort(section.name, section.algorithms) }
})
