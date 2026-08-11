// Decode-only HPACK (RFC 7541) — turns one complete, already-reassembled HTTP/2 header
// block's bytes into a list of {name, value} pairs. Deliberately decode-only (this tool
// is a passive observer, never an HPACK encoder) and a pure function of (bytes, prior
// table state) — no cross-call state of its own. The dynamic table's per-connection,
// per-direction persistence (RFC 7541 §2.3.2) is the caller's job: a framer script
// threads the returned `table` back in on its next call via its own persisted `state`,
// the same way it already threads a byte-carry buffer between frame() calls. Reassembling
// HEADERS+CONTINUATION frames into one complete block before calling decodeHeaderBlock is
// also the caller's job — this module only ever sees one complete block at a time.
//
// Every "sym" (0-255 plus EOS=256) in HUFFMAN_TABLE, and every entry in STATIC_TABLE, is
// transcribed directly from RFC 7541 Appendices A and B — the Huffman table specifically
// via a small script parsing the RFC's own hex/length columns programmatically rather
// than by hand, then cross-checked against Kraft's inequality (the codes form a complete
// prefix-free code) and the RFC's own worked example (symbol 47 '/' = 0x18, 6 bits) — see
// hpackDecode.test.js's own structural test for the same check, so a future accidental
// edit here fails loudly rather than silently miscompiling some rarely-used byte's code.

const DEFAULT_MAX_TABLE_SIZE = 4096 // HTTP/2's SETTINGS_HEADER_TABLE_SIZE default
const MAX_INTEGER = 0x0fffffff // sanity cap against a malformed/hostile stream

// RFC 7541 Appendix A — index 1..61; resolveIndex below adds the dynamic-table offset.
export const STATIC_TABLE = [
    [':authority', ''], [':method', 'GET'], [':method', 'POST'],
    [':path', '/'], [':path', '/index.html'],
    [':scheme', 'http'], [':scheme', 'https'],
    [':status', '200'], [':status', '204'], [':status', '206'],
    [':status', '304'], [':status', '400'], [':status', '404'], [':status', '500'],
    ['accept-charset', ''], ['accept-encoding', 'gzip, deflate'], ['accept-language', ''],
    ['accept-ranges', ''], ['accept', ''], ['access-control-allow-origin', ''],
    ['age', ''], ['allow', ''], ['authorization', ''], ['cache-control', ''],
    ['content-disposition', ''], ['content-encoding', ''], ['content-language', ''],
    ['content-length', ''], ['content-location', ''], ['content-range', ''],
    ['content-type', ''], ['cookie', ''], ['date', ''], ['etag', ''], ['expect', ''],
    ['expires', ''], ['from', ''], ['host', ''], ['if-match', ''],
    ['if-modified-since', ''], ['if-none-match', ''], ['if-range', ''],
    ['if-unmodified-since', ''], ['last-modified', ''], ['link', ''], ['location', ''],
    ['max-forwards', ''], ['proxy-authenticate', ''], ['proxy-authorization', ''],
    ['range', ''], ['referer', ''], ['refresh', ''], ['retry-after', ''], ['server', ''],
    ['set-cookie', ''], ['strict-transport-security', ''], ['transfer-encoding', ''],
    ['user-agent', ''], ['vary', ''], ['via', ''], ['www-authenticate', ''],
]

// RFC 7541 Appendix B — indexed by symbol (0-255 = that octet value, 256 = EOS), each
// entry [code, bitLength]. code is the Huffman code aligned to its LSB (i.e. the value
// you'd get reading the code's bits as a plain binary number), matching the RFC's own
// "code as hex ... aligned to LSB" column.
export const HUFFMAN_TABLE = [
    [0x1ff8, 13], [0x7fffd8, 23], [0xfffffe2, 28], [0xfffffe3, 28],
    [0xfffffe4, 28], [0xfffffe5, 28], [0xfffffe6, 28], [0xfffffe7, 28],
    [0xfffffe8, 28], [0xffffea, 24], [0x3ffffffc, 30], [0xfffffe9, 28],
    [0xfffffea, 28], [0x3ffffffd, 30], [0xfffffeb, 28], [0xfffffec, 28],
    [0xfffffed, 28], [0xfffffee, 28], [0xfffffef, 28], [0xffffff0, 28],
    [0xffffff1, 28], [0xffffff2, 28], [0x3ffffffe, 30], [0xffffff3, 28],
    [0xffffff4, 28], [0xffffff5, 28], [0xffffff6, 28], [0xffffff7, 28],
    [0xffffff8, 28], [0xffffff9, 28], [0xffffffa, 28], [0xffffffb, 28],
    [0x14, 6], [0x3f8, 10], [0x3f9, 10], [0xffa, 12],
    [0x1ff9, 13], [0x15, 6], [0xf8, 8], [0x7fa, 11],
    [0x3fa, 10], [0x3fb, 10], [0xf9, 8], [0x7fb, 11],
    [0xfa, 8], [0x16, 6], [0x17, 6], [0x18, 6],
    [0x0, 5], [0x1, 5], [0x2, 5], [0x19, 6],
    [0x1a, 6], [0x1b, 6], [0x1c, 6], [0x1d, 6],
    [0x1e, 6], [0x1f, 6], [0x5c, 7], [0xfb, 8],
    [0x7ffc, 15], [0x20, 6], [0xffb, 12], [0x3fc, 10],
    [0x1ffa, 13], [0x21, 6], [0x5d, 7], [0x5e, 7],
    [0x5f, 7], [0x60, 7], [0x61, 7], [0x62, 7],
    [0x63, 7], [0x64, 7], [0x65, 7], [0x66, 7],
    [0x67, 7], [0x68, 7], [0x69, 7], [0x6a, 7],
    [0x6b, 7], [0x6c, 7], [0x6d, 7], [0x6e, 7],
    [0x6f, 7], [0x70, 7], [0x71, 7], [0x72, 7],
    [0xfc, 8], [0x73, 7], [0xfd, 8], [0x1ffb, 13],
    [0x7fff0, 19], [0x1ffc, 13], [0x3ffc, 14], [0x22, 6],
    [0x7ffd, 15], [0x3, 5], [0x23, 6], [0x4, 5],
    [0x24, 6], [0x5, 5], [0x25, 6], [0x26, 6],
    [0x27, 6], [0x6, 5], [0x74, 7], [0x75, 7],
    [0x28, 6], [0x29, 6], [0x2a, 6], [0x7, 5],
    [0x2b, 6], [0x76, 7], [0x2c, 6], [0x8, 5],
    [0x9, 5], [0x2d, 6], [0x77, 7], [0x78, 7],
    [0x79, 7], [0x7a, 7], [0x7b, 7], [0x7ffe, 15],
    [0x7fc, 11], [0x3ffd, 14], [0x1ffd, 13], [0xffffffc, 28],
    [0xfffe6, 20], [0x3fffd2, 22], [0xfffe7, 20], [0xfffe8, 20],
    [0x3fffd3, 22], [0x3fffd4, 22], [0x3fffd5, 22], [0x7fffd9, 23],
    [0x3fffd6, 22], [0x7fffda, 23], [0x7fffdb, 23], [0x7fffdc, 23],
    [0x7fffdd, 23], [0x7fffde, 23], [0xffffeb, 24], [0x7fffdf, 23],
    [0xffffec, 24], [0xffffed, 24], [0x3fffd7, 22], [0x7fffe0, 23],
    [0xffffee, 24], [0x7fffe1, 23], [0x7fffe2, 23], [0x7fffe3, 23],
    [0x7fffe4, 23], [0x1fffdc, 21], [0x3fffd8, 22], [0x7fffe5, 23],
    [0x3fffd9, 22], [0x7fffe6, 23], [0x7fffe7, 23], [0xffffef, 24],
    [0x3fffda, 22], [0x1fffdd, 21], [0xfffe9, 20], [0x3fffdb, 22],
    [0x3fffdc, 22], [0x7fffe8, 23], [0x7fffe9, 23], [0x1fffde, 21],
    [0x7fffea, 23], [0x3fffdd, 22], [0x3fffde, 22], [0xfffff0, 24],
    [0x1fffdf, 21], [0x3fffdf, 22], [0x7fffeb, 23], [0x7fffec, 23],
    [0x1fffe0, 21], [0x1fffe1, 21], [0x3fffe0, 22], [0x1fffe2, 21],
    [0x7fffed, 23], [0x3fffe1, 22], [0x7fffee, 23], [0x7fffef, 23],
    [0xfffea, 20], [0x3fffe2, 22], [0x3fffe3, 22], [0x3fffe4, 22],
    [0x7ffff0, 23], [0x3fffe5, 22], [0x3fffe6, 22], [0x7ffff1, 23],
    [0x3ffffe0, 26], [0x3ffffe1, 26], [0xfffeb, 20], [0x7fff1, 19],
    [0x3fffe7, 22], [0x7ffff2, 23], [0x3fffe8, 22], [0x1ffffec, 25],
    [0x3ffffe2, 26], [0x3ffffe3, 26], [0x3ffffe4, 26], [0x7ffffde, 27],
    [0x7ffffdf, 27], [0x3ffffe5, 26], [0xfffff1, 24], [0x1ffffed, 25],
    [0x7fff2, 19], [0x1fffe3, 21], [0x3ffffe6, 26], [0x7ffffe0, 27],
    [0x7ffffe1, 27], [0x3ffffe7, 26], [0x7ffffe2, 27], [0xfffff2, 24],
    [0x1fffe4, 21], [0x1fffe5, 21], [0x3ffffe8, 26], [0x3ffffe9, 26],
    [0xffffffd, 28], [0x7ffffe3, 27], [0x7ffffe4, 27], [0x7ffffe5, 27],
    [0xfffec, 20], [0xfffff3, 24], [0xfffed, 20], [0x1fffe6, 21],
    [0x3fffe9, 22], [0x1fffe7, 21], [0x1fffe8, 21], [0x7ffff3, 23],
    [0x3fffea, 22], [0x3fffeb, 22], [0x1ffffee, 25], [0x1ffffef, 25],
    [0xfffff4, 24], [0xfffff5, 24], [0x3ffffea, 26], [0x7ffff4, 23],
    [0x3ffffeb, 26], [0x7ffffe6, 27], [0x3ffffec, 26], [0x3ffffed, 26],
    [0x7ffffe7, 27], [0x7ffffe8, 27], [0x7ffffe9, 27], [0x7ffffea, 27],
    [0x7ffffeb, 27], [0xffffffe, 28], [0x7ffffec, 27], [0x7ffffed, 27],
    [0x7ffffee, 27], [0x7ffffef, 27], [0x7fffff0, 27], [0x3ffffee, 26],
    [0x3fffffff, 30], // 256 = EOS
]

// Built once at module load: a binary trie keyed by bit ('0'/'1' child), leaf nodes
// carry `sym`. Exported for hpackDecode.test.js's own from-scratch structural checks
// (Kraft's inequality, prefix-freedom) against HUFFMAN_TABLE directly, independent of
// this tree-building code.
function buildHuffmanTree() {
    const root = {}
    for (let sym = 0; sym < HUFFMAN_TABLE.length; sym++) {
        const [code, length] = HUFFMAN_TABLE[sym]
        let node = root
        for (let i = length - 1; i >= 0; i--) {
            const bit = (code >>> i) & 1
            const key = bit ? 'one' : 'zero'
            if (!node[key]) node[key] = {}
            node = node[key]
        }
        node.sym = sym
    }
    return root
}
const HUFFMAN_TREE = buildHuffmanTree()

function bytesToLatin1(bytes) {
    let s = ''
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
    return s
}

// RFC 7541 §5.1 — prefix-continuation variable-length integer, starting at bit 0 of
// bytes[offset] (i.e. offset already points past whichever representation-type bits
// precede the prefix — those are the caller's concern, not this function's).
export function decodeInteger(bytes, offset, prefixBits) {
    if (offset >= bytes.length) throw new Error('hpack: truncated integer')
    const prefixMax = (1 << prefixBits) - 1
    const value0 = bytes[offset] & prefixMax
    if (value0 < prefixMax) return { value: value0, nextOffset: offset + 1 }

    let value = value0
    let pos = offset + 1
    let m = 0
    for (;;) {
        if (pos >= bytes.length) throw new Error('hpack: truncated integer')
        const b = bytes[pos]
        value += (b & 0x7f) * 2 ** m
        pos++
        if (value > MAX_INTEGER) throw new Error('hpack: integer too large')
        if ((b & 0x80) === 0) break
        m += 7
    }
    return { value, nextOffset: pos }
}

// RFC 7541 Appendix B / §5.2's Huffman decoding: a bit-by-bit walk of HUFFMAN_TREE
// (no dynamic tree construction needed — unlike DEFLATE, HPACK's Huffman code is a
// single fixed spec constant, which is the whole reason this is small enough to
// hand-write instead of vendoring a library, the way fflate is vendored for DEFLATE).
// Trailing padding bits (up to 7, always 1-bits — HUFFMAN_TABLE's EOS entry is all
// 1s, so "a prefix of EOS" and "all 1 bits" are the same requirement here) are valid;
// anything else left over, or the EOS symbol appearing as if it were real content, is a
// decoding error per §5.2.
function decodeHuffmanString(bytes) {
    let node = HUFFMAN_TREE
    let result = ''
    let pendingBits = 0
    let pendingAllOnes = true
    for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]
        for (let b = 7; b >= 0; b--) {
            const bit = (byte >> b) & 1
            node = bit ? node.one : node.zero
            if (!node) throw new Error('hpack: invalid Huffman code')
            pendingBits++
            if (bit === 0) pendingAllOnes = false
            if (node.sym !== undefined) {
                if (node.sym === 256) throw new Error('hpack: EOS symbol found in Huffman-encoded string')
                result += String.fromCharCode(node.sym)
                node = HUFFMAN_TREE
                pendingBits = 0
                pendingAllOnes = true
            }
        }
    }
    if (node !== HUFFMAN_TREE && (!pendingAllOnes || pendingBits > 7)) {
        throw new Error('hpack: invalid Huffman padding')
    }
    return result
}

// RFC 7541 §5.2 — 1-bit Huffman flag, 7-bit-prefix length, then that many octets (either
// raw or Huffman-encoded).
function decodeString(bytes, offset) {
    if (offset >= bytes.length) throw new Error('hpack: truncated string literal')
    const huffman = (bytes[offset] & 0x80) !== 0
    const { value: length, nextOffset } = decodeInteger(bytes, offset, 7)
    const end = nextOffset + length
    if (end > bytes.length) throw new Error('hpack: truncated string literal')
    const raw = bytes.subarray(nextOffset, end)
    const value = huffman ? decodeHuffmanString(raw) : bytesToLatin1(raw)
    return { value, nextOffset: end }
}

function entrySize(name, value) {
    return 32 + name.length + value.length // RFC §4.1 — name/value are byte-preserving strings, so .length is the octet count
}

// RFC §4.4: inserting an entry larger than maxSize (on its own) empties the table
// entirely rather than erroring — the eviction loop below produces that outcome without
// needing to special-case it, since it evicts the new entry itself once nothing else is
// left to evict.
function insertEntry(table, name, value) {
    const entries = [{ name, value }, ...table.entries]
    let total = table.size + entrySize(name, value)
    while (total > table.maxSize && entries.length > 0) {
        const evicted = entries.pop()
        total -= entrySize(evicted.name, evicted.value)
    }
    return { entries, size: total, maxSize: table.maxSize }
}

// RFC §6.3 — an in-band Dynamic Table Size Update. This is the only source of truth this
// module uses for the table's max size; it deliberately never tracks SETTINGS frames; see
// this file's header comment.
function applySizeUpdate(table, newMaxSize) {
    const entries = table.entries.slice()
    let total = table.size
    while (total > newMaxSize && entries.length > 0) {
        const evicted = entries.pop()
        total -= entrySize(evicted.name, evicted.value)
    }
    return { entries, size: total, maxSize: newMaxSize }
}

// index is 1-based per RFC §2.3.3: 1..STATIC_TABLE.length is the static table;
// STATIC_TABLE.length+1.. is the dynamic table, newest entry first (so it lines up
// directly with table.entries' own newest-first order, no reversal needed).
function resolveIndex(index, table) {
    if (index >= 1 && index <= STATIC_TABLE.length) {
        const [name, value] = STATIC_TABLE[index - 1]
        return { name, value }
    }
    const dynIdx = index - STATIC_TABLE.length - 1
    if (dynIdx >= 0 && dynIdx < table.entries.length) {
        return table.entries[dynIdx]
    }
    throw new Error(`hpack: header field index ${index} out of range`)
}

// Decodes one complete header block (already reassembled across HEADERS/CONTINUATION
// frames by the caller — see this file's header comment). table is the previous call's
// returned table, or undefined/null for a direction's first block (treated as an empty
// table at the default max size — mirrors how state.carry starts undefined in the
// existing example framers). Returns { headers: [{name, value}], table }. Throws on
// malformed input (bad integer/Huffman encoding, out-of-range table index) rather than
// a silent best-effort decode, matching this codebase's other framer/dissector examples'
// "throw on implausible input" convention.
export function decodeHeaderBlock(bytes, table) {
    let t = table ?? { entries: [], size: 0, maxSize: DEFAULT_MAX_TABLE_SIZE }
    const headers = []
    let pos = 0

    while (pos < bytes.length) {
        const first = bytes[pos]

        if (first & 0x80) {
            // §6.1 Indexed Header Field
            const { value: index, nextOffset } = decodeInteger(bytes, pos, 7)
            if (index === 0) throw new Error('hpack: indexed header field index 0 is invalid')
            headers.push(resolveIndex(index, t))
            pos = nextOffset
        } else if (first & 0x40) {
            // §6.2.1 Literal Header Field with Incremental Indexing
            const { value: index, nextOffset } = decodeInteger(bytes, pos, 6)
            pos = nextOffset
            let name
            if (index === 0) {
                const r = decodeString(bytes, pos)
                name = r.value
                pos = r.nextOffset
            } else {
                name = resolveIndex(index, t).name
            }
            const r = decodeString(bytes, pos)
            headers.push({ name, value: r.value })
            t = insertEntry(t, name, r.value)
            pos = r.nextOffset
        } else if (first & 0x20) {
            // §6.3 Dynamic Table Size Update
            const { value: newMaxSize, nextOffset } = decodeInteger(bytes, pos, 5)
            t = applySizeUpdate(t, newMaxSize)
            pos = nextOffset
        } else {
            // §6.2.2 Literal without Indexing (0000xxxx) / §6.2.3 Literal Never Indexed
            // (0001xxxx) — same 4-bit-prefix wire shape, identical decoding; the only
            // difference between them is a "don't cache me" hint to a re-encoding
            // intermediary, irrelevant to a passive decoder, so both fall through here.
            const { value: index, nextOffset } = decodeInteger(bytes, pos, 4)
            pos = nextOffset
            let name
            if (index === 0) {
                const r = decodeString(bytes, pos)
                name = r.value
                pos = r.nextOffset
            } else {
                name = resolveIndex(index, t).name
            }
            const r = decodeString(bytes, pos)
            headers.push({ name, value: r.value })
            pos = r.nextOffset
        }
    }

    return { headers, table: t }
}
