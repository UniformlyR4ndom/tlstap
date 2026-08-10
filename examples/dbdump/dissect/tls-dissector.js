// TLS record-layer dissector — breaks one TLS record frame (as produced by
// examples/dbdump/framer/tls-framer.js) into its RFC 8446 §5.1 fixed header fields:
// Content Type (1 byte), legacy_record_version (2 bytes), length (2 bytes), followed by
// the record's fragment. Deliberately shallow, per doc/design/packet-dissector.md's
// "no very deep details" scope — it doesn't descend into the fragment itself (e.g.
// handshake message parsing), only the record header every TLS record shares regardless
// of content type or encryption state (the header is never encrypted, so this dissects
// unmodified before and after encryption starts, same as the framer it pairs with).

const HEADER_LEN = 5

const CONTENT_TYPES = {
    20: 'change_cipher_spec',
    21: 'alert',
    22: 'handshake',
    23: 'application_data',
    24: 'heartbeat',
}

const VERSION_NAMES = {
    '3.0': 'SSL 3.0',
    '3.1': 'TLS 1.0',
    '3.2': 'TLS 1.1',
    '3.3': 'TLS 1.2',
    '3.4': 'TLS 1.3',
}

function dissect(bytes, frame) {
    if (bytes.length < HEADER_LEN) {
        return [{ label: 'Record', content: `truncated (${bytes.length} byte(s) loaded, need at least ${HEADER_LEN})` }]
    }

    const type      = bytes[0]
    const verMaj    = bytes[1]
    const verMin    = bytes[2]
    const length    = dissector.number.decodeU16be(bytes.slice(3, 5))
    const typeName  = CONTENT_TYPES[type] ?? `unknown(${type})`
    const versionId = `${verMaj}.${verMin}`
    const versionName = VERSION_NAMES[versionId] ?? `unknown (${versionId})`

    const nodes = [
        {
            label: 'Content Type',
            offset: 0, length: 1, 'display-hint': 'hex',
            sub: [{ label: 'Value', content: `${typeName} (${type})` }],
        },
        {
            label: 'Version',
            offset: 1, length: 2, 'display-hint': 'hex',
            sub: [{ label: 'Value', content: versionName }],
        },
        {
            label: 'Length',
            offset: 3, length: 2, 'display-hint': 'hex',
            sub: [{ label: 'Value', content: `${length} byte(s)` }],
        },
    ]

    // The dissected frame may hold less than the full record if it's still loading (see
    // TrafficView.js's onHeaderClick — dissection runs on whatever bytes are currently
    // available, not necessarily frame.length) — fragmentLength reflects that reality,
    // not the header's own declared length above.
    const fragmentLength = bytes.length - HEADER_LEN
    if (fragmentLength > 0) {
        nodes.push({
            label: 'Fragment',
            offset: HEADER_LEN, length: fragmentLength, 'display-hint': 'hexdump',
        })
    }

    return nodes
}
