import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'
import { searchText } from '../api.js'

const html = htm.bind(h)

// ── pattern encoding helpers ──────────────────────────────────────────────────

function unescapeAscii(s) {
    return s.replace(/\\(n|r|t|\\)/g, (_, c) => ({ n: '\n', r: '\r', t: '\t', '\\': '\\' })[c])
}

// Accepts: 0xff0x00, \xff\x00, ff 00, ff,00, ff001f, 0xff 0x00, etc.
function parseHex(s) {
    const cleaned = s.replace(/(?:0x|\\x)/gi, '').replace(/[\s,]+/g, '')
    if (cleaned.length === 0) throw new Error('empty hex pattern')
    if (cleaned.length % 2 !== 0) throw new Error('odd number of hex digits')
    const bytes = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < cleaned.length; i += 2) {
        const b = parseInt(cleaned.slice(i, i + 2), 16)
        if (isNaN(b)) throw new Error(`invalid hex: "${cleaned.slice(i, i + 2)}"`)
        bytes[i / 2] = b
    }
    return bytes
}

function toUtf16(s, littleEndian) {
    const bytes = new Uint8Array(s.length * 2)
    const view  = new DataView(bytes.buffer)
    for (let i = 0; i < s.length; i++) view.setUint16(i * 2, s.charCodeAt(i), littleEndian)
    return bytes
}

function toBase64(bytes) {
    return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
}

function decodePattern(pattern, format) {
    switch (format) {
        case 'ascii':   return new TextEncoder().encode(unescapeAscii(pattern))
        case 'utf16le': return toUtf16(pattern, true)
        case 'utf16be': return toUtf16(pattern, false)
        case 'hex':     return parseHex(pattern)
        default:        throw new Error('unknown format: ' + format)
    }
}

const PLACEHOLDERS = {
    ascii:   'Pattern… (\\n \\r \\t supported)',
    utf16le: 'Pattern (UTF-16 LE)',
    utf16be: 'Pattern (UTF-16 BE)',
    hex:     '0xdeadc0de',
    regex:   'Go regex… (e.g. GET /\\S+)',
}

// ── component ─────────────────────────────────────────────────────────────────

export default function SearchPanel({ session, stream, onJump }) {
    const [pattern,     setPattern]     = useState('')
    const [format,      setFormat]      = useState('ascii')
    const [direction,   setDirection]   = useState('')   // '' = both, '0' = c→s, '1' = s→c
    const [contiguous,  setContiguous]  = useState(false)
    const [streamInput, setStreamInput] = useState('')   // empty = all streams
    const [results,     setResults]     = useState(null) // null = not yet searched
    const [searching,   setSearching]   = useState(false)
    const [error,       setError]       = useState(null)

    if (!session) return html`<div class="panel-placeholder">Select a session first</div>`

    async function handleSearch(e) {
        e?.preventDefault()
        if (!pattern) return

        let reqPattern, reqEncoding
        if (format === 'regex') {
            reqPattern  = pattern
            reqEncoding = 'regex'
        } else {
            try {
                reqPattern  = toBase64(decodePattern(pattern, format))
                reqEncoding = 'base64'
            } catch (err) {
                setError(err.message)
                return
            }
        }

        const req = { session: session.id, pattern: reqPattern, pattern_encoding: reqEncoding, contiguous }
        if (direction !== '') req.direction = parseInt(direction, 10)
        const sid = streamInput.trim()
        if (sid !== '') {
            const n = parseInt(sid, 10)
            if (!isNaN(n)) req.stream = n
        }

        setSearching(true)
        setError(null)
        setResults(null)
        try {
            setResults(await searchText(req))
        } catch (err) {
            setError(err.message)
        } finally {
            setSearching(false)
        }
    }

    const streamPlaceholder = stream ? `#${stream.id}` : 'all'

    return html`
        <div class="search-panel">
            <form class="search-form" onsubmit=${handleSearch}>
                <input
                    class="search-input"
                    type="text"
                    placeholder=${PLACEHOLDERS[format]}
                    value=${pattern}
                    oninput=${e => setPattern(e.target.value)}
                    spellcheck="false"
                />
                <select class="goto-select" value=${format} onchange=${e => setFormat(e.target.value)}>
                    <option value="ascii">ASCII</option>
                    <option value="utf16le">UTF-16 LE</option>
                    <option value="utf16be">UTF-16 BE</option>
                    <option value="hex">Hex</option>
                    <option value="regex">Regex</option>
                </select>
                <select class="goto-select" value=${direction} onchange=${e => setDirection(e.target.value)}>
                    <option value="">both</option>
                    <option value="0">c→s</option>
                    <option value="1">s→c</option>
                </select>
                <label class="search-check">
                    <input type="checkbox" checked=${contiguous} onchange=${e => setContiguous(e.target.checked)} />
                    Contiguous
                </label>
                <span class="search-stream-wrap">
                    <span class="search-stream-label">stream</span>
                    <input
                        class="search-stream-input"
                        type="text"
                        placeholder=${streamPlaceholder}
                        value=${streamInput}
                        oninput=${e => setStreamInput(e.target.value)}
                    />
                </span>
                <button class="btn" type="submit" disabled=${searching || !pattern}>
                    ${searching ? '…' : 'Search'}
                </button>
            </form>
            ${error && html`<div class="error-msg" style="padding: 4px 14px;">${error}</div>`}
            ${results !== null && html`
                <div class="search-results">
                    ${results.length === 0
                        ? html`<div class="search-no-results">No matches</div>`
                        : html`
                            <div class="search-results-header">${results.length} match${results.length === 1 ? '' : 'es'}</div>
                            ${results.map((m, idx) => html`
                                <div key=${idx} class="search-result"
                                     onclick=${() => onJump?.({ streamId: m.stream, direction: m.direction, offset: m.offset })}>
                                    <span class="search-result-stream">stream ${m.stream}</span>
                                    <span class=${'search-result-dir ' + (m.direction === 0 ? 'c2s' : 's2c')}>
                                        ${m.direction === 0 ? 'c→s' : 's→c'}
                                    </span>
                                    <span class="search-result-off">0x${m.offset.toString(16).padStart(8, '0')}</span>
                                </div>
                            `)}
                        `
                    }
                </div>
            `}
        </div>
    `
}
