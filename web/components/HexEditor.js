import { h } from 'preact'
import { useState, useRef } from 'preact/hooks'
import htm from 'htm'
import { ROW_HEIGHT } from './HexDump.js'

const html = htm.bind(h)

const ROW_BYTES = 16

function insertBytes(bytes, index, newBytes) {
    const out = new Uint8Array(bytes.length + newBytes.length)
    out.set(bytes.subarray(0, index), 0)
    out.set(newBytes, index)
    out.set(bytes.subarray(index), index + newBytes.length)
    return out
}

function removeByte(bytes, index) {
    const out = new Uint8Array(bytes.length - 1)
    out.set(bytes.subarray(0, index), 0)
    out.set(bytes.subarray(index + 1), index)
    return out
}

function rowStart(index) { return index - (index % ROW_BYTES) }

// A small, non-virtualized hex/ASCII editor for typed or pasted input. Distinct from the
// read-only, virtualized HexDump.js (built for large captured traffic) — this widget only
// needs to handle modest, user-entered buffers, with a real insertion cursor.
export default function HexEditor({ bytes, onChange, style, readOnly, direction, onContextMenu }) {
    const [cursor, setCursor] = useState({ index: 0, area: 'hex' })
    const [pendingNibble, setPendingNibble] = useState(null)
    const containerRef = useRef(null)

    function moveTo(index, area) {
        setCursor({ index: clampIndex(index), area })
        setPendingNibble(null)
    }
    function clampIndex(i) { return Math.min(Math.max(i, 0), bytes.length) }

    function handleClick(e) {
        const el = e.target.closest('[data-index]')
        if (!el) return
        moveTo(parseInt(el.dataset.index, 10), el.dataset.area)
        containerRef.current?.focus()
    }

    // Reports a right-click to the caller instead of rendering any menu itself — HexEditor
    // is shared with TransformPanel, which has no notion of what a context menu here would
    // even mean, so ownership of the menu's content/behavior stays entirely with whichever
    // caller opts in by passing onContextMenu (only the Tamper detail panel does). index is
    // null when the click didn't land on a real byte or the trailing insertion cell (e.g. a
    // filler cell, or empty space below the last row) — deliberately not the same as "index
    // 0", so callers can tell "no byte position" apart from "the first byte" (see
    // TamperDetailPanel.js's Split menu item, which needs exactly that distinction).
    function handleContextMenu(e) {
        if (!onContextMenu) return
        e.preventDefault()
        const el = e.target.closest('[data-index]')
        const index = el ? parseInt(el.dataset.index, 10) : null
        onContextMenu({ index, x: e.clientX, y: e.clientY })
    }

    function handleKeyDown(e) {
        const { index, area } = cursor

        if (area === 'hex' && !e.ctrlKey && !e.metaKey && !e.altKey && /^[0-9a-fA-F]$/.test(e.key)) {
            e.preventDefault()
            if (readOnly) return
            if (pendingNibble === null) {
                setPendingNibble(e.key)
            } else {
                const value = parseInt(pendingNibble + e.key, 16)
                onChange(insertBytes(bytes, index, new Uint8Array([value])))
                setPendingNibble(null)
                setCursor({ index: index + 1, area })
            }
            return
        }
        if (area === 'ascii' && e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
            e.preventDefault()
            if (readOnly) return
            const value = e.key.charCodeAt(0) & 0xFF
            onChange(insertBytes(bytes, index, new Uint8Array([value])))
            setCursor({ index: index + 1, area })
            return
        }

        switch (e.key) {
            case 'Backspace':
                e.preventDefault()
                if (readOnly) return
                if (pendingNibble !== null) { setPendingNibble(null); return }
                if (index > 0) {
                    onChange(removeByte(bytes, index - 1))
                    setCursor({ index: index - 1, area })
                }
                return
            case 'Delete':
                e.preventDefault()
                if (readOnly) return
                if (index < bytes.length) onChange(removeByte(bytes, index))
                return
            case 'ArrowLeft':
                e.preventDefault()
                moveTo(index - 1, area)
                return
            case 'ArrowRight':
                e.preventDefault()
                moveTo(index + 1, area)
                return
            case 'ArrowUp':
                e.preventDefault()
                moveTo(index - ROW_BYTES, area)
                return
            case 'ArrowDown':
                e.preventDefault()
                moveTo(index + ROW_BYTES, area)
                return
            case 'Home':
                e.preventDefault()
                moveTo(e.ctrlKey ? 0 : rowStart(index), area)
                return
            case 'End':
                e.preventDefault()
                moveTo(e.ctrlKey ? bytes.length : Math.min(rowStart(index) + ROW_BYTES, bytes.length), area)
                return
            case 'Tab':
                e.preventDefault()
                setCursor({ index, area: area === 'hex' ? 'ascii' : 'hex' })
                setPendingNibble(null)
                return
        }
    }

    function handlePaste(e) {
        e.preventDefault()
        if (readOnly) return
        const text = e.clipboardData.getData('text')
        const { index, area } = cursor
        let newBytes
        if (area === 'hex') {
            const hexChars = text.match(/[0-9a-fA-F]/g) ?? []
            const vals = []
            for (let i = 0; i + 1 < hexChars.length; i += 2) vals.push(parseInt(hexChars[i] + hexChars[i + 1], 16))
            newBytes = new Uint8Array(vals)
        } else {
            newBytes = new Uint8Array(Array.from(text, ch => ch.charCodeAt(0) & 0xFF))
        }
        if (newBytes.length === 0) return
        onChange(insertBytes(bytes, index, newBytes))
        setCursor({ index: index + newBytes.length, area })
        setPendingNibble(null)
    }

    const rows = []
    for (let i = 0; i < bytes.length; i += ROW_BYTES) rows.push(i)
    // An empty buffer has no rows at all from the loop above, but still needs one to hold the
    // insertion cursor. A non-empty buffer never needs an extra row for this: whenever the
    // last row isn't completely full, it already renders its own trailing insertion cell (see
    // HexEditorRow below); when the last row IS exactly full (an exact multiple of ROW_BYTES),
    // deliberately don't add a further row just to hold the cursor — that would be an empty
    // hexdump line with no bytes on it.
    if (bytes.length === 0) rows.push(0)

    // Direction is optional (e.g. TransformPanel has no notion of c2s/s2c); only the Tamper
    // detail panel passes it, to get the same green/blue direction tint HexDump.js uses.
    const dirClass = direction === 0 ? 'c2s' : direction === 1 ? 's2c' : ''

    return html`
        <div
            class=${'hexed-container' + (dirClass ? ' ' + dirClass : '')}
            ref=${containerRef}
            tabIndex="0"
            onClick=${handleClick}
            onKeyDown=${handleKeyDown}
            onPaste=${handlePaste}
            onContextMenu=${handleContextMenu}
            style=${`${style ?? ''}; --hexed-row-height: ${ROW_HEIGHT}px`}
        >
            ${rows.map(rowOffset => html`
                <${HexEditorRow}
                    key=${rowOffset}
                    rowOffset=${rowOffset}
                    bytes=${bytes.subarray(rowOffset, rowOffset + ROW_BYTES)}
                    cursor=${cursor}
                    pendingNibble=${pendingNibble}
                    bufferLength=${bytes.length}
                    dirClass=${dirClass}
                />
            `)}
        </div>
    `
}

function HexEditorRow({ rowOffset, bytes, cursor, pendingNibble, bufferLength, dirClass }) {
    const offStr = rowOffset.toString(16).padStart(8, '0')

    const hexCells = []
    for (let i = 0; i < bytes.length; i++) {
        const index = rowOffset + i
        hexCells.push(renderHexCell(index, bytes[i], cursor, pendingNibble))
    }
    // Trailing insertion point at the very end of the buffer.
    if (rowOffset + bytes.length === bufferLength && bytes.length < ROW_BYTES) {
        hexCells.push(renderHexCell(bufferLength, null, cursor, pendingNibble))
    }
    // Pad short rows (only possible on the last row) out to a fixed cell count, so the ASCII
    // column stays aligned across rows instead of creeping left when the hex column shrinks.
    while (hexCells.length < ROW_BYTES) {
        hexCells.push(renderFillerCell(hexCells.length))
    }
    // Group separator between the two 8-byte halves, matching HexDump.js's hex column.
    hexCells.splice(8, 0, html`<span key="gap" class="hexed-gap"></span>`)

    const asciiCells = []
    for (let i = 0; i < bytes.length; i++) {
        const index = rowOffset + i
        asciiCells.push(renderAsciiCell(index, bytes[i], cursor))
    }

    return html`
        <div class=${'hexed-row' + (dirClass ? ' ' + dirClass : '')}>
            <span class="hexed-off">${offStr}</span>
            <span class="hexed-hex">${hexCells}</span>
            <span class="hexed-ascii">|${asciiCells}|</span>
        </div>
    `
}

function renderHexCell(index, byte, cursor, pendingNibble) {
    const isCursor = cursor.area === 'hex' && cursor.index === index
    const text = byte === null ? '  ' : byte.toString(16).padStart(2, '0')
    const display = isCursor && pendingNibble !== null ? pendingNibble + '_' : text
    const cls = ['hexed-byte', isCursor ? 'hexed-cursor' : null, isCursor && pendingNibble !== null ? 'hexed-pending' : null]
        .filter(Boolean).join(' ')
    return html`<span key=${index} data-index=${index} data-area="hex" class=${cls}> ${display}</span>`
}

// Purely cosmetic width-matching for padded-out rows — deliberately has no data-index/data-area
// so it's inert (not clickable, never matches the cursor), unlike a real/insertion-point cell.
function renderFillerCell(key) {
    return html`<span key=${'fill-' + key} class="hexed-byte">   </span>`
}

function renderAsciiCell(index, byte, cursor) {
    const isCursor = cursor.area === 'ascii' && cursor.index === index
    const ch = byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.'
    const cls = ['hexed-char', isCursor ? 'hexed-cursor' : null].filter(Boolean).join(' ')
    return html`<span key=${index} data-index=${index} data-area="ascii" class=${cls}>${ch}</span>`
}
