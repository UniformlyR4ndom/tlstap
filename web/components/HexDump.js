import { h } from 'preact'
import { useState, useEffect, useLayoutEffect, useRef } from 'preact/hooks'
import htm from 'htm'

const html = htm.bind(h)

export const ROW_HEIGHT    = 22
const BUFFER               = 8
const PREFETCH_FRACTION    = 0.1

export default function HexDump({ rows, onScrollEnd, scrollAdjust, adjustVersion, scrollTo, scrollToVersion, globalOffset }) {
    const containerRef = useRef(null)
    const [scrollTop, setScrollTop] = useState(0)
    const [height,    setHeight]    = useState(400)
    const [sel,       setSel]       = useState(null)  // null | { direction, start, end }
    const [menu,      setMenu]      = useState(null)  // null | { x, y, bytes, baseOffset }
    const anchorRef   = useRef(null)                  // { direction, offset } of mousedown byte
    const draggingRef = useRef(false)

    useEffect(() => {
        const el = containerRef.current
        if (!el) return
        const obs = new ResizeObserver(entries => setHeight(entries[0].contentRect.height))
        obs.observe(el)
        return () => obs.disconnect()
    }, [])

    // Apply signed scroll delta synchronously before paint.
    // Negative = scroll up (front eviction); positive = scroll down (back eviction after prepend).
    useLayoutEffect(() => {
        if (adjustVersion > 0 && containerRef.current) {
            containerRef.current.scrollTop += scrollAdjust
            setScrollTop(st => st + scrollAdjust)
        }
    }, [adjustVersion])

    // Set absolute scroll position synchronously before paint (used by jump-to).
    useLayoutEffect(() => {
        if (scrollToVersion > 0 && containerRef.current) {
            containerRef.current.scrollTop = scrollTo
            setScrollTop(scrollTo)
        }
    }, [scrollToVersion])

    // After scroll stops, notify parent if near either end.
    useEffect(() => {
        const el = containerRef.current
        if (!el || !onScrollEnd) return
        const handle = () => {
            const threshold = rows.length * PREFETCH_FRACTION
            const rowsAbove = Math.floor(el.scrollTop / ROW_HEIGHT)
            const rowsBelow = rows.length - Math.ceil((el.scrollTop + el.clientHeight) / ROW_HEIGHT)
            if (rowsBelow < threshold) onScrollEnd(1)
            if (rowsAbove < threshold) onScrollEnd(-1)
        }
        el.addEventListener('scrollend', handle)
        return () => el.removeEventListener('scrollend', handle)
    }, [rows.length, onScrollEnd])

    // End drag on mouseup anywhere in the document.
    useEffect(() => {
        const up = () => { draggingRef.current = false }
        document.addEventListener('mouseup', up)
        return () => document.removeEventListener('mouseup', up)
    }, [])

    // Dismiss context menu on outside click or Escape.
    useEffect(() => {
        if (!menu) return
        const close = () => setMenu(null)
        const onKey = e => { if (e.key === 'Escape') setMenu(null) }
        document.addEventListener('mousedown', close)
        document.addEventListener('keydown', onKey)
        return () => {
            document.removeEventListener('mousedown', close)
            document.removeEventListener('keydown', onKey)
        }
    }, [!!menu])

    function getByteInfo(e) {
        const el = e.target.closest('[data-off]')
        if (!el) return null
        return { offset: parseInt(el.dataset.off, 10), direction: parseInt(el.dataset.dir, 10) }
    }

    function onMouseDown(e) {
        if (e.button !== 0) return
        const info = getByteInfo(e)
        if (!info) { setSel(null); return }
        anchorRef.current  = info
        draggingRef.current = true
        setSel({ direction: info.direction, start: info.offset, end: info.offset })
        e.preventDefault()
    }

    function onContextMenu(e) {
        e.preventDefault()
        const el = containerRef.current
        if (!el) return
        const rect = el.getBoundingClientRect()
        const absoluteY = el.scrollTop + (e.clientY - rect.top)
        const rowIndex = Math.floor(absoluteY / ROW_HEIGHT)
        if (rowIndex < 0 || rowIndex >= rows.length) return

        let result = null
        const row = rows[rowIndex]
        if (row.type === 'header') {
            result = collectChunkBytes(rowIndex)
        } else if (row.type === 'hex') {
            const info = getByteInfo(e)
            if (info && sel && sel.direction === info.direction && info.offset >= sel.start && info.offset <= sel.end) {
                result = collectSelectionBytes()
            } else {
                let hi = rowIndex - 1
                while (hi >= 0 && rows[hi].type !== 'header') hi--
                result = collectChunkBytes(hi)
            }
        }
        if (!result || result.bytes.length === 0) return
        setMenu({ x: e.clientX, y: e.clientY, ...result })
    }

    function collectChunkBytes(headerIdx) {
        const parts = []
        let baseOffset = null
        for (let i = headerIdx + 1; i < rows.length; i++) {
            if (rows[i].type === 'header') break
            if (rows[i].type === 'hex') {
                if (baseOffset === null) baseOffset = rows[i].offset
                parts.push(rows[i].bytes)
            }
        }
        return { bytes: mergeUint8Arrays(parts), baseOffset: baseOffset ?? 0 }
    }

    function collectSelectionBytes() {
        const { direction, start, end } = sel
        const parts = []
        for (const row of rows) {
            if (row.type !== 'hex' || row.direction !== direction) continue
            for (let i = 0; i < row.bytes.length; i++) {
                const off = row.offset + i
                if (off >= start && off <= end) parts.push(row.bytes[i])
            }
        }
        return { bytes: new Uint8Array(parts), baseOffset: start }
    }

    function onMouseMove(e) {
        if (!draggingRef.current) return
        const info = getByteInfo(e)
        if (!info || info.direction !== anchorRef.current.direction) return
        const anchor = anchorRef.current.offset
        setSel({ direction: info.direction, start: Math.min(anchor, info.offset), end: Math.max(anchor, info.offset) })
    }

    const startIdx     = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - BUFFER)
    const endIdx       = Math.min(rows.length, startIdx + Math.ceil(height / ROW_HEIGHT) + 2 * BUFFER)
    const topSpacer    = startIdx * ROW_HEIGHT
    const bottomSpacer = (rows.length - endIdx) * ROW_HEIGHT

    return html`
        <div class="hexdump-wrap">
            <div
                class="hexdump-scroll"
                ref=${containerRef}
                onScroll=${e => setScrollTop(e.currentTarget.scrollTop)}
                onMouseDown=${onMouseDown}
                onMouseMove=${onMouseMove}
                onContextMenu=${onContextMenu}
            >
                <div style=${{ height: topSpacer + 'px' }} />
                ${rows.slice(startIdx, endIdx).map((row, i) =>
                    row.type === 'header'
                        ? html`<${ChunkHeader} key=${startIdx + i} row=${row} />`
                        : html`<${HexRow}      key=${startIdx + i} row=${row} globalOffset=${globalOffset} sel=${sel} />`
                )}
                <div style=${{ height: bottomSpacer + 'px' }} />
            </div>
            ${menu && html`
                <div class="ctx-menu" style=${{ left: menu.x + 'px', top: menu.y + 'px' }}
                     onMouseDown=${e => e.stopPropagation()}>
                    <div class="ctx-item" onClick=${() => { navigator.clipboard.writeText(fmtAsHex(menu.bytes)); setMenu(null) }}>Copy as hex</div>
                    <div class="ctx-item" onClick=${() => { navigator.clipboard.writeText(fmtAsAscii(menu.bytes)); setMenu(null) }}>Copy as ASCII</div>
                    <div class="ctx-item" onClick=${() => { navigator.clipboard.writeText(fmtAsHexdump(menu.bytes, menu.baseOffset)); setMenu(null) }}>Copy as hexdump</div>
                    <div class="ctx-item" onClick=${() => { navigator.clipboard.writeText(fmtAsBase64(menu.bytes)); setMenu(null) }}>Copy as base64</div>
                </div>
            `}
        </div>
    `
}

function ChunkHeader({ row }) {
    const dir        = row.direction === 0 ? 'c2s' : 's2c'
    const label      = row.direction === 0 ? 'CLIENT → SERVER' : 'SERVER → CLIENT'
    const stidPart   = row.stid   != null ? ` [#${row.stid}]`   : ''
    const streamPart = row.stream != null ? `  stream ${row.stream}` : ''
    return html`
        <div class=${'chunk-hdr ' + dir}>
            ${`[${row.relTime}]${stidPart} ${label}${streamPart}  #${row.chunkId}  ${fmtBytes(row.size)}`}
        </div>
    `
}

function HexRow({ row, globalOffset, sel }) {
    const { bytes, offset, localOffset, direction } = row
    const dir    = direction === 0 ? 'c2s' : 's2c'
    const offStr = (globalOffset ? offset : localOffset).toString(16).padStart(8, '0')

    // Build hex section: '  ' leader + per-byte spans with spaces + padding + '  ' trailer.
    // Between group 1 (bytes 0-7) and group 2 (bytes 8-15) there is an extra space.
    const hexContent = ['  ']
    for (let i = 0; i < bytes.length; i++) {
        if (i === 8)    hexContent.push('  ')  // double-space group separator
        else if (i > 0) hexContent.push(' ')
        const byteOff = offset + i
        const hl = sel && sel.direction === direction && byteOff >= sel.start && byteOff <= sel.end
        hexContent.push(html`<span data-off=${byteOff} data-dir=${direction} class=${hl ? 'sel-hl' : undefined}>${bytes[i].toString(16).padStart(2, '0')}</span>`)
    }
    // Pad to 48 chars so short rows align with full rows.
    const used = bytes.length <= 8 ? bytes.length * 3 - 1 : bytes.length * 3
    if (used < 48) hexContent.push(' '.repeat(48 - used))
    hexContent.push('  ')

    // Build ASCII section: '|' + per-char spans + '|'.
    const asciiContent = ['|']
    for (let i = 0; i < bytes.length; i++) {
        const byteOff = offset + i
        const hl = sel && sel.direction === direction && byteOff >= sel.start && byteOff <= sel.end
        const ch = bytes[i] >= 0x20 && bytes[i] < 0x7f ? String.fromCharCode(bytes[i]) : '.'
        asciiContent.push(html`<span data-off=${byteOff} data-dir=${direction} class=${hl ? 'sel-hl' : undefined}>${ch}</span>`)
    }
    asciiContent.push('|')

    return html`<div class=${'hex-row ' + dir}><span class="hex-off">${offStr}</span>${hexContent}<span class="hex-asc">${asciiContent}</span></div>`
}

function fmtBytes(n) {
    if (n < 1024)    return `${n} B`
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / 1048576).toFixed(1)} MB`
}

function mergeUint8Arrays(arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const a of arrays) { out.set(a, off); off += a.length }
    return out
}

function fmtAsBase64(bytes) {
    return btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''))
}

function fmtAsHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function fmtAsAscii(bytes) {
    return Array.from(bytes, b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('')
}

function fmtAsHexdump(bytes, baseOffset) {
    const lines = []
    for (let i = 0; i < bytes.length; i += 16) {
        const slice = bytes.slice(i, i + 16)
        const off = (baseOffset + i).toString(16).padStart(8, '0')
        const hexParts = Array.from(slice, b => b.toString(16).padStart(2, '0'))
        const g1 = hexParts.slice(0, 8).join(' ').padEnd(23)
        const g2 = hexParts.slice(8).join(' ').padEnd(23)
        const asc = Array.from(slice, b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('')
        lines.push(`${off}  ${g1}  ${g2}  |${asc}|`)
    }
    return lines.join('\n')
}
