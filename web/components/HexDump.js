import { h } from 'preact'
import { useState, useEffect, useLayoutEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import { fmtAsBase64, fmtAsHex, fmtAsAscii, fmtAsHexdump, mergeUint8Arrays, fmtByteSize } from '../format.js'
import { dirClass, DIRNUM_C2S, DIRNUM_S2C } from '../direction.js'

const html = htm.bind(h)

export const ROW_HEIGHT    = 22
const BUFFER               = 8
const PREFETCH_FRACTION    = 0.1

export default function HexDump({ rows, onScrollEnd, scrollAdjust, adjustVersion, scrollTo, scrollToVersion, globalOffset, onSetMarker, onClearMarker, onSetExtractStart, onSetExtractEnd, onSetExtractRange, onViewportChange, markers }) {
    const containerRef = useRef(null)
    const [scrollTop, setScrollTop] = useState(0)
    const [height,    setHeight]    = useState(400)
    const [sel,       setSel]       = useState(null)  // null | { direction, start, end }
    const [menu,      setMenu]      = useState(null)  // null | { x, y, bytes, baseOffset, byteInfo }
    const anchorRef   = useRef(null)                  // { direction, offset } of mousedown byte
    const draggingRef = useRef(false)
    const vpCallbackRef = useRef(onViewportChange)
    useEffect(() => { vpCallbackRef.current = onViewportChange }, [onViewportChange])

    useEffect(() => {
        const el = containerRef.current
        if (!el) return
        const obs = new ResizeObserver(entries => {
            const h = entries[0].contentRect.height
            setHeight(h)
            vpCallbackRef.current?.(el.scrollTop, h)
        })
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
        let byteInfo = null
        const row = rows[rowIndex]
        if (row.type === 'header') {
            result = collectChunkBytes(rowIndex)
        } else if (row.type === 'hex') {
            const info = getByteInfo(e)
            byteInfo = info
            if (info && sel && sel.direction === info.direction && info.offset >= sel.start && info.offset <= sel.end) {
                result = collectSelectionBytes()
                byteInfo = { ...info, selStart: sel.start, selEnd: sel.end }
            } else {
                let hi = rowIndex - 1
                while (hi >= 0 && rows[hi].type !== 'header') hi--
                result = collectChunkBytes(hi)
            }
        }
        if (!result || result.bytes.length === 0) return
        setMenu({ x: e.clientX, y: e.clientY, byteInfo, ...result })
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

    const markedC2S = markers?.length ? new Set(markers.filter(m => m.direction === DIRNUM_C2S).map(m => m.offset)) : null
    const markedS2C = markers?.length ? new Set(markers.filter(m => m.direction === DIRNUM_S2C).map(m => m.offset)) : null

    return html`
        <div class="hexdump-wrap">
            <div
                class="hexdump-scroll"
                ref=${containerRef}
                onScroll=${e => { const st = e.currentTarget.scrollTop; setScrollTop(st); onViewportChange?.(st, height) }}
                onMouseDown=${onMouseDown}
                onMouseMove=${onMouseMove}
                onContextMenu=${onContextMenu}
            >
                <div style=${{ height: topSpacer + 'px' }} />
                ${rows.slice(startIdx, endIdx).map((row, i) =>
                    row.type === 'header'
                        ? html`<${ChunkHeader} key=${startIdx + i} row=${row} />`
                        : html`<${HexRow}      key=${startIdx + i} row=${row} globalOffset=${globalOffset} sel=${sel} markedC2S=${markedC2S} markedS2C=${markedS2C} />`
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
                    ${menu.byteInfo && (onSetExtractStart || onSetExtractEnd || onSetExtractRange) && html`
                        <div class="ctx-sep" />
                        ${menu.byteInfo.selStart != null && onSetExtractRange && html`
                            <div class="ctx-item" onClick=${() => { onSetExtractRange(menu.byteInfo.direction, menu.byteInfo.selStart, menu.byteInfo.selEnd); setMenu(null) }}>Set selection (range)</div>
                        `}
                        <div class="ctx-item" onClick=${() => { onSetExtractStart?.(menu.byteInfo.direction, menu.byteInfo.offset); setMenu(null) }}>Set selection start</div>
                        <div class="ctx-item" onClick=${() => { onSetExtractEnd?.(menu.byteInfo.direction, menu.byteInfo.offset); setMenu(null) }}>Set selection end</div>
                    `}
                    ${menu.byteInfo && (onSetMarker || onClearMarker) && (() => {
                        const { direction, offset } = menu.byteInfo
                        const markedSet = direction === DIRNUM_C2S ? markedC2S : markedS2C
                        const isMarked = markedSet?.has(offset)
                        return html`
                            <div class="ctx-sep" />
                            ${isMarked
                                ? html`<div class="ctx-item" onClick=${() => { onClearMarker?.(direction, offset); setMenu(null) }}>Clear marker</div>`
                                : html`<div class="ctx-item" onClick=${() => { onSetMarker?.(direction, offset); setMenu(null) }}>Set marker</div>`
                            }
                        `
                    })()}
                </div>
            `}
        </div>
    `
}

function ChunkHeader({ row }) {
    const dir        = dirClass(row.direction)
    const label      = row.direction === DIRNUM_C2S ? 'CLIENT → SERVER' : 'SERVER → CLIENT'
    const stidPart   = row.stid   != null ? ` [#${row.stid}]`   : ''
    const streamPart = row.stream != null ? `  stream ${row.stream}` : ''
    return html`
        <div class=${'chunk-hdr ' + dir}>
            ${`[${row.relTime}]${stidPart} ${label}${streamPart}  #${row.chunkId}  ${fmtByteSize(row.size)}`}
        </div>
    `
}

function HexRow({ row, globalOffset, sel, markedC2S, markedS2C }) {
    const { bytes, offset, localOffset, direction } = row
    const dir      = dirClass(direction)
    const offStr   = (globalOffset ? offset : localOffset).toString(16).padStart(8, '0')
    const markedSet = direction === DIRNUM_C2S ? markedC2S : markedS2C

    // Build hex section: '  ' leader + per-byte spans with spaces + padding + '  ' trailer.
    // Between group 1 (bytes 0-7) and group 2 (bytes 8-15) there is an extra space.
    const hexContent = ['  ']
    for (let i = 0; i < bytes.length; i++) {
        if (i === 8)    hexContent.push('  ')  // double-space group separator
        else if (i > 0) hexContent.push(' ')
        const byteOff = offset + i
        const hl      = sel && sel.direction === direction && byteOff >= sel.start && byteOff <= sel.end
        const marked  = markedSet?.has(byteOff)
        const cls     = [hl ? 'sel-hl' : null, marked ? 'hex-byte-marked' : null].filter(Boolean).join(' ') || undefined
        hexContent.push(html`<span data-off=${byteOff} data-dir=${direction} class=${cls}>${bytes[i].toString(16).padStart(2, '0')}</span>`)
    }
    // Pad to 48 chars so short rows align with full rows.
    const used = bytes.length <= 8 ? bytes.length * 3 - 1 : bytes.length * 3
    if (used < 48) hexContent.push(' '.repeat(48 - used))
    hexContent.push('  ')

    // Build ASCII section: '|' + per-char spans + '|'.
    const asciiContent = ['|']
    for (let i = 0; i < bytes.length; i++) {
        const byteOff = offset + i
        const hl      = sel && sel.direction === direction && byteOff >= sel.start && byteOff <= sel.end
        const marked  = markedSet?.has(byteOff)
        const cls     = [hl ? 'sel-hl' : null, marked ? 'asc-byte-marked' : null].filter(Boolean).join(' ') || undefined
        const ch = bytes[i] >= 0x20 && bytes[i] < 0x7f ? String.fromCharCode(bytes[i]) : '.'
        asciiContent.push(html`<span data-off=${byteOff} data-dir=${direction} class=${cls}>${ch}</span>`)
    }
    asciiContent.push('|')

    return html`<div class=${'hex-row ' + dir}><span class="hex-off">${offStr}</span>${hexContent}<span class="hex-asc">${asciiContent}</span></div>`
}
