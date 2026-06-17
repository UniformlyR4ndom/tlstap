import { h } from 'preact'
import { useState, useEffect, useLayoutEffect, useRef } from 'preact/hooks'
import htm from 'htm'

const html = htm.bind(h)

export const ROW_HEIGHT = 22
const BUFFER        = 8
const PREFETCH_ROWS = 200

export default function HexDump({ rows, onScrollEnd, scrollAdjust, adjustVersion }) {
    const containerRef = useRef(null)
    const [scrollTop, setScrollTop] = useState(0)
    const [height,    setHeight]    = useState(400)

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

    // After scroll stops, notify parent if near either end.
    useEffect(() => {
        const el = containerRef.current
        if (!el || !onScrollEnd) return
        const handle = () => {
            const rowsAbove = Math.floor(el.scrollTop / ROW_HEIGHT)
            const rowsBelow = rows.length - Math.ceil((el.scrollTop + el.clientHeight) / ROW_HEIGHT)
            if (rowsBelow < PREFETCH_ROWS) onScrollEnd(1)
            if (rowsAbove < PREFETCH_ROWS) onScrollEnd(-1)
        }
        el.addEventListener('scrollend', handle)
        return () => el.removeEventListener('scrollend', handle)
    }, [rows.length, onScrollEnd])

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
            >
                <div style=${{ height: topSpacer + 'px' }} />
                ${rows.slice(startIdx, endIdx).map((row, i) =>
                    row.type === 'header'
                        ? html`<${ChunkHeader} key=${startIdx + i} row=${row} />`
                        : html`<${HexRow}      key=${startIdx + i} row=${row} />`
                )}
                <div style=${{ height: bottomSpacer + 'px' }} />
            </div>
        </div>
    `
}

function ChunkHeader({ row }) {
    const dir   = row.direction === 0 ? 'c2s' : 's2c'
    const label = row.direction === 0 ? 'CLIENT → SERVER' : 'SERVER → CLIENT'
    return html`
        <div class=${'chunk-hdr ' + dir}>
            ${`[${row.relTime}] ${label}  #${row.chunkId}  ${fmtBytes(row.size)}`}
        </div>
    `
}

function HexRow({ row }) {
    const { bytes, offset, direction } = row
    const dir     = direction === 0 ? 'c2s' : 's2c'
    const off     = offset.toString(16).padStart(8, '0')
    const hexArr  = Array.from(bytes).map(b => b.toString(16).padStart(2, '0'))
    const hex1    = hexArr.slice(0, 8).join(' ')
    const hex2    = hexArr.slice(8).join(' ')
    const hexPart = (hex2 ? hex1 + '  ' + hex2 : hex1).padEnd(48, ' ')
    const ascii   = Array.from(bytes).map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('')
    return html`
        <div class=${'hex-row ' + dir}>
            <span class="hex-off">${off}</span>${'  ' + hexPart + '  '}<span class="hex-asc">${'|' + ascii + '|'}</span>
        </div>
    `
}

function fmtBytes(n) {
    if (n < 1024)    return `${n} B`
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / 1048576).toFixed(1)} MB`
}
