import { h } from 'preact'
import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import htm from 'htm'
import { openStidStream, getChunkStid, getByteStid } from '../api.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'
import MarkersPanel from './MarkersPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { useChunkBuffer, BATCH } from '../useChunkBuffer.js'
import { fmtByteSize, fmtDuration, fmtRelTime } from '../format.js'
import { DIRNUM_C2S, DIRNUM_S2C } from '../direction.js'

const html = htm.bind(h)

function fetchPage(ws, stream, start, n) {
    return ws.fetch(stream.session, stream.id, start, n)
}

function getId(row) {
    return row.stid
}

function isClosed(stream) {
    return !!stream.end
}

function buildRows(chunks, streamStart) {
    const rows = []
    for (const chunk of chunks) {
        rows.push({
            type:      'header',
            direction: chunk.direction,
            stid:      chunk.stid,
            chunkId:   chunk.chunkId,
            relTime:   fmtRelTime(chunk.time, streamStart),
            size:      chunk.data.length,
        })
        for (let off = 0; off < chunk.data.length; off += 16) {
            rows.push({
                type:        'hex',
                direction:   chunk.direction,
                bytes:       chunk.data.slice(off, off + 16),
                offset:      chunk.offset + off,
                localOffset: off,
            })
        }
    }
    return rows
}

export default function TrafficView({ stream, globalOffset, jumpTo, refreshKey, markers, onAddMarker, onRemoveMarker, onUpdateMarkerLabel, onMarkerJumpRequest, onImportMarkers, onSetExtractStart, onSetExtractEnd, onSetExtractRange }) {
    const [totalBytes, setTotalBytes] = useState({ up: -1, down: -1 })
    const [markersPanelCollapsed, setMarkersPanelCollapsed] = useState(false)
    const [markersWidth, handleMarkersResize] = useResizableLayout('markersWidth', { sign: -1, min: 150, max: 500 })
    const viewHeightRef = useRef(0)

    const { display, loading, error, setError, handleScrollEnd, reloadFrom } = useChunkBuffer({
        entity: stream,
        refreshKey,
        openStream: openStidStream,
        fetchPage,
        getId,
        buildRows,
        isClosed,
    })

    // totalBytes is independent of the hook's fetch/display state, so it gets its own effect.
    useEffect(() => {
        setTotalBytes(stream ? { up: stream.length0 ?? -1, down: stream.length1 ?? -1 } : { up: -1, down: -1 })
    }, [stream?.id])

    // Jump effect — resolves jumpTo to a target stid, then calls the hook's reloadFrom.
    // `cancelled` guards against a stale resolution superseding a newer jump.
    useEffect(() => {
        if (!jumpTo || !stream) return
        let cancelled = false

        ;(async () => {
            try {
                let targetStid = jumpTo.value
                let targetByteOffset = null
                let targetDirection = null
                if (jumpTo.unit === 'chunks-c2s' || jumpTo.unit === 'chunks-s2c') {
                    const direction = jumpTo.unit === 'chunks-c2s' ? DIRNUM_C2S : DIRNUM_S2C
                    const result = await getChunkStid(stream.session, stream.id, direction, jumpTo.value)
                    if (cancelled) return
                    targetStid = result.stid
                } else if (jumpTo.unit === 'offset-c2s' || jumpTo.unit === 'offset-s2c') {
                    const direction = jumpTo.unit === 'offset-c2s' ? DIRNUM_C2S : DIRNUM_S2C
                    const result = await getByteStid(stream.session, stream.id, direction, jumpTo.value)
                    if (cancelled) return
                    targetStid = result.stid
                    targetByteOffset = jumpTo.value
                    targetDirection = direction
                }
                if (cancelled) return

                const startStid = Math.max(0, targetStid - Math.floor(BATCH / 2))
                reloadFrom(startStid, {
                    computeExtra: rows => {
                        let targetRowPx = 0
                        for (let i = 0; i < rows.length; i++) {
                            const row = rows[i]
                            if (targetByteOffset !== null) {
                                if (row.type === 'hex' && row.direction === targetDirection && row.offset <= targetByteOffset && targetByteOffset < row.offset + row.bytes.length) {
                                    targetRowPx = i * ROW_HEIGHT
                                    break
                                }
                            } else {
                                if (row.type === 'header' && row.stid === targetStid) {
                                    targetRowPx = i * ROW_HEIGHT
                                    break
                                }
                            }
                        }
                        const scrollTo = jumpTo.align === 'top'
                            ? targetRowPx
                            : Math.max(0, targetRowPx - Math.floor(viewHeightRef.current / 2))
                        return { scrollTo, scrollToVersion: jumpTo.version }
                    },
                })
            } catch (e) {
                if (!cancelled) setError(e.message)
            }
        })()

        return () => { cancelled = true }
    }, [jumpTo?.version])

    const handleViewportChange = useCallback((scrollTop, height) => {
        viewHeightRef.current = height
    }, [])

    const handleSetMarker = useCallback((direction, offset) => {
        if (!stream) return
        onAddMarker?.({ session: stream.session, stream: stream.id, direction, offset, label: '' })
    }, [stream, onAddMarker])

    const handleClearMarker = useCallback((direction, offset) => {
        if (!stream) return
        const m = (markers ?? []).find(
            mk => mk.session === stream.session && mk.stream === stream.id && mk.direction === direction && mk.offset === offset
        )
        if (m) onRemoveMarker?.(m.id)
    }, [stream, markers, onRemoveMarker])

    const streamMarkers = (markers ?? []).filter(m => m.session === stream?.session && m.stream === stream?.id)

    if (!stream) return html`<div class="placeholder">Select a stream to view traffic</div>`

    const { up, down } = totalBytes
    return html`
        <div class="traffic-view">
            <div class="stream-meta">
                <span><span class="meta-label">src</span><span class="c2s">${stream.src}</span></span>
                <span><span class="meta-label">dst</span>${stream.dst}</span>
                <span><span class="meta-label">↑</span>${fmtByteSize(up)}</span>
                <span><span class="meta-label">↓</span>${fmtByteSize(down)}</span>
                <span><span class="meta-label">duration</span>${fmtDuration(stream.start, stream.end)}</span>
                ${loading && html`<span class="meta-loading">loading…</span>`}
            </div>
            ${error && html`<div class="error-msg">${error}</div>`}
            <div class="traffic-body">
                <${HexDump}
                    key=${stream.id}
                    rows=${display.rows}
                    onScrollEnd=${handleScrollEnd}
                    scrollAdjust=${display.scrollAdjust}
                    adjustVersion=${display.adjustVersion}
                    scrollTo=${display.scrollTo}
                    scrollToVersion=${display.scrollToVersion}
                    globalOffset=${globalOffset}
                    onSetMarker=${handleSetMarker}
                    onClearMarker=${handleClearMarker}
                    onSetExtractStart=${onSetExtractStart}
                    onSetExtractEnd=${onSetExtractEnd}
                    onSetExtractRange=${onSetExtractRange}
                    onViewportChange=${handleViewportChange}
                    markers=${streamMarkers}
                />
                ${!markersPanelCollapsed && html`<${ResizeHandle} orientation="v" onResize=${handleMarkersResize} />`}
                <${MarkersPanel}
                    markers=${(markers ?? []).filter(m => m.session === stream.session)}
                    onRemove=${onRemoveMarker}
                    onUpdateLabel=${onUpdateMarkerLabel}
                    onJump=${m => onMarkerJumpRequest?.(m)}
                    onImport=${onImportMarkers}
                    collapsed=${markersPanelCollapsed}
                    onToggle=${() => setMarkersPanelCollapsed(v => !v)}
                    width=${markersWidth}
                />
            </div>
        </div>
    `
}
