import { h } from 'preact'
import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import htm from 'htm'
import { openStidStream, getChunkStid, getByteStid } from '../api.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'
import MarkersPanel from './MarkersPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { loadLayout, saveLayoutValue } from '../layout.js'

const html = htm.bind(h)

const BATCH = 50

function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }

export default function TrafficView({ stream, globalOffset, jumpTo, markers, onAddMarker, onRemoveMarker, onUpdateMarkerLabel, onMarkerJumpRequest, onImportMarkers, onSetExtractStart, onSetExtractEnd, onSetExtractRange }) {
    const [display,    setDisplay]    = useState({ rows: [], scrollAdjust: 0, adjustVersion: 0, scrollTo: 0, scrollToVersion: 0 })
    const [loading,    setLoading]    = useState(false)
    const [error,      setError]      = useState(null)
    const [totalBytes, setTotalBytes] = useState({ up: -1, down: -1 })
    const [markersPanelCollapsed, setMarkersPanelCollapsed] = useState(false)
    const [markersWidth, setMarkersWidth] = useState(() => loadLayout().markersWidth)
    const viewHeightRef = useRef(0)

    function handleMarkersResize(deltaX) {
        setMarkersWidth(w => {
            const next = clamp(w - deltaX, 150, 500)
            saveLayoutValue('markersWidth', next)
            return next
        })
    }

    // nextStidRef: first stid to load on forward scroll (exclusive upper bound of buffer)
    // prevStidRef: stid of the first chunk in the buffer (for backward scroll guard + fetch)
    const nextStidRef    = useRef(0)
    const prevStidRef    = useRef(0)
    const hasMoreRef     = useRef(false)
    const loadingMoreRef = useRef(false)
    const generationRef  = useRef(0)
    const streamRef      = useRef(stream)
    const wsRef          = useRef(null)
    useEffect(() => { streamRef.current = stream }, [stream])

    // Initial load — runs whenever the selected stream changes.
    useEffect(() => {
        if (!stream) {
            setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
            setTotalBytes({ up: -1, down: -1 })
            return
        }

        const ws = openStidStream()
        wsRef.current = ws

        generationRef.current++
        const gen = generationRef.current

        setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
        setLoading(true)
        setError(null)
        setTotalBytes({ up: stream.length0 ?? -1, down: stream.length1 ?? -1 })
        nextStidRef.current    = 0
        prevStidRef.current    = 0
        hasMoreRef.current     = false
        loadingMoreRef.current = false

        ;(async () => {
            try {
                const chunks = await ws.fetch(stream.session, stream.id, 0, BATCH)
                if (generationRef.current !== gen) return
                prevStidRef.current = chunks[0]?.stid ?? 0
                nextStidRef.current = chunks.length > 0 ? chunks[chunks.length - 1].stid + 1 : 0
                hasMoreRef.current  = chunks.length === BATCH
                setDisplay({ rows: buildRows(chunks, stream.start), scrollAdjust: 0, adjustVersion: 0 })
            } catch (e) {
                if (generationRef.current === gen) setError(e.message)
            } finally {
                if (generationRef.current === gen) setLoading(false)
            }
        })()

        return () => {
            ws.close()
            wsRef.current = null
        }
    }, [stream?.id])

    // Jump effect — fires when jumpTo.version changes.
    useEffect(() => {
        if (!jumpTo || !streamRef.current) return
        const s = streamRef.current

        // Close any in-flight WS and open a fresh one to ensure clean state.
        wsRef.current?.close()
        const ws = openStidStream()
        wsRef.current = ws

        generationRef.current++
        const gen = generationRef.current

        loadingMoreRef.current = false
        setLoading(true)
        setError(null)
        setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })

        ;(async () => {
            try {
                let targetStid = jumpTo.value
                let targetByteOffset = null
                let targetDirection = null
                if (jumpTo.unit === 'chunks-c2s' || jumpTo.unit === 'chunks-s2c') {
                    const direction = jumpTo.unit === 'chunks-c2s' ? 0 : 1
                    const result = await getChunkStid(s.session, s.id, direction, jumpTo.value)
                    if (generationRef.current !== gen) return
                    targetStid = result.stid
                } else if (jumpTo.unit === 'offset-c2s' || jumpTo.unit === 'offset-s2c') {
                    const direction = jumpTo.unit === 'offset-c2s' ? 0 : 1
                    const result = await getByteStid(s.session, s.id, direction, jumpTo.value)
                    if (generationRef.current !== gen) return
                    targetStid = result.stid
                    targetByteOffset = jumpTo.value
                    targetDirection = direction
                }
                const startStid = Math.max(0, targetStid - Math.floor(BATCH / 2))
                const chunks = await ws.fetch(s.session, s.id, startStid, BATCH)
                if (generationRef.current !== gen) return
                prevStidRef.current = chunks[0]?.stid ?? startStid
                nextStidRef.current = chunks.length > 0 ? chunks[chunks.length - 1].stid + 1 : startStid
                hasMoreRef.current  = chunks.length === BATCH
                const rows = buildRows(chunks, s.start)
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
                setDisplay({ rows, scrollAdjust: 0, adjustVersion: 0, scrollTo, scrollToVersion: jumpTo.version })
            } catch (e) {
                if (generationRef.current === gen) setError(e.message)
            } finally {
                if (generationRef.current === gen) setLoading(false)
            }
        })()
    }, [jumpTo?.version])

    // Stable callback — reads all mutable state via refs.
    const handleScrollEnd = useCallback(async (scrollDir) => {
        const goingForward = scrollDir === 1

        if (goingForward  && !hasMoreRef.current)        return
        if (!goingForward && prevStidRef.current === 0)  return
        if (loadingMoreRef.current) return

        const capturedGen    = generationRef.current
        const capturedStream = streamRef.current
        const capturedWs     = wsRef.current
        if (!capturedStream || !capturedWs) return

        loadingMoreRef.current = true
        setLoading(true)

        try {
            let chunks
            if (goingForward) {
                chunks = await capturedWs.fetch(capturedStream.session, capturedStream.id, nextStidRef.current, BATCH)
            } else {
                const start = Math.max(0, prevStidRef.current - BATCH)
                const n     = prevStidRef.current - start
                chunks = await capturedWs.fetch(capturedStream.session, capturedStream.id, start, n)
            }
            if (generationRef.current !== capturedGen) return
            if (chunks.length === 0) return

            const newChunkRows = buildRows(chunks, capturedStream.start)

            setDisplay(prev => {
                if (goingForward) {
                    const cutIdx = findChunkBoundaryNearHalf(prev.rows, 0)
                    if (cutIdx > 0) prevStidRef.current = prev.rows[cutIdx].stid
                    for (let i = newChunkRows.length - 1; i >= 0; i--) {
                        if (newChunkRows[i].type === 'header') { nextStidRef.current = newChunkRows[i].stid + 1; break }
                    }
                    hasMoreRef.current = chunks.length === BATCH
                    return {
                        rows:          [...prev.rows.slice(cutIdx), ...newChunkRows],
                        scrollAdjust:  -(cutIdx * ROW_HEIGHT),
                        adjustVersion: prev.adjustVersion + 1,
                    }
                } else {
                    const keepLen = findChunkBoundaryNearHalf(prev.rows, prev.rows.length)
                    for (let i = keepLen - 1; i >= 0; i--) {
                        if (prev.rows[i].type === 'header') { nextStidRef.current = prev.rows[i].stid + 1; break }
                    }
                    if (newChunkRows[0]?.type === 'header') prevStidRef.current = newChunkRows[0].stid
                    hasMoreRef.current = true
                    return {
                        rows:          [...newChunkRows, ...prev.rows.slice(0, keepLen)],
                        scrollAdjust:  newChunkRows.length * ROW_HEIGHT,
                        adjustVersion: prev.adjustVersion + 1,
                    }
                }
            })
        } catch (e) {
            if (generationRef.current === capturedGen) setError(e.message)
        } finally {
            loadingMoreRef.current = false
            if (generationRef.current === capturedGen) setLoading(false)
        }
    }, [])

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
                <span><span class="meta-label">↑</span>${fmtBytes(up)}</span>
                <span><span class="meta-label">↓</span>${fmtBytes(down)}</span>
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

// ── pure helpers ─────────────────────────────────────────────────────────────

function findChunkBoundaryNearHalf(rows, fallback) {
    const half = Math.floor(rows.length / 2)
    for (let i = half; i < rows.length; i++) {
        if (rows[i].type === 'header') return i
    }
    for (let i = half - 1; i >= 1; i--) {
        if (rows[i].type === 'header') return i
    }
    return fallback
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

function fmtRelTime(ms, base) {
    const d = ms - base
    return `+${Math.floor(d / 1000)}.${String(d % 1000).padStart(3, '0')}s`
}

function fmtBytes(n) {
    if (n < 0)       return '?'
    if (n < 1024)    return `${n} B`
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / 1048576).toFixed(1)} MB`
}

function fmtDuration(start, end) {
    if (!end) return 'ongoing'
    const d = end - start
    if (d < 1000)  return `${d}ms`
    if (d < 60000) return `${(d / 1000).toFixed(2)}s`
    return `${Math.floor(d / 60000)}m ${Math.floor((d % 60000) / 1000)}s`
}
