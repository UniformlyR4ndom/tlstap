import { h } from 'preact'
import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import htm from 'htm'
import { openStidStream, getChunkStid, getByteStid, fetchDirectionChunks } from '../api.js'
import { listFramesTimeline, getFramerScript } from '../dbdumpFramerApi.js'
import { catchUpFramer, sha256Hex } from '../framerRun.js'
import { loadStreamFramerScript, saveStreamFramerScript } from '../framerPrefs.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'
import MarkersPanel from './MarkersPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { useChunkBuffer, BATCH } from '../useChunkBuffer.js'
import { fmtByteSize, fmtDuration, fmtRelTime } from '../format.js'
import { DIRNUM_C2S, DIRNUM_S2C } from '../direction.js'

const html = htm.bind(h)

// no-op "connection" for the frame-mode useChunkBuffer instance — frames are plain REST,
// not a persistent WebSocket, but the hook's contract expects something with .close().
function openNullStream() {
    return { close() {} }
}

// Slices [offset, offset+length) out of a set of possibly-overlapping raw chunks (a
// frame's own bytes can span more than one underlying chunk).
function sliceFrameBytes(chunks, offset, length) {
    const out = new Uint8Array(length)
    const end = offset + length
    for (const c of chunks) {
        const cEnd = c.offset + c.data.length
        if (cEnd <= offset || c.offset >= end) continue
        const srcStart  = Math.max(0, offset - c.offset)
        const srcEnd    = Math.min(c.data.length, end - c.offset)
        const destStart = Math.max(0, c.offset - offset)
        out.set(c.data.subarray(srcStart, srcEnd), destStart)
    }
    return out
}

// fetchPage/getId/buildRows for the frame-mode useChunkBuffer instance. entity is the
// synthetic object built below (frameEntity). A page can contain frames from both
// directions, so covering chunks are fetched once per direction actually present in the
// page, not once overall.
async function frameFetchPage(ws, entity, startId, n) {
    const key = { session: entity.session, stream: entity.streamId, script: entity.script, scriptVersion: entity.scriptVersion }
    const frames = await listFramesTimeline(key, startId, n)
    if (frames.length === 0) return []

    const rangeByDirection = new Map() // direction -> {min, max}
    for (const f of frames) {
        const end = f.offset + f.length - 1
        const range = rangeByDirection.get(f.direction)
        if (!range) rangeByDirection.set(f.direction, { min: f.offset, max: end })
        else { range.min = Math.min(range.min, f.offset); range.max = Math.max(range.max, end) }
    }
    const chunksByDirection = new Map()
    for (const [direction, range] of rangeByDirection) {
        chunksByDirection.set(direction, await fetchDirectionChunks(entity.session, entity.streamId, direction, range.min, range.max))
    }

    return frames.map(f => ({ ...f, data: sliceFrameBytes(chunksByDirection.get(f.direction), f.offset, f.length) }))
}

// stid (inherited from whichever raw chunk a frame completes on) is the cross-direction
// ordering key. Not unique per row (multiple frames can complete on the same chunk),
// but that's fine for pagination — the server guarantees a page never splits such a group.
function frameGetId(row) {
    return row.stid
}

// No relTime (frames aren't captured, so have no timestamp). chunkId reuses the
// header's "#N" slot for the frame's own per-direction id; direction is a per-frame
// field since a page can mix both.
function frameBuildRows(frames) {
    const rows = []
    for (const f of frames) {
        rows.push({ type: 'header', stid: f.stid, chunkId: f.id, direction: f.direction, size: f.data.length })
        for (let off = 0; off < f.data.length; off += 16) {
            rows.push({ type: 'hex', direction: f.direction, bytes: f.data.slice(off, off + 16), offset: f.offset + off, localOffset: off })
        }
    }
    return rows
}

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

export default function TrafficView({ stream, globalOffset, jumpTo, refreshKey, latestStid, markers, onAddMarker, onRemoveMarker, onUpdateMarkerLabel, onMarkerJumpRequest, onImportMarkers, onSetExtractStart, onSetExtractEnd, onSetExtractRange, onLeaveStream, jumpRef, framerScripts }) {
    const [totalBytes, setTotalBytes] = useState({ up: -1, down: -1 })
    const [markersPanelCollapsed, setMarkersPanelCollapsed] = useState(false)
    const [markersWidth, handleMarkersResize] = useResizableLayout('markersWidth', { sign: -1, min: 150, max: 500 })
    const viewHeightRef = useRef(0)
    const scrollTopRef = useRef(0)

    // Framer state. frameState: 'raw' | 'framing' | 'framed'; never persisted (always
    // starts back at 'raw' on a stream (re)selection — only the script choice below
    // survives that). frameScriptRunning caches the content/version Run last used, so
    // the live-tailing effect below doesn't need to re-fetch the script on every poll tick.
    const [framerSelected, setFramerSelected] = useState('')
    const [frameState, setFrameState] = useState('raw')
    const [frameError, setFrameError] = useState(null)
    const [frameScriptRunning, setFrameScriptRunning] = useState(null) // { name, version, content }
    const [frameRefreshKey, setFrameRefreshKey] = useState(0)

    const { display, loading, error, setError, handleScrollEnd, reloadFrom, displayRef, jumpToTop, jumpToBottom } = useChunkBuffer({
        entity: stream,
        refreshKey,
        openStream: openStidStream,
        fetchPage,
        getId,
        buildRows,
        isClosed,
        latestId: latestStid,
    })

    const frameEntity = (frameState === 'framed' && frameScriptRunning && stream) ? {
        id: `${stream.id}:${frameScriptRunning.version}`,
        end: stream.end,
        session: stream.session,
        streamId: stream.id,
        script: frameScriptRunning.name,
        scriptVersion: frameScriptRunning.version,
    } : null

    const {
        display: frameDisplay,
        loading: frameLoading,
        error: frameFetchError,
        handleScrollEnd: frameHandleScrollEnd,
    } = useChunkBuffer({
        entity: frameEntity,
        refreshKey: frameRefreshKey,
        openStream: openNullStream,
        fetchPage: frameFetchPage,
        getId: frameGetId,
        buildRows: frameBuildRows,
        isClosed,
    })

    // Resets on every stream (re)selection — frame view is never remembered across a
    // switch, only which script is selected is (falls back to the global default when
    // this stream has no override of its own yet).
    useEffect(() => {
        setFrameState('raw')
        setFrameError(null)
        setFrameScriptRunning(null)
        setFramerSelected(stream ? (loadStreamFramerScript(stream.session, stream.id) ?? '') : '')
    }, [stream?.id])

    function handleFramerSelect(name) {
        setFramerSelected(name)
        if (stream) saveStreamFramerScript(stream.session, stream.id, name)
    }

    async function handleRunFramer() {
        if (!stream || !framerSelected) return
        setFrameState('framing')
        setFrameError(null)
        try {
            const content = await getFramerScript(framerSelected)
            await Promise.all([
                catchUpFramer(stream.session, stream.id, DIRNUM_C2S, framerSelected, content),
                catchUpFramer(stream.session, stream.id, DIRNUM_S2C, framerSelected, content),
            ])
            const version = await sha256Hex(content)
            saveStreamFramerScript(stream.session, stream.id, framerSelected)
            setFrameScriptRunning({ name: framerSelected, version, content })
            setFrameState('framed')
        } catch (e) {
            setFrameError(`Framer "${framerSelected}" failed: ${e.message}`)
            setFrameState('raw')
        }
    }

    // Live-tailing (eager): once frame view is active, re-runs the framer against
    // whatever's newly arrived on every central-poll tick, then tops up the frame-mode
    // hook's own buffer. Best-effort — a transient failure here just retries next tick;
    // the initial Run already surfaced a real failure via frameError.
    useEffect(() => {
        if (frameState !== 'framed' || !frameScriptRunning || !stream) return
        let cancelled = false
        ;(async () => {
            try {
                await Promise.all([
                    catchUpFramer(stream.session, stream.id, DIRNUM_C2S, frameScriptRunning.name, frameScriptRunning.content),
                    catchUpFramer(stream.session, stream.id, DIRNUM_S2C, frameScriptRunning.name, frameScriptRunning.content),
                ])
            } catch { /* best-effort; see comment above */ }
            if (!cancelled) setFrameRefreshKey(k => k + 1)
        })()
        return () => { cancelled = true }
    }, [latestStid])

    // totalBytes is independent of the hook's fetch/display state, so it gets its own effect.
    useEffect(() => {
        setTotalBytes(stream ? { up: stream.length0 ?? -1, down: stream.length1 ?? -1 } : { up: -1, down: -1 })
    }, [stream?.id])

    // Exposes the hook's jump functions for the caller's header buttons. No dependency
    // array — jumpToTop/jumpToBottom aren't stable identities from the hook, so this
    // just re-runs every render rather than risk going stale behind a gated dependency array.
    useEffect(() => { if (jumpRef) jumpRef.current = { jumpToTop, jumpToBottom } })

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
        scrollTopRef.current = scrollTop
    }, [])

    // Reports the byte position at the top of the viewport when leaving a stream, for
    // "remember stream position." Resolved lazily here (not on every scroll tick) since
    // it's only ever needed once, at leave time.
    useEffect(() => {
        const leavingStream = stream
        return () => {
            if (!leavingStream) return
            const rows = displayRef.current.rows
            let i = Math.floor(scrollTopRef.current / ROW_HEIGHT)
            while (i < rows.length && rows[i].type === 'header') i++
            const row = rows[i]
            if (row?.type === 'hex') onLeaveStream?.(leavingStream, { direction: row.direction, offset: row.offset })
        }
    }, [stream?.id])

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
    const inFrameView = frameState === 'framed'
    return html`
        <div class="traffic-view">
            <div class="stream-meta">
                <span><span class="meta-label">src</span><span class="c2s">${stream.src}</span></span>
                <span><span class="meta-label">dst</span>${stream.dst}</span>
                <span><span class="meta-label">↑</span>${fmtByteSize(up)}</span>
                <span><span class="meta-label">↓</span>${fmtByteSize(down)}</span>
                <span><span class="meta-label">duration</span>${fmtDuration(stream.start, stream.end)}</span>
                ${(inFrameView ? frameLoading : loading) && html`<span class="meta-loading">loading…</span>`}
                <span class="framer-controls">
                    <span class="meta-label">framer</span>
                    ${!inFrameView ? html`
                        <select class="goto-select" value=${framerSelected} onchange=${e => handleFramerSelect(e.target.value)}>
                            <option value="">(none)</option>
                            ${framerScripts.map(s => html`<option value=${s.name}>${s.name}</option>`)}
                        </select>
                        <button class="btn" disabled=${!framerSelected || frameState === 'framing'} onclick=${handleRunFramer}>
                            ${frameState === 'framing' ? 'Framing…' : 'Run'}
                        </button>
                    ` : html`
                        <span>${frameScriptRunning.name}</span>
                        <button class="btn" onclick=${() => setFrameState('raw')}>Show raw chunks</button>
                    `}
                </span>
            </div>
            ${error && html`<div class="error-msg">${error}</div>`}
            ${frameError && html`<div class="error-msg">${frameError}</div>`}
            ${inFrameView && frameFetchError && html`<div class="error-msg">${frameFetchError}</div>`}
            <div class="traffic-body">
                ${inFrameView ? html`
                    <${HexDump}
                        key=${frameEntity.id}
                        rows=${frameDisplay.rows}
                        onScrollEnd=${frameHandleScrollEnd}
                        scrollAdjust=${frameDisplay.scrollAdjust}
                        adjustVersion=${frameDisplay.adjustVersion}
                        scrollTo=${frameDisplay.scrollTo}
                        scrollToVersion=${frameDisplay.scrollToVersion}
                        globalOffset=${globalOffset}
                        onViewportChange=${handleViewportChange}
                        markers=${[]}
                    />
                ` : html`
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
                `}
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
