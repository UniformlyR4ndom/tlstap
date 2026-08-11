import { h } from 'preact'
import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import htm from 'htm'
import { getChunkStid, getByteStid } from '../api.js'
import { getFramerScript, clearStreamFrames } from '../dbdumpFramerApi.js'
import { catchUpFramer, sha256Hex } from '../framerRun.js'
import { loadStreamFramerScript, saveStreamFramerScript } from '../framerPrefs.js'
import { loadStreamDissectScript, saveStreamDissectScript } from '../dissectPrefs.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'
import DissectPanel from './DissectPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { useByteBuffer, FILL_TARGET_SEGMENTS } from '../useByteBuffer.js'
import { openConnection as openChunkSegments, fillForward as fillChunkForward, fillBackward as fillChunkBackward } from '../chunkSegments.js'
import { openConnection as openFrameSegments, fillForward as fillFrameForward, fillBackward as fillFrameBackward } from '../frameSegments.js'
import { fmtByteSize, fmtDuration, fmtLogArgs } from '../format.js'
import { DIRNUM_C2S, DIRNUM_S2C } from '../direction.js'

const html = htm.bind(h)

function isClosed(stream) {
    return !!stream.end
}

// The downstream (client-facing) TLS session's negotiated parameters, or null for a
// plain-mode proxy or a detecttls connection that hasn't upgraded (yet) — mirrors
// proxy.ConnInfo.TLS's own nil convention. tls_version is the presence check (matches
// the backend's own NULL-guard column — see dbdump's ConnectionUpgraded).
function streamTlsInfo(stream) {
    return stream.tls_version != null
        ? { sni: stream.sni, alpn: stream.alpn, version: stream.tls_version, cipherSuite: stream.cipher_suite }
        : null
}

export default function TrafficView({ stream, globalOffset, sizeFormat, pinHeader, jumpTo, refreshKey, latestStid, markers, onAddMarker, onRemoveMarker, onSetExtractStart, onSetExtractEnd, onSetExtractRange, onLeaveStream, jumpRef, framerScripts, onFramerLog, onFramerLogReset, dissectScripts }) {
    const [totalBytes, setTotalBytes] = useState({ up: -1, down: -1 })
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

    // Dissector state (frame view only). selectedFrame: null | { key, frame: {offset,
    // length, direction, kind, meta}, bytes } — set by clicking a frame's header row
    // (HexDump's onHeaderClick), built entirely from what's already loaded (see
    // handleFrameHeaderClick below), no fetch of its own. dissectHighlight: null |
    // {direction, start, end}, absolute stream offsets, set by clicking a field node.
    // Both are invalidated (not just left stale) wherever the frame timeline itself is —
    // a stream switch, leaving frame view, or a fresh Run, all of which can make the
    // previously-selected frame's key meaningless.
    const [dissectorSelected, setDissectorSelected] = useState('')
    const [selectedFrame, setSelectedFrame] = useState(null)
    const [dissectHighlight, setDissectHighlight] = useState(null)
    const [dissectPanelWidth, handleDissectPanelResize] = useResizableLayout('dissectPanelWidth', { sign: -1, min: 200, max: 500 })

    const {
        display, loading, error, setError, handleScrollEnd, reloadFrom, displayRef,
        jumpToTop, jumpToBottom, jumpToNextSegment, jumpToPrevSegment,
    } = useByteBuffer({
        entity: stream,
        refreshKey,
        openConnection: openChunkSegments,
        fillForward: fillChunkForward,
        fillBackward: fillChunkBackward,
        isClosed,
        latestId: latestStid,
    })

    const inFrameView = frameState === 'framed'

    const frameEntity = (inFrameView && frameScriptRunning && stream) ? {
        id: `${stream.id}:${frameScriptRunning.version}`,
        end: stream.end,
        start: stream.start,
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
        jumpToTop: frameJumpToTop,
        jumpToBottom: frameJumpToBottom,
        jumpToNextSegment: frameJumpToNextSegment,
        jumpToPrevSegment: frameJumpToPrevSegment,
    } = useByteBuffer({
        entity: frameEntity,
        refreshKey: frameRefreshKey,
        openConnection: openFrameSegments,
        fillForward: fillFrameForward,
        fillBackward: fillFrameBackward,
        isClosed,
        // A frame's own stid is always that of the raw chunk containing its last byte, so
        // the chunk-level latestStid is a valid upper bound for "the end" of the frame
        // timeline too, even though it's not literally the latest frame's own id — good
        // enough for jumpToBottom below. This also means this hook's own live-poll top-up
        // reaction can fire alongside the live-tailing effect further down; harmless (a
        // redundant top-up when nothing's new is one cheap metadata query), not worth
        // suppressing separately.
        latestId: latestStid,
    })

    // Resets on every stream (re)selection — frame view is never remembered across a
    // switch, only which script is selected is (falls back to the global default when
    // this stream has no override of its own yet).
    useEffect(() => {
        setFrameState('raw')
        setFrameError(null)
        setFrameScriptRunning(null)
        setFramerSelected(stream ? (loadStreamFramerScript(stream.session, stream.id) ?? '') : '')
        setDissectorSelected(stream ? (loadStreamDissectScript(stream.session, stream.id) ?? '') : '')
        setSelectedFrame(null)
        setDissectHighlight(null)
        onFramerLogReset?.()
    }, [stream?.id])

    function handleFramerSelect(name) {
        setFramerSelected(name)
        if (stream) saveStreamFramerScript(stream.session, stream.id, name)
    }

    function handleDissectorSelect(name) {
        setDissectorSelected(name)
        if (stream) saveStreamDissectScript(stream.session, stream.id, name)
    }

    function handleShowRawChunks() {
        setFrameState('raw')
        setSelectedFrame(null)
        setDissectHighlight(null)
    }

    // A frame's own header row, from HexDump's onHeaderClick — bytesInfo is exactly what
    // collectChunkBytes(headerIdx) already computes for the context menu (bytes currently
    // loaded starting at baseOffset), reused as-is rather than a second fetch: no
    // guarantee the whole frame is loaded for a still-partially-loaded huge one, so
    // dissection simply runs on whatever's available (see DissectPanel.js's own note).
    // kind is hoisted out of the framer's own free-form meta by convention (no dedicated
    // backend field for it) — see doc/design/packet-dissector.md.
    function handleFrameHeaderClick(row, bytesInfo) {
        setSelectedFrame({
            key: `${row.direction}:${row.chunkId}`,
            frame: { offset: bytesInfo.baseOffset, length: bytesInfo.bytes.length, direction: row.direction, kind: row.meta?.kind, meta: row.meta },
            bytes: bytesInfo.bytes,
        })
        setDissectHighlight(null)
    }

    function handleDissectNodeClick(direction, start, end) {
        setDissectHighlight({ direction, start, end })
    }

    // Shared between the initial Run and the live-tailing effect below — both must
    // format/tag a script's framer.log(...) calls identically.
    function handleFramerScriptLog(direction, args) {
        onFramerLog?.(direction, fmtLogArgs(args), 'log')
    }

    async function handleRunFramer() {
        if (!stream || !framerSelected) return
        setFrameState('framing')
        setFrameError(null)
        // clearStreamFrames below wipes any other (script, version)'s frame data for this
        // stream — a frame previously selected for dissection may no longer exist.
        setSelectedFrame(null)
        setDissectHighlight(null)
        try {
            const content = await getFramerScript(framerSelected)
            const version = await sha256Hex(content)
            // Enforces "at most one framing view per stream": purges any other
            // script/version's frame data for this stream first. A no-op if this exact
            // (script, version) is already the one active here, so catchUpFramer still
            // resumes rather than reprocessing.
            await clearStreamFrames({ session: stream.session, stream: stream.id, script: framerSelected, scriptVersion: version })
            await catchUpFramer(stream.session, stream.id, framerSelected, content, stream.end, streamTlsInfo(stream), handleFramerScriptLog)
            saveStreamFramerScript(stream.session, stream.id, framerSelected)
            setFrameScriptRunning({ name: framerSelected, version, content })
            setFrameState('framed')
        } catch (e) {
            setFrameError(`Framer "${framerSelected}" failed: ${e.message}`)
            setFrameState('raw')
            // direction: null — a script-level failure (e.g. no top-level frame function)
            // isn't attributable to one direction specifically.
            onFramerLog?.(null, e.message, 'error')
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
                await catchUpFramer(stream.session, stream.id, frameScriptRunning.name, frameScriptRunning.content, stream.end, streamTlsInfo(stream), handleFramerScriptLog)
            } catch { /* best-effort; see comment above */ }
            if (!cancelled) setFrameRefreshKey(k => k + 1)
        })()
        return () => { cancelled = true }
    }, [latestStid])

    // totalBytes is independent of the hook's fetch/display state, so it gets its own effect.
    useEffect(() => {
        setTotalBytes(stream ? { up: stream.length0 ?? -1, down: stream.length1 ?? -1 } : { up: -1, down: -1 })
    }, [stream?.id])

    // Exposes whichever hook's jump functions are actually on screen for the caller's
    // header buttons — frame view renders frameDisplay (below), not display, so jumping
    // the raw hook while in frame view would silently move a buffer nobody's looking at.
    // jumpToNextSegment/jumpToPrevSegment need the viewport's current row, which the hook
    // doesn't track itself — wrapped here so the caller's buttons keep the same zero-arg
    // signature as jumpToTop/jumpToBottom, reading scrollTopRef fresh at click time (the
    // same ref/math the "remember stream position" leave-effect below already uses).
    // No dependency array — none of these are stable identities from the hook, so this
    // just re-runs every render rather than risk going stale behind a gated dependency array.
    useEffect(() => {
        if (!jumpRef) return
        const currentRow = () => Math.floor(scrollTopRef.current / ROW_HEIGHT)
        jumpRef.current = inFrameView
            ? {
                jumpToTop: frameJumpToTop, jumpToBottom: frameJumpToBottom,
                jumpToNextSegment: () => frameJumpToNextSegment(currentRow()),
                jumpToPrevSegment: () => frameJumpToPrevSegment(currentRow()),
            }
            : {
                jumpToTop, jumpToBottom,
                jumpToNextSegment: () => jumpToNextSegment(currentRow()),
                jumpToPrevSegment: () => jumpToPrevSegment(currentRow()),
            }
    })

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

                const startStid = Math.max(0, targetStid - Math.floor(FILL_TARGET_SEGMENTS / 2))
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
                        <button class="btn" onclick=${handleShowRawChunks}>Show raw chunks</button>
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
                        sizeFormat=${sizeFormat}
                        pinHeader=${pinHeader}
                        onViewportChange=${handleViewportChange}
                        markers=${[]}
                        onHeaderClick=${handleFrameHeaderClick}
                        selectedHeaderKey=${selectedFrame?.key}
                        highlightRange=${dissectHighlight}
                    />
                    <${ResizeHandle} orientation="v" onResize=${handleDissectPanelResize} />
                    <${DissectPanel}
                        selectedFrame=${selectedFrame}
                        dissectScripts=${dissectScripts}
                        dissectorSelected=${dissectorSelected}
                        onDissectorSelect=${handleDissectorSelect}
                        onNodeClick=${handleDissectNodeClick}
                        style=${`width: ${dissectPanelWidth}px`}
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
                        sizeFormat=${sizeFormat}
                        pinHeader=${pinHeader}
                        onSetMarker=${handleSetMarker}
                        onClearMarker=${handleClearMarker}
                        onSetExtractStart=${onSetExtractStart}
                        onSetExtractEnd=${onSetExtractEnd}
                        onSetExtractRange=${onSetExtractRange}
                        onViewportChange=${handleViewportChange}
                        markers=${streamMarkers}
                    />
                `}
            </div>
        </div>
    `
}
