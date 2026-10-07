import { h } from 'preact'
import { useState, useEffect, useRef, useCallback, useMemo } from 'preact/hooks'
import htm from 'htm'
import { sha256Hex, createFramerRun, streamTlsInfo } from '../framerRun.js'
import { loadStreamFramerScript, saveStreamFramerScript, loadResumeScript, saveResumeScript } from '../framerPrefs.js'
import { loadStreamDissectScript, saveStreamDissectScript } from '../dissectPrefs.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'
import DissectPanel from './DissectPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { useByteBuffer } from '../useByteBuffer.js'
import { createChunkSegmentsAdapter } from '../chunkSegments.js'
import { createFrameSegmentsAdapter } from '../frameSegments.js'
import { fmtByteSize, fmtDuration, fmtLogArgs } from '../format.js'
import { DIRNUM_C2S, DIRNUM_S2C, dirLabel } from '../direction.js'

const html = htm.bind(h)

function isClosed(stream) {
    return !!stream.end
}

export default function TrafficView({ dbdumpApi, framerApi, dissectApi, stream, globalOffset, sizeFormat, pinHeader, jumpTo, onJumpError, refreshKey, latestStid, markers, onAddMarker, onRemoveMarker, onSetExtractStart, onSetExtractEnd, onSetExtractRange, onLeaveStream, jumpRef, framerScripts, onFramerLog, onFramerLogReset, dissectScripts }) {
    const [totalBytes, setTotalBytes] = useState({ up: -1, down: -1 })
    const chunkAdapter = useMemo(() => createChunkSegmentsAdapter(dbdumpApi), [dbdumpApi])
    const frameAdapter = useMemo(() => createFrameSegmentsAdapter(dbdumpApi, framerApi), [dbdumpApi, framerApi])
    const { catchUpFramer } = useMemo(() => createFramerRun(dbdumpApi, framerApi), [dbdumpApi, framerApi])
    const viewHeightRef = useRef(0)
    const scrollTopRef = useRef(0)
    const pinHeaderRef = useRef(pinHeader)
    pinHeaderRef.current = pinHeader
    // Tracks the jumpTo.version last (about to be) handled by the jump effect below —
    // read fresh each render (not itself a hook) so hasPendingJump is already correct by
    // the time useByteBuffer's own entity-change effect runs in the same commit; updated
    // inside the jump effect itself once it starts handling a version, so this is true for
    // exactly the one render where a genuinely new jump is still unprocessed.
    const lastJumpVersionRef = useRef(0)
    const hasPendingJump = !!jumpTo && jumpTo.version !== lastJumpVersionRef.current

    // Framer state. frameState: 'raw' | 'framing' | 'framed' — not itself persisted, but
    // the stream-reselection effect below auto-resumes 'framed' (re-running the framer)
    // when framerPrefs.js's resumeScript still matches the current script selection; see
    // that effect's own comment. frameScriptRunning caches the content/version Run last
    // used, so the live-tailing effect below doesn't need to re-fetch the script on every
    // poll tick.
    const [framerSelected, setFramerSelected] = useState('')
    const [frameState, setFrameState] = useState('raw')
    const [frameError, setFrameError] = useState(null)
    const [frameScriptRunning, setFrameScriptRunning] = useState(null) // { name, version, content }
    const [frameRefreshKey, setFrameRefreshKey] = useState(0)
    // Bumped by the stream-reselection effect; a runFramerFor call in flight checks this
    // hasn't moved on before applying its result, so a stream switch that fires while an
    // auto-resume (or a manual Run) is still pending can't clobber the newly-selected
    // stream's state with a stale completion.
    const streamGenRef = useRef(0)

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
    // Raw-mode counterpart to dissectHighlight, driven by a Search-panel result jump
    // (jumpTo.highlight) instead of a dissector field click — set/cleared inside the jump
    // effect below, since jumpTo.highlight is only ever present on a search-originated jump.
    const [searchHighlight, setSearchHighlight] = useState(null)
    const [dissectPanelWidth, handleDissectPanelResize] = useResizableLayout('dissectPanelWidth', { sign: -1, min: 200, max: 800 })

    const {
        display, loading, error, setError, handleScrollEnd, reloadFrom, reloadCenteredOn, displayRef,
        jumpToTop, jumpToBottom, jumpToNextSegment, jumpToPrevSegment,
    } = useByteBuffer({
        entity: stream,
        refreshKey,
        openConnection: chunkAdapter.openConnection,
        fillForward: chunkAdapter.fillForward,
        fillBackward: chunkAdapter.fillBackward,
        isClosed,
        latestId: latestStid,
        hasPendingJump,
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
        openConnection: frameAdapter.openConnection,
        fillForward: frameAdapter.fillForward,
        fillBackward: frameAdapter.fillBackward,
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

    // Shared between the initial Run and the live-tailing effect below — both must
    // format/tag a script's framer.log(...) calls identically.
    function handleFramerScriptLog(direction, args) {
        onFramerLog?.(direction, fmtLogArgs(args), 'log')
    }

    // Shared by the button's own Run click and the stream-reselection effect below's
    // auto-resume — takes scriptName/targetStream explicitly rather than reading
    // framerSelected/stream from closure, since the auto-resume call fires from inside the
    // very effect that's still in the middle of updating framerSelected for the newly
    // (re)selected stream. Guards against a stream switch firing again while this is still
    // in flight (manual or automatic) via streamGenRef — without it, a stale completion
    // could clobber the newly-selected stream's state with the old one's result.
    async function runFramerFor(scriptName, targetStream) {
        if (!targetStream || !scriptName) return
        const gen = streamGenRef.current
        setFrameState('framing')
        setFrameError(null)
        // clearStreamFrames below wipes any other (script, version)'s frame data for this
        // stream — a frame previously selected for dissection may no longer exist.
        setSelectedFrame(null)
        setDissectHighlight(null)
        try {
            const content = await framerApi.getFramerScript(scriptName)
            const version = await sha256Hex(content)
            // Enforces "at most one framing view per stream": purges any other
            // script/version's frame data for this stream first. A no-op if this exact
            // (script, version) is already the one active here, so catchUpFramer still
            // resumes rather than reprocessing — this is what makes an auto-resume of an
            // up-to-date stream cheap, and a resume after the script was edited a correct
            // full reprocess, with no separate version comparison needed on our side.
            await framerApi.clearStreamFrames({ session: targetStream.session, stream: targetStream.id, script: scriptName, scriptVersion: version })
            await catchUpFramer(targetStream.session, targetStream.id, scriptName, content, targetStream.end, streamTlsInfo(targetStream), handleFramerScriptLog)
            if (streamGenRef.current !== gen) return // superseded by a newer stream selection
            saveStreamFramerScript(targetStream.session, targetStream.id, scriptName)
            saveResumeScript(targetStream.session, targetStream.id, scriptName)
            setFrameScriptRunning({ name: scriptName, version, content })
            setFrameState('framed')
        } catch (e) {
            if (streamGenRef.current !== gen) return
            setFrameError(`Framer "${scriptName}" failed: ${e.message}`)
            setFrameState('raw')
            // direction: null — a script-level failure (e.g. no top-level frame function)
            // isn't attributable to one direction specifically.
            onFramerLog?.(null, e.message, 'error')
        }
    }

    function handleRunFramer() {
        runFramerFor(framerSelected, stream)
    }

    // Resets on every stream (re)selection. Which script is selected always survives (via
    // framerPrefs.js, falling back to the global default when this stream has no override
    // of its own yet) — frame view itself auto-resumes too, but only when this exact
    // stream was actually successfully framed with this exact script before:
    // loadResumeScript(...) (set on a successful run, cleared by "Show raw chunks") must
    // still equal the script currently selected. A script merely being selected (e.g. an
    // inherited global default the user never actually ran here) is not enough — this is
    // what stops a framer from ever being run against a stream it has no established
    // business with. When it does match, runFramerFor below re-runs the exact same Run
    // path a click would — cheap/idempotent if nothing changed since, a real catch-up or
    // reprocess if the stream grew or the script was edited.
    useEffect(() => {
        streamGenRef.current += 1
        setFrameError(null)
        setFrameScriptRunning(null)
        setSelectedFrame(null)
        setDissectHighlight(null)
        setSearchHighlight(null)
        onFramerLogReset?.()
        const savedScript = stream ? (loadStreamFramerScript(stream.session, stream.id) ?? '') : ''
        setFramerSelected(savedScript)
        setDissectorSelected(stream ? (loadStreamDissectScript(stream.session, stream.id) ?? '') : '')

        const canResume = stream && savedScript && loadResumeScript(stream.session, stream.id) === savedScript
        if (canResume) {
            runFramerFor(savedScript, stream)
        } else {
            setFrameState('raw')
        }
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
        // Explicit opt-out: stops the next reselection of this stream from auto-resuming
        // framed view again (see the stream-reselection effect above).
        if (stream) saveResumeScript(stream.session, stream.id, null)
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
    // `cancelled` guards against a stale resolution superseding a newer jump. Each unit
    // that resolves against a value the caller could have gotten wrong (Goto's manually-
    // typed value, not a marker/search-result jump — those always target real, already-
    // found data) is validated against what's actually captured *before* reloading
    // anything, so a bad target shows an error instead of silently landing somewhere else
    // — assumes the target stream is already the one selected, true for every current
    // caller (Goto never switches streams); a hypothetical future jump that both switches
    // streams and fails this check would leave the newly-selected entity unloaded, since
    // hasPendingJump already told its own initial-load effect to stand down.
    useEffect(() => {
        if (!jumpTo || !stream) return
        let cancelled = false
        lastJumpVersionRef.current = jumpTo.version
        setSearchHighlight(jumpTo.highlight ?? null)

        // A jump tagged with its own source (currently just Goto — App.js's handleGoTo)
        // reports failures to that source's own UI via onJumpError instead of the generic
        // top-of-view banner, since "why didn't my typed value work" reads better right
        // next to the input that produced it. Search-result/marker jumps are untagged and
        // keep the banner — their own target is never wrong (always real, already-found
        // data), so a failure there is a genuine buffer/network problem, not user input.
        function reportError(message) {
            if (jumpTo.source && onJumpError) onJumpError(jumpTo, message)
            else setError(message)
        }

        ;(async () => {
            try {
                let targetStid = jumpTo.value
                let targetByteOffset = null
                let targetDirection = null
                if (jumpTo.unit === 'chunks') {
                    // No resolution call for this unit (targetStid is already the raw
                    // value), so it's the one case latestStid can pre-validate without an
                    // extra round trip — a bogus/too-large value would otherwise silently
                    // land wherever the backward-filled tail of the stream happens to be
                    // (fillToTarget's mustReachStid chase never finds a stid that doesn't
                    // exist, same failure shape /byte-stid's own case below has).
                    if (latestStid != null && latestStid >= 0 && jumpTo.value > latestStid) {
                        reportError(`Chunk #${jumpTo.value} doesn't exist yet; the latest is #${latestStid}.`)
                        return
                    }
                } else if (jumpTo.unit === 'chunks-c2s' || jumpTo.unit === 'chunks-s2c') {
                    const direction = jumpTo.unit === 'chunks-c2s' ? DIRNUM_C2S : DIRNUM_S2C
                    // Same pre-check as the 'chunks' (total) unit above, unified in
                    // phrasing — /chunk-stid does 404 correctly on a bad id (unlike
                    // /byte-stid below), but its own "chunk not found" text reads
                    // inconsistently next to the other two units' own messages here.
                    const list = await dbdumpApi.getChunkList(stream.session, stream.id)
                    if (cancelled) return
                    const latestForDir = direction === DIRNUM_C2S ? list.latest0 : list.latest1
                    if (latestForDir == null || latestForDir < 0 || jumpTo.value > latestForDir) {
                        const latestStr = latestForDir != null && latestForDir >= 0 ? `#${latestForDir}` : 'none yet'
                        reportError(`Chunk #${jumpTo.value} (${dirLabel(direction)}) doesn't exist yet; the latest is ${latestStr}.`)
                        return
                    }
                    const result = await dbdumpApi.getChunkStid(stream.session, stream.id, direction, jumpTo.value)
                    if (cancelled) return
                    targetStid = result.stid
                } else if (jumpTo.unit === 'offset-c2s' || jumpTo.unit === 'offset-s2c') {
                    const direction = jumpTo.unit === 'offset-c2s' ? DIRNUM_C2S : DIRNUM_S2C
                    // /byte-stid resolves to the *last* chunk (never 404s) for an offset
                    // past what's captured so far — checked against the stream's own
                    // known length here, before even asking, rather than after the fact:
                    // otherwise the jump "succeeds" by silently landing at the top of that
                    // last chunk instead of at the (nonexistent) requested byte.
                    const totalLen = direction === DIRNUM_C2S ? stream.length0 : stream.length1
                    if (totalLen == null || totalLen < 0 || jumpTo.value >= totalLen) {
                        const have = totalLen != null && totalLen >= 0 ? `only ${totalLen} (0x${totalLen.toString(16)}) bytes captured so far` : 'nothing captured yet'
                        reportError(`Offset 0x${jumpTo.value.toString(16)} is beyond the captured ${dirLabel(direction)} data (${have}).`)
                        return
                    }
                    const result = await dbdumpApi.getByteStid(stream.session, stream.id, direction, jumpTo.value)
                    if (cancelled) return
                    targetStid = result.stid
                    targetByteOffset = jumpTo.value
                    targetDirection = direction
                }
                if (cancelled) return

                // reloadCenteredOn (not reloadFrom) — it loads directly at targetStid
                // (backward for leading context, forward starting *at* it) rather than
                // walking forward from a segment-count-computed boundary that can be far
                // from the target in byte terms for realistic chunk sizes.
                reloadCenteredOn(targetStid, {
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
                        // A pinned header covers the top row, so a byte target lands one row lower.
                        const pinnedOffset = pinHeader && targetByteOffset !== null ? ROW_HEIGHT : 0
                        const scrollTo = jumpTo.align === 'top'
                            ? Math.max(0, targetRowPx - pinnedOffset)
                            : Math.max(0, targetRowPx - Math.floor(viewHeightRef.current / 2))
                        return { scrollTo, scrollToVersion: jumpTo.version }
                    },
                })
            } catch (e) {
                if (!cancelled) reportError(e.message)
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
            if (pinHeaderRef.current && rows[i] && rows[i].type !== 'header') i++
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
                        dissectApi=${dissectApi}
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
                        highlightRange=${searchHighlight}
                    />
                `}
            </div>
        </div>
    `
}
