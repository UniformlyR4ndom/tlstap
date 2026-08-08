import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import { ROW_HEIGHT } from './components/HexDump.js'
import {
    MAX_BUFFERED_BYTES, MAX_BUFFERED_SEGMENTS, FILL_TARGET_BYTES, FILL_TARGET_SEGMENTS,
    totalBytes, isWindowFull, buildRows, evict, fillToTarget,
} from './byteBufferCore.js'

export { MAX_BUFFERED_BYTES, MAX_BUFFERED_SEGMENTS, FILL_TARGET_SEGMENTS }

// Byte-budgeted replacement for useChunkBuffer.js's item-count-based windowing — see
// doc/design/hexview-segment-buffer.md for the full design this implements, and
// byteBufferCore.js for the pure buffer/eviction/fill-target logic this hook wraps with
// Preact state. Not yet wired into any view (see that document's "Migration plan"); this
// file only needs to satisfy the design, not any particular caller yet.
//
// entity: current stream/session (or the synthetic frame-mode entity), or null.
// openConnection(entity): opens whatever connection fillForward/fillBackward need (a
// persistent WS for chunk mode; a no-op stub for frame mode, which is plain REST) —
// returns a handle with an optional close(), mirroring useChunkBuffer.js's openStream.
// fillForward(handle, entity, {afterStid, resumeWindow, maxBytes, maxSegments}) /
// fillBackward(handle, entity, {beforeStid, resumeWindow, maxBytes, maxSegments}) both
// resolve to {windows: SegmentWindow[], reachedEnd} — see doc/design/
// hexview-segment-buffer.md's "Adapter contract" section for the full contract these
// must satisfy, including why fillForward/fillBackward are two distinctly-named
// functions rather than one taking a direction parameter. isClosed(entity): optional,
// stops refresh/live-poll top-up once true. latestId: optional, a plain number (the hook
// itself does no polling); omit to disable the live-poll reaction below.
//
// No fetchPage/getId/buildRows props here, unlike useChunkBuffer.js — pagination is
// entirely the adapter's concern now (there's no single "next id" the hook manages
// itself), and row-building is shared/internal (byteBufferCore.js's buildRows) since the
// row shape no longer differs between chunk mode and frame mode.
export function useByteBuffer({ entity, refreshKey, openConnection, fillForward, fillBackward, isClosed, latestId }) {
    const [display, setDisplay] = useState({ rows: [], scrollAdjust: 0, adjustVersion: 0, scrollTo: 0, scrollToVersion: 0 })
    const [loading, setLoading] = useState(false)
    const [error,   setError]   = useState(null)

    const windowsRef           = useRef([])
    const reachedForwardRef    = useRef(false)
    const reachedBackwardRef   = useRef(false)
    const loadingMoreRef       = useRef(false)
    const generationRef        = useRef(0)
    const entityRef            = useRef(entity)
    const handleRef            = useRef(null)
    const displayRef           = useRef(display)
    const hasMountedRef        = useRef(false)
    useEffect(() => { entityRef.current = entity }, [entity])
    useEffect(() => { displayRef.current = display }, [display])

    // The next stid a forward fill would start from — used only to cheaply decide
    // whether a live-poll tick's latestId is worth acting on at all.
    function nextBoundaryStid() {
        const windows = windowsRef.current
        if (windows.length === 0) return 0
        const tail = windows[windows.length - 1]
        return isWindowFull(tail) ? tail.segment.stid + 1 : tail.segment.stid
    }

    // Opens a fresh connection and fills toward FILL_TARGET_BYTES/FILL_TARGET_SEGMENTS
    // starting at boundaryStid, in direction dir (1 = forward, -1 = backward), replacing
    // display. computeExtra(rows) merges extra fields into display, same as
    // useChunkBuffer.js's reloadFrom.
    function reloadFromBoundary(dir, boundaryStid, { computeExtra } = {}) {
        handleRef.current?.close?.()
        const handle = openConnection(entityRef.current)
        handleRef.current = handle

        generationRef.current++
        const gen = generationRef.current

        loadingMoreRef.current = false
        windowsRef.current = []
        setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
        setLoading(true)
        setError(null)

        ;(async () => {
            try {
                const windows = []
                const fill = dir === 1 ? fillForward : fillBackward
                const { reachedEnd } = await fillToTarget(
                    fill, handle, entityRef.current, windows, dir, boundaryStid, null,
                    FILL_TARGET_BYTES, FILL_TARGET_SEGMENTS, generationRef, gen,
                )
                if (generationRef.current !== gen) return
                windowsRef.current = windows
                // The direction just filled has a real reachedEnd; the other direction is
                // unknown from here — assume there's more and let it be discovered lazily
                // on the first scroll that way, same approximate spirit as
                // useChunkBuffer.js's prevIdRef===0 heuristic.
                if (dir === 1) { reachedForwardRef.current = reachedEnd; reachedBackwardRef.current = false }
                else            { reachedBackwardRef.current = reachedEnd; reachedForwardRef.current = false }
                const rows  = buildRows(windows, entityRef.current.start)
                const extra = computeExtra ? computeExtra(rows) : {}
                setDisplay({ rows, scrollAdjust: 0, adjustVersion: 0, ...extra })
            } catch (e) {
                if (generationRef.current === gen) setError(e.message)
            } finally {
                if (generationRef.current === gen) setLoading(false)
            }
        })()
    }

    // Forward reload from startId (inclusive) — the general-purpose entry point
    // (initial load, jump-to-top, jump-to-stid), mirroring useChunkBuffer.js's
    // reloadFrom(startId) signature exactly so a future migration barely touches call sites.
    function reloadFrom(startId, opts) {
        reloadFromBoundary(1, startId - 1, opts)
    }

    // Initial load — runs whenever the selected entity changes.
    useEffect(() => {
        if (!entity) {
            setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
            return
        }
        reachedForwardRef.current  = false
        reachedBackwardRef.current = false
        reloadFrom(0)
        return () => {
            handleRef.current?.close?.()
            handleRef.current = null
        }
    }, [entity?.id])

    // Tops up the buffer with newly available segments, if there's room under the
    // absolute caps (not FILL_TARGET_*, which is only the per-scroll-trigger amount).
    // Never evicts and never adjusts scroll — new rows append straight to the end, which
    // is what makes a top-up visually silent when the new data isn't on screen. Shared by
    // the refresh-button path and the live-poll effect below.
    function topUp() {
        const e = entityRef.current
        if (!e) return
        if (isClosed?.(e)) return
        if (loadingMoreRef.current) return

        const windows = windowsRef.current
        const roomBytes    = MAX_BUFFERED_BYTES    - totalBytes(windows)
        const roomSegments = MAX_BUFFERED_SEGMENTS - windows.length
        if (roomBytes <= 0 || roomSegments <= 0) return

        const capturedGen    = generationRef.current
        const capturedHandle = handleRef.current
        if (!capturedHandle) return

        loadingMoreRef.current = true
        setLoading(true)

        ;(async () => {
            try {
                const tail    = windows[windows.length - 1]
                const boundary = tail ? tail.segment.stid : -1
                const initialResume = tail && !isWindowFull(tail) ? tail : null
                const newWindows = windows.slice()
                const { addedBytes, addedSegments, reachedEnd } = await fillToTarget(
                    fillForward, capturedHandle, e, newWindows, 1, boundary, initialResume,
                    roomBytes, roomSegments, generationRef, capturedGen,
                )
                if (generationRef.current !== capturedGen) return
                reachedForwardRef.current = reachedEnd
                if (addedBytes === 0 && addedSegments === 0) return
                windowsRef.current = newWindows
                const rows = buildRows(newWindows, e.start)
                setDisplay(prev => ({ ...prev, rows }))
            } catch (e2) {
                if (generationRef.current === capturedGen) setError(e2.message)
            } finally {
                loadingMoreRef.current = false
                if (generationRef.current === capturedGen) setLoading(false)
            }
        })()
    }

    // Refresh button — unconditional top-up attempt on every tick.
    useEffect(() => {
        if (!hasMountedRef.current) { hasMountedRef.current = true; return }
        topUp()
    }, [refreshKey])

    // Live-poll reaction: calls topUp() when latestId moves ahead of what's already
    // buffered. No fetching/interval of its own — topUp() already guards on all of that.
    useEffect(() => {
        if (latestId != null && latestId >= nextBoundaryStid()) topUp()
    }, [latestId])

    // Jump-to-top/bottom. jumpToTop is a forward reload from stid 0. jumpToBottom fills
    // *backward* from just past latestId — unlike useChunkBuffer.js's id-count-based
    // guess (BATCH items back from latestId), this reuses the same fillToTarget machinery
    // as a real backward scroll, so it naturally loads exactly FILL_TARGET_BYTES/
    // FILL_TARGET_SEGMENTS worth regardless of how large the segments near the end are —
    // HexDump's scroll-to effect still does the exact landing via its own clamp to the
    // DOM's real scrollHeight, same as before. version is read fresh off displayRef
    // rather than kept as a separate counter, since a caller-owned jump effect can write
    // into this same display.scrollToVersion field through a different path — always
    // basing the next version off whatever's currently there avoids two independent
    // counters coincidentally landing on the same number and silently dropping a jump.
    function jumpToTop() {
        if (!entityRef.current) return
        const version = (displayRef.current.scrollToVersion ?? 0) + 1
        reloadFrom(0, { computeExtra: () => ({ scrollTo: 0, scrollToVersion: version }) })
    }

    function jumpToBottom() {
        if (!entityRef.current || latestId == null || latestId < 0) return
        const version = (displayRef.current.scrollToVersion ?? 0) + 1
        reloadFromBoundary(-1, latestId + 1, { computeExtra: () => ({ scrollTo: Number.MAX_SAFE_INTEGER, scrollToVersion: version }) })
    }

    // Stable callback — reads all mutable state via refs, same discipline
    // useChunkBuffer.js's own handleScrollEnd uses.
    const handleScrollEnd = useCallback(async (scrollDir) => {
        const goingForward = scrollDir === 1

        if (goingForward  && reachedForwardRef.current)  return
        if (!goingForward && reachedBackwardRef.current) return
        if (loadingMoreRef.current) return

        const capturedGen    = generationRef.current
        const capturedEntity = entityRef.current
        const capturedHandle = handleRef.current
        if (!capturedEntity || !capturedHandle) return

        const windows = windowsRef.current.slice()
        if (windows.length === 0) return

        loadingMoreRef.current = true
        setLoading(true)

        try {
            const dir  = goingForward ? 1 : -1
            const edge = goingForward ? windows[windows.length - 1] : windows[0]
            const initialResume = isWindowFull(edge) ? null : edge
            const boundary = edge.segment.stid

            const fill = goingForward ? fillForward : fillBackward
            const { addedBytes, addedSegments, addedRows, reachedEnd } = await fillToTarget(
                fill, capturedHandle, capturedEntity, windows, dir, boundary, initialResume,
                FILL_TARGET_BYTES, FILL_TARGET_SEGMENTS, generationRef, capturedGen,
            )
            if (generationRef.current !== capturedGen) return

            if (goingForward) reachedForwardRef.current  = reachedEnd
            else               reachedBackwardRef.current = reachedEnd
            if (addedBytes === 0 && addedSegments === 0) return

            // Evict from the side opposite the one just extended — front for a forward
            // fill (oldest content, scrolled away from), back for a backward one (content
            // furthest from the now-topmost viewport).
            const { windows: trimmed, removedRows } = evict(windows, goingForward ? 1 : -1, MAX_BUFFERED_BYTES, MAX_BUFFERED_SEGMENTS)
            windowsRef.current = trimmed
            const rows = buildRows(trimmed, capturedEntity.start)

            if (goingForward) {
                setDisplay(prev => ({
                    rows,
                    scrollAdjust:  -(removedRows * ROW_HEIGHT),
                    adjustVersion: prev.adjustVersion + 1,
                }))
            } else {
                setDisplay(prev => ({
                    rows,
                    scrollAdjust:  addedRows * ROW_HEIGHT,
                    adjustVersion: prev.adjustVersion + 1,
                }))
            }
        } catch (e) {
            if (generationRef.current === capturedGen) setError(e.message)
        } finally {
            loadingMoreRef.current = false
            if (generationRef.current === capturedGen) setLoading(false)
        }
    }, [])

    return { display, loading, error, setError, handleScrollEnd, reloadFrom, displayRef, jumpToTop, jumpToBottom }
}
