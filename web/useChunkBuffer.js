import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import { ROW_HEIGHT } from './components/HexDump.js'

// Exported for consumers that need to center a fetch window on their own resolved id.
export const BATCH = 50
const MAX_BUFFERED_CHUNKS = BATCH * 2

function countChunks(rows) {
    let n = 0
    for (const row of rows) if (row.type === 'header') n++
    return n
}

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

// Backs a windowed/paginated chunk buffer, keyed by either a stream-scoped or
// session-scoped id: initial load, refresh top-up, and forward/backward scroll eviction.
//
// `entity`: current stream/session, or null. `openStream`: opens the underlying WebSocket
// connection. `fetchPage(ws, entity, startId, n)`: wraps the entity-specific fetch call.
// `getId(obj)`: extracts the pagination id (same field name on a chunk and a header row
// built from it). `buildRows(chunks, startMs)`: caller-owned row builder. `isClosed(entity)`:
// optional; stops refresh top-up once true.
export function useChunkBuffer({ entity, refreshKey, openStream, fetchPage, getId, buildRows, isClosed }) {
    const [display, setDisplay] = useState({ rows: [], scrollAdjust: 0, adjustVersion: 0, scrollTo: 0, scrollToVersion: 0 })
    const [loading, setLoading] = useState(false)
    const [error,   setError]   = useState(null)

    const prevIdRef      = useRef(0)
    const nextIdRef      = useRef(0)
    const hasMoreRef     = useRef(false)
    const loadingMoreRef = useRef(false)
    const generationRef  = useRef(0)
    const entityRef      = useRef(entity)
    const wsRef          = useRef(null)
    const displayRef     = useRef(display)
    const hasMountedRef  = useRef(false)
    useEffect(() => { entityRef.current = entity }, [entity])
    useEffect(() => { displayRef.current = display }, [display])

    // Opens a fresh connection, fetches one BATCH window from `startId`, and replaces `display`.
    // `computeExtra(rows)` merges extra fields into `display`, computed from the fetched rows.
    function reloadFrom(startId, { computeExtra } = {}) {
        wsRef.current?.close()
        const ws = openStream()
        wsRef.current = ws

        generationRef.current++
        const gen = generationRef.current

        loadingMoreRef.current = false
        setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
        setLoading(true)
        setError(null)

        ;(async () => {
            try {
                const chunks = await fetchPage(ws, entityRef.current, startId, BATCH)
                if (generationRef.current !== gen) return
                prevIdRef.current = chunks[0] ? getId(chunks[0]) : startId
                nextIdRef.current = chunks.length > 0 ? getId(chunks[chunks.length - 1]) + 1 : startId
                hasMoreRef.current = chunks.length === BATCH
                const rows  = buildRows(chunks, entityRef.current.start)
                const extra = computeExtra ? computeExtra(rows) : {}
                setDisplay({ rows, scrollAdjust: 0, adjustVersion: 0, ...extra })
            } catch (e) {
                if (generationRef.current === gen) setError(e.message)
            } finally {
                if (generationRef.current === gen) setLoading(false)
            }
        })()
    }

    // Initial load — runs whenever the selected entity changes.
    useEffect(() => {
        if (!entity) {
            setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
            return
        }
        prevIdRef.current  = 0
        nextIdRef.current  = 0
        hasMoreRef.current = false
        reloadFrom(0)
        return () => {
            wsRef.current?.close()
            wsRef.current = null
        }
    }, [entity?.id])

    // Refresh — tops up the buffer with newly available chunks, if there's room.
    // Never evicts and never adjusts scroll; only appends to the tail.
    useEffect(() => {
        if (!hasMountedRef.current) { hasMountedRef.current = true; return }

        const e = entityRef.current
        if (!e) return
        if (isClosed?.(e)) return
        if (loadingMoreRef.current) return

        const room = MAX_BUFFERED_CHUNKS - countChunks(displayRef.current.rows)
        if (room <= 0) return

        const capturedGen = generationRef.current
        const capturedWs  = wsRef.current
        if (!capturedWs) return

        loadingMoreRef.current = true
        setLoading(true)

        ;(async () => {
            try {
                const chunks = await fetchPage(capturedWs, e, nextIdRef.current, room)
                if (generationRef.current !== capturedGen) return
                if (chunks.length === 0) return

                const newChunkRows = buildRows(chunks, e.start)
                nextIdRef.current  = getId(chunks[chunks.length - 1]) + 1
                hasMoreRef.current = chunks.length === room

                setDisplay(prev => ({ ...prev, rows: [...prev.rows, ...newChunkRows] }))
            } catch (e) {
                if (generationRef.current === capturedGen) setError(e.message)
            } finally {
                loadingMoreRef.current = false
                if (generationRef.current === capturedGen) setLoading(false)
            }
        })()
    }, [refreshKey])

    // Stable callback — reads all mutable state via refs.
    const handleScrollEnd = useCallback(async (scrollDir) => {
        const goingForward = scrollDir === 1

        if (goingForward  && !hasMoreRef.current)       return
        if (!goingForward && prevIdRef.current === 0)   return
        if (loadingMoreRef.current) return

        const capturedGen    = generationRef.current
        const capturedEntity = entityRef.current
        const capturedWs     = wsRef.current
        if (!capturedEntity || !capturedWs) return

        loadingMoreRef.current = true
        setLoading(true)

        try {
            let chunks
            if (goingForward) {
                chunks = await fetchPage(capturedWs, capturedEntity, nextIdRef.current, BATCH)
            } else {
                const start = Math.max(0, prevIdRef.current - BATCH)
                const n     = prevIdRef.current - start
                chunks = await fetchPage(capturedWs, capturedEntity, start, n)
            }
            if (generationRef.current !== capturedGen) return
            if (chunks.length === 0) return

            const newChunkRows = buildRows(chunks, capturedEntity.start)

            setDisplay(prev => {
                if (goingForward) {
                    const cutIdx = findChunkBoundaryNearHalf(prev.rows, 0)
                    if (cutIdx > 0) prevIdRef.current = getId(prev.rows[cutIdx])
                    for (let i = newChunkRows.length - 1; i >= 0; i--) {
                        if (newChunkRows[i].type === 'header') { nextIdRef.current = getId(newChunkRows[i]) + 1; break }
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
                        if (prev.rows[i].type === 'header') { nextIdRef.current = getId(prev.rows[i]) + 1; break }
                    }
                    if (newChunkRows[0]?.type === 'header') prevIdRef.current = getId(newChunkRows[0])
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

    // setError lets a caller's own async work surface a failure before reloadFrom is
    // even called.
    return { display, loading, error, setError, handleScrollEnd, reloadFrom }
}
