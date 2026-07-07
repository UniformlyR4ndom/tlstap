import { h } from 'preact'
import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import htm from 'htm'
import { openSgidStream } from '../api.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'

const html = htm.bind(h)

const BATCH = 50
const MAX_BUFFERED_CHUNKS = BATCH * 2

function countChunks(rows) {
    let n = 0
    for (const row of rows) if (row.type === 'header') n++
    return n
}

export default function CombinedView({ session, globalOffset, refreshKey }) {
    const [display,    setDisplay] = useState({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
    const [loading,    setLoading] = useState(false)
    const [error,      setError]   = useState(null)

    const firstSgidRef   = useRef(0)
    const lastSgidRef    = useRef(-1)
    const hasMoreRef     = useRef(false)
    const loadingMoreRef = useRef(false)
    const generationRef  = useRef(0)
    const sessionRef     = useRef(session)
    const wsRef          = useRef(null)
    const displayRef     = useRef(display)
    const hasMountedRef  = useRef(false)
    useEffect(() => { sessionRef.current = session }, [session])
    useEffect(() => { displayRef.current = display }, [display])

    useEffect(() => {
        if (!session) {
            setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
            return
        }

        const ws = openSgidStream()
        wsRef.current = ws

        generationRef.current++
        const gen = generationRef.current

        setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
        setLoading(true)
        setError(null)
        firstSgidRef.current   = 0
        lastSgidRef.current    = -1
        hasMoreRef.current     = false
        loadingMoreRef.current = false

        ;(async () => {
            try {
                const chunks = await ws.fetch(session.id, 0, BATCH)
                if (generationRef.current !== gen) return

                firstSgidRef.current = chunks[0]?.sgid ?? 0
                lastSgidRef.current  = chunks[chunks.length - 1]?.sgid ?? -1
                hasMoreRef.current   = chunks.length === BATCH

                setDisplay({
                    rows:          buildRows(chunks, session.start),
                    scrollAdjust:  0,
                    adjustVersion: 0,
                })
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
    }, [session?.id])

    // Refresh — tops up the buffer with newly available chunks, if there's room.
    // Never evicts and never adjusts scroll; only appends to the tail.
    useEffect(() => {
        if (!hasMountedRef.current) { hasMountedRef.current = true; return }

        const s = sessionRef.current
        if (!s) return
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
                const chunks = await capturedWs.fetch(s.id, lastSgidRef.current + 1, room)
                if (generationRef.current !== capturedGen) return
                if (chunks.length === 0) return

                const newChunkRows = buildRows(chunks, s.start)
                lastSgidRef.current = chunks[chunks.length - 1].sgid
                hasMoreRef.current  = chunks.length === room

                setDisplay(prev => ({ ...prev, rows: [...prev.rows, ...newChunkRows] }))
            } catch (e) {
                if (generationRef.current === capturedGen) setError(e.message)
            } finally {
                loadingMoreRef.current = false
                if (generationRef.current === capturedGen) setLoading(false)
            }
        })()
    }, [refreshKey])

    const handleScrollEnd = useCallback(async (scrollDir) => {
        const goingForward = scrollDir === 1

        if (goingForward  && !hasMoreRef.current)          return
        if (!goingForward && firstSgidRef.current === 0)   return
        if (loadingMoreRef.current) return

        const capturedGen     = generationRef.current
        const capturedSession = sessionRef.current
        const capturedWs      = wsRef.current
        if (!capturedSession || !capturedWs) return

        loadingMoreRef.current = true
        setLoading(true)

        try {
            let chunks
            if (goingForward) {
                chunks = await capturedWs.fetch(capturedSession.id, lastSgidRef.current + 1, BATCH)
            } else {
                const start = Math.max(0, firstSgidRef.current - BATCH)
                const n     = firstSgidRef.current - start
                chunks = await capturedWs.fetch(capturedSession.id, start, n)
            }
            if (generationRef.current !== capturedGen) return
            if (chunks.length === 0) return

            const newChunkRows = buildRows(chunks, capturedSession.start)

            setDisplay(prev => {
                if (goingForward) {
                    const cutIdx = findChunkBoundaryNearHalf(prev.rows, 0)
                    if (cutIdx > 0) firstSgidRef.current = prev.rows[cutIdx].sgid
                    for (let i = newChunkRows.length - 1; i >= 0; i--) {
                        if (newChunkRows[i].type === 'header') { lastSgidRef.current = newChunkRows[i].sgid; break }
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
                        if (prev.rows[i].type === 'header') { lastSgidRef.current = prev.rows[i].sgid; break }
                    }
                    if (newChunkRows[0]?.type === 'header') firstSgidRef.current = newChunkRows[0].sgid
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

    if (!session) return html`<div class="placeholder">Select a session to view combined traffic</div>`

    return html`
        <div class="traffic-view">
            <div class="stream-meta">
                <span><span class="meta-label">session</span>${session.id}</span>
                <span><span class="meta-label">proxy</span>${session.config?.name ?? '—'}</span>
                ${loading && html`<span class="meta-loading">loading…</span>`}
            </div>
            ${error && html`<div class="error-msg">${error}</div>`}
            <${HexDump}
                rows=${display.rows}
                onScrollEnd=${handleScrollEnd}
                scrollAdjust=${display.scrollAdjust}
                adjustVersion=${display.adjustVersion}
                globalOffset=${globalOffset}
            />
        </div>
    `
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

function buildRows(chunks, sessionStart) {
    const rows = []
    for (const chunk of chunks) {
        rows.push({
            type:      'header',
            direction: chunk.direction,
            stream:    chunk.stream,
            sgid:      chunk.sgid,
            chunkId:   chunk.chunkId,
            relTime:   fmtRelTime(chunk.time, sessionStart),
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
