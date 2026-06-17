import { h } from 'preact'
import { useState, useEffect, useRef, useCallback } from 'preact/hooks'
import htm from 'htm'
import { getChunkList, fetchChunks } from '../api.js'
import HexDump, { ROW_HEIGHT } from './HexDump.js'

const html = htm.bind(h)

const BATCH = 50

export default function TrafficView({ stream }) {
    const [display,    setDisplay]    = useState({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
    const [loading,    setLoading]    = useState(false)
    const [error,      setError]      = useState(null)
    const [totalBytes, setTotalBytes] = useState({ up: -1, down: -1 })

    // Mutable state accessed by the stable handleScrollEnd callback.
    const nextIdRef      = useRef([0, 0])   // next chunk ID to load forward, per chunk direction
    const prevIdRef      = useRef([0, 0])   // earliest chunk ID in buffer, per chunk direction
    const hasMoreRef     = useRef([false, false])
    const loadingMoreRef = useRef(false)
    const generationRef  = useRef(0)        // increments on each new stream; stale fetches bail on mismatch
    const streamRef      = useRef(stream)
    useEffect(() => { streamRef.current = stream }, [stream])

    // Initial load — runs whenever the selected stream changes.
    useEffect(() => {
        if (!stream) {
            setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
            return
        }

        generationRef.current++
        const gen = generationRef.current

        setDisplay({ rows: [], scrollAdjust: 0, adjustVersion: 0 })
        setLoading(true)
        setError(null)
        setTotalBytes({ up: stream.length0 ?? -1, down: stream.length1 ?? -1 })
        nextIdRef.current      = [0, 0]
        prevIdRef.current      = [0, 0]
        hasMoreRef.current     = [false, false]
        loadingMoreRef.current = false

        ;(async () => {
            try {
                const cl = await getChunkList(stream.id)
                if (generationRef.current !== gen) return
                setTotalBytes({ up: cl.length0, down: cl.length1 })

                const [c0, c1] = await Promise.all([
                    cl.latest0 >= 0 ? fetchChunks(stream.id, 0, 0, BATCH) : Promise.resolve([]),
                    cl.latest1 >= 0 ? fetchChunks(stream.id, 1, 0, BATCH) : Promise.resolve([]),
                ])
                if (generationRef.current !== gen) return

                nextIdRef.current  = [c0.length, c1.length]
                prevIdRef.current  = [0, 0]
                hasMoreRef.current = [c0.length === BATCH, c1.length === BATCH]

                setDisplay({
                    rows:          buildRows(interleave(c0, c1), stream.start),
                    scrollAdjust:  0,
                    adjustVersion: 0,
                })
            } catch (e) {
                if (generationRef.current === gen) setError(e.message)
            } finally {
                if (generationRef.current === gen) setLoading(false)
            }
        })()
    }, [stream?.id])

    // Stable callback — reads all mutable state via refs.
    // scrollDir: 1 = near bottom (load forward), -1 = near top (load backward)
    const handleScrollEnd = useCallback(async (scrollDir) => {
        const goingForward = scrollDir === 1

        if (goingForward) {
            if (!hasMoreRef.current[0] && !hasMoreRef.current[1]) return
        } else {
            if (prevIdRef.current[0] === 0 && prevIdRef.current[1] === 0) return
        }
        if (loadingMoreRef.current) return

        const capturedGen    = generationRef.current
        const capturedStream = streamRef.current
        if (!capturedStream) return

        loadingMoreRef.current = true
        setLoading(true)

        try {
            let c0, c1
            if (goingForward) {
                ;[c0, c1] = await Promise.all([
                    hasMoreRef.current[0]
                        ? fetchChunks(capturedStream.id, 0, nextIdRef.current[0], BATCH)
                        : Promise.resolve([]),
                    hasMoreRef.current[1]
                        ? fetchChunks(capturedStream.id, 1, nextIdRef.current[1], BATCH)
                        : Promise.resolve([]),
                ])
            } else {
                ;[c0, c1] = await Promise.all([
                    prevIdRef.current[0] > 0
                        ? fetchChunks(capturedStream.id, 0, Math.max(0, prevIdRef.current[0] - BATCH), BATCH)
                        : Promise.resolve([]),
                    prevIdRef.current[1] > 0
                        ? fetchChunks(capturedStream.id, 1, Math.max(0, prevIdRef.current[1] - BATCH), BATCH)
                        : Promise.resolve([]),
                ])
            }
            if (generationRef.current !== capturedGen) return

            if (goingForward) {
                nextIdRef.current  = [nextIdRef.current[0] + c0.length, nextIdRef.current[1] + c1.length]
                hasMoreRef.current = [c0.length === BATCH, c1.length === BATCH]
            } else {
                prevIdRef.current  = [prevIdRef.current[0] - c0.length, prevIdRef.current[1] - c1.length]
            }

            const newChunks = interleave(c0, c1)
            if (newChunks.length === 0) return

            const newChunkRows = buildRows(newChunks, capturedStream.start)

            setDisplay(prev => {
                if (goingForward) {
                    // Evict front half, append new rows at back, scroll up.
                    const cutIdx   = findChunkBoundaryNearHalf(prev.rows, 0)
                    const newPrevId = [...prevIdRef.current]
                    for (let i = 0; i < cutIdx; i++) {
                        if (prev.rows[i].type === 'header') {
                            newPrevId[prev.rows[i].direction] = prev.rows[i].chunkId + 1
                        }
                    }
                    prevIdRef.current = newPrevId
                    return {
                        rows:          [...prev.rows.slice(cutIdx), ...newChunkRows],
                        scrollAdjust:  -(cutIdx * ROW_HEIGHT),
                        adjustVersion: prev.adjustVersion + 1,
                    }
                } else {
                    // Prepend new rows at front, evict back half, scroll down.
                    const keepLen    = findChunkBoundaryNearHalf(prev.rows, prev.rows.length)
                    const newNextId  = [...nextIdRef.current]
                    const newHasMore = [...hasMoreRef.current]
                    for (let i = keepLen; i < prev.rows.length; i++) {
                        if (prev.rows[i].type === 'header') {
                            const dir = prev.rows[i].direction
                            if (prev.rows[i].chunkId < newNextId[dir]) newNextId[dir] = prev.rows[i].chunkId
                            newHasMore[dir] = true
                        }
                    }
                    nextIdRef.current  = newNextId
                    hasMoreRef.current = newHasMore
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
            <${HexDump}
                key=${stream.id}
                rows=${display.rows}
                onScrollEnd=${handleScrollEnd}
                scrollAdjust=${display.scrollAdjust}
                adjustVersion=${display.adjustVersion}
            />
        </div>
    `
}

// ── pure helpers ──────────────────────────────────────────────────────────────

// Returns the index of the first chunk header at or after the midpoint.
// Falls back to scanning backward if the second half has no headers.
// `fallback` is returned when no header is found at all:
//   - pass 0           when used as an evict-from-front cutpoint (no eviction)
//   - pass rows.length when used as a keep-until-back endpoint  (no eviction)
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

function interleave(c0, c1) {
    const out = []
    let i = 0, j = 0
    while (i < c0.length && j < c1.length) {
        if (c0[i].time <= c1[j].time) out.push(c0[i++])
        else out.push(c1[j++])
    }
    while (i < c0.length) out.push(c0[i++])
    while (j < c1.length) out.push(c1[j++])
    return out
}

function buildRows(chunks, streamStart) {
    const rows = []
    for (const chunk of chunks) {
        rows.push({
            type:      'header',
            direction: chunk.direction,
            chunkId:   chunk.chunkId,
            relTime:   fmtRelTime(chunk.time, streamStart),
            size:      chunk.data.length,
        })
        for (let off = 0; off < chunk.data.length; off += 16) {
            rows.push({
                type:      'hex',
                direction: chunk.direction,
                bytes:     chunk.data.slice(off, off + 16),
                offset:    chunk.offset + off,
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
