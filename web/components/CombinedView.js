import { h } from 'preact'
import { useEffect } from 'preact/hooks'
import htm from 'htm'
import HexDump from './HexDump.js'
import { useChunkBuffer } from '../useChunkBuffer.js'
import { fmtRelTime } from '../format.js'

const html = htm.bind(h)

function fetchPage(ws, session, start, n) {
    return ws.fetch(session.id, start, n)
}

function getId(obj) {
    return obj.sgid
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

export default function CombinedView({ dbdumpApi, session, globalOffset, sizeFormat, pinHeader, refreshKey, latestSgid, jumpRef }) {
    const { display, loading, error, handleScrollEnd, jumpToTop, jumpToBottom } = useChunkBuffer({
        entity: session,
        refreshKey,
        openStream: dbdumpApi.openSgidStream,
        fetchPage,
        getId,
        buildRows,
        latestId: latestSgid,
    })

    // See TrafficView.js's identical effect for why this has no dependency array.
    useEffect(() => { if (jumpRef) jumpRef.current = { jumpToTop, jumpToBottom } })

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
                scrollTo=${display.scrollTo}
                scrollToVersion=${display.scrollToVersion}
                globalOffset=${globalOffset}
                sizeFormat=${sizeFormat}
                pinHeader=${pinHeader}
            />
        </div>
    `
}
