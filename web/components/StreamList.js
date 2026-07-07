import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import { getStreams } from '../api.js'

const html = htm.bind(h)

export default function StreamList({ session, selected, onSelect, onLoad, refreshKey }) {
    const [streams, setStreams] = useState([])
    const [desc,    setDesc]   = useState(false)

    useEffect(() => {
        if (!session) { setStreams([]); onLoad?.([]); return }
        getStreams(session.id).then(ss => { setStreams(ss); onLoad?.(ss) }).catch(() => { setStreams([]); onLoad?.([]) })
    }, [session?.id, refreshKey])

    useEffect(() => { setDesc(false) }, [session?.id])

    const sorted = desc ? [...streams].reverse() : streams

    return html`
        <div class="panel">
            <div class="panel-header">
                Streams
                <span class="badge">${streams.length}</span>
                <span class="sort-toggle" onclick=${() => setDesc(d => !d)} title=${desc ? 'Newest first' : 'Oldest first'}>
                    ${desc ? '▼' : '▲'}
                </span>
            </div>
            <div class="panel-list">
                ${streams.length === 0 && html`
                    <div class="empty">${session ? 'No streams' : 'Select a session'}</div>
                `}
                ${sorted.map(s => html`
                    <div
                        key=${s.id}
                        class=${'list-item' + (selected?.id === s.id ? ' selected' : '')}
                        onclick=${() => onSelect(s)}
                    >
                        <div class="list-item-title">#${s.id} · <span class="c2s">${s.src}</span></div>
                        <div class="list-item-sub">→ ${s.dst} · ${fmtDuration(s.start, s.end)}</div>
                    </div>
                `)}
            </div>
        </div>
    `
}

function fmtDuration(start, end) {
    const d = (end || Date.now()) - start
    let s
    if (d < 1000) s = `${d}ms`
    else if (d < 60000) s = `${(d / 1000).toFixed(2)}s`
    else s = `${Math.floor(d / 60000)}m ${Math.floor((d % 60000) / 1000)}s`
    return end ? s : `${s} (ongoing)`
}
