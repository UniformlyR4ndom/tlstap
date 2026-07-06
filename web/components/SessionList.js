import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import { getSessions } from '../api.js'

const html = htm.bind(h)

export default function SessionList({ selected, onSelect, refreshKey, onLoad }) {
    const [sessions, setSessions] = useState([])
    const [error,    setError]    = useState(null)
    const [desc,     setDesc]     = useState(false)

    useEffect(() => {
        getSessions()
            .then(data => { setSessions(data); onLoad?.(data); setError(null) })
            .catch(e => setError(e.message))
    }, [refreshKey])

    const sorted = desc ? [...sessions].reverse() : sessions

    return html`
        <div class="panel">
            <div class="panel-header">
                Sessions
                <span class="badge">${sessions.length}</span>
                <span class="sort-toggle" onclick=${() => setDesc(d => !d)} title=${desc ? 'Newest first' : 'Oldest first'}>
                    ${desc ? '▼' : '▲'}
                </span>
            </div>
            <div class="panel-list">
                ${error && html`<div class="error-msg">${error}</div>`}
                ${!error && sessions.length === 0 && html`<div class="empty">No sessions</div>`}
                ${sorted.map(s => html`
                    <div
                        key=${s.id}
                        class=${'list-item' + (selected?.id === s.id ? ' selected' : '')}
                        onclick=${() => onSelect(s)}
                    >
                        <div class="list-item-title">#${s.id} · ${s.config?.name ?? '—'}</div>
                        <div class="list-item-sub">${s.config?.listen ?? ''} · ${fmtDate(s.start)}</div>
                    </div>
                `)}
            </div>
        </div>
    `
}

function fmtDate(ms) {
    return new Date(ms).toLocaleString()
}
