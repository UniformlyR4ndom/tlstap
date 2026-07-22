import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import { getSessions } from '../api.js'
import ListPanel from './ListPanel.js'

const html = htm.bind(h)

export default function SessionList({ selected, onSelect, refreshKey, onLoad }) {
    const [sessions, setSessions] = useState([])
    const [error,    setError]    = useState(null)

    useEffect(() => {
        getSessions()
            .then(data => { setSessions(data); onLoad?.(data); setError(null) })
            .catch(e => setError(e.message))
    }, [refreshKey])

    return html`
        <${ListPanel}
            title="Sessions"
            items=${sessions}
            error=${error}
            emptyMessage="No sessions"
            selected=${selected}
            onSelect=${onSelect}
            renderItem=${s => html`
                <div class="list-item-title">#${s.id} · ${s.config?.name ?? '—'}</div>
                <div class="list-item-sub">${s.config?.listen ?? ''} · ${fmtDate(s.start)}</div>
            `}
        />
    `
}

function fmtDate(ms) {
    return new Date(ms).toLocaleString()
}
