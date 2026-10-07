import { h } from 'preact'
import { useState, useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import ListPanel from './ListPanel.js'

const html = htm.bind(h)

export default function SessionList({ dbdumpApi, selected, onSelect, refreshKey, onLoad, latestSessionId }) {
    const [sessions, setSessions] = useState([])
    const [error,    setError]    = useState(null)
    const lastSeenIdRef = useRef(-1)

    function load() {
        return dbdumpApi.getSessions()
            .then(data => { setSessions(data); onLoad?.(data); setError(null) })
            .catch(e => setError(e.message))
    }

    // Seeds the baseline from the current prop value (rather than a network round trip)
    // without depending on it, so the poll-reaction effect below is the only one that
    // reacts to it changing. Also reruns on a dbdumpApi change (switching instance) —
    // App.js's own instance-switch effect already clears session/stream state, so this
    // just needs to repopulate the list against the newly-selected instance.
    useEffect(() => {
        lastSeenIdRef.current = latestSessionId
        load()
    }, [refreshKey, dbdumpApi])

    // The central live poll updates `latestSessionId`; just react when it moves.
    useEffect(() => {
        if (latestSessionId === lastSeenIdRef.current) return
        lastSeenIdRef.current = latestSessionId
        load()
    }, [latestSessionId])

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
