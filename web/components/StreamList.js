import { h } from 'preact'
import { useState, useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import { getStreams } from '../api.js'
import { fmtDuration } from '../format.js'
import ListPanel from './ListPanel.js'

const html = htm.bind(h)

export default function StreamList({ session, selected, onSelect, onLoad, refreshKey, streamsVersion }) {
    const [streams, setStreams] = useState([])
    const lastSeenVersionRef = useRef(-1)

    function load(sessionId) {
        return getStreams(sessionId).then(ss => { setStreams(ss); onLoad?.(ss) }).catch(() => { setStreams([]); onLoad?.([]) })
    }

    // Seeding from `streamsVersion`'s current value (rather than a network round trip)
    // is deliberately not in this effect's dependency array — it's read once per
    // entity/refresh, not on every value it takes afterward; the poll-reaction effect
    // below owns reacting to it changing.
    useEffect(() => {
        lastSeenVersionRef.current = streamsVersion
        if (!session) { setStreams([]); onLoad?.([]); return }
        load(session.id)
    }, [session?.id, refreshKey])

    // The central live poll updates `streamsVersion`; just react when it moves.
    useEffect(() => {
        if (!session || streamsVersion === lastSeenVersionRef.current) return
        lastSeenVersionRef.current = streamsVersion
        load(session.id)
    }, [streamsVersion])

    return html`
        <${ListPanel}
            title="Streams"
            items=${streams}
            emptyMessage=${session ? 'No streams' : 'Select a session'}
            selected=${selected}
            onSelect=${onSelect}
            resetSortKey=${session?.id}
            renderItem=${s => html`
                <div class="list-item-title">#${s.id} · <span class="c2s">${s.src}</span></div>
                <div class="list-item-sub">→ ${s.dst} · ${fmtDuration(s.start, s.end)}</div>
            `}
        />
    `
}
