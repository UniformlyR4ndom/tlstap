import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import { getStreams } from '../api.js'
import { fmtDuration } from '../format.js'
import ListPanel from './ListPanel.js'

const html = htm.bind(h)

export default function StreamList({ session, selected, onSelect, onLoad, refreshKey }) {
    const [streams, setStreams] = useState([])

    useEffect(() => {
        if (!session) { setStreams([]); onLoad?.([]); return }
        getStreams(session.id).then(ss => { setStreams(ss); onLoad?.(ss) }).catch(() => { setStreams([]); onLoad?.([]) })
    }, [session?.id, refreshKey])

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
