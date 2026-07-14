import { h } from 'preact'
import { useState, useEffect, useMemo, useRef } from 'preact/hooks'
import htm from 'htm'
import ResizeHandle from './ResizeHandle.js'
import TamperStreamsList from './TamperStreamsList.js'
import TamperQueueList from './TamperQueueList.js'
import TamperDetailPanel from './TamperDetailPanel.js'
import { openTamperControl } from '../tamperApi.js'
import { loadLayout, saveLayoutValue } from '../layout.js'

const html = htm.bind(h)

function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }

// Top-level container for the "Tamper" tab: owns the single control connection and
// all live state, laid out as toolbar / (streams list + queue list) / detail panel.
// Unlike the Analysis tab, state here is entirely live (no sessions/history) — every
// push event just triggers a fresh list-streams call rather than incremental local
// patching, since list-streams's "pending" array is already a complete snapshot.
export default function TamperView() {
    const [connected,     setConnected]     = useState(false)
    const [streams,       setStreams]       = useState([])
    const [selectedKey,   setSelectedKey]   = useState(null)
    const [autoIntercept, setAutoIntercept] = useState(false)
    const [detailHeight,  setDetailHeight]  = useState(() => loadLayout().tamperDetailHeight)
    const controlRef = useRef(null)

    function resync() {
        controlRef.current?.listStreams().catch(() => {})
    }

    function connect() {
        if (controlRef.current) return
        const control = openTamperControl({
            onOpen: () => { setConnected(true); control.listStreams().catch(() => {}) },
            onClose: () => { setConnected(false); controlRef.current = null },
            onStreamCreated: resync,
            onStreamTerminated: resync,
            onHeld: resync,
            onStreamList: setStreams,
        })
        controlRef.current = control
    }

    useEffect(() => {
        connect()
        return () => { controlRef.current?.close(); controlRef.current = null }
    }, [])

    const queue = useMemo(() => {
        const flat = streams.flatMap(s => s.pending.map(p => ({ ...p, conn: s.conn, src: s.src, dst: s.dst })))
        flat.sort((a, b) => a.time - b.time)
        return flat
    }, [streams])

    // Keep selection valid: auto-advance to the new first item once the selected chunk
    // is no longer in the queue (resolved — by us or force-released elsewhere — timed
    // out, or its stream terminated). Also the initial auto-select when nothing chosen
    // yet, and the post-resolve auto-advance the Tamper tab is meant to provide.
    useEffect(() => {
        if (selectedKey && queue.some(e => e.conn === selectedKey.conn && e.id === selectedKey.id)) return
        setSelectedKey(queue.length > 0 ? { conn: queue[0].conn, id: queue[0].id } : null)
    }, [queue])

    function handleToggleMode(conn, intercepting) {
        controlRef.current?.setMode(conn, intercepting).then(resync).catch(() => {})
    }

    function handleSetAutoIntercept(enabled) {
        if (!controlRef.current) return
        controlRef.current.setAutoIntercept(enabled).then(() => setAutoIntercept(enabled)).catch(() => {})
    }

    function handleResolve(conn, id, action, editedBytes) {
        if (!controlRef.current) return Promise.reject(new Error('not connected'))
        // A successful resolve produces no push event of its own (e.g. "drop" means no
        // further traffic ever flows on that stream, so nothing would otherwise trigger
        // a resync) — explicitly refresh so the queue reflects it immediately, rather
        // than relying on some later, unrelated event to happen to clean it up.
        return controlRef.current.resolve(conn, id, action, editedBytes).then(res => { resync(); return res })
    }

    function handleDetailResize(deltaY) {
        setDetailHeight(h => {
            const next = clamp(h - deltaY, 120, Math.floor(window.innerHeight * 0.7))
            saveLayoutValue('tamperDetailHeight', next)
            return next
        })
    }

    const selectedEntry = selectedKey
        ? queue.find(e => e.conn === selectedKey.conn && e.id === selectedKey.id)
        : null

    return html`
        <div class="tamper-view">
            <div class="tamper-toolbar">
                <span class=${'tamper-status' + (connected ? ' tamper-status-connected' : ' tamper-status-disconnected')}>
                    ${connected ? '● Connected' : '○ Disconnected'}
                </span>
                ${!connected && html`<button class="btn" onclick=${connect}>Reconnect</button>`}
                <label class="tamper-auto-toggle">
                    <input
                        type="checkbox"
                        checked=${autoIntercept}
                        disabled=${!connected}
                        onchange=${e => handleSetAutoIntercept(e.target.checked)}
                    />
                    Auto-intercept new connections
                </label>
                <button class="btn" disabled=${!connected} onclick=${resync}>Refresh</button>
            </div>
            <div class="tamper-body">
                <${TamperStreamsList} streams=${streams} onToggleMode=${handleToggleMode} />
                <${TamperQueueList} queue=${queue} selectedKey=${selectedKey} onSelect=${setSelectedKey} />
            </div>
            <${ResizeHandle} orientation="h" onResize=${handleDetailResize} />
            <div class="tamper-detail-wrap" style=${`height: ${detailHeight}px`}>
                <${TamperDetailPanel} entry=${selectedEntry} onResolve=${handleResolve} />
            </div>
        </div>
    `
}
