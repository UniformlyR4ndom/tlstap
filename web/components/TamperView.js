import { h } from 'preact'
import { useState, useEffect, useMemo, useRef } from 'preact/hooks'
import htm from 'htm'
import ResizeHandle from './ResizeHandle.js'
import TamperStreamsList from './TamperStreamsList.js'
import TamperQueueList from './TamperQueueList.js'
import TamperDetailPanel from './TamperDetailPanel.js'
import TamperScriptsPanel from './TamperScriptsPanel.js'
import { openTamperControl, peekBuffer } from '../tamperApi.js'
import { createScriptRuntime } from '../scriptRuntime.js'
import { loadLayout, saveLayoutValue } from '../layout.js'

const html = htm.bind(h)

function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }

const LOG_LIMIT = 500

// Stringifies a running script's tamper.log(...) arguments into one display line —
// arguments arrive over postMessage structured clone, so they can be arbitrary values,
// not just strings.
function formatLogArgs(args) {
    return args.map(a => {
        if (typeof a === 'string') return a
        if (a instanceof Uint8Array) return `Uint8Array(${a.length})`
        try { return JSON.stringify(a) } catch { return String(a) }
    }).join(' ')
}

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
    const [subTab,        setSubTab]        = useState('intercept') // 'intercept' | 'scripts'
    const [runningScript, setRunningScript] = useState(null)
    const [scriptLog,     setScriptLog]     = useState([])
    const [scriptsRefreshSignal, setScriptsRefreshSignal] = useState(0)
    // Set of "conn:direction" keys currently suspended in a script's ctx.pause(), waiting
    // on a human "Continue" — see TamperDetailPanel's restricted toolbar for those entries.
    const [pausedEntries, setPausedEntries] = useState(() => new Set())
    const controlRef = useRef(null)

    function resync() {
        controlRef.current?.listStreams().catch(() => {})
    }

    // Lazily created once (the `if` guard, not useMemo, is what keeps createScriptRuntime
    // from re-running every render — its own handlers only ever touch controlRef.current
    // at call time, so binding them once here is safe even though controlRef itself is
    // reassigned across reconnects). See scriptRuntime.js and TamperScriptsPanel.js.
    const scriptRuntimeRef = useRef(null)
    if (!scriptRuntimeRef.current) {
        scriptRuntimeRef.current = createScriptRuntime({
            peek: (conn, direction) => peekBuffer(conn, direction),
            release: (conn, direction, opts, editedBytes) => handleRelease(conn, direction, opts, editedBytes),
            dropConnection: (conn, direction) => handleDropConnection(conn, direction),
            setMode: (conn, intercepting) => controlRef.current
                ? controlRef.current.setMode(conn, intercepting).then(res => { resync(); return res })
                : Promise.reject(new Error('not connected')),
            listStreams: () => controlRef.current
                ? controlRef.current.listStreams().then(res => res.streams)
                : Promise.reject(new Error('not connected')),
            onLog: (level, args) => setScriptLog(log => [...log, { level, text: formatLogArgs(args) }].slice(-LOG_LIMIT)),
            onStatusChange: setRunningScript,
            // A pause just started: surface it like a breakpoint — jump to the Intercept
            // sub-tab and select the paused entry so the human actually notices it, rather
            // than leaving them to stumble on it in the queue list.
            onPauseChange: (conn, direction, paused) => {
                setPausedEntries(prev => {
                    const key = `${conn}:${direction}`
                    if (paused === prev.has(key)) return prev
                    const next = new Set(prev)
                    paused ? next.add(key) : next.delete(key)
                    return next
                })
                if (paused) {
                    setSubTab('intercept')
                    setSelectedKey({ conn, direction })
                }
            },
        })
    }

    function connect() {
        if (controlRef.current) return
        const control = openTamperControl({
            onOpen: () => { setConnected(true); control.listStreams().catch(() => {}) },
            onClose: () => {
                setConnected(false)
                controlRef.current = null
                // A running script talks to the control connection via this component's
                // handlers; once it's gone there's nothing left for the script to act on,
                // and reconnecting fresh shouldn't silently resume a script that was
                // reacting to a now-stale view of the world.
                scriptRuntimeRef.current.stop()
            },
            onStreamCreated: msg => {
                resync()
                scriptRuntimeRef.current.dispatch('onConnect', msg.conn, [{ conn: msg.conn, src: msg.src, dst: msg.dst }])
            },
            onStreamTerminated: msg => {
                resync()
                // Unstick any ctx.pause() suspended on this conn immediately — its
                // Intercept-tab entry (and so the human's only way to click Continue) is
                // about to disappear. Must happen before/independent of the queued onClose
                // dispatch below, not routed through it, since the per-conn event queue
                // itself can't advance past a still-pending pause on its own.
                scriptRuntimeRef.current.rejectPause(msg.conn)
                scriptRuntimeRef.current.dispatch('onClose', msg.conn, [])
            },
            onHeld: msg => {
                resync()
                scriptRuntimeRef.current.dispatch('onReceive', msg.conn, [msg.direction, msg.offset, msg.length])
            },
            onStreamList: setStreams,
            onScriptUpdated: () => setScriptsRefreshSignal(v => v + 1),
        })
        controlRef.current = control
    }

    useEffect(() => {
        connect()
        return () => {
            controlRef.current?.close()
            controlRef.current = null
            scriptRuntimeRef.current.stop()
        }
    }, [])

    // One entry per (conn, direction) that currently has something held — a summary
    // (chunks/length), not individually-addressable chunks, since the new protocol has
    // no more per-chunk ids. Sorted by conn/direction for a stable order (the old
    // oldest-first sort relied on a per-chunk "time" that stream-list's pendingInfo
    // deliberately no longer carries — see TamperQueueList.js).
    const queue = useMemo(() => {
        const flat = streams.flatMap(s => s.pending.map(p => ({ ...p, conn: s.conn, src: s.src, dst: s.dst })))
        flat.sort((a, b) => a.conn - b.conn || a.direction - b.direction)
        return flat
    }, [streams])

    // Keep selection valid: auto-advance to the new first item once the selected buffer
    // is no longer in the queue (fully released — by us or force-released elsewhere,
    // timed out, or its stream terminated). Also the initial auto-select when nothing
    // chosen yet, and the post-release auto-advance the Tamper tab is meant to provide.
    useEffect(() => {
        if (selectedKey && queue.some(e => e.conn === selectedKey.conn && e.direction === selectedKey.direction)) return
        setSelectedKey(queue.length > 0 ? { conn: queue[0].conn, direction: queue[0].direction } : null)
    }, [queue])

    function handleToggleMode(conn, intercepting) {
        controlRef.current?.setMode(conn, intercepting).then(resync).catch(() => {})
    }

    function handleSetAutoIntercept(enabled) {
        if (!controlRef.current) return
        controlRef.current.setAutoIntercept(enabled).then(() => setAutoIntercept(enabled)).catch(() => {})
    }

    function handleRelease(conn, direction, opts, editedBytes) {
        if (!controlRef.current) return Promise.reject(new Error('not connected'))
        // A successful release produces no push event of its own (e.g. "drop" means no
        // further traffic ever flows on that stream, so nothing would otherwise trigger
        // a resync) — explicitly refresh so the queue reflects it immediately, rather
        // than relying on some later, unrelated event to happen to clean it up.
        return controlRef.current.release(conn, direction, opts, editedBytes).then(res => { resync(); return res })
    }

    function handleDropConnection(conn, direction) {
        if (!controlRef.current) return Promise.reject(new Error('not connected'))
        return controlRef.current.dropConnection(conn, direction).then(res => { resync(); return res })
    }

    // "Continue" on a script-paused entry: commits any pending edit (opts mirrors what
    // TamperDetailPanel's own Forward/Drop would send, just forced to releaseChunks: 0 —
    // an edit-only hold, same as a plain "Save" would be), then hands control back to the
    // script's suspended ctx.pause() call rather than releasing anything to the wire —
    // the script itself decides what happens to the buffer next.
    function handleContinue(conn, direction, opts, editedBytes) {
        if (!controlRef.current) return Promise.reject(new Error('not connected'))
        // Nothing to commit — skip the network round-trip and resume the script directly.
        if (!opts.edited) {
            scriptRuntimeRef.current.continuePause(conn)
            return Promise.resolve()
        }
        return controlRef.current.release(conn, direction, { ...opts, action: 'forward', releaseChunks: 0 }, editedBytes)
            .then(res => { resync(); scriptRuntimeRef.current.continuePause(conn); return res })
    }

    function handleDetailResize(deltaY) {
        setDetailHeight(h => {
            const next = clamp(h - deltaY, 120, Math.floor(window.innerHeight * 0.7))
            saveLayoutValue('tamperDetailHeight', next)
            return next
        })
    }

    const selectedEntry = selectedKey
        ? queue.find(e => e.conn === selectedKey.conn && e.direction === selectedKey.direction)
        : null
    const selectedPaused = !!(selectedEntry && pausedEntries.has(`${selectedEntry.conn}:${selectedEntry.direction}`))

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
            <div class="tamper-subtabs">
                <div class=${'top-tab' + (subTab === 'intercept' ? ' active' : '')} onclick=${() => setSubTab('intercept')}>Intercept</div>
                <div class=${'top-tab' + (subTab === 'scripts'   ? ' active' : '')} onclick=${() => setSubTab('scripts')}>Scripts${runningScript ? ' ●' : ''}</div>
            </div>
            ${subTab === 'intercept' && html`
                <div class="tamper-body">
                    <${TamperStreamsList} streams=${streams} onToggleMode=${handleToggleMode} />
                    <${TamperQueueList} queue=${queue} selectedKey=${selectedKey} onSelect=${setSelectedKey} pausedEntries=${pausedEntries} />
                </div>
                <${ResizeHandle} orientation="h" onResize=${handleDetailResize} />
                <div class="tamper-detail-wrap" style=${`height: ${detailHeight}px`}>
                    <${TamperDetailPanel}
                        entry=${selectedEntry}
                        onRelease=${handleRelease}
                        onDropConnection=${handleDropConnection}
                        paused=${selectedPaused}
                        onContinue=${handleContinue}
                    />
                </div>
            `}
            ${subTab === 'scripts' && html`
                <${TamperScriptsPanel}
                    connected=${connected}
                    running=${runningScript}
                    onRun=${(name, source) => scriptRuntimeRef.current.start(name, source)}
                    onStop=${() => scriptRuntimeRef.current.stop()}
                    logLines=${scriptLog}
                    onClearLog=${() => setScriptLog([])}
                    refreshSignal=${scriptsRefreshSignal}
                />
            `}
        </div>
    `
}
