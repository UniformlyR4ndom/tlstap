import { h } from 'preact'
import { useState, useEffect, useMemo, useRef } from 'preact/hooks'
import htm from 'htm'
import ResizeHandle from './ResizeHandle.js'
import TamperStreamsList from './TamperStreamsList.js'
import TamperQueueList from './TamperQueueList.js'
import TamperDetailPanel from './TamperDetailPanel.js'
import TamperScriptsPanel from './TamperScriptsPanel.js'
import TamperFramerScriptsPanel from './TamperFramerScriptsPanel.js'
import { createTamperApi } from '../tamperApi.js'
import { createTamperFramerApi } from '../tamperFramerApi.js'
import { createScriptRuntime } from '../scriptRuntime.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { fmtLogArgs } from '../format.js'

const html = htm.bind(h)

const LOG_LIMIT = 500

// Top-level container for the "Tamper" tab: owns the single control connection and
// all live state, laid out as toolbar / (streams list + queue list) / detail panel.
// Unlike the Analysis tab, state here is entirely live (no sessions/history) — every
// push event just triggers a fresh list-streams call rather than incremental local
// patching, since list-streams's "pending" array is already a complete snapshot.
//
// basePath identifies one tamper interceptor instance (see the GET /api/instances
// discovery endpoint). App.js remounts this whole component (via a `key` keyed on
// basePath) on instance switch rather than reacting to a changed prop here — control
// reconnection is already a full resync by design (see intercept/tamper/CLAUDE.md), so a
// remount reproduces "close old control socket, open new one, resync" for free and also
// correctly discards script-runtime/selected-queue-entry state that has no meaning
// against a different instance. tamperApi/tamperFramerApi are therefore built once, not
// memoized against a basePath change this component never actually sees happen to it.
export default function TamperView({ basePath }) {
    const tamperApi = createTamperApi(basePath)
    const tamperFramerApi = createTamperFramerApi(basePath)
    const [connected,     setConnected]     = useState(false)
    const [streams,       setStreams]       = useState([])
    const [selectedKey,   setSelectedKey]   = useState(null)
    const [autoIntercept, setAutoIntercept] = useState(false)
    const [detailHeight,  handleDetailResize] = useResizableLayout('tamperDetailHeight', { sign: -1, min: 120, max: () => Math.floor(window.innerHeight * 0.7) })
    const [subTab,        setSubTab]        = useState('intercept') // 'intercept' | 'scripts' | 'framer-scripts'
    const [runningScript, setRunningScript] = useState(null)
    const [scriptLog,     setScriptLog]     = useState([])
    const [scriptsRefreshSignal, setScriptsRefreshSignal] = useState(0)
    // Framer selection is plain, non-persisted state: unlike dbdump's per-stream
    // framerPrefs.js, there's only one "current" choice here (one script run at a time),
    // not one per stream.
    const [framerScripts, setFramerScripts] = useState([])
    const [framerScriptsRefreshSignal, setFramerScriptsRefreshSignal] = useState(0)
    const [framerSelected, setFramerSelected] = useState('')
    // logFileInfo: whether the server persists the script log to a file (static for the
    // server's run, fetched once on mount). bypassBrowserLog: skip the browser's own
    // in-memory copy, offered only while a log file is active. Both are read inside onLog
    // below, a callback created once — logFileRef/bypassLogRef keep it seeing live values
    // instead of what was captured at first render.
    const [logFileInfo,     setLogFileInfo]     = useState({ enabled: false, filename: '' })
    const [bypassBrowserLog, setBypassBrowserLog] = useState(false)
    const logFileRef = useRef(logFileInfo)
    logFileRef.current = logFileInfo
    const bypassLogRef = useRef(bypassBrowserLog)
    bypassLogRef.current = bypassBrowserLog
    // Set of "conn:direction" keys currently suspended in a script's ctx.pause(), waiting
    // on a human "Continue".
    const [pausedEntries, setPausedEntries] = useState(() => new Set())
    const controlRef = useRef(null)

    function resync() {
        controlRef.current?.listStreams().catch(() => {})
    }

    // Lazily created once — the `if` guard (not useMemo) keeps createScriptRuntime from
    // re-running every render; its handlers only touch controlRef.current at call time,
    // so binding them once here is safe even though controlRef itself is reassigned
    // across reconnects.
    const scriptRuntimeRef = useRef(null)
    if (!scriptRuntimeRef.current) {
        scriptRuntimeRef.current = createScriptRuntime({
            peek: (conn, direction) => tamperApi.peekBuffer(conn, direction),
            release: (conn, direction, opts, editedBytes) => handleRelease(conn, direction, opts, editedBytes),
            dropConnection: (conn, direction) => handleDropConnection(conn, direction),
            // Wire command underneath (setMode) stays named after the "set-mode"
            // control-protocol command; only the script-facing name changed.
            setIntercept: (conn, intercepting) => controlRef.current
                ? controlRef.current.setMode(conn, intercepting).then(res => { resync(); return res })
                : Promise.reject(new Error('not connected')),
            listStreams: () => controlRef.current
                ? controlRef.current.listStreams().then(res => res.streams)
                : Promise.reject(new Error('not connected')),
            // prefix (ctx.log only) is a ready-made connection-summary + timestamp line,
            // rendered above the args rather than joined into them so it stays visually
            // distinct even when args is empty (a bare ctx.log() still logs something
            // useful on its own).
            onLog: (level, args, prefix) => {
                const text = prefix ? (args.length ? `${prefix}\n${fmtLogArgs(args)}` : prefix) : fmtLogArgs(args)
                // Persistence is independent of the browser copy below: it always happens
                // while a log file is configured, regardless of the bypass checkbox, which
                // only controls the memory-bounded browser copy.
                if (logFileRef.current.enabled) controlRef.current?.scriptLog(level, text)
                if (!logFileRef.current.enabled || !bypassLogRef.current) {
                    setScriptLog(log => [...log, { level, text }].slice(-LOG_LIMIT))
                }
            },
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
        const control = tamperApi.openTamperControl({
            onOpen: () => { setConnected(true); control.listStreams().catch(() => {}) },
            onClose: () => {
                setConnected(false)
                controlRef.current = null
                // A running script talks to the control connection via these handlers;
                // once it's gone there's nothing left for it to act on, and reconnecting
                // fresh shouldn't silently resume a script reacting to a now-stale view
                // of the world.
                scriptRuntimeRef.current.stop()
            },
            onStreamCreated: msg => {
                resync()
                scriptRuntimeRef.current.dispatch('onConnect', msg.conn, [{ conn: msg.conn, src: msg.src, dst: msg.dst }])
            },
            onStreamTerminated: msg => {
                resync()
                // Unsticks any ctx.pause() suspended on this conn immediately, before the
                // queued onClose dispatch below — the per-conn event queue can't advance
                // past a still-pending pause on its own.
                scriptRuntimeRef.current.rejectPause(msg.conn)
                scriptRuntimeRef.current.dispatch('onClose', msg.conn, [])
            },
            onHeld: msg => {
                resync()
                scriptRuntimeRef.current.dispatch('onReceive', msg.conn, [msg.direction, msg.offset, msg.length])
            },
            onStreamList: setStreams,
            onScriptUpdated: () => setScriptsRefreshSignal(v => v + 1),
            onFramerScriptUpdated: () => {
                setFramerScriptsRefreshSignal(v => v + 1)
                tamperFramerApi.listFramerScripts().then(setFramerScripts).catch(() => {})
            },
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

    // Independent of the control connection (a REST GET, not pushed over the
    // WebSocket) since log-file config never changes for the server's lifetime.
    useEffect(() => {
        tamperApi.getLogFileInfo().then(setLogFileInfo).catch(() => {})
    }, [])

    // Also independent of the control connection's own lifecycle (a REST GET) — kept
    // fresh afterward via the control connection's "framer-script-updated" push event
    // instead (onFramerScriptUpdated below), same as the interception scripts list.
    useEffect(() => {
        tamperFramerApi.listFramerScripts().then(setFramerScripts).catch(() => {})
    }, [])

    // One entry per (conn, direction) with something held — a summary (chunks/length),
    // not individually-addressable chunks, since there are no per-chunk ids. Sorted by
    // conn/direction for a stable order (no per-buffer timestamp to sort by instead).
    const queue = useMemo(() => {
        const flat = streams.flatMap(s => s.pending.map(p => ({ ...p, conn: s.conn, src: s.src, dst: s.dst })))
        flat.sort((a, b) => a.conn - b.conn || a.direction - b.direction)
        return flat
    }, [streams])

    // Keep selection valid: auto-advance to the new first item once the selected buffer
    // is no longer in the queue (released, timed out, or its stream terminated) — also
    // covers the initial auto-select.
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
        // A successful release produces no push event of its own, so explicitly resync
        // rather than relying on some later, unrelated event to clean up the queue.
        return controlRef.current.release(conn, direction, opts, editedBytes).then(res => { resync(); return res })
    }

    function handleDropConnection(conn, direction) {
        if (!controlRef.current) return Promise.reject(new Error('not connected'))
        return controlRef.current.dropConnection(conn, direction).then(res => { resync(); return res })
    }

    // "Continue" on a script-paused entry: commits any pending edit as an edit-only hold
    // (releaseChunks: 0), then hands control back to the script's suspended ctx.pause()
    // call — the script itself decides what happens to the buffer next.
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

    // Composes the selected framer script (if any) with the interception script being
    // run: fetches the framer's current source first (mirroring TrafficView.js's own
    // handleRunFramer), so a failed fetch is reported the same way a script error is
    // (the log panel) rather than silently starting framer-less.
    async function handleRunScript(name, source) {
        if (!framerSelected) {
            scriptRuntimeRef.current.start(name, source)
            return
        }
        try {
            const framerSource = await tamperFramerApi.getFramerScript(framerSelected)
            scriptRuntimeRef.current.start(name, source, framerSelected, framerSource)
        } catch (e) {
            setScriptLog(log => [...log, { level: 'error', text: `Framer "${framerSelected}" failed to load: ${e.message}` }].slice(-LOG_LIMIT))
        }
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
                <div class=${'top-tab' + (subTab === 'framer-scripts' ? ' active' : '')} onclick=${() => setSubTab('framer-scripts')}>Framer Scripts</div>
            </div>
            ${subTab === 'intercept' && html`
                <div class="tamper-body">
                    <${TamperStreamsList} streams=${streams} onToggleMode=${handleToggleMode} />
                    <${TamperQueueList} queue=${queue} selectedKey=${selectedKey} onSelect=${setSelectedKey} pausedEntries=${pausedEntries} />
                </div>
                <${ResizeHandle} orientation="h" onResize=${handleDetailResize} />
                <div class="tamper-detail-wrap" style=${`height: ${detailHeight}px`}>
                    <${TamperDetailPanel}
                        peekBuffer=${tamperApi.peekBuffer}
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
                    tamperApi=${tamperApi}
                    connected=${connected}
                    running=${runningScript}
                    onRun=${handleRunScript}
                    onStop=${() => scriptRuntimeRef.current.stop()}
                    logLines=${scriptLog}
                    onClearLog=${() => setScriptLog([])}
                    refreshSignal=${scriptsRefreshSignal}
                    logFile=${logFileInfo}
                    bypassBrowserLog=${bypassBrowserLog}
                    onBypassBrowserLogChange=${setBypassBrowserLog}
                    framerScripts=${framerScripts}
                    framerSelected=${framerSelected}
                    onFramerSelectedChange=${setFramerSelected}
                />
            `}
            ${subTab === 'framer-scripts' && html`
                <${TamperFramerScriptsPanel} tamperFramerApi=${tamperFramerApi} refreshSignal=${framerScriptsRefreshSignal} />
            `}
        </div>
    `
}
