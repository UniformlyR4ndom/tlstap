import { h } from 'preact'
import { useState, useEffect, useRef, useMemo } from 'preact/hooks'
import htm from 'htm'
import SessionList from './SessionList.js'
import StreamList from './StreamList.js'
import TrafficView from './TrafficView.js'
import CombinedView from './CombinedView.js'
import GoToPanel from './GoToPanel.js'
import MarkersPanel from './MarkersPanel.js'
import SearchPanel, { INITIAL_SEARCH_STATE } from './SearchPanel.js'
import ExtractPanel from './ExtractPanel.js'
import TransformPanel, { INITIAL_TRANSFORM_STATE } from './TransformPanel.js'
import TamperView from './TamperView.js'
import FramingPanel from './FramingPanel.js'
import DissectScriptsPanel from './DissectScriptsPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { loadMarkers, saveMarkers, makeMarkerId } from '../markers.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { usePoll } from '../usePoll.js'
import { createDbDumpApi } from '../api.js'
import { createDbDumpFramerApi } from '../dbdumpFramerApi.js'
import { createDbDumpDissectApi } from '../dbdumpDissectApi.js'
import { useFramerJobsListener } from '../framerJobsListener.js'
import { useDissectorJobsListener } from '../dissectorJobsListener.js'
import { loadDefaultFramerScript, saveDefaultFramerScript } from '../framerPrefs.js'
import { loadDefaultDissectScript, saveDefaultDissectScript } from '../dissectPrefs.js'
import { DIRNUM_C2S } from '../direction.js'

const html = htm.bind(h)

const POLL_INTERVAL_MS = 500
const FRAME_LOG_LIMIT = 500

function posKey(s) { return `${s.session}:${s.id}` }

export default function App() {
    const [view,         setView]         = useState('analysis') // 'analysis' | 'tamper'
    // Multi-instance discovery (GET /api/instances — see cli/CLAUDE.md's "REST API"
    // section): lets each of the two tabs pick which proxy's own dbdump/tamper instance
    // it's looking at. null while not yet discovered — SessionList etc. hold off
    // fetching until a real instance is selected (see the placeholder branches below),
    // so there's no transient request against a bogus/incomplete base path.
    const [dbdumpInstances, setDbdumpInstances] = useState([])
    const [tamperInstances, setTamperInstances] = useState([])
    const [dbdumpInstance,  setDbdumpInstance]  = useState(null)
    const [tamperInstance,  setTamperInstance]  = useState(null)
    const [instancesLoaded, setInstancesLoaded] = useState(false)
    const [session,      setSession]      = useState(null)
    const [stream,       setStream]       = useState(null)
    const [streamList,   setStreamList]   = useState([])
    const [sessions,     setSessions]     = useState([])
    const [refreshKey,   setRefreshKey]   = useState(0)
    const [openMenu,     setOpenMenu]     = useState(null)
    const [globalOffset, setGlobalOffset] = useState(true)
    const [sizeFormat,   setSizeFormat]   = useState('size')  // 'size' | 'count', chunk header banner
    const [pinHeader,    setPinHeader]    = useState(true)    // pin a scrolled-past chunk header to the top
    const [rememberPosition, setRememberPosition] = useState(false)
    const [viewMode,     setViewMode]     = useState('single')
    const [bottomTab,    setBottomTab]    = useState(null)  // null = collapsed, 'goto' | 'markers' | 'search' | 'extract' | 'transform' | 'framing' | 'dissect'
    const [frameLog,     setFrameLog]     = useState([])  // [{direction, text, level}], scoped to the current stream — see handleFramerLogReset
    const [jumpTo,       setJumpTo]       = useState(null)
    const [gotoError,    setGotoError]    = useState(null)  // TrafficView.js's jump effect reports Goto-sourced failures here instead of its own generic banner — see handleJumpError
    const [markers,      setMarkers]      = useState(() => loadMarkers())
    const [extractDir,   setExtractDir]   = useState(String(DIRNUM_C2S))
    const [extractFrom,  setExtractFrom]  = useState('')
    const [extractTo,    setExtractTo]    = useState('')
    const [gotoUnit,     setGotoUnit]     = useState('chunks')
    const [searchState,  setSearchState]  = useState(INITIAL_SEARCH_STATE)
    const [transformState, setTransformState] = useState(INITIAL_TRANSFORM_STATE)
    const [latest,       setLatest]       = useState({ latest_session_id: -1, latest_sgid: -1, streams_version: -1, latest_stid: -1 })
    const [framerScripts, setFramerScripts] = useState([])
    const [defaultFramerScript, setDefaultFramerScriptState] = useState(() => loadDefaultFramerScript())
    const [dissectScripts, setDissectScripts] = useState([])
    const [defaultDissectScript, setDefaultDissectScriptState] = useState(() => loadDefaultDissectScript())
    const [remoteFramerJobs, setRemoteFramerJobs] = useState(false) // "Remote framer runs" View-menu toggle — see framerJobsListener.js
    const [remoteDissectorJobs, setRemoteDissectorJobs] = useState(false) // "Remote dissector runs" View-menu toggle — see dissectorJobsListener.js
    const [sidebarWidth, handleSidebarResize] = useResizableLayout('sidebarWidth', { min: 180, max: 600 })
    const [bottomHeight, handleBottomResize]  = useResizableLayout('bottomHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })
    const menubarRef     = useRef(null)
    const pendingJumpRef = useRef(null)  // { stream: id, direction, offset } waiting for StreamList load
    const autoSelectFirstRef = useRef(false)  // set on session select, consumed by the next StreamList load
    const positionsRef       = useRef(new Map())  // posKey(stream) -> { direction, offset }, in-memory only
    const rememberPositionRef = useRef(rememberPosition)
    const viewJumpRef    = useRef({ jumpToTop: () => {}, jumpToBottom: () => {} })  // whichever of TrafficView/CombinedView is mounted registers here — jumpToNextSegment/jumpToPrevSegment (TrafficView.js only) are called via optional chaining below, since CombinedView.js's registration doesn't provide them

    useEffect(() => { saveMarkers(markers) }, [markers])
    useEffect(() => { rememberPositionRef.current = rememberPosition }, [rememberPosition])
    useEffect(() => { setGotoError(null) }, [stream?.id]) // a stale Goto error refers to the stream being left
    useEffect(() => { updateSearchState({ results: null }) }, [session])

    // Discovers every registered interceptor instance once at mount (see the endpoint's
    // own doc comment, cli/cli.go). Sorted by proxy name for a deterministic default —
    // the first entry of each type is auto-selected below. Not re-fetched on refresh:
    // which proxies/interceptors exist is fixed for the server's whole run.
    useEffect(() => {
        fetch('/api/instances').then(r => r.json()).then(all => {
            const byType = t => all.filter(i => i.interceptor === t).sort((a, b) => a.proxy.localeCompare(b.proxy))
            const dd = byType('dbdump')
            const tt = byType('tamper')
            setDbdumpInstances(dd)
            setTamperInstances(tt)
            if (dd.length > 0) setDbdumpInstance(dd[0].basePath)
            if (tt.length > 0) setTamperInstance(tt[0].basePath)
            setInstancesLoaded(true)
        }).catch(() => setInstancesLoaded(true))
    }, [])

    const dbdumpApi = useMemo(() => dbdumpInstance != null ? createDbDumpApi(dbdumpInstance) : null, [dbdumpInstance])
    const framerApi = useMemo(() => dbdumpInstance != null ? createDbDumpFramerApi(dbdumpInstance) : null, [dbdumpInstance])
    const dissectApi = useMemo(() => dbdumpInstance != null ? createDbDumpDissectApi(dbdumpInstance) : null, [dbdumpInstance])
    const framerJobsStatus = useFramerJobsListener(remoteFramerJobs, dbdumpApi, framerApi)
    const dissectorJobsStatus = useDissectorJobsListener(remoteDissectorJobs, dbdumpApi, framerApi, dissectApi)

    // Sessions/streams belong to one specific dbdump instance — there's no meaningful
    // selection to carry across a switch. Skipped on the very first resolution (session
    // is already null then) — this only matters once the user actually picks a different
    // instance from the selector below.
    const firstDbdumpInstanceRef = useRef(true)
    useEffect(() => {
        if (dbdumpInstance == null) return
        if (firstDbdumpInstanceRef.current) { firstDbdumpInstanceRef.current = false; return }
        setSession(null)
        setStream(null)
        setStreamList([])
        setLatest({ latest_session_id: -1, latest_sgid: -1, streams_version: -1, latest_stid: -1 })
    }, [dbdumpInstance])

    // Fetched once here (not per-component) since multiple consumers need the same
    // list; re-fetched on Refresh, or on switching dbdump instance, in case scripts were
    // added/removed externally in the meantime (there's no in-app editor yet). A 501
    // (scripts-dir not configured) or any other failure just leaves the list empty.
    useEffect(() => {
        if (!framerApi) return
        framerApi.listFramerScripts().then(setFramerScripts).catch(() => setFramerScripts([]))
    }, [refreshKey, framerApi])

    // Same reasoning/convention as the framer scripts fetch above, for dbdump's separate
    // dissector script store.
    useEffect(() => {
        if (!dissectApi) return
        dissectApi.listDissectScripts().then(setDissectScripts).catch(() => setDissectScripts([]))
    }, [refreshKey, dissectApi])

    function handleSetDefaultFramer(name) {
        setDefaultFramerScriptState(name || null)
        saveDefaultFramerScript(name || null)
        setOpenMenu(null)
    }

    function handleSetDefaultDissect(name) {
        setDefaultDissectScriptState(name || null)
        saveDefaultDissectScript(name || null)
        setOpenMenu(null)
    }

    // Deliberately doesn't close the menu, unlike every other toggle above — the point is
    // watching framerJobsStatus go from "connecting" to "connected" right after toggling on.
    function toggleRemoteFramerJobs() {
        setRemoteFramerJobs(v => !v)
    }

    // Same reasoning as toggleRemoteFramerJobs above, kept as an independent toggle.
    function toggleRemoteDissectorJobs() {
        setRemoteDissectorJobs(v => !v)
    }

    // Single central live poll for the whole Analysis view — one request per tick
    // instead of one per consumer. `stream` is only included while a specific stream is
    // actually the visible view (single mode); the combined view has no use for
    // latest_stid, so there's no reason to compute it server-side while it's mounted.
    usePoll(true, POLL_INTERVAL_MS, async () => {
        if (!dbdumpApi) return
        try {
            const params = {}
            if (session) params.session = session.id
            if (session && viewMode === 'single' && stream) params.stream = stream.id
            setLatest(await dbdumpApi.getLatest(params))
        } catch {
            // Transient poll failures are silently ignored; the next tick retries.
        }
    })

    function addMarker(m) {
        setMarkers(prev => [...prev, { ...m, id: makeMarkerId() }])
    }
    function removeMarker(id) {
        setMarkers(prev => prev.filter(m => m.id !== id))
    }
    function updateMarkerLabel(id, label) {
        setMarkers(prev => prev.map(m => m.id === id ? { ...m, label } : m))
    }

    function selectBottomTab(name) { setBottomTab(name) }

    function handleSetExtractStart(direction, offset) {
        setExtractDir(String(direction))
        setExtractFrom('0x' + offset.toString(16))
        selectBottomTab('extract')
    }
    function handleSetExtractEnd(direction, offset) {
        setExtractDir(String(direction))
        setExtractTo('0x' + offset.toString(16))
        selectBottomTab('extract')
    }
    function handleSetExtractRange(direction, fromOffset, toOffset) {
        setExtractDir(String(direction))
        setExtractFrom('0x' + fromOffset.toString(16))
        setExtractTo('0x' + toOffset.toString(16))
        selectBottomTab('extract')
    }
    function handleGoTo(args) {
        setGotoError(null) // cleared optimistically; handleJumpError re-sets it if this attempt fails too
        setJumpTo(prev => ({ ...args, source: 'goto', version: (prev?.version ?? 0) + 1 }))
    }

    // TrafficView.js's jump effect calls this instead of its own generic top-of-view
    // banner for any jump tagged with a source (currently only handleGoTo's own) — routes
    // the failure back to that source's own UI instead. jt is the jumpTo object the
    // failing attempt was built from; checking jt.source (not just "the only source that
    // exists today") is what keeps this from mis-routing if a second tagged source is
    // ever added.
    function handleJumpError(jt, message) {
        if (jt.source === 'goto') setGotoError(message)
    }

    // frameLog is scoped to whichever stream is currently selected — TrafficView.js's own
    // stream-switch reset effect calls onFramerLogReset, since that's also where
    // frameState/frameScriptRunning reset (a framer run has no continuity across a
    // stream switch, unlike tamper's single proxy-wide running script).
    function handleFramerLog(direction, text, level) {
        setFrameLog(log => [...log, { direction, text, level }].slice(-FRAME_LOG_LIMIT))
    }
    function handleFramerLogReset() { setFrameLog([]) }

    // highlight (optional): {direction, start, end} of a byte range to highlight once the
    // jump lands — TrafficView.js picks it up off jumpTo itself, so a jump built without
    // one (every caller but handleSearchJump) leaves the hex view's highlight untouched by
    // simply never setting it, rather than this function having to clear a separate piece
    // of state on every other jump path.
    function jumpToOffset(streamObj, direction, offset, align, highlight) {
        if (stream?.id !== streamObj.id) setStream(streamObj)
        const unit = direction === DIRNUM_C2S ? 'offset-c2s' : 'offset-s2c'
        setJumpTo(prev => ({ value: offset, unit, align, highlight, version: (prev?.version ?? 0) + 1 }))
    }

    function selectStream(s) {
        if (stream?.session === s.session && stream?.id === s.id) return
        const saved = rememberPosition ? positionsRef.current.get(posKey(s)) : null
        if (saved) jumpToOffset(s, saved.direction, saved.offset, 'top')
        else setStream(s)
    }

    function handleLeaveStream(streamObj, position) {
        if (!rememberPositionRef.current || !position) return
        positionsRef.current.set(posKey(streamObj), position)
    }

    function updateSearchState(patch) { setSearchState(s => ({ ...s, ...patch })) }

    function handleSearchJump({ streamId, direction, offset, length }) {
        const target = streamList.find(s => s.id === streamId)
        if (!target) return
        const highlight = { direction, start: offset, end: offset + Math.max(length, 1) - 1 }
        jumpToOffset(target, direction, offset, undefined, highlight)
    }

    function handleMarkerJumpRequest(marker) {
        handleMarkerTabJump(marker)
    }

    function handleMarkerTabJump(marker) {
        const unit = marker.direction === DIRNUM_C2S ? 'offset-c2s' : 'offset-s2c'
        const doJump = (streamObj) => {
            setStream(streamObj)
            setJumpTo(prev => ({ value: marker.offset, unit, align: 'top', version: (prev?.version ?? 0) + 1 }))
        }
        if (session?.id === marker.session) {
            const target = streamList.find(s => s.id === marker.stream)
            if (target) { doJump(target); return }
        }
        // Different session: switch and defer jump until StreamList loads.
        const targetSession = sessions.find(s => s.id === marker.session)
        if (!targetSession) return
        pendingJumpRef.current = { streamId: marker.stream, direction: marker.direction, offset: marker.offset }
        setSession(targetSession)
        setStream(null)
    }

    // Close any open menu when clicking outside the menu bar.
    useEffect(() => {
        if (!openMenu) return
        const handler = e => {
            if (menubarRef.current && !menubarRef.current.contains(e.target))
                setOpenMenu(null)
        }
        document.addEventListener('mousedown', handler)
        return () => document.removeEventListener('mousedown', handler)
    }, [openMenu])

    function toggleMenu(name) { setOpenMenu(m => m === name ? null : name) }

    function selectSession(s) {
        pendingJumpRef.current = null
        autoSelectFirstRef.current = true
        setSession(s)
        setStream(null)
    }

    function handleStreamLoad(ss) {
        setStreamList(ss)
        const pending = pendingJumpRef.current
        if (pending) {
            const target = ss.find(s => s.id === pending.streamId)
            if (!target) return
            pendingJumpRef.current = null
            autoSelectFirstRef.current = false
            const unit = pending.direction === DIRNUM_C2S ? 'offset-c2s' : 'offset-s2c'
            setStream(target)
            setJumpTo(prev => ({ value: pending.offset, unit, align: 'top', version: (prev?.version ?? 0) + 1 }))
            return
        }
        if (autoSelectFirstRef.current) {
            autoSelectFirstRef.current = false
            if (ss.length > 0) setStream(ss[0])
        }
    }

    return html`
        <div class="layout">
            ${!window.isSecureContext && html`
                <div class="insecure-context-banner">
                    ⚠ Not a secure context — some features (e.g. crypto features,
                    clipboard/file-save dialogs) may not work correctly here.
                </div>
            `}
            <header class="header">
                <span class="title">tlstap · Traffic Analyzer</span>
                <button class="btn btn-icon" onclick=${() => viewJumpRef.current.jumpToTop()} title="Jump to top">
                    <svg viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="2" rx="1" /><polygon points="12,9 17,15 14,15 14,20 10,20 10,15 7,15" /></svg>
                </button>
                <button class="btn btn-icon" onclick=${() => viewJumpRef.current.jumpToBottom()} title="Jump to bottom">
                    <svg viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="17" width="14" height="2" rx="1" /><polygon points="12,15 17,9 14,9 14,4 10,4 10,9 7,9" /></svg>
                </button>
                <button
                    class="btn btn-icon" disabled=${viewMode !== 'single'}
                    onclick=${() => viewJumpRef.current.jumpToPrevSegment?.()} title="Jump to previous segment"
                >
                    <svg viewBox="0 0 24 24" fill="currentColor"><polygon points="12,7 18,15 6,15" /></svg>
                </button>
                <button
                    class="btn btn-icon" disabled=${viewMode !== 'single'}
                    onclick=${() => viewJumpRef.current.jumpToNextSegment?.()} title="Jump to next segment"
                >
                    <svg viewBox="0 0 24 24" fill="currentColor"><polygon points="12,17 6,9 18,9" /></svg>
                </button>
                <button class="btn btn-refresh" onclick=${() => setRefreshKey(k => k + 1)} title="Refresh">↺</button>
            </header>
            <div class="top-tabs">
                <div class=${'top-tab' + (view === 'analysis' ? ' active' : '')} onclick=${() => setView('analysis')}>Analysis</div>
                ${tamperInstances.length > 0 && html`
                    <div class=${'top-tab' + (view === 'tamper' ? ' active' : '')} onclick=${() => setView('tamper')}>Tamper</div>
                `}
                ${view === 'analysis' && dbdumpInstances.length > 1 && html`
                    <div class="instance-selector">
                        <span>instance</span>
                        <select class="goto-select" value=${dbdumpInstance} onchange=${e => setDbdumpInstance(e.target.value)}>
                            ${dbdumpInstances.map(i => html`<option value=${i.basePath}>${i.proxy}</option>`)}
                        </select>
                    </div>
                `}
                ${view === 'tamper' && tamperInstances.length > 1 && html`
                    <div class="instance-selector">
                        <span>instance</span>
                        <select class="goto-select" value=${tamperInstance} onchange=${e => setTamperInstance(e.target.value)}>
                            ${tamperInstances.map(i => html`<option value=${i.basePath}>${i.proxy}</option>`)}
                        </select>
                    </div>
                `}
            </div>
            ${view === 'tamper' && html`<${TamperView} key=${tamperInstance} basePath=${tamperInstance} />`}
            ${view === 'analysis' && html`
            <nav class="menubar" ref=${menubarRef}>
                <div class=${'menu' + (openMenu === 'view' ? ' open' : '')}>
                    <div class="menu-label" onclick=${() => toggleMenu('view')}>View</div>
                    ${openMenu === 'view' && html`
                        <div class="menu-dropdown">
                            <div class="menu-item" onclick=${() => { setGlobalOffset(v => !v); setOpenMenu(null) }}>
                                <span class="menu-check">${globalOffset ? '✓' : ''}</span>
                                Global offset
                            </div>
                            <div class="menu-sep" />
                            <div class="menu-item" onclick=${() => { setViewMode('single');   setOpenMenu(null) }}>
                                <span class="menu-check">${viewMode === 'single'   ? '✓' : ''}</span>
                                Single stream
                            </div>
                            <div class="menu-item" onclick=${() => { setViewMode('combined'); setOpenMenu(null) }}>
                                <span class="menu-check">${viewMode === 'combined' ? '✓' : ''}</span>
                                Combined streams
                            </div>
                            <div class="menu-sep" />
                            <div class="menu-item" onclick=${() => { setSizeFormat('size');  setOpenMenu(null) }}>
                                <span class="menu-check">${sizeFormat === 'size'  ? '✓' : ''}</span>
                                Size (e.g. 2.7 KB)
                            </div>
                            <div class="menu-item" onclick=${() => { setSizeFormat('count'); setOpenMenu(null) }}>
                                <span class="menu-check">${sizeFormat === 'count' ? '✓' : ''}</span>
                                Byte count (e.g. 2,733 B)
                            </div>
                            <div class="menu-sep" />
                            <div class="menu-item" onclick=${() => { setPinHeader(v => !v); setOpenMenu(null) }}>
                                <span class="menu-check">${pinHeader ? '✓' : ''}</span>
                                Pin header when scrolled past
                            </div>
                            <div class="menu-sep" />
                            <div class="menu-item" onclick=${() => { setRememberPosition(v => !v); setOpenMenu(null) }}>
                                <span class="menu-check">${rememberPosition ? '✓' : ''}</span>
                                Remember stream position
                            </div>
                            <div class="menu-sep" />
                            <div class="menu-item" onclick=${toggleRemoteFramerJobs}>
                                <span class="menu-check">${remoteFramerJobs ? '✓' : ''}</span>
                                Remote framer runs
                                <span style="margin-left:auto">${
                                    !remoteFramerJobs ? '' : framerJobsStatus === 'connected' ? '● connected' : framerJobsStatus === 'connecting' ? 'connecting…' : '○ disconnected'
                                }</span>
                            </div>
                            <div class="menu-item" onclick=${toggleRemoteDissectorJobs}>
                                <span class="menu-check">${remoteDissectorJobs ? '✓' : ''}</span>
                                Remote dissector runs
                                <span style="margin-left:auto">${
                                    !remoteDissectorJobs ? '' : dissectorJobsStatus === 'connected' ? '● connected' : dissectorJobsStatus === 'connecting' ? 'connecting…' : '○ disconnected'
                                }</span>
                            </div>
                            <div class="menu-sep" />
                            <div class="menu-item">
                                <span>Default framer</span>
                                <select
                                    class="goto-select"
                                    style="margin-left:auto"
                                    value=${defaultFramerScript ?? ''}
                                    onchange=${e => handleSetDefaultFramer(e.target.value)}
                                >
                                    <option value="">(none)</option>
                                    ${framerScripts.map(s => html`<option value=${s.name}>${s.name}</option>`)}
                                </select>
                            </div>
                            <div class="menu-item">
                                <span>Default dissector</span>
                                <select
                                    class="goto-select"
                                    style="margin-left:auto"
                                    value=${defaultDissectScript ?? ''}
                                    onchange=${e => handleSetDefaultDissect(e.target.value)}
                                >
                                    <option value="">(none)</option>
                                    ${dissectScripts.map(s => html`<option value=${s.name}>${s.name}</option>`)}
                                </select>
                            </div>
                        </div>
                    `}
                </div>
            </nav>
            <div class="body">
              ${!dbdumpApi ? html`<div class="placeholder">${instancesLoaded ? 'No dbdump instance configured' : 'Loading…'}</div>` : html`
                <aside class="sidebar" style=${`width: ${sidebarWidth}px`}>
                    <${SessionList}
                        dbdumpApi=${dbdumpApi}
                        selected=${session}
                        onSelect=${selectSession}
                        refreshKey=${refreshKey}
                        onLoad=${setSessions}
                        latestSessionId=${latest.latest_session_id}
                    />
                    <${StreamList}
                        dbdumpApi=${dbdumpApi}
                        session=${session}
                        selected=${stream}
                        onSelect=${selectStream}
                        onLoad=${handleStreamLoad}
                        refreshKey=${refreshKey}
                        streamsVersion=${latest.streams_version}
                    />
                </aside>
                <${ResizeHandle} orientation="v" onResize=${handleSidebarResize} />
                <main class="main">
                    ${viewMode === 'combined'
                        ? html`<${CombinedView} dbdumpApi=${dbdumpApi} session=${session} globalOffset=${globalOffset} sizeFormat=${sizeFormat} pinHeader=${pinHeader} refreshKey=${refreshKey} latestSgid=${latest.latest_sgid} jumpRef=${viewJumpRef} />`
                        : html`<${TrafficView}
                            dbdumpApi=${dbdumpApi}
                            framerApi=${framerApi}
                            dissectApi=${dissectApi}
                            stream=${stream}
                            jumpRef=${viewJumpRef}
                            globalOffset=${globalOffset}
                            sizeFormat=${sizeFormat}
                            pinHeader=${pinHeader}
                            jumpTo=${jumpTo}
                            onJumpError=${handleJumpError}
                            refreshKey=${refreshKey}
                            latestStid=${latest.latest_stid}
                            markers=${markers}
                            onAddMarker=${addMarker}
                            onRemoveMarker=${removeMarker}
                            onSetExtractStart=${handleSetExtractStart}
                            onSetExtractEnd=${handleSetExtractEnd}
                            onSetExtractRange=${handleSetExtractRange}
                            onLeaveStream=${handleLeaveStream}
                            framerScripts=${framerScripts}
                            onFramerLog=${handleFramerLog}
                            onFramerLogReset=${handleFramerLogReset}
                            dissectScripts=${dissectScripts}
                          />`
                    }
                </main>
              `}
            </div>
            <div class="bottom-panel">
                ${bottomTab && html`<${ResizeHandle} orientation="h" onResize=${handleBottomResize} />`}
                <div class="bottom-tabs">
                    <div class=${'bottom-tab' + (bottomTab === 'goto'    ? ' active' : '')} onclick=${() => selectBottomTab('goto')}>Goto</div>
                    <div class=${'bottom-tab' + (bottomTab === 'markers' ? ' active' : '')} onclick=${() => selectBottomTab('markers')}>Markers</div>
                    <div class=${'bottom-tab' + (bottomTab === 'search'  ? ' active' : '')} onclick=${() => selectBottomTab('search')}>Search</div>
                    <div class=${'bottom-tab' + (bottomTab === 'extract'   ? ' active' : '')} onclick=${() => selectBottomTab('extract')}>Extract</div>
                    <div class=${'bottom-tab' + (bottomTab === 'transform' ? ' active' : '')} onclick=${() => selectBottomTab('transform')}>Transform</div>
                    <div class=${'bottom-tab' + (bottomTab === 'framing'  ? ' active' : '')} onclick=${() => selectBottomTab('framing')}>Framing</div>
                    <div class=${'bottom-tab' + (bottomTab === 'dissect'  ? ' active' : '')} onclick=${() => selectBottomTab('dissect')}>Dissect</div>
                    ${bottomTab && html`<div class="bottom-collapse" onclick=${() => setBottomTab(null)} title="Collapse">▼</div>`}
                </div>
                ${bottomTab && html`
                    <div class="bottom-content" style=${`height: ${bottomHeight}px`}>
                        ${bottomTab === 'goto'    && html`<${GoToPanel}     stream=${stream}   onGoTo=${handleGoTo} error=${gotoError} unit=${gotoUnit} onUnitChange=${setGotoUnit} />`}
                        ${bottomTab === 'markers' && html`<${MarkersPanel}
                            session=${session}
                            markers=${markers}
                            onRemove=${removeMarker}
                            onUpdateLabel=${updateMarkerLabel}
                            onJump=${handleMarkerJumpRequest}
                            onImport=${setMarkers}
                        />`}
                        ${bottomTab === 'search'  && dbdumpApi && html`<${SearchPanel}   dbdumpApi=${dbdumpApi} session=${session} stream=${stream} onJump=${handleSearchJump} searchState=${searchState} onSearchStateChange=${updateSearchState} />`}
                        ${bottomTab === 'extract' && dbdumpApi && html`<${ExtractPanel}
                            dbdumpApi=${dbdumpApi}
                            session=${session}
                            stream=${stream}
                            direction=${extractDir}
                            from=${extractFrom}
                            to=${extractTo}
                            onDirectionChange=${setExtractDir}
                            onFromChange=${setExtractFrom}
                            onToChange=${setExtractTo}
                        />`}
                        ${bottomTab === 'transform' && html`<${TransformPanel} transformState=${transformState} onTransformStateChange=${setTransformState} />`}
                        ${bottomTab === 'framing' && framerApi && html`<${FramingPanel} framerApi=${framerApi} refreshSignal=${refreshKey} frameLog=${frameLog} onClearFrameLog=${handleFramerLogReset} />`}
                        ${bottomTab === 'dissect' && dissectApi && html`<${DissectScriptsPanel} dissectApi=${dissectApi} refreshSignal=${refreshKey} />`}
                    </div>`}
            </div>
            `}
        </div>
    `
}
