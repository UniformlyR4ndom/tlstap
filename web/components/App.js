import { h } from 'preact'
import { useState, useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import SessionList from './SessionList.js'
import StreamList from './StreamList.js'
import TrafficView from './TrafficView.js'
import CombinedView from './CombinedView.js'
import GoToPanel from './GoToPanel.js'
import SearchPanel from './SearchPanel.js'
import ExtractPanel from './ExtractPanel.js'
import TransformPanel from './TransformPanel.js'
import TamperView from './TamperView.js'
import ResizeHandle from './ResizeHandle.js'
import { loadMarkers, saveMarkers, makeMarkerId } from '../markers.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { usePoll } from '../usePoll.js'
import { getLatest } from '../api.js'
import { listFramerScripts } from '../dbdumpFramerApi.js'
import { loadDefaultFramerScript, saveDefaultFramerScript } from '../framerPrefs.js'
import { DIRNUM_C2S } from '../direction.js'

const html = htm.bind(h)

const POLL_INTERVAL_MS = 500

function posKey(s) { return `${s.session}:${s.id}` }

export default function App() {
    const [view,         setView]         = useState('analysis') // 'analysis' | 'tamper'
    const [session,      setSession]      = useState(null)
    const [stream,       setStream]       = useState(null)
    const [streamList,   setStreamList]   = useState([])
    const [sessions,     setSessions]     = useState([])
    const [refreshKey,   setRefreshKey]   = useState(0)
    const [openMenu,     setOpenMenu]     = useState(null)
    const [globalOffset, setGlobalOffset] = useState(true)
    const [rememberPosition, setRememberPosition] = useState(false)
    const [viewMode,     setViewMode]     = useState('single')
    const [bottomTab,    setBottomTab]    = useState(null)  // null = collapsed, 'goto' | 'search' | 'extract' | 'transform'
    const [jumpTo,       setJumpTo]       = useState(null)
    const [markers,      setMarkers]      = useState(() => loadMarkers())
    const [extractDir,   setExtractDir]   = useState(String(DIRNUM_C2S))
    const [extractFrom,  setExtractFrom]  = useState('')
    const [extractTo,    setExtractTo]    = useState('')
    const [latest,       setLatest]       = useState({ latest_session_id: -1, latest_sgid: -1, streams_version: -1, latest_stid: -1 })
    const [framerScripts, setFramerScripts] = useState([])
    const [defaultFramerScript, setDefaultFramerScriptState] = useState(() => loadDefaultFramerScript())
    const [sidebarWidth, handleSidebarResize] = useResizableLayout('sidebarWidth', { min: 180, max: 600 })
    const [bottomHeight, handleBottomResize]  = useResizableLayout('bottomHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })
    const menubarRef     = useRef(null)
    const pendingJumpRef = useRef(null)  // { stream: id, direction, offset } waiting for StreamList load
    const positionsRef       = useRef(new Map())  // posKey(stream) -> { direction, offset }, in-memory only
    const rememberPositionRef = useRef(rememberPosition)
    const viewJumpRef    = useRef({ jumpToTop: () => {}, jumpToBottom: () => {} })  // whichever of TrafficView/CombinedView is mounted registers here

    useEffect(() => { saveMarkers(markers) }, [markers])
    useEffect(() => { rememberPositionRef.current = rememberPosition }, [rememberPosition])

    // Fetched once here (not per-component) since multiple consumers need the same
    // list; re-fetched on Refresh in case scripts were added/removed externally in the
    // meantime (there's no in-app editor yet). A 501 (scripts-dir not configured) or any
    // other failure just leaves the list empty.
    useEffect(() => {
        listFramerScripts().then(setFramerScripts).catch(() => setFramerScripts([]))
    }, [refreshKey])

    function handleSetDefaultFramer(name) {
        setDefaultFramerScriptState(name || null)
        saveDefaultFramerScript(name || null)
        setOpenMenu(null)
    }

    // Single central live poll for the whole Analysis view — one request per tick
    // instead of one per consumer. `stream` is only included while a specific stream is
    // actually the visible view (single mode); the combined view has no use for
    // latest_stid, so there's no reason to compute it server-side while it's mounted.
    usePoll(true, POLL_INTERVAL_MS, async () => {
        try {
            const params = {}
            if (session) params.session = session.id
            if (session && viewMode === 'single' && stream) params.stream = stream.id
            setLatest(await getLatest(params))
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
    function handleGoTo(args) { setJumpTo(prev => ({ ...args, version: (prev?.version ?? 0) + 1 })) }

    function jumpToOffset(streamObj, direction, offset, align) {
        if (stream?.id !== streamObj.id) setStream(streamObj)
        const unit = direction === DIRNUM_C2S ? 'offset-c2s' : 'offset-s2c'
        setJumpTo(prev => ({ value: offset, unit, align, version: (prev?.version ?? 0) + 1 }))
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

    function handleSearchJump({ streamId, direction, offset }) {
        const target = streamList.find(s => s.id === streamId)
        if (!target) return
        jumpToOffset(target, direction, offset)
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
        setSession(s)
        setStream(null)
    }

    function handleStreamLoad(ss) {
        setStreamList(ss)
        const pending = pendingJumpRef.current
        if (!pending) return
        const target = ss.find(s => s.id === pending.streamId)
        if (!target) return
        pendingJumpRef.current = null
        const unit = pending.direction === DIRNUM_C2S ? 'offset-c2s' : 'offset-s2c'
        setStream(target)
        setJumpTo(prev => ({ value: pending.offset, unit, align: 'top', version: (prev?.version ?? 0) + 1 }))
    }

    return html`
        <div class="layout">
            <header class="header">
                <span class="title">tlstap · Traffic Analyzer</span>
                <button class="btn btn-icon" onclick=${() => viewJumpRef.current.jumpToTop()} title="Jump to top">
                    <svg viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="5" width="14" height="2" rx="1" /><polygon points="12,9 17,15 14,15 14,20 10,20 10,15 7,15" /></svg>
                </button>
                <button class="btn btn-icon" onclick=${() => viewJumpRef.current.jumpToBottom()} title="Jump to bottom">
                    <svg viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="17" width="14" height="2" rx="1" /><polygon points="12,15 17,9 14,9 14,4 10,4 10,9 7,9" /></svg>
                </button>
                <button class="btn btn-refresh" onclick=${() => setRefreshKey(k => k + 1)} title="Refresh">↺</button>
            </header>
            <div class="top-tabs">
                <div class=${'top-tab' + (view === 'analysis' ? ' active' : '')} onclick=${() => setView('analysis')}>Analysis</div>
                <div class=${'top-tab' + (view === 'tamper'   ? ' active' : '')} onclick=${() => setView('tamper')}>Tamper</div>
            </div>
            ${view === 'tamper' && html`<${TamperView} />`}
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
                            <div class="menu-item" onclick=${() => { setRememberPosition(v => !v); setOpenMenu(null) }}>
                                <span class="menu-check">${rememberPosition ? '✓' : ''}</span>
                                Remember stream position
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
                        </div>
                    `}
                </div>
            </nav>
            <div class="body">
                <aside class="sidebar" style=${`width: ${sidebarWidth}px`}>
                    <${SessionList}
                        selected=${session}
                        onSelect=${selectSession}
                        refreshKey=${refreshKey}
                        onLoad=${setSessions}
                        latestSessionId=${latest.latest_session_id}
                    />
                    <${StreamList}
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
                        ? html`<${CombinedView} session=${session} globalOffset=${globalOffset} refreshKey=${refreshKey} latestSgid=${latest.latest_sgid} jumpRef=${viewJumpRef} />`
                        : html`<${TrafficView}
                            stream=${stream}
                            jumpRef=${viewJumpRef}
                            globalOffset=${globalOffset}
                            jumpTo=${jumpTo}
                            refreshKey=${refreshKey}
                            latestStid=${latest.latest_stid}
                            markers=${markers}
                            onAddMarker=${addMarker}
                            onRemoveMarker=${removeMarker}
                            onUpdateMarkerLabel=${updateMarkerLabel}
                            onMarkerJumpRequest=${handleMarkerJumpRequest}
                            onImportMarkers=${setMarkers}
                            onSetExtractStart=${handleSetExtractStart}
                            onSetExtractEnd=${handleSetExtractEnd}
                            onSetExtractRange=${handleSetExtractRange}
                            onLeaveStream=${handleLeaveStream}
                            framerScripts=${framerScripts}
                          />`
                    }
                </main>
            </div>
            <div class="bottom-panel">
                ${bottomTab && html`<${ResizeHandle} orientation="h" onResize=${handleBottomResize} />`}
                <div class="bottom-tabs">
                    <div class=${'bottom-tab' + (bottomTab === 'goto'    ? ' active' : '')} onclick=${() => selectBottomTab('goto')}>Goto</div>
                    <div class=${'bottom-tab' + (bottomTab === 'search'  ? ' active' : '')} onclick=${() => selectBottomTab('search')}>Search</div>
                    <div class=${'bottom-tab' + (bottomTab === 'extract'   ? ' active' : '')} onclick=${() => selectBottomTab('extract')}>Extract</div>
                    <div class=${'bottom-tab' + (bottomTab === 'transform' ? ' active' : '')} onclick=${() => selectBottomTab('transform')}>Transform</div>
                    ${bottomTab && html`<div class="bottom-collapse" onclick=${() => setBottomTab(null)} title="Collapse">▼</div>`}
                </div>
                ${bottomTab && html`
                    <div class="bottom-content" style=${`height: ${bottomHeight}px`}>
                        ${bottomTab === 'goto'    && html`<${GoToPanel}     stream=${stream}   onGoTo=${handleGoTo} />`}
                        ${bottomTab === 'search'  && html`<${SearchPanel}   session=${session} stream=${stream} onJump=${handleSearchJump} />`}
                        ${bottomTab === 'extract' && html`<${ExtractPanel}
                            session=${session}
                            stream=${stream}
                            direction=${extractDir}
                            from=${extractFrom}
                            to=${extractTo}
                            onDirectionChange=${setExtractDir}
                            onFromChange=${setExtractFrom}
                            onToChange=${setExtractTo}
                        />`}
                        ${bottomTab === 'transform' && html`<${TransformPanel} />`}
                    </div>`}
            </div>
            `}
        </div>
    `
}
