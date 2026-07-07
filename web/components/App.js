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
import ResizeHandle from './ResizeHandle.js'
import { loadMarkers, saveMarkers, makeMarkerId } from '../markers.js'
import { loadLayout, saveLayoutValue } from '../layout.js'

const html = htm.bind(h)

function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }

export default function App() {
    const [session,      setSession]      = useState(null)
    const [stream,       setStream]       = useState(null)
    const [streamList,   setStreamList]   = useState([])
    const [sessions,     setSessions]     = useState([])
    const [refreshKey,   setRefreshKey]   = useState(0)
    const [openMenu,     setOpenMenu]     = useState(null)
    const [globalOffset, setGlobalOffset] = useState(true)
    const [autoRefresh,  setAutoRefresh]  = useState(false)
    const [viewMode,     setViewMode]     = useState('single')
    const [bottomTab,    setBottomTab]    = useState(null)  // null = collapsed, 'goto' | 'search' | 'extract' | 'transform'
    const [jumpTo,       setJumpTo]       = useState(null)
    const [markers,      setMarkers]      = useState(() => loadMarkers())
    const [extractDir,   setExtractDir]   = useState('0')
    const [extractFrom,  setExtractFrom]  = useState('')
    const [extractTo,    setExtractTo]    = useState('')
    const [sidebarWidth, setSidebarWidth] = useState(() => loadLayout().sidebarWidth)
    const [bottomHeight, setBottomHeight] = useState(() => loadLayout().bottomHeight)
    const menubarRef     = useRef(null)
    const pendingJumpRef = useRef(null)  // { stream: id, direction, offset } waiting for StreamList load

    function handleSidebarResize(deltaX) {
        setSidebarWidth(w => {
            const next = clamp(w + deltaX, 180, 600)
            saveLayoutValue('sidebarWidth', next)
            return next
        })
    }

    function handleBottomResize(deltaY) {
        setBottomHeight(h => {
            const next = clamp(h - deltaY, 80, Math.floor(window.innerHeight * 0.7))
            saveLayoutValue('bottomHeight', next)
            return next
        })
    }

    useEffect(() => { saveMarkers(markers) }, [markers])

    useEffect(() => {
        if (!autoRefresh) return
        const id = setInterval(() => setRefreshKey(k => k + 1), 1000)
        return () => clearInterval(id)
    }, [autoRefresh])

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

    function jumpToOffset(streamObj, direction, offset) {
        if (stream?.id !== streamObj.id) setStream(streamObj)
        const unit = direction === 0 ? 'offset-c2s' : 'offset-s2c'
        setJumpTo(prev => ({ value: offset, unit, version: (prev?.version ?? 0) + 1 }))
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
        const unit = marker.direction === 0 ? 'offset-c2s' : 'offset-s2c'
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
        const unit = pending.direction === 0 ? 'offset-c2s' : 'offset-s2c'
        setStream(target)
        setJumpTo(prev => ({ value: pending.offset, unit, align: 'top', version: (prev?.version ?? 0) + 1 }))
    }

    return html`
        <div class="layout">
            <header class="header">
                <span class="title">tlstap · Traffic Analyzer</span>
                <button class="btn btn-refresh" onclick=${() => setRefreshKey(k => k + 1)} title="Refresh">↺</button>
            </header>
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
                            <div class="menu-item" onclick=${() => { setAutoRefresh(v => !v); setOpenMenu(null) }}>
                                <span class="menu-check">${autoRefresh ? '✓' : ''}</span>
                                Auto-Refresh
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
                    />
                    <${StreamList}
                        session=${session}
                        selected=${stream}
                        onSelect=${setStream}
                        onLoad=${handleStreamLoad}
                        refreshKey=${refreshKey}
                    />
                </aside>
                <${ResizeHandle} orientation="v" onResize=${handleSidebarResize} />
                <main class="main">
                    ${viewMode === 'combined'
                        ? html`<${CombinedView} session=${session} globalOffset=${globalOffset} refreshKey=${refreshKey} />`
                        : html`<${TrafficView}
                            stream=${stream}
                            globalOffset=${globalOffset}
                            jumpTo=${jumpTo}
                            refreshKey=${refreshKey}
                            markers=${markers}
                            onAddMarker=${addMarker}
                            onRemoveMarker=${removeMarker}
                            onUpdateMarkerLabel=${updateMarkerLabel}
                            onMarkerJumpRequest=${handleMarkerJumpRequest}
                            onImportMarkers=${setMarkers}
                            onSetExtractStart=${handleSetExtractStart}
                            onSetExtractEnd=${handleSetExtractEnd}
                            onSetExtractRange=${handleSetExtractRange}
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
        </div>
    `
}
