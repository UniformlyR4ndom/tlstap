import { h } from 'preact'
import { useState, useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import SessionList from './SessionList.js'
import StreamList from './StreamList.js'
import TrafficView from './TrafficView.js'
import CombinedView from './CombinedView.js'
import GoToPanel from './GoToPanel.js'
import SearchPanel from './SearchPanel.js'

const html = htm.bind(h)

export default function App() {
    const [session,      setSession]      = useState(null)
    const [stream,       setStream]       = useState(null)
    const [streamList,   setStreamList]   = useState([])
    const [refreshKey,   setRefreshKey]   = useState(0)
    const [openMenu,     setOpenMenu]     = useState(null)
    const [globalOffset, setGlobalOffset] = useState(true)
    const [viewMode,     setViewMode]     = useState('single')
    const [bottomTab,    setBottomTab]    = useState(null)  // null = collapsed, 'goto' | 'search'
    const [jumpTo,       setJumpTo]       = useState(null)
    const menubarRef = useRef(null)

    function selectBottomTab(name) { setBottomTab(name) }
    function handleGoTo(args) { setJumpTo(prev => ({ ...args, version: (prev?.version ?? 0) + 1 })) }

    function handleSearchJump({ streamId, direction, offset }) {
        const target = streamList.find(s => s.id === streamId)
        if (!target) return
        if (stream?.id !== streamId) setStream(target)
        const unit = direction === 0 ? 'offset-c2s' : 'offset-s2c'
        setJumpTo(prev => ({ value: offset, unit, version: (prev?.version ?? 0) + 1 }))
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
        setSession(s)
        setStream(null)
    }

    return html`
        <div class="layout">
            <header class="header">
                <span class="title">tlstap · Traffic Analyzer</span>
                <button class="btn" onclick=${() => setRefreshKey(k => k + 1)}>↺ Refresh</button>
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
                        </div>
                    `}
                </div>
            </nav>
            <div class="body">
                <aside class="sidebar">
                    <${SessionList}
                        selected=${session}
                        onSelect=${selectSession}
                        refreshKey=${refreshKey}
                    />
                    <${StreamList}
                        session=${session}
                        selected=${stream}
                        onSelect=${setStream}
                        onLoad=${setStreamList}
                    />
                </aside>
                <main class="main">
                    ${viewMode === 'combined'
                        ? html`<${CombinedView} session=${session} globalOffset=${globalOffset} />`
                        : html`<${TrafficView}  stream=${stream}  globalOffset=${globalOffset} jumpTo=${jumpTo} />`
                    }
                </main>
            </div>
            <div class="bottom-panel">
                <div class="bottom-tabs">
                    <div class=${'bottom-tab' + (bottomTab === 'goto'   ? ' active' : '')} onclick=${() => selectBottomTab('goto')}>Goto</div>
                    <div class=${'bottom-tab' + (bottomTab === 'search' ? ' active' : '')} onclick=${() => selectBottomTab('search')}>Search</div>
                    ${bottomTab && html`<div class="bottom-collapse" onclick=${() => setBottomTab(null)} title="Collapse">▼</div>`}
                </div>
                ${bottomTab && html`
                    <div class="bottom-content">
                        ${bottomTab === 'goto'   && html`<${GoToPanel}    stream=${stream}   onGoTo=${handleGoTo} />`}
                        ${bottomTab === 'search' && html`<${SearchPanel} session=${session} stream=${stream} onJump=${handleSearchJump} />`}
                    </div>
                `}
            </div>
        </div>
    `
}
