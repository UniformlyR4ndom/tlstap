import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import { listScripts, getScript, putScript, deleteScript } from '../tamperApi.js'
import ScriptEditor from './ScriptEditor.js'
import ResizeHandle from './ResizeHandle.js'
import { loadLayout, saveLayoutValue } from '../layout.js'

const html = htm.bind(h)

function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }

// "Scripts" sub-tab of the Tamper view: CRUD over the server-side script store (see
// intercept/tamper/scripts.go) plus Run/Stop for the one script instance TamperView's
// scriptRuntime can have active at a time. The running script and its log survive
// switching away from this sub-tab (both are lifted to TamperView); the list/editor/
// selection here are local and simply refetched each time this panel mounts.
//
// logFile ({enabled, filename}, from getLogFileInfo) and bypassBrowserLog/
// onBypassBrowserLogChange are also owned by TamperView — the actual decisions of
// whether to persist a line server-side and whether to also keep it in the browser's
// own copy happen there (in the onLog handler passed to createScriptRuntime), not here;
// this panel only renders what those choices imply (see the Log panel header below).
export default function TamperScriptsPanel({
    connected, running, onRun, onStop, logLines, onClearLog, refreshSignal,
    logFile, bypassBrowserLog, onBypassBrowserLogChange,
}) {
    const [scripts,      setScripts]      = useState([])
    const [selectedName, setSelectedName] = useState(null)
    const [source,       setSource]       = useState('')
    const [savedSource,  setSavedSource]  = useState('')
    const [loading,      setLoading]      = useState(false)
    const [saving,       setSaving]       = useState(false)
    const [status,       setStatus]       = useState(null) // null | { ok, msg }
    const [creatingNew,  setCreatingNew]  = useState(false)
    const [newName,      setNewName]      = useState('')
    const [listWidth,    setListWidth]    = useState(() => loadLayout().scriptsListWidth)
    const [logHeight,    setLogHeight]    = useState(() => loadLayout().scriptsLogHeight)
    // Bumped exactly once per genuine external reset of the editor's content (initial
    // load, script switch, Reload) — see ScriptEditor.js's doc comment for why it must be
    // an explicit signal rather than inferred from `source` changing (ordinary typing also
    // changes `source`, via ScriptEditor's own onChange).
    const [loadVersion,  setLoadVersion]  = useState(0)

    // Handle sits after the list panel in DOM order, so a positive deltaX (dragging
    // right) grows it — same convention as App.js's sidebar handle.
    function handleListResize(deltaX) {
        setListWidth(w => {
            const next = clamp(w + deltaX, 150, 500)
            saveLayoutValue('scriptsListWidth', next)
            return next
        })
    }

    // Handle sits before the log panel (above it), so a negative deltaY (dragging up)
    // grows it — same convention as App.js's bottom-panel handle.
    function handleLogResize(deltaY) {
        setLogHeight(h => {
            const next = clamp(h - deltaY, 80, Math.floor(window.innerHeight * 0.7))
            saveLayoutValue('scriptsLogHeight', next)
            return next
        })
    }

    function refreshList() {
        listScripts().then(setScripts).catch(err => setStatus({ ok: false, msg: err.message }))
    }

    useEffect(refreshList, [refreshSignal])

    function loadScript(name) {
        setLoading(true)
        setStatus(null)
        getScript(name)
            .then(text => { setSource(text); setSavedSource(text); setLoadVersion(v => v + 1) })
            .catch(err => setStatus({ ok: false, msg: err.message }))
            .finally(() => setLoading(false))
    }

    useEffect(() => { if (selectedName) loadScript(selectedName) }, [selectedName])

    const dirty = source !== savedSource

    function selectScript(name) {
        setCreatingNew(false)
        setSelectedName(name)
    }

    function handleSave() {
        setSaving(true)
        setStatus(null)
        putScript(selectedName, source)
            .then(() => { setSavedSource(source); refreshList() })
            .catch(err => setStatus({ ok: false, msg: err.message }))
            .finally(() => setSaving(false))
    }

    function handleReload() {
        loadScript(selectedName)
    }

    function handleDelete(name) {
        if (!window.confirm(`Delete script "${name}"?`)) return
        deleteScript(name)
            .then(() => {
                refreshList()
                if (selectedName === name) { setSelectedName(null); setSource(''); setSavedSource('') }
            })
            .catch(err => setStatus({ ok: false, msg: err.message }))
    }

    // Only rendered/reachable when no server-side log file is configured (see logFile
    // prop below) — once one is, "Logged to <filename>" replaces this button entirely,
    // since the server-persisted copy is the better source for anything sizable anyway.
    // Plain per-line text; error lines get a textual [ERROR] marker since the red
    // .tamper-log-error styling doesn't survive into a downloaded file. Always a plain
    // anchor-click download rather than showSaveFilePicker (like ExtractPanel.js/
    // MarkersPanel.js use for their explicit file/clipboard choice) — this button is
    // just "Download", not "Save As", and showSaveFilePicker's OS-native dialog turned
    // out to hang with no visible feedback in at least one real environment, with no
    // error to even report; a plain download has no such failure mode.
    function handleDownloadLog() {
        const text = logLines.map(l => l.level === 'error' ? `[ERROR] ${l.text}` : l.text).join('\n')
        const blob = new Blob([text], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = 'tamper-script-log.txt'
        document.body.appendChild(a); a.click()
        document.body.removeChild(a); URL.revokeObjectURL(url)
    }

    function handleCreate() {
        const name = newName.trim()
        if (!name) return
        const existing = scripts.find(s => s.name === name)
        if (existing) { selectScript(name); setCreatingNew(false); setNewName(''); return }
        putScript(name, '')
            .then(() => { refreshList(); selectScript(name); setNewName(''); setCreatingNew(false) })
            .catch(err => setStatus({ ok: false, msg: err.message }))
    }

    return html`
        <div class="tamper-scripts-view">
            <div class="tamper-scripts-main">
                <div class="panel tamper-scripts-list-panel" style=${`width: ${listWidth}px`}>
                    <div class="panel-header">
                        Scripts
                        <span class="badge">${scripts.length}</span>
                        <button class="btn btn-sm" onclick=${() => { setCreatingNew(v => !v); setNewName('') }}>+ New</button>
                    </div>
                    ${creatingNew && html`
                        <div class="tamper-script-new-row">
                            <input
                                class="tamper-script-new-input"
                                type="text"
                                placeholder="script name"
                                value=${newName}
                                spellcheck="false"
                                onkeydown=${e => { if (e.key === 'Enter') handleCreate(); if (e.key === 'Escape') setCreatingNew(false) }}
                                oninput=${e => setNewName(e.target.value)}
                            />
                            <button class="btn btn-sm" onclick=${handleCreate}>Create</button>
                        </div>
                    `}
                    <div class="panel-list">
                        ${scripts.length === 0 && html`<div class="empty">No scripts</div>`}
                        ${scripts.map(s => html`
                            <div
                                key=${s.name}
                                class=${'list-item tamper-script-row' + (selectedName === s.name ? ' selected' : '')}
                                onclick=${() => selectScript(s.name)}
                            >
                                <span class="tamper-script-name">
                                    ${running === s.name && html`<span class="tamper-script-running-dot">●</span>`}
                                    ${s.name}
                                </span>
                                <span class="tamper-script-size">${s.size} B</span>
                            </div>
                        `)}
                    </div>
                </div>
                <${ResizeHandle} orientation="v" onResize=${handleListResize} />
                <div class="tamper-scripts-editor-wrap">
                    ${!selectedName && html`<div class="panel-placeholder">Select or create a script</div>`}
                    ${selectedName && html`
                        <div class="tamper-scripts-toolbar">
                            <span class="tamper-scripts-title">${selectedName}${dirty ? ' *' : ''}</span>
                            <button class="btn" disabled=${!dirty || saving} onclick=${handleSave}>${saving ? 'Saving…' : 'Save'}</button>
                            <button class="btn" disabled=${loading} onclick=${handleReload}>Reload</button>
                            <button class="btn" onclick=${() => handleDelete(selectedName)}>Delete</button>
                            <span class="tamper-scripts-toolbar-spacer" />
                            ${running === selectedName
                                ? html`<button class="btn" onclick=${onStop}>■ Stop</button>`
                                : html`<button class="btn" disabled=${!connected} onclick=${() => onRun(selectedName, source)}>▶ Run</button>`}
                        </div>
                        <${ScriptEditor}
                            value=${source}
                            onChange=${setSource}
                            loadVersion=${loadVersion}
                            readOnly=${loading}
                        />
                    `}
                    ${status && html`<div class=${'tamper-scripts-status ' + (status.ok ? 'extract-status-ok' : 'extract-status-err')}>${status.msg}</div>`}
                </div>
            </div>
            <${ResizeHandle} orientation="h" onResize=${handleLogResize} />
            <div class="tamper-scripts-log" style=${`height: ${logHeight}px`}>
                <div class="panel-header">
                    Log
                    ${logFile?.enabled && html`<span class="tamper-log-file-status">Logged to ${logFile.filename}</span>`}
                    <span class="tamper-scripts-toolbar-spacer" />
                    ${logFile?.enabled && html`
                        <label class="tamper-log-bypass-toggle">
                            <input
                                type="checkbox"
                                checked=${bypassBrowserLog}
                                onchange=${e => onBypassBrowserLogChange(e.target.checked)}
                            />
                            Skip browser log
                        </label>
                    `}
                    ${!logFile?.enabled && html`<button class="btn btn-sm" disabled=${logLines.length === 0} onclick=${handleDownloadLog}>Download</button>`}
                    <button class="btn btn-sm" onclick=${onClearLog}>Clear</button>
                </div>
                <div class="tamper-scripts-log-body">
                    ${logLines.length === 0 && html`<div class="empty">No output</div>`}
                    ${logLines.map((l, i) => html`
                        <div key=${i} class=${'tamper-log-line tamper-log-' + l.level}>${l.text}</div>
                    `)}
                </div>
            </div>
        </div>
    `
}
