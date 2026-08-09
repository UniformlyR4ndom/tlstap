import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import ScriptEditor from './ScriptEditor.js'
import ResizeHandle from './ResizeHandle.js'
import { useResizableLayout } from '../useResizableLayout.js'

const html = htm.bind(h)

// Generic CRUD list+editor chrome for a name->content *.js script store — extracted from
// TamperScriptsPanel.js so tamper's and dbdump's framer scripts (and, per
// doc/design/packet-dissector.md's "Script storage" section, eventually a dissector
// script store too) share one implementation. The list/editor/selection here are local
// and simply refetch each time this panel mounts or refreshSignal bumps; anything that
// needs to survive a caller's own remount (a running script, its log) stays owned by the
// caller and is threaded in via `controls`/`rowDecoration`, not by this component.
//
// list()->[{name,size}], get(name)->text, put(name,content)->void, del(name)->void: the
// REST CRUD functions (tamperApi.js's and dbdumpFramerApi.js's script functions are
// byte-for-byte this same shape). completions is passed straight through to
// ScriptEditor's own completions prop. listWidthKey is a layout.js key for the
// resizable list-panel width, since each caller needs its own persisted width.
// controls(selectedName, source) and rowDecoration(scriptName), both optional, are
// render-prop extension points: tamper supplies its Run/Stop button pair and the ●
// running-dot; a CRUD-only caller (framer) supplies neither.
export default function ScriptsCrudPanel({
    className, list, get, put, del, completions, refreshSignal, listWidthKey, controls, rowDecoration,
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
    // Handle sits after the list panel in DOM order, so a positive deltaX (dragging
    // right) grows it.
    const [listWidth, handleListResize] = useResizableLayout(listWidthKey, { min: 150, max: 500 })
    // Bumped exactly once per genuine external reset of the editor's content (initial
    // load, script switch, Reload) — must be an explicit signal rather than inferred
    // from `source` changing, since ordinary typing also changes `source`.
    const [loadVersion,  setLoadVersion]  = useState(0)

    function refreshList() {
        list().then(setScripts).catch(err => setStatus({ ok: false, msg: err.message }))
    }

    useEffect(refreshList, [refreshSignal])

    function loadScript(name) {
        setLoading(true)
        setStatus(null)
        get(name)
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
        put(selectedName, source)
            .then(() => { setSavedSource(source); refreshList() })
            .catch(err => setStatus({ ok: false, msg: err.message }))
            .finally(() => setSaving(false))
    }

    function handleReload() {
        loadScript(selectedName)
    }

    function handleDelete(name) {
        if (!window.confirm(`Delete script "${name}"?`)) return
        del(name)
            .then(() => {
                refreshList()
                if (selectedName === name) { setSelectedName(null); setSource(''); setSavedSource('') }
            })
            .catch(err => setStatus({ ok: false, msg: err.message }))
    }

    function handleCreate() {
        const name = newName.trim()
        if (!name) return
        const existing = scripts.find(s => s.name === name)
        if (existing) { selectScript(name); setCreatingNew(false); setNewName(''); return }
        put(name, '')
            .then(() => { refreshList(); selectScript(name); setNewName(''); setCreatingNew(false) })
            .catch(err => setStatus({ ok: false, msg: err.message }))
    }

    return html`
        <div class=${className}>
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
                                ${rowDecoration?.(s.name)}
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
                        ${controls?.(selectedName, source)}
                    </div>
                    <${ScriptEditor}
                        value=${source}
                        onChange=${setSource}
                        loadVersion=${loadVersion}
                        completions=${completions}
                        readOnly=${loading}
                    />
                `}
                ${status && html`<div class=${'tamper-scripts-status ' + (status.ok ? 'extract-status-ok' : 'extract-status-err')}>${status.msg}</div>`}
            </div>
        </div>
    `
}
