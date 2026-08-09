import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'
import { parseRaw, fmtAsRaw, fmtAsBase64, mergeUint8Arrays } from '../format.js'
import { downloadBlob, acquireSaveHandle, writeToFileHandle } from '../download.js'
import { dirClass, dirLabel } from '../direction.js'

const html = htm.bind(h)

// ── compress / decompress ─────────────────────────────────────────────────────

async function compress(str) {
    const bytes = parseRaw(str)
    const cs    = new CompressionStream('deflate')
    const w     = cs.writable.getWriter()
    w.write(bytes); w.close()
    const chunks = []
    const r = cs.readable.getReader()
    for (;;) { const { done, value } = await r.read(); if (done) break; chunks.push(value) }
    return fmtAsBase64(mergeUint8Arrays(chunks))
}

async function decompress(b64) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
    const ds    = new DecompressionStream('deflate')
    const w     = ds.writable.getWriter()
    w.write(bytes); w.close()
    const chunks = []
    const r = ds.readable.getReader()
    for (;;) { const { done, value } = await r.read(); if (done) break; chunks.push(value) }
    return fmtAsRaw(mergeUint8Arrays(chunks))
}

function parseImport(text) {
    try {
        const parsed = JSON.parse(text)
        if (!Array.isArray(parsed?.markers)) return null
        for (const m of parsed.markers) {
            if (typeof m.id !== 'string')        return null
            if (typeof m.session !== 'number')   return null
            if (typeof m.stream !== 'number')    return null
            if (typeof m.direction !== 'number') return null
            if (typeof m.offset !== 'number')    return null
        }
        return parsed.markers
    } catch { return null }
}

// ── component ─────────────────────────────────────────────────────────────────

// "Markers" bottom-panel tab of the Analysis view: every marker in the current session
// (across all its streams — a marker's own stream is shown per row since more than one
// can appear here), a table row each. Session-scoped rather than stream-scoped, same
// filter-by-session convention as before this moved out of TrafficView.js's side panel.
export default function MarkersPanel({ session, markers, onRemove, onUpdateLabel, onJump, onImport }) {
    const [ioMethod, setIoMethod] = useState('clipboard')
    const [status,   setStatus]   = useState(null)  // null | { ok: bool, msg: string }

    if (!session) return html`<div class="panel-placeholder">Select a session first</div>`

    const sessionMarkers = (markers ?? []).filter(m => m.session === session.id)

    // ── export ────────────────────────────────────────────────────────────────

    async function handleExport() {
        setStatus(null)

        // Acquire file handle immediately (before any await) so user activation is preserved.
        let fileHandle = null
        if (ioMethod === 'file' && window.showSaveFilePicker) {
            try {
                fileHandle = await acquireSaveHandle('markers.tlstap-markers', 'text/plain', '.tlstap-markers', 'tlstap markers')
            } catch (e) {
                setStatus({ ok: false, msg: e.message })
                return
            }
            if (!fileHandle) return // user dismissed the picker
        }

        let encoded
        try {
            const raw = localStorage.getItem('tlstap-markers') ?? JSON.stringify({ version: 1, markers: [] })
            encoded   = await compress(raw)
        } catch (e) {
            setStatus({ ok: false, msg: 'Compression failed: ' + e.message })
            return
        }

        try {
            if (ioMethod === 'clipboard') {
                await navigator.clipboard.writeText(encoded)
                setStatus({ ok: true, msg: 'Exported to clipboard' })
            } else if (fileHandle) {
                await writeToFileHandle(fileHandle, encoded, 'text/plain')
                setStatus({ ok: true, msg: 'Exported to file' })
            } else {
                downloadBlob(encoded, 'markers.tlstap-markers', 'text/plain')
                setStatus({ ok: true, msg: 'Exported to file' })
            }
        } catch (e) {
            setStatus({ ok: false, msg: e.message })
        }
    }

    // ── import ────────────────────────────────────────────────────────────────

    async function handleImport() {
        setStatus(null)
        if (ioMethod === 'clipboard') {
            let text
            try { text = await navigator.clipboard.readText() }
            catch (e) { setStatus({ ok: false, msg: 'Clipboard read failed: ' + e.message }); return }
            await finishImport(text)
        } else {
            const input    = document.createElement('input')
            input.type     = 'file'
            input.accept   = '.tlstap-markers,.txt'
            input.onchange = async e => {
                const file = e.target.files?.[0]
                if (!file) return
                try { await finishImport(await file.text()) }
                catch (e) { setStatus({ ok: false, msg: e.message }) }
            }
            input.click()
        }
    }

    async function finishImport(encoded) {
        let json
        try { json = await decompress(encoded) }
        catch (e) { setStatus({ ok: false, msg: 'Decompression failed: ' + e.message }); return }
        const imported = parseImport(json)
        if (!imported) { setStatus({ ok: false, msg: 'Invalid marker data' }); return }
        onImport?.(imported)
        setStatus({ ok: true, msg: `Imported ${imported.length} marker${imported.length === 1 ? '' : 's'}` })
    }

    // ── render ────────────────────────────────────────────────────────────────

    return html`
        <div class="markers-tab">
            <div class="markers-tab-header">${sessionMarkers.length} marker${sessionMarkers.length === 1 ? '' : 's'}</div>
            <div class="markers-tab-list">
                ${sessionMarkers.length === 0
                    ? html`<div class="empty">No markers set</div>`
                    : sessionMarkers.map(m => html`
                        <${MarkerRow}
                            key=${m.id}
                            marker=${m}
                            onRemove=${onRemove}
                            onUpdateLabel=${onUpdateLabel}
                            onJump=${onJump}
                        />
                    `)
                }
            </div>
            <div class="markers-io-bar">
                <select class="goto-select markers-io-select" value=${ioMethod} onchange=${e => setIoMethod(e.target.value)}>
                    <option value="clipboard">clipboard</option>
                    <option value="file">file</option>
                </select>
                <button class="btn markers-io-btn" type="button" onclick=${handleImport}>Import</button>
                <button class="btn markers-io-btn" type="button" onclick=${handleExport}>Export</button>
            </div>
            ${status && html`
                <div class=${'markers-io-status ' + (status.ok ? 'markers-io-status-ok' : 'markers-io-status-err')}>
                    ${status.msg}
                </div>
            `}
        </div>
    `
}

function MarkerRow({ marker, onRemove, onUpdateLabel, onJump }) {
    const [editing, setEditing] = useState(false)
    const [draft,   setDraft]   = useState(marker.label)
    const dir   = dirClass(marker.direction)
    const label = dirLabel(marker.direction)

    function commitEdit() {
        setEditing(false)
        if (draft !== marker.label) onUpdateLabel(marker.id, draft)
    }

    return html`
        <div class="markers-tab-row">
            <span class="mtab-session">#${marker.session}</span>
            <span class="mtab-stream">#${marker.stream}</span>
            <span class=${'mtab-dir ' + dir}>${label}</span>
            <span class="mtab-off">0x${marker.offset.toString(16).padStart(8, '0')}</span>
            ${editing
                ? html`
                    <input
                        class="mtab-label-input"
                        value=${draft}
                        oninput=${e => setDraft(e.target.value)}
                        onblur=${commitEdit}
                        onkeydown=${e => { if (e.key === 'Enter') commitEdit(); if (e.key === 'Escape') { setDraft(marker.label); setEditing(false) } }}
                        ref=${el => el?.focus()}
                    />
                `
                : html`
                    <span
                        class=${'mtab-label' + (marker.label ? '' : ' mtab-label-empty')}
                        onclick=${() => { setDraft(marker.label); setEditing(true) }}
                        title="Click to edit"
                    >
                        ${marker.label || 'click to add note…'}
                    </span>
                `
            }
            <button class="btn mtab-go" type="button" onclick=${() => onJump(marker)}>Go</button>
            <span class="mtab-del" onclick=${() => onRemove(marker.id)} title="Delete">×</span>
        </div>
    `
}
