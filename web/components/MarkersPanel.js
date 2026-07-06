import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'

const html = htm.bind(h)

// ── compress / decompress ─────────────────────────────────────────────────────

async function compress(str) {
    const bytes = new TextEncoder().encode(str)
    const cs    = new CompressionStream('deflate')
    const w     = cs.writable.getWriter()
    w.write(bytes); w.close()
    const chunks = []
    const r = cs.readable.getReader()
    for (;;) { const { done, value } = await r.read(); if (done) break; chunks.push(value) }
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
    let off = 0; for (const c of chunks) { out.set(c, off); off += c.length }
    return btoa(Array.from(out, b => String.fromCharCode(b)).join(''))
}

async function decompress(b64) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
    const ds    = new DecompressionStream('deflate')
    const w     = ds.writable.getWriter()
    w.write(bytes); w.close()
    const chunks = []
    const r = ds.readable.getReader()
    for (;;) { const { done, value } = await r.read(); if (done) break; chunks.push(value) }
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
    let off = 0; for (const c of chunks) { out.set(c, off); off += c.length }
    return new TextDecoder().decode(out)
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

export default function MarkersPanel({ markers, onRemove, onUpdateLabel, onJump, onImport, collapsed, onToggle, width }) {
    const [ioMethod, setIoMethod] = useState('clipboard')
    const [status,   setStatus]   = useState(null)  // null | { ok: bool, msg: string }

    if (collapsed) {
        return html`
            <div class="markers-strip" onclick=${onToggle} title="Expand markers">
                <span class="markers-strip-triangle">◀</span>
                <span class="markers-strip-label">Markers</span>
            </div>
        `
    }

    // ── export ────────────────────────────────────────────────────────────────

    async function handleExport() {
        setStatus(null)

        // Acquire file handle immediately (before any await) so user activation is preserved.
        let fileHandle = null
        if (ioMethod === 'file' && window.showSaveFilePicker) {
            try {
                fileHandle = await window.showSaveFilePicker({
                    suggestedName: 'markers.tlstap-markers',
                    types: [{ description: 'tlstap markers', accept: { 'text/plain': ['.tlstap-markers'] } }],
                })
            } catch (e) {
                if (e.name !== 'AbortError') setStatus({ ok: false, msg: e.message })
                return
            }
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
                const writable = await fileHandle.createWritable()
                await writable.write(new Blob([encoded], { type: 'text/plain' }))
                await writable.close()
                setStatus({ ok: true, msg: 'Exported to file' })
            } else {
                const url = URL.createObjectURL(new Blob([encoded], { type: 'text/plain' }))
                const a   = document.createElement('a')
                a.href = url; a.download = 'markers.tlstap-markers'
                document.body.appendChild(a); a.click()
                document.body.removeChild(a); URL.revokeObjectURL(url)
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
        <div class="markers-side" style=${`width: ${width}px`}>
            <div class="markers-side-header">
                <span>Markers</span>
                <span class="markers-collapse-btn" onclick=${onToggle} title="Collapse">▶</span>
            </div>
            <div class="markers-side-list">
                ${markers.length === 0
                    ? html`<div class="markers-empty">No markers set</div>`
                    : markers.map(m => html`
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
    const dir      = marker.direction === 0 ? 'c2s' : 's2c'
    const dirLabel = marker.direction === 0 ? 'c→s' : 's→c'

    function commitEdit() {
        setEditing(false)
        if (draft !== marker.label) onUpdateLabel(marker.id, draft)
    }

    return html`
        <div class="marker-row" onclick=${() => onJump(marker)}>
            <div class="marker-row-top">
                <span class="marker-loc">
                    [${marker.stream}]
                    <span class=${'marker-dir ' + dir}>${dirLabel}</span>
                    <span class="marker-off">0x${marker.offset.toString(16).padStart(8, '0')}</span>
                </span>
                <span class="marker-del" onclick=${e => { e.stopPropagation(); onRemove(marker.id) }} title="Delete">×</span>
            </div>
            ${editing
                ? html`
                    <input
                        class="marker-label-input"
                        value=${draft}
                        oninput=${e => setDraft(e.target.value)}
                        onblur=${commitEdit}
                        onkeydown=${e => { if (e.key === 'Enter') commitEdit(); if (e.key === 'Escape') { setDraft(marker.label); setEditing(false) } }}
                        onClick=${e => e.stopPropagation()}
                        ref=${el => el?.focus()}
                    />
                `
                : html`
                    <div
                        class=${'marker-label' + (marker.label ? '' : ' marker-label-empty')}
                        onclick=${e => { e.stopPropagation(); setDraft(marker.label); setEditing(true) }}
                        title="Click to edit"
                    >
                        ${marker.label || 'click to add note…'}
                    </div>
                `
            }
        </div>
    `
}
