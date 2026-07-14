import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import HexEditor from './HexEditor.js'
import { peekChunk } from '../tamperApi.js'

const html = htm.bind(h)

function bytesEqual(a, b) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
    return true
}

// Bottom panel of the Tamper tab: shows the currently-selected queued chunk's bytes
// (fetched on demand via peek, since "held" never carries them inline) and the
// forward/drop/drop-connection actions that resolve it.
export default function TamperDetailPanel({ entry, onResolve }) {
    const [bytes,         setBytes]         = useState(null)
    const [originalBytes, setOriginalBytes] = useState(null)
    const [loading,       setLoading]       = useState(false)
    const [loadError,     setLoadError]     = useState(null)
    const [busy,          setBusy]          = useState(false)
    const [actionError,   setActionError]   = useState(null)

    useEffect(() => {
        setBytes(null)
        setOriginalBytes(null)
        setLoadError(null)
        setActionError(null)
        if (!entry) return

        let cancelled = false
        setLoading(true)
        peekChunk(entry.conn, entry.id)
            .then(chunk => {
                if (cancelled) return
                setBytes(chunk.data)
                setOriginalBytes(chunk.data)
            })
            .catch(err => { if (!cancelled) setLoadError(err.message) })
            .finally(() => { if (!cancelled) setLoading(false) })

        return () => { cancelled = true }
    }, [entry?.conn, entry?.id])

    function act(action) {
        if (!entry || busy) return
        setBusy(true)
        setActionError(null)
        const edited = action === 'forward' && bytes && originalBytes && !bytesEqual(bytes, originalBytes)
        onResolve(entry.conn, entry.id, action, edited ? bytes : undefined)
            .catch(err => setActionError(err.message))
            .finally(() => setBusy(false))
    }

    if (!entry) {
        return html`<div class="tamper-detail-panel"><div class="placeholder">Select a held chunk</div></div>`
    }

    return html`
        <div class="tamper-detail-panel">
            <div class="tamper-detail-toolbar">
                <span class="tamper-detail-title">
                    #${entry.conn} · <span class=${entry.direction === 0 ? 'c2s' : 's2c'}>${entry.direction === 0 ? 'C→S' : 'S→C'}</span>
                    · ${entry.length} B
                </span>
                <button class="btn" disabled=${busy || loading || !!loadError} onclick=${() => act('forward')}>Forward</button>
                <button class="btn" disabled=${busy || loading || !!loadError} onclick=${() => act('drop')}>Drop</button>
                <button class="btn" disabled=${busy || loading || !!loadError} onclick=${() => act('drop-connection')}>Drop Connection</button>
                ${actionError && html`<span class="error-msg">${actionError}</span>`}
            </div>
            ${loading && html`<div class="placeholder">Loading…</div>`}
            ${loadError && html`<div class="error-msg">${loadError}</div>`}
            ${bytes && html`<${HexEditor} bytes=${bytes} onChange=${setBytes} direction=${entry.direction} style="flex: 1; min-height: 0;" />`}
        </div>
    `
}
