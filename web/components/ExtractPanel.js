import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'
import { openStidStream, getByteStid } from '../api.js'
import { fmtAsRaw, fmtAsBase64, fmtAsHex, fmtAsHexdump, mergeUint8Arrays } from '../format.js'

const html = htm.bind(h)

function parseOffset(s) {
    const t = s.trim()
    if (!t) return null
    const n = t.startsWith('0x') || t.startsWith('0X') ? parseInt(t, 16) : parseInt(t, 10)
    return isNaN(n) || n < 0 ? null : n
}

function encodeForClipboard(bytes, format, baseOffset) {
    switch (format) {
        case 'base64':  return fmtAsBase64(bytes)
        case 'hex':     return fmtAsHex(bytes)
        case 'hexdump': return fmtAsHexdump(bytes, baseOffset)
        default:        return fmtAsRaw(bytes)
    }
}

const FILE_META = {
    raw:     { ext: '.bin', mime: 'application/octet-stream', desc: 'Binary file' },
    base64:  { ext: '.b64', mime: 'text/plain',               desc: 'Base64 file' },
    hex:     { ext: '.hex', mime: 'text/plain',               desc: 'Hex file'    },
    hexdump: { ext: '.txt', mime: 'text/plain',               desc: 'Text file'   },
}

// Must be called while a user gesture is still active (before any unrelated awaits).
async function acquireFileHandle(format) {
    const { ext, mime, desc } = FILE_META[format] ?? FILE_META.raw
    return window.showSaveFilePicker({
        suggestedName: `extract${ext}`,
        types: [{ description: desc, accept: { [mime]: [ext] } }],
    })
}

async function writeToHandle(handle, bytes, format, baseOffset) {
    let content
    switch (format) {
        case 'base64':  content = fmtAsBase64(bytes);              break
        case 'hex':     content = fmtAsHex(bytes);                 break
        case 'hexdump': content = fmtAsHexdump(bytes, baseOffset);  break
        default:        content = bytes;                            break
    }
    const { mime } = FILE_META[format] ?? FILE_META.raw
    const blob     = new Blob([content], { type: mime })
    const writable = await handle.createWritable()
    await writable.write(blob)
    await writable.close()
}

function downloadFallback(bytes, format, baseOffset) {
    let content
    switch (format) {
        case 'base64':  content = fmtAsBase64(bytes);              break
        case 'hex':     content = fmtAsHex(bytes);                 break
        case 'hexdump': content = fmtAsHexdump(bytes, baseOffset);  break
        default:        content = bytes;                            break
    }
    const { ext, mime } = FILE_META[format] ?? FILE_META.raw
    const url = URL.createObjectURL(new Blob([content], { type: mime }))
    const a   = document.createElement('a')
    a.href = url; a.download = `extract${ext}`
    document.body.appendChild(a); a.click()
    document.body.removeChild(a); URL.revokeObjectURL(url)
}

async function fetchRange(session, stream, dir, fromOffset, toOffset) {
    const [startRes, endRes] = await Promise.all([
        getByteStid(session.id, stream.id, dir, fromOffset),
        getByteStid(session.id, stream.id, dir, toOffset),
    ])
    const startStid = startRes.stid
    const n         = endRes.stid - startStid + 1

    const ws = openStidStream()
    try {
        const chunks = await ws.fetch(session.id, stream.id, startStid, n)
        const parts = []
        for (const chunk of chunks) {
            if (chunk.direction !== dir) continue
            if (chunk.offset + chunk.data.length - 1 < fromOffset) continue
            if (chunk.offset > toOffset) continue
            const sliceStart = Math.max(0, fromOffset - chunk.offset)
            const sliceEnd   = Math.min(chunk.data.length, toOffset - chunk.offset + 1)
            parts.push(chunk.data.slice(sliceStart, sliceEnd))
        }
        return mergeUint8Arrays(parts)
    } finally {
        ws.close()
    }
}

export default function ExtractPanel({ session, stream, direction, from, to, onDirectionChange, onFromChange, onToChange }) {
    const [format,  setFormat]  = useState('raw')
    const [method,  setMethod]  = useState('clipboard')
    const [working, setWorking] = useState(false)
    const [status,  setStatus]  = useState(null)  // null | { ok: bool, msg: string }

    if (!stream) return html`<div class="panel-placeholder">Select a stream first</div>`

    async function handleExtract() {
        const fromOffset = parseOffset(from)
        const toOffset   = parseOffset(to)
        if (fromOffset === null || toOffset === null) {
            setStatus({ ok: false, msg: 'Invalid offset' })
            return
        }
        if (fromOffset > toOffset) {
            setStatus({ ok: false, msg: 'From must be ≤ To' })
            return
        }

        // For file saves: acquire the handle NOW while the user gesture is still active,
        // before any async data fetching consumes the transient activation.
        let fileHandle = null
        if (method === 'file' && window.showSaveFilePicker) {
            try {
                fileHandle = await acquireFileHandle(format)
            } catch (err) {
                if (err.name !== 'AbortError') setStatus({ ok: false, msg: err.message })
                return
            }
        }

        setWorking(true)
        setStatus(null)
        try {
            const dir   = parseInt(direction, 10)
            const bytes = await fetchRange(session, stream, dir, fromOffset, toOffset)
            if (method === 'clipboard') {
                await navigator.clipboard.writeText(encodeForClipboard(bytes, format, fromOffset))
                setStatus({ ok: true, msg: `Copied ${bytes.length} B` })
            } else if (fileHandle) {
                await writeToHandle(fileHandle, bytes, format, fromOffset)
                setStatus({ ok: true, msg: `Saved ${bytes.length} B` })
            } else {
                downloadFallback(bytes, format, fromOffset)
                setStatus({ ok: true, msg: `Downloaded ${bytes.length} B (no save dialog in this browser)` })
            }
        } catch (err) {
            setStatus({ ok: false, msg: err.message })
        } finally {
            setWorking(false)
        }
    }

    return html`
        <form class="extract-form" onsubmit=${e => e.preventDefault()}>
            <span class="extract-stream-label">stream <span class="extract-stream-id">#${stream.id}</span></span>
            <select class="goto-select" value=${direction} onchange=${e => onDirectionChange(e.target.value)}>
                <option value="0">c→s</option>
                <option value="1">s→c</option>
            </select>
            <span class="extract-sep" />
            <label class="extract-field-label">From</label>
            <input
                class="goto-input extract-offset-input"
                type="text"
                placeholder="0"
                value=${from}
                oninput=${e => onFromChange(e.target.value)}
                spellcheck="false"
            />
            <label class="extract-field-label">To</label>
            <input
                class="goto-input extract-offset-input"
                type="text"
                placeholder="0"
                value=${to}
                oninput=${e => onToChange(e.target.value)}
                spellcheck="false"
            />
            <span class="extract-sep" />
            <select class="goto-select" value=${format} onchange=${e => setFormat(e.target.value)}>
                <option value="raw">raw</option>
                <option value="base64">base64</option>
                <option value="hex">hex</option>
                <option value="hexdump">hexdump</option>
            </select>
            <select class="goto-select" value=${method} onchange=${e => setMethod(e.target.value)}>
                <option value="file">file</option>
                <option value="clipboard">clipboard</option>
            </select>
            <button class="btn" type="button" disabled=${working} onclick=${handleExtract}>
                ${working ? '…' : 'Extract'}
            </button>
            ${status && html`<span class=${'extract-status ' + (status.ok ? 'extract-status-ok' : 'extract-status-err')}>${status.msg}</span>`}
        </form>
    `
}
