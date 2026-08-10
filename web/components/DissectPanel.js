import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'
import { getDissectScript } from '../dbdumpDissectApi.js'
import { runDissector } from '../dissectRuntime.js'
import { fmtAsAscii, fmtAsHex, fmtAsHexdump, fmtAsBase64, fmtAsRaw, parseBase64 } from '../format.js'

const html = htm.bind(h)

// display-hint -> format.js formatter, applied to raw bytes (a content node's decoded
// base64, or an offset/length node's frame slice). Unrecognized/omitted hint on a
// byte-shaped value falls back to hex, same convention TransformPanel's own output panel
// defaults to for non-printable bytes.
const FORMATTERS = {
    ascii:   b => fmtAsAscii(b),
    hex:     b => fmtAsHex(b),
    hexdump: b => fmtAsHexdump(b, 0),
    base64:  b => fmtAsBase64(b),
    raw:     b => fmtAsRaw(b),
}

function formatBytes(bytes, hint) {
    return (FORMATTERS[hint] ?? FORMATTERS.hex)(bytes)
}

// A node carries at most one of content/offset+length (doc/design/packet-dissector.md's
// "Field node schema") — resolves whichever is present into { text, bytes? }. bytes is
// only set when the node is byte-shaped (a content string, decoded from base64; or an
// offset/length slice of the frame) and thus eligible for both a display-hint and
// click-to-highlight; a number/bool content, or a hint-less string content (rendered
// as-is — a script's own already-formatted label), have no bytes of their own.
// A malformed node (invalid base64 content, an offset/length outside frameBytes handled
// by slice()'s own clamping) must not throw mid-render — there's no error boundary in
// this codebase, so an uncaught exception here would blank the whole panel rather than
// just this one row.
function resolveValue(node, frameBytes) {
    try {
        if (node.offset != null && node.length != null) {
            const bytes = frameBytes.slice(node.offset, node.offset + node.length)
            return { text: formatBytes(bytes, node['display-hint']), bytes }
        }
        if (typeof node.content === 'number' || typeof node.content === 'boolean') {
            return { text: String(node.content), bytes: null }
        }
        if (typeof node.content === 'string') {
            if (!node['display-hint']) return { text: node.content, bytes: null }
            const bytes = parseBase64(node.content)
            return { text: formatBytes(bytes, node['display-hint']), bytes }
        }
        return { text: '', bytes: null } // pure grouping row: label + sub only
    } catch (e) {
        return { text: `(invalid: ${e.message})`, bytes: null }
    }
}

function FieldNode({ node, depth, frameOffset, frameBytes, onNodeClick }) {
    const [expanded, setExpanded] = useState(true)
    // A non-object array entry is a script bug — render inline rather than throw (see
    // resolveValue's own comment on why this codebase has no error boundary to catch it).
    if (!node || typeof node !== 'object') {
        return html`<div class="dissect-node" style=${`padding-left: ${depth * 14}px`}>
            <div class="dissect-node-row"><span class="dissect-node-value">(invalid field node)</span></div>
        </div>`
    }
    const hasSub = Array.isArray(node.sub) && node.sub.length > 0
    const highlightable = node.offset != null && node.length != null
    const { text } = resolveValue(node, frameBytes)

    function handleClick() {
        if (!highlightable) return
        onNodeClick(node.offset + frameOffset, node.offset + node.length - 1 + frameOffset)
    }

    return html`
        <div class="dissect-node" style=${`padding-left: ${depth * 14}px`}>
            <div class=${'dissect-node-row' + (highlightable ? ' dissect-node-clickable' : '')} onClick=${handleClick}>
                ${hasSub
                    ? html`<span class="dissect-node-toggle" onClick=${e => { e.stopPropagation(); setExpanded(v => !v) }}>${expanded ? '▾' : '▸'}</span>`
                    : html`<span class="dissect-node-toggle-spacer" />`}
                <span class="dissect-node-label">${node.label}</span>
                ${text !== '' && html`<span class="dissect-node-value">${text}</span>`}
            </div>
            ${hasSub && expanded && node.sub.map((child, i) => html`
                <${FieldNode} key=${i} node=${child} depth=${depth + 1} frameOffset=${frameOffset} frameBytes=${frameBytes} onNodeClick=${onNodeClick} />
            `)}
        </div>
    `
}

// Side panel in TrafficView.js's frame view: runs the selected dissector script against
// selectedFrame's bytes whenever either changes, and renders the resulting field tree.
// selectedFrame: null | { key, frame: {offset, length, direction, kind, meta}, bytes } —
// frame.offset/bytes are the loaded window's own (see TrafficView.js's onHeaderClick),
// not necessarily the segment's full declared span for a still-partially-loaded huge
// frame; dissection simply runs on whatever's currently available, no dedicated fetch.
export default function DissectPanel({ selectedFrame, dissectScripts, dissectorSelected, onDissectorSelect, onNodeClick, style }) {
    const [nodes,   setNodes]   = useState(null)
    const [loading, setLoading] = useState(false)
    const [error,   setError]   = useState(null)

    useEffect(() => {
        if (!selectedFrame || !dissectorSelected) { setNodes(null); setError(null); return }
        let cancelled = false
        setLoading(true)
        setError(null)
        ;(async () => {
            try {
                const content = await getDissectScript(dissectorSelected)
                const result = await runDissector(dissectorSelected, content, selectedFrame.bytes, selectedFrame.frame)
                if (!cancelled) setNodes(result)
            } catch (e) {
                if (!cancelled) { setError(e.message); setNodes(null) }
            } finally {
                if (!cancelled) setLoading(false)
            }
        })()
        return () => { cancelled = true }
    }, [selectedFrame?.key, dissectorSelected])

    return html`
        <div class="dissect-panel" style=${style}>
            <div class="panel-header">
                Dissect
                <select class="goto-select" value=${dissectorSelected} onchange=${e => onDissectorSelect(e.target.value)}>
                    <option value="">(none)</option>
                    ${dissectScripts.map(s => html`<option value=${s.name}>${s.name}</option>`)}
                </select>
            </div>
            <div class="dissect-body">
                ${!selectedFrame && html`<div class="panel-placeholder">Click a frame to dissect it</div>`}
                ${selectedFrame && !dissectorSelected && html`<div class="panel-placeholder">Select a dissector script</div>`}
                ${loading && html`<div class="panel-placeholder">Dissecting…</div>`}
                ${error && html`<div class="error-msg">${error}</div>`}
                ${!loading && !error && nodes && nodes.length === 0 && html`<div class="empty">No fields</div>`}
                ${!loading && !error && nodes && nodes.map((node, i) => html`
                    <${FieldNode}
                        key=${i} node=${node} depth=${0}
                        frameOffset=${selectedFrame.frame.offset} frameBytes=${selectedFrame.bytes}
                        onNodeClick=${(start, end) => onNodeClick(selectedFrame.frame.direction, start, end)}
                    />
                `)}
            </div>
        </div>
    `
}
