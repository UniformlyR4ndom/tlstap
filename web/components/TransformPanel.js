import { h } from 'preact'
import { useState, useMemo, useRef } from 'preact/hooks'
import htm from 'htm'
import ResizeHandle from './ResizeHandle.js'
import HexEditor from './HexEditor.js'
import { clamp } from '../layout.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { useDismissOnOutsideClick } from '../useDismissOnOutsideClick.js'
import { OPERATIONS, ALGORITHM_SECTIONS, sectionPrefix } from '../transforms.js'
import { fmtAsHex, fmtAsRaw, parseRaw } from '../format.js'

const html = htm.bind(h)

// Groups a step's body params (i.e. excluding any `inHeader` ones) into render units: params
// sharing the same `row` key render together on one labeled line (e.g. checksum.js's `init` and
// `refin` both under "XOR in"); a param with no `row` renders alone, unchanged from the original
// flat per-param layout. `rowLabel` may be set on any member of the group (first one found wins)
// since a group's shared label isn't naturally "owned" by any single param in it.
function groupParams(params) {
    const rows = []
    const indexByRow = new Map()
    for (const p of params) {
        if (!p.row) {
            rows.push({ label: null, members: [p] })
            continue
        }
        if (!indexByRow.has(p.row)) {
            indexByRow.set(p.row, rows.length)
            rows.push({ label: null, members: [] })
        }
        const row = rows[indexByRow.get(p.row)]
        row.members.push(p)
        if (!row.label && p.rowLabel) row.label = p.rowLabel
    }
    return rows
}

// Plain hex text -> bytes, for the Hex view. Distinct from transforms/basic.js's hex-decode
// operation (which has a configurable separator param for the step pipeline) — this is a
// simpler, fixed-format decode for the base view mode. Tolerates incidental whitespace so
// pasted/pre-formatted hex still works; anything else invalid throws.
function hexTextToBytes(text) {
    const cleaned = text.replace(/\s+/g, '')
    if (cleaned.length % 2 !== 0) throw new Error('odd number of hex digits')
    if (!/^[0-9a-fA-F]*$/.test(cleaned)) throw new Error('invalid hex digit')
    const out = new Uint8Array(cleaned.length / 2)
    for (let i = 0; i < cleaned.length; i += 2) out[i / 2] = parseInt(cleaned.slice(i, i + 2), 16)
    return out
}

// Bytes are "printable" (safe to default to the raw text view) if every byte is a
// printable ASCII character or common whitespace; anything else defaults to hex view.
function isPrintable(bytes) {
    for (const b of bytes) {
        if (b === 0x09 || b === 0x0a || b === 0x0d) continue
        if (b < 0x20 || b >= 0x7f) return false
    }
    return true
}

// The Transform bottom-panel tab: an options column on the left, and a stacked
// input/output pair on the right, connected by a step pipeline.
export default function TransformPanel() {
    // Canonical content, regardless of which view is active. Text mode derives its
    // display from this (decode-on-render) rather than storing its own copy, so
    // toggling views never loses data unless the user actively edits lossy text.
    const [bytes, setBytes] = useState(() => new Uint8Array(0))
    // 'raw' | 'hex' | 'hexdump'
    const [inputView, setInputView] = useState('raw')
    const [outputView, setOutputView] = useState('raw')
    // Buffer for the input Hex view only: holds exactly what was typed, since hex decoding can
    // fail on incomplete input (e.g. an odd number of digits mid-keystroke) — unlike Raw view,
    // whose UTF-8 encode/decode always succeeds and can therefore be derived from `bytes` on
    // every render. `bytes` is only updated from this buffer when it currently parses as valid
    // hex; resynced from `bytes` whenever the view switches into 'hex'.
    const [hexText, setHexText] = useState('')
    const [optionsWidth, handleOptionsResize] = useResizableLayout('encdecOptionsWidth', { min: 100, max: 400 })
    const [inputHeight, handleInputResize]    = useResizableLayout('encdecInputHeight', { min: 30, max: 2000 })
    const [steps, setSteps] = useState([])
    const [menuOpen, setMenuOpen] = useState(false)
    const [collapsedSections, setCollapsedSections] = useState(() => new Set(ALGORITHM_SECTIONS.map(s => s.name)))
    const [dragOverId, setDragOverId] = useState(null)
    const [outputBytes, setOutputBytes] = useState(null)
    const [outputError, setOutputError] = useState(null)
    const toolbarRef = useRef(null)
    const dragIdRef = useRef(null)

    function addStep(op, label) {
        const def = OPERATIONS[op]
        if (!def) return
        const params = {}
        for (const p of def.params ?? []) params[p.key] = p.default
        setSteps(prev => [...prev, { id: crypto.randomUUID(), op, label, params }])
    }
    function removeStep(id) {
        setSteps(prev => prev.filter(s => s.id !== id))
    }
    // paramDef.onSet(value, params) may return extra params to merge in alongside the changed
    // key — used by checksum.js's `variant` select to copy a preset's poly/init/refin/refout/
    // xorout into the step so `Custom` starts from (and non-Custom reflects) that preset.
    function updateStepParam(id, key, value, paramDef) {
        let v = value
        if (paramDef.type === 'number') {
            v = clamp(Math.round(Number(value)), paramDef.min, paramDef.max)
            if (!Number.isFinite(v)) return
        }
        setSteps(prev => prev.map(s => {
            if (s.id !== id) return s
            const extra = paramDef.onSet ? paramDef.onSet(v, s.params) : null
            return { ...s, params: { ...s.params, [key]: v, ...extra } }
        }))
    }

    function handleDragStart(e, id) {
        dragIdRef.current = id
        e.dataTransfer.effectAllowed = 'move'
        e.dataTransfer.setData('text/plain', id)
    }
    function handleDragOver(e, id) {
        e.preventDefault()
        e.dataTransfer.dropEffect = 'move'
        if (dragOverId !== id) setDragOverId(id)
    }
    function handleDragLeave(id) {
        setDragOverId(prev => (prev === id ? null : prev))
    }
    function handleDrop(e, targetId) {
        e.preventDefault()
        setDragOverId(null)
        const sourceId = dragIdRef.current
        dragIdRef.current = null
        if (!sourceId || sourceId === targetId) return
        setSteps(prev => {
            const next = [...prev]
            const from = next.findIndex(s => s.id === sourceId)
            const to = next.findIndex(s => s.id === targetId)
            if (from === -1 || to === -1) return prev
            const [moved] = next.splice(from, 1)
            next.splice(to, 0, moved)
            return next
        })
    }
    function handleDragEnd() {
        dragIdRef.current = null
        setDragOverId(null)
    }

    function handleAddClick() {
        setMenuOpen(v => !v)
    }

    function toggleSection(name) {
        setCollapsedSections(prev => {
            const next = new Set(prev)
            if (next.has(name)) next.delete(name)
            else next.add(name)
            return next
        })
    }

    // Resync the Hex-view buffer from the canonical bytes only when entering the view — this
    // is what makes leaving-and-returning discard any stale/invalid uncommitted text rather
    // than trying to preserve it.
    function handleInputViewChange(e) {
        const next = e.target.value
        if (next === 'hex' && inputView !== 'hex') setHexText(fmtAsHex(bytes))
        setInputView(next)
    }

    function handleHexInput(e) {
        const text = e.target.value
        setHexText(text)
        try {
            setBytes(hexTextToBytes(text))
        } catch {
            // Left as typed; not yet valid hex. No live warning (would fire on every other
            // keystroke) — handleGo() re-validates and surfaces an error there instead.
        }
    }

    // Steps normally run synchronously, but a step's run() may return a Promise (e.g. the
    // Compression operations, which are stream-based) — awaiting is a no-op for plain values.
    async function handleGo() {
        let current = bytes
        if (inputView === 'hex') {
            try {
                current = hexTextToBytes(hexText)
            } catch (err) {
                setOutputBytes(null)
                setOutputError(`Input (Hex view): ${err.message}`)
                return
            }
        }
        for (const step of steps) {
            const def = OPERATIONS[step.op]
            if (!def) continue
            try {
                current = await def.run(current, step.params)
            } catch (err) {
                setOutputBytes(null)
                setOutputError(`${step.label}: ${err.message}`)
                return
            }
        }
        setOutputError(null)
        setOutputBytes(current)
        setOutputView(isPrintable(current) ? 'raw' : 'hexdump')
    }

    // Decoding is non-fatal (invalid UTF-8 becomes U+FFFD) and only used for display/typing
    // in text mode — it's never written back into `bytes` except via the textarea's own
    // input, so merely viewing lossy text through the toggle doesn't destroy data.
    const decodedText = useMemo(() => fmtAsRaw(bytes), [bytes])
    const hasReplacementChars = decodedText.includes('�')
    const decodedOutputText = useMemo(
        () => outputBytes ? fmtAsRaw(outputBytes) : '',
        [outputBytes]
    )

    // Dismiss the algorithm menu on outside click or Escape.
    useDismissOnOutsideClick(toolbarRef, () => setMenuOpen(false), menuOpen)

    // `prefix` (from sectionPrefix(), based on the enclosing section/subsection name) is
    // applied only to the step's stored label, not to what's shown here in the menu itself —
    // the [E]/[D] marking is meant to disambiguate steps once they're in the chain, not to
    // clutter the selection list where the Encode/Decode grouping is already visible from
    // the section headers.
    function renderAlgoItem(entry, prefix) {
        const def = OPERATIONS[entry.op]
        if (!def) {
            return html`<div class="algo-menu-item algo-menu-item-todo" key=${entry.label}>${entry.label} [TODO]</div>`
        }
        return html`<div class="algo-menu-item" key=${entry.label} onClick=${() => { addStep(entry.op, (prefix ?? '') + entry.label); setMenuOpen(false) }}>${entry.label}</div>`
    }

    function renderStepParam(s, p) {
        if (p.type === 'boolean') {
            return html`
                <label key=${p.key} class="encdec-step-checkbox" title=${p.label}>
                    <input
                        type="checkbox"
                        checked=${s.params[p.key]}
                        onChange=${e => updateStepParam(s.id, p.key, e.target.checked, p)}
                    />
                    ${p.label}
                </label>
            `
        }
        if (p.type === 'select') {
            return html`
                <select
                    key=${p.key}
                    class="encdec-step-select-param"
                    title=${p.label}
                    value=${s.params[p.key]}
                    onChange=${e => updateStepParam(s.id, p.key, e.target.value, p)}
                >
                    ${p.options.map(o => html`<option value=${o.value}>${o.label}</option>`)}
                </select>
            `
        }
        if (p.type === 'text') {
            return html`
                <input
                    key=${p.key}
                    type="text"
                    class=${'encdec-step-param' + (p.wide ? ' encdec-step-param-wide' : '')}
                    title=${p.label}
                    placeholder=${p.label}
                    value=${s.params[p.key]}
                    onInput=${e => updateStepParam(s.id, p.key, e.target.value, p)}
                />
            `
        }
        return html`
            <input
                key=${p.key}
                type="number"
                class="encdec-step-param"
                title=${p.label}
                min=${p.min}
                max=${p.max}
                value=${s.params[p.key]}
                onInput=${e => updateStepParam(s.id, p.key, e.target.value, p)}
            />
        `
    }

    return html`
        <div class="encdec-panel">
            <div class="encdec-options" style=${`width: ${optionsWidth}px`}>
                <div class="encdec-options-toolbar" ref=${toolbarRef}>
                    <button class="btn" onclick=${handleAddClick} title="Add transform step">+</button>
                    ${menuOpen && html`
                        <div class="algo-menu">
                            ${ALGORITHM_SECTIONS.map(section => {
                                const collapsed = collapsedSections.has(section.name)
                                return html`
                                    <div class="algo-menu-section" key=${section.name}>
                                        <div class="algo-menu-section-label" onClick=${() => toggleSection(section.name)}>
                                            <span class="algo-menu-triangle">${collapsed ? '▶' : '▼'}</span>${section.name}
                                        </div>
                                        ${!collapsed && (section.subsections
                                            ? section.subsections.map(sub => html`
                                                <div class="algo-menu-subsection" key=${sub.name}>
                                                    <div class="algo-menu-subsection-label">${sub.name}</div>
                                                    ${sub.algorithms.map(a => renderAlgoItem(a, sectionPrefix(sub.name)))}
                                                </div>
                                            `)
                                            : section.algorithms.map(a => renderAlgoItem(a, sectionPrefix(section.name)))
                                        )}
                                    </div>
                                `
                            })}
                        </div>
                    `}
                </div>
                <div class="encdec-steps">
                    ${steps.map(s => {
                        const visibleParams = (OPERATIONS[s.op]?.params ?? []).filter(p => !p.showIf || p.showIf(s.params))
                        const headerParams = visibleParams.filter(p => p.inHeader)
                        const bodyRows = groupParams(visibleParams.filter(p => !p.inHeader))
                        return html`
                        <div
                            class=${'encdec-step' + (dragOverId === s.id ? ' encdec-step-drag-over' : '')}
                            key=${s.id}
                            draggable="true"
                            onDragStart=${e => handleDragStart(e, s.id)}
                            onDragOver=${e => handleDragOver(e, s.id)}
                            onDragLeave=${() => handleDragLeave(s.id)}
                            onDrop=${e => handleDrop(e, s.id)}
                            onDragEnd=${handleDragEnd}
                        >
                            <div class="encdec-step-header">
                                <span class="encdec-step-handle">⠿</span>
                                <span class="encdec-step-label">${s.label}</span>
                                ${headerParams.map(p => renderStepParam(s, p))}
                                <span class="encdec-step-remove" onclick=${() => removeStep(s.id)} title="Remove">×</span>
                            </div>
                            ${bodyRows.length > 0 && html`
                                <div class="encdec-step-params">
                                    ${bodyRows.map(row => row.label
                                        ? html`
                                            <div class="encdec-step-param-row" key=${row.members[0].key}>
                                                <span class="encdec-step-param-row-label">${row.label}</span>
                                                ${row.members.map(p => renderStepParam(s, p))}
                                            </div>
                                        `
                                        : row.members.map(p => renderStepParam(s, p))
                                    )}
                                </div>
                            `}
                        </div>
                    `})}
                </div>
            </div>
            <${ResizeHandle} orientation="v" onResize=${handleOptionsResize} />
            <div class="encdec-io">
                <div class="encdec-input-toolbar">
                    <label class="encdec-view-label">
                        View
                        <select class="encdec-view-select" value=${inputView} onChange=${handleInputViewChange}>
                            <option value="raw">Raw</option>
                            <option value="hex">Hex</option>
                            <option value="hexdump">Hexdump</option>
                        </select>
                    </label>
                    ${inputView === 'raw' && hasReplacementChars && html`
                        <span class="encdec-warning" title="Some bytes aren't valid UTF-8 and are shown as �. Editing this text will bake that in when switching to Hex or Hexdump view.">
                            ⚠ contains replacement characters
                        </span>
                    `}
                </div>
                ${inputView === 'hexdump'
                    ? html`<${HexEditor} bytes=${bytes} onChange=${setBytes} style=${`flex: 0 1 ${inputHeight}px`} />`
                    : inputView === 'hex'
                        ? html`<textarea
                            class="encdec-textarea encdec-input"
                            placeholder="Input…"
                            spellcheck="false"
                            value=${hexText}
                            oninput=${handleHexInput}
                            style=${`flex: 0 1 ${inputHeight}px`}
                        />`
                        : html`<textarea
                            class="encdec-textarea encdec-input"
                            placeholder="Input…"
                            spellcheck="false"
                            value=${decodedText}
                            oninput=${e => setBytes(parseRaw(e.target.value))}
                            style=${`flex: 0 1 ${inputHeight}px`}
                        />`
                }
                <${ResizeHandle} orientation="h" onResize=${handleInputResize} />
                <div class="encdec-output-toolbar">
                    <label class="encdec-view-label">
                        View
                        <select class="encdec-view-select" value=${outputView} onChange=${e => setOutputView(e.target.value)}>
                            <option value="raw">Raw</option>
                            <option value="hex">Hex</option>
                            <option value="hexdump">Hexdump</option>
                        </select>
                    </label>
                    <button class="btn encdec-go-btn" onclick=${handleGo}>Go</button>
                </div>
                ${outputError
                    ? html`<div class="encdec-output-error">${outputError}</div>`
                    : outputView === 'hexdump'
                        ? html`<${HexEditor} bytes=${outputBytes ?? new Uint8Array(0)} onChange=${() => {}} readOnly=${true} />`
                        : html`<textarea
                            class="encdec-textarea encdec-output"
                            placeholder="Output"
                            spellcheck="false"
                            readonly
                            value=${outputView === 'hex' ? fmtAsHex(outputBytes ?? new Uint8Array(0)) : decodedOutputText}
                        />`
                }
            </div>
        </div>
    `
}
