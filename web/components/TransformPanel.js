import { h } from 'preact'
import { useState, useEffect, useMemo, useRef } from 'preact/hooks'
import htm from 'htm'
import ResizeHandle from './ResizeHandle.js'
import HexEditor from './HexEditor.js'
import { loadLayout, saveLayoutValue } from '../layout.js'
import { OPERATIONS, ALGORITHM_SECTIONS } from '../transforms.js'

const html = htm.bind(h)

function clamp(v, lo, hi) { return Math.min(Math.max(v, lo), hi) }

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
    const [hexdumpView, setHexdumpView] = useState(false)
    const [optionsWidth, setOptionsWidth] = useState(() => loadLayout().encdecOptionsWidth)
    const [inputHeight, setInputHeight] = useState(() => loadLayout().encdecInputHeight)
    const [steps, setSteps] = useState([])
    const [menuOpen, setMenuOpen] = useState(false)
    const [dragOverId, setDragOverId] = useState(null)
    const [outputBytes, setOutputBytes] = useState(null)
    const [outputError, setOutputError] = useState(null)
    const [outputHexdumpView, setOutputHexdumpView] = useState(false)
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
    function updateStepParam(id, key, value, paramDef) {
        let v = value
        if (paramDef.type === 'number') {
            v = clamp(Math.round(Number(value)), paramDef.min, paramDef.max)
            if (!Number.isFinite(v)) return
        }
        setSteps(prev => prev.map(s => s.id === id ? { ...s, params: { ...s.params, [key]: v } } : s))
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

    function handleHexdumpViewToggle(e) {
        setHexdumpView(e.target.checked)
    }

    function handleGo() {
        let current = bytes
        for (const step of steps) {
            const def = OPERATIONS[step.op]
            if (!def) continue
            try {
                current = def.run(current, step.params)
            } catch (err) {
                setOutputBytes(null)
                setOutputError(`${step.label}: ${err.message}`)
                return
            }
        }
        setOutputError(null)
        setOutputBytes(current)
        setOutputHexdumpView(!isPrintable(current))
    }

    // Decoding is non-fatal (invalid UTF-8 becomes U+FFFD) and only used for display/typing
    // in text mode — it's never written back into `bytes` except via the textarea's own
    // input, so merely viewing lossy text through the toggle doesn't destroy data.
    const decodedText = useMemo(() => new TextDecoder('utf-8', { fatal: false }).decode(bytes), [bytes])
    const hasReplacementChars = decodedText.includes('�')
    const decodedOutputText = useMemo(
        () => outputBytes ? new TextDecoder('utf-8', { fatal: false }).decode(outputBytes) : '',
        [outputBytes]
    )

    // Dismiss the algorithm menu on outside click or Escape.
    useEffect(() => {
        if (!menuOpen) return
        const close = e => {
            if (toolbarRef.current && !toolbarRef.current.contains(e.target)) setMenuOpen(false)
        }
        const onKey = e => { if (e.key === 'Escape') setMenuOpen(false) }
        document.addEventListener('mousedown', close)
        document.addEventListener('keydown', onKey)
        return () => {
            document.removeEventListener('mousedown', close)
            document.removeEventListener('keydown', onKey)
        }
    }, [menuOpen])

    function handleOptionsResize(deltaX) {
        setOptionsWidth(w => {
            const next = clamp(w + deltaX, 100, 400)
            saveLayoutValue('encdecOptionsWidth', next)
            return next
        })
    }

    function handleInputResize(deltaY) {
        setInputHeight(h => {
            const next = clamp(h + deltaY, 30, 2000)
            saveLayoutValue('encdecInputHeight', next)
            return next
        })
    }

    function renderAlgoItem(entry) {
        const def = OPERATIONS[entry.op]
        if (!def) {
            return html`<div class="algo-menu-item algo-menu-item-todo" key=${entry.label}>${entry.label} [TODO]</div>`
        }
        return html`<div class="algo-menu-item" key=${entry.label} onClick=${() => { addStep(entry.op, entry.label); setMenuOpen(false) }}>${entry.label}</div>`
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
                            ${ALGORITHM_SECTIONS.map(section => html`
                                <div class="algo-menu-section" key=${section.name}>
                                    <div class="algo-menu-section-label">${section.name}</div>
                                    ${section.subsections
                                        ? section.subsections.map(sub => html`
                                            <div class="algo-menu-subsection" key=${sub.name}>
                                                <div class="algo-menu-subsection-label">${sub.name}</div>
                                                ${sub.algorithms.map(renderAlgoItem)}
                                            </div>
                                        `)
                                        : section.algorithms.map(renderAlgoItem)
                                    }
                                </div>
                            `)}
                        </div>
                    `}
                </div>
                <div class="encdec-steps">
                    ${steps.map(s => html`
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
                            <span class="encdec-step-handle">⠿</span>
                            <span class="encdec-step-label">${s.label}</span>
                            ${(OPERATIONS[s.op]?.params ?? []).map(p => renderStepParam(s, p))}
                            <span class="encdec-step-remove" onclick=${() => removeStep(s.id)} title="Remove">×</span>
                        </div>
                    `)}
                </div>
            </div>
            <${ResizeHandle} orientation="v" onResize=${handleOptionsResize} />
            <div class="encdec-io">
                <div class="encdec-input-toolbar">
                    <label class="encdec-checkbox-label">
                        <input type="checkbox" checked=${hexdumpView} onchange=${handleHexdumpViewToggle} />
                        Hexdump view
                    </label>
                    ${!hexdumpView && hasReplacementChars && html`
                        <span class="encdec-warning" title="Some bytes aren't valid UTF-8 and are shown as �. Editing this text will bake that in when switching back to Hexdump view.">
                            ⚠ contains replacement characters
                        </span>
                    `}
                </div>
                ${hexdumpView
                    ? html`<${HexEditor} bytes=${bytes} onChange=${setBytes} style=${`flex: 0 1 ${inputHeight}px`} />`
                    : html`<textarea
                        class="encdec-textarea encdec-input"
                        placeholder="Input…"
                        spellcheck="false"
                        value=${decodedText}
                        oninput=${e => setBytes(new TextEncoder().encode(e.target.value))}
                        style=${`flex: 0 1 ${inputHeight}px`}
                    />`
                }
                <${ResizeHandle} orientation="h" onResize=${handleInputResize} />
                <div class="encdec-output-toolbar">
                    <label class="encdec-checkbox-label">
                        <input type="checkbox" checked=${outputHexdumpView} onchange=${e => setOutputHexdumpView(e.target.checked)} />
                        Hexdump view
                    </label>
                    <button class="btn encdec-go-btn" onclick=${handleGo}>Go</button>
                </div>
                ${outputError
                    ? html`<div class="encdec-output-error">${outputError}</div>`
                    : outputHexdumpView
                        ? html`<${HexEditor} bytes=${outputBytes ?? new Uint8Array(0)} onChange=${() => {}} readOnly=${true} />`
                        : html`<textarea
                            class="encdec-textarea encdec-output"
                            placeholder="Output"
                            spellcheck="false"
                            readonly
                            value=${decodedOutputText}
                        />`
                }
            </div>
        </div>
    `
}
