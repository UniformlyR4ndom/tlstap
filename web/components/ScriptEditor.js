import { h } from 'preact'
import { useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import {
    EditorState, EditorView, Compartment, basicSetup, keymap, indentWithTab,
    javascript,
    HighlightStyle, syntaxHighlighting, tags,
} from '../vendor/codemirror.module.js'

const html = htm.bind(h)

// Dark theme + syntax colors matching this app's own CSS variables (index.html) — kept
// here rather than in index.html's CSS since CodeMirror styles its content via classed
// spans generated from the HighlightStyle below, not plain CSS selectors an external
// stylesheet could target on its own.
const theme = EditorView.theme({
    '&': { color: 'var(--text)', backgroundColor: 'var(--bg)', height: '100%' },
    '.cm-content': { caretColor: 'var(--text)', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace', fontSize: '12.5px' },
    '.cm-gutters': { backgroundColor: 'var(--surface)', color: 'var(--text-dim)', border: 'none' },
    '.cm-activeLine': { backgroundColor: 'var(--hover-bg)' },
    '.cm-activeLineGutter': { backgroundColor: 'var(--hover-bg)' },
    '.cm-selectionBackground, &.cm-focused .cm-selectionBackground': { backgroundColor: 'var(--selected-bg) !important' },
    '.cm-cursor': { borderLeftColor: 'var(--text)' },
    '.cm-tooltip': { backgroundColor: 'var(--surface)', border: '1px solid var(--border)', color: 'var(--text)' },
    '.cm-tooltip-autocomplete ul li[aria-selected]': { backgroundColor: 'var(--selected-bg)', color: 'var(--text)' },
    '.cm-scroller': { lineHeight: '1.5' },
}, { dark: true })

const highlightStyle = HighlightStyle.define([
    { tag: tags.comment, color: 'var(--text-dim)', fontStyle: 'italic' },
    { tag: tags.string, color: '#a5d6ff' },
    { tag: [tags.number, tags.bool, tags.null], color: '#79c0ff' },
    { tag: [tags.keyword, tags.controlKeyword, tags.operatorKeyword], color: '#ff7b72' },
    { tag: [tags.function(tags.variableName), tags.function(tags.propertyName)], color: '#d2a8ff' },
    { tag: tags.propertyName, color: '#79c0ff' },
    { tag: tags.definition(tags.variableName), color: 'var(--text)' },
    { tag: tags.variableName, color: 'var(--text)' },
    { tag: tags.className, color: '#ffa657' },
    { tag: tags.punctuation, color: 'var(--text-dim)' },
])

// Controlled-ish component, same contract as HexEditor.js: <${ScriptEditor} value=${text}
// onChange=${text => ...} loadVersion=${n} readOnly? />. CodeMirror owns the actual DOM/
// cursor/undo-history state internally; this wrapper reports every edit upward via
// onChange, but only ever pushes `value` INTO CodeMirror when `loadVersion` changes — the
// caller must bump it on every genuinely external reset (initial load, script switch,
// Reload), and only then. It deliberately does NOT infer "was this value change external,
// or just our own edit echoing back down through the parent's state?" from comparing
// strings (what this used to do, first against a live `view.state.doc.toString()` read,
// then against a `lastEmittedRef` of our last-reported text) — both are "always current"
// references updated synchronously the instant a keystroke lands, compared against a
// `value` snapshot from whichever render this effect instance happens to close over,
// which can be arbitrarily stale: CodeMirror processes every keystroke immediately,
// independent of Preact's own (deferred) effect scheduling, so several real keystrokes can
// land before an earlier render's effect finally runs. When it does, it sees `value` (its
// own stale snapshot) differ from the live/ref reference (which has since moved on) and
// dispatches a destructive full-document replace using the stale text — rolling back real
// keystrokes. That rollback is itself a docChange, which fires onChange again, which can
// race the NEXT pending effect the same way; reproduced firsthand as an actual
// content-duplicating, CPU-pegging freeze during ordinary typing (no highlighting, no
// large paste required — just enough keystrokes landing before Preact's effect flush
// catches up). No string-equality heuristic closes this race, since the staleness is about
// *when* the effect runs relative to real keystrokes, not what it's compared against.
// Gating the sync entirely on an explicit `loadVersion` signal sidesteps it structurally:
// the sync effect literally never runs during typing, regardless of any reordering.
export default function ScriptEditor({ value, onChange, loadVersion, readOnly = false }) {
    const containerRef = useRef(null)
    const viewRef = useRef(null)
    const readOnlyCompartmentRef = useRef(null)
    const onChangeRef = useRef(onChange)
    onChangeRef.current = onChange
    const loadVersionRef = useRef(loadVersion)

    useEffect(() => {
        const readOnlyCompartment = new Compartment()
        readOnlyCompartmentRef.current = readOnlyCompartment
        const view = new EditorView({
            state: EditorState.create({
                doc: value,
                extensions: [
                    basicSetup,
                    keymap.of([indentWithTab]),
                    javascript(),
                    syntaxHighlighting(highlightStyle),
                    theme,
                    readOnlyCompartment.of(EditorState.readOnly.of(readOnly)),
                    EditorView.updateListener.of(update => {
                        if (update.docChanged) {
                            onChangeRef.current?.(update.state.doc.toString())
                        }
                    }),
                ],
            }),
            parent: containerRef.current,
        })
        viewRef.current = view
        return () => { view.destroy(); viewRef.current = null }
    }, []) // one persistent EditorView per mounted ScriptEditor instance

    useEffect(() => {
        const view = viewRef.current
        if (!view) return
        view.dispatch({ effects: readOnlyCompartmentRef.current.reconfigure(EditorState.readOnly.of(readOnly)) })
    }, [readOnly])

    // Gated on loadVersion, NOT value — see the module doc comment above for why a
    // value-equality heuristic can't safely detect "external change" here. The caller
    // (TamperScriptsPanel.js) bumps loadVersion exactly once per genuine external reset;
    // ordinary typing never touches it, so this effect simply never runs while typing.
    useEffect(() => {
        const view = viewRef.current
        if (!view) return
        if (loadVersion === loadVersionRef.current) return
        loadVersionRef.current = loadVersion
        const current = view.state.doc.toString()
        if (current === value) return // already matches (e.g. Reload with no server-side change)
        view.dispatch({ changes: { from: 0, to: current.length, insert: value } })
    }, [loadVersion])

    return html`<div class="tamper-scripts-editor-mount" ref=${containerRef} />`
}
