import { h } from 'preact'
import { useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import {
    EditorState, EditorView, Compartment, basicSetup, keymap, indentWithTab,
    javascript, scopeCompletionSource,
    HighlightStyle, syntaxHighlighting, tags,
} from '../vendor/codemirror.module.js'

const html = htm.bind(h)

// Dark theme + syntax colors matching this app's own CSS variables — kept here rather
// than in a stylesheet since CodeMirror styles its content via classed spans generated
// from the HighlightStyle below, not selectors an external stylesheet could target.
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

// Controlled-ish: <${ScriptEditor} value onChange loadVersion completions readOnly? />.
// CodeMirror owns the DOM/cursor/undo-history state internally; this wrapper reports
// every edit upward via onChange, but only pushes `value` into CodeMirror when
// `loadVersion` changes — the caller must bump it on every genuinely external reset, and
// only then. `completions` is an object passed straight to CodeMirror's
// scopeCompletionSource (e.g. `{tamper: TAMPER_COMPLETION_SHAPE, ctx: CTX_COMPLETION_SHAPE}`
// for a tamper script, `{framer: FRAMER_COMPLETION_SHAPE}` for a framer script) — baked
// into the editor once at mount, not reactive to later changes (no caller needs that).
//
// A string-equality check can't substitute for loadVersion: CodeMirror applies
// keystrokes synchronously, independent of Preact's deferred effect scheduling, so an
// effect can run after more keystrokes have landed than the `value` it closed over
// accounts for, see a stale mismatch, and dispatch a destructive full-document replace
// that rolls back real typing — and since that rollback is itself a docChange, it can
// trigger the same race again. Gating on an explicit loadVersion signal sidesteps this
// structurally: the sync effect never runs during typing at all.
export default function ScriptEditor({ value, onChange, loadVersion, completions, readOnly = false }) {
    const containerRef = useRef(null)
    const viewRef = useRef(null)
    const readOnlyCompartmentRef = useRef(null)
    const onChangeRef = useRef(onChange)
    onChangeRef.current = onChange
    const loadVersionRef = useRef(loadVersion)

    useEffect(() => {
        const readOnlyCompartment = new Compartment()
        readOnlyCompartmentRef.current = readOnlyCompartment
        const jsLanguage = javascript()
        const view = new EditorView({
            state: EditorState.create({
                doc: value,
                extensions: [
                    basicSetup,
                    keymap.of([indentWithTab]),
                    jsLanguage,
                    jsLanguage.language.data.of({ autocomplete: scopeCompletionSource(completions) }),
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

    // Gated on loadVersion, not value — see the module doc comment above for why a
    // value-equality heuristic can't safely detect "external change" here. The caller
    // bumps loadVersion exactly once per genuine external reset; ordinary typing never
    // touches it, so this effect simply never runs while typing.
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
