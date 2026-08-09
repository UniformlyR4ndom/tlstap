import { h } from 'preact'
import htm from 'htm'
import { listScripts, getScript, putScript, deleteScript } from '../tamperApi.js'
import { OPERATIONS_BY_CATEGORY } from '../transforms.js'
import { NUMBER_TYPES } from '../transforms/numbers.js'
import { camelCaseOpId, capitalizeTypeId } from '../transformWorkerApi.js'
import ScriptsCrudPanel from './ScriptsCrudPanel.js'
import ResizeHandle from './ResizeHandle.js'
import { useResizableLayout } from '../useResizableLayout.js'
import { downloadBlob } from '../download.js'

const html = htm.bind(h)

// Reflection-only mirror of the real self.tamper API, for scopeCompletionSource to read
// property names/types off of — never called. transform's shape is generated from
// OPERATIONS_BY_CATEGORY/camelCaseOpId, number's from NUMBER_TYPES/capitalizeTypeId — the
// same inputs the real API uses, so a new transform op or number type appears here
// without a separate update.
const TAMPER_COMPLETION_SHAPE = {
    register: () => {},
    peek: () => {},
    release: () => {},
    dropConnection: () => {},
    setIntercept: () => {},
    listStreams: () => {},
    fs: {
        listFiles: () => {},
        readFile: () => {},
        writeFile: () => {},
        appendFile: () => {},
    },
    transform: Object.fromEntries(Object.entries(OPERATIONS_BY_CATEGORY).map(([category, ops]) =>
        [category, Object.fromEntries(Object.keys(ops).map(opId => [camelCaseOpId(opId), () => {}]))])),
    encode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    decode: { hex: () => {}, base64: () => {}, hexdump: () => {} },
    number: Object.fromEntries(NUMBER_TYPES.flatMap(t => {
        const suffix = capitalizeTypeId(t.id)
        return [[`decode${suffix}`, () => {}], [`encode${suffix}`, () => {}]]
    })),
    log: () => {},
}

// Same idea as TAMPER_COMPLETION_SHAPE, mirroring the real ctx object handed to
// onReceive (minus __flush, internal-only there). scopeCompletionSource matches on
// identifier text alone, not real lexical scope, so `ctx.` completes anywhere in the
// document, including outside an onReceive callback — a one-time, deliberate
// imprecision: harmless since it only ever adds unwanted suggestions, never blocks or
// slows typing.
const CTX_COMPLETION_SHAPE = {
    conn: 0,
    direction: 'c2s',
    newLength: 0,
    get: () => {},
    set: () => {},
    append: () => {},
    release: () => {},
    drop: () => {},
    pause: () => {},
    log: () => {},
}

const COMPLETIONS = { tamper: TAMPER_COMPLETION_SHAPE, ctx: CTX_COMPLETION_SHAPE }

// "Scripts" sub-tab of the Tamper view: ScriptsCrudPanel.js's generic list+editor chrome
// plus Run/Stop for the one script instance that can be active at a time, and a resizable
// log panel. The running script and its log survive switching away from this sub-tab
// (both are lifted to the parent, TamperView.js).
//
// logFile ({enabled, filename}) and bypassBrowserLog/onBypassBrowserLogChange are also
// owned by the parent — the actual decisions of whether to persist a line server-side
// and whether to also keep it in the browser's own copy happen there; this panel only
// renders what those choices imply.
export default function TamperScriptsPanel({
    connected, running, onRun, onStop, logLines, onClearLog, refreshSignal,
    logFile, bypassBrowserLog, onBypassBrowserLogChange,
}) {
    // Handle sits before the log panel (above it), so a negative deltaY (dragging up)
    // grows it.
    const [logHeight, handleLogResize]  = useResizableLayout('scriptsLogHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })

    // Only rendered/reachable when no server-side log file is configured — once one is,
    // "Logged to <filename>" replaces this button entirely. Plain per-line text; error
    // lines get a textual [ERROR] marker since the red .tamper-log-error styling doesn't
    // survive into a downloaded file. Always a plain anchor-click download, not
    // showSaveFilePicker — this button is "Download," not "Save As," and the native save
    // dialog can hang with no error and no visible feedback; a plain download has no
    // such failure mode.
    function handleDownloadLog() {
        const text = logLines.map(l => l.level === 'error' ? `[ERROR] ${l.text}` : l.text).join('\n')
        downloadBlob(text, 'tamper-script-log.txt', 'text/plain')
    }

    return html`
        <div class="tamper-scripts-view">
            <${ScriptsCrudPanel}
                className="tamper-scripts-main"
                list=${listScripts} get=${getScript} put=${putScript} del=${deleteScript}
                completions=${COMPLETIONS}
                refreshSignal=${refreshSignal}
                listWidthKey="scriptsListWidth"
                rowDecoration=${name => running === name && html`<span class="tamper-script-running-dot">●</span>`}
                controls=${(name, source) => running === name
                    ? html`<button class="btn" onclick=${onStop}>■ Stop</button>`
                    : html`<button class="btn" disabled=${!connected} onclick=${() => onRun(name, source)}>▶ Run</button>`}
            />
            <${ResizeHandle} orientation="h" onResize=${handleLogResize} />
            <div class="tamper-scripts-log" style=${`height: ${logHeight}px`}>
                <div class="panel-header">
                    Log
                    ${logFile?.enabled && html`<span class="tamper-log-file-status">Logged to ${logFile.filename}</span>`}
                    <span class="tamper-scripts-toolbar-spacer" />
                    ${logFile?.enabled && html`
                        <label class="tamper-log-bypass-toggle">
                            <input
                                type="checkbox"
                                checked=${bypassBrowserLog}
                                onchange=${e => onBypassBrowserLogChange(e.target.checked)}
                            />
                            Skip browser log
                        </label>
                    `}
                    ${!logFile?.enabled && html`<button class="btn btn-sm" disabled=${logLines.length === 0} onclick=${handleDownloadLog}>Download</button>`}
                    <button class="btn btn-sm" onclick=${onClearLog}>Clear</button>
                </div>
                <div class="tamper-scripts-log-body">
                    ${logLines.length === 0 && html`<div class="empty">No output</div>`}
                    ${logLines.map((l, i) => html`
                        <div key=${i} class=${'tamper-log-line tamper-log-' + l.level}>${l.text}</div>
                    `)}
                </div>
            </div>
        </div>
    `
}
