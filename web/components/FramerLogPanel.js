import { h } from 'preact'
import htm from 'htm'
import { downloadBlob } from '../download.js'

const html = htm.bind(h)

// "Log" bottom-panel tab of the Analysis view: a framer script's framer.log(...) output
// for the currently-selected stream (App.js owns `lines`, reset whenever the stream
// changes — see TrafficView.js's onFramerLogReset). Reuses tamper's log-line/error CSS
// classes (.tamper-log-line/.tamper-log-error, .tamper-scripts-log-body) since the
// rendering is identical; only the root layout class (.framer-log-panel, height:100%
// rather than flex:1 — see ScriptsCrudPanel.js's CSS note) is new.
export default function FramerLogPanel({ lines, onClear }) {
    // Plain per-line text; error lines get a textual [ERROR] marker and each line its
    // direction, since neither the red styling nor the [c2s]/[s2c] prefix survives into
    // a downloaded file. Always a plain anchor-click download, not showSaveFilePicker —
    // same reasoning as TamperScriptsPanel.js's own log download.
    function handleDownload() {
        const text = lines.map(l => {
            const dir = l.direction ? `[${l.direction}] ` : ''
            return l.level === 'error' ? `${dir}[ERROR] ${l.text}` : `${dir}${l.text}`
        }).join('\n')
        downloadBlob(text, 'framer-log.txt', 'text/plain')
    }

    return html`
        <div class="framer-log-panel">
            <div class="panel-header">
                Log
                <button class="btn btn-sm" disabled=${lines.length === 0} onclick=${handleDownload}>Download</button>
                <button class="btn btn-sm" onclick=${onClear}>Clear</button>
            </div>
            <div class="tamper-scripts-log-body">
                ${lines.length === 0 && html`<div class="empty">No output</div>`}
                ${lines.map((l, i) => html`
                    <div key=${i} class=${'tamper-log-line tamper-log-' + l.level}>${l.direction ? `[${l.direction}] ` : ''}${l.text}</div>
                `)}
            </div>
        </div>
    `
}
