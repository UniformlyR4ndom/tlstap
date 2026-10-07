import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'
import FramerScriptsPanel from './FramerScriptsPanel.js'
import FramerLogPanel from './FramerLogPanel.js'

const html = htm.bind(h)

// "Framing" bottom-panel tab of the Analysis view: groups the framer-script editor and
// its run log under one tab, Scripts/Log as sub-tabs — same shape as the Tamper tab's own
// Intercept/Scripts split (TamperView.js). refreshKey/frameLog/onClearFrameLog are owned
// by App.js (frameLog specifically needs to survive switching sub-tabs here without
// resetting, the same reason TamperView.js lifts its own script log above its sub-tabs).
export default function FramingPanel({ framerApi, refreshSignal, frameLog, onClearFrameLog }) {
    const [subTab, setSubTab] = useState('scripts') // 'scripts' | 'log'

    return html`
        <div class="framing-panel">
            <div class="tamper-subtabs">
                <div class=${'top-tab' + (subTab === 'scripts' ? ' active' : '')} onclick=${() => setSubTab('scripts')}>Scripts</div>
                <div class=${'top-tab' + (subTab === 'log'     ? ' active' : '')} onclick=${() => setSubTab('log')}>Log</div>
            </div>
            <div class="framing-body">
                ${subTab === 'scripts' && html`<${FramerScriptsPanel} framerApi=${framerApi} refreshSignal=${refreshSignal} />`}
                ${subTab === 'log'     && html`<${FramerLogPanel} lines=${frameLog} onClear=${onClearFrameLog} />`}
            </div>
        </div>
    `
}
