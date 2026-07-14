import { h } from 'preact'
import htm from 'htm'

const html = htm.bind(h)

function fmtAgo(ms) {
    const d = Date.now() - ms
    if (d < 1000) return 'just now'
    if (d < 60000) return `${Math.floor(d / 1000)}s ago`
    return `${Math.floor(d / 60000)}m ago`
}

function isSelected(selectedKey, entry) {
    return selectedKey && selectedKey.conn === entry.conn && selectedKey.id === entry.id
}

// The main panel of the Tamper tab: every currently-held chunk across every stream,
// oldest first. Selecting a row is the entry point into TamperDetailPanel.
export default function TamperQueueList({ queue, selectedKey, onSelect }) {
    return html`
        <div class="panel tamper-queue-panel">
            <div class="panel-header">
                Held chunks
                <span class="badge">${queue.length}</span>
            </div>
            <div class="panel-list">
                ${queue.length === 0 && html`<div class="empty">Nothing held right now</div>`}
                ${queue.map(entry => html`
                    <div
                        key=${`${entry.conn}-${entry.id}`}
                        class=${'list-item tamper-queue-row' + (isSelected(selectedKey, entry) ? ' selected' : '')}
                        onclick=${() => onSelect({ conn: entry.conn, id: entry.id })}
                    >
                        <span class="tamper-queue-line">
                            #${entry.conn} ·
                            <span class=${entry.direction === 0 ? 'c2s' : 's2c'}>${entry.direction === 0 ? 'C→S' : 'S→C'}</span>
                            · ${entry.length} B · ${fmtAgo(entry.time)} ·
                            ${entry.src} ↔ ${entry.dst}
                        </span>
                    </div>
                `)}
            </div>
        </div>
    `
}
