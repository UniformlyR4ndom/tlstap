import { h } from 'preact'
import htm from 'htm'
import { dirClass, dirLabel } from '../direction.js'

const html = htm.bind(h)

function isSelected(selectedKey, entry) {
    return selectedKey && selectedKey.conn === entry.conn && selectedKey.direction === entry.direction
}

// The main panel of the Tamper tab: one row per (stream, direction) that currently has
// something held, summarized as chunk count + byte length — not one row per chunk, since
// a direction's held bytes are one growing, editable buffer (see intercept/tamper/buffer.go),
// with no per-chunk ids. Selecting a row is the entry point into TamperDetailPanel. No
// relative "held Xs ago" time here — stream-list's pendingInfo carries no timestamp for a
// buffer as a whole (see protocol.go).
export default function TamperQueueList({ queue, selectedKey, onSelect, pausedEntries }) {
    return html`
        <div class="panel tamper-queue-panel">
            <div class="panel-header">
                Held buffers
                <span class="badge">${queue.length}</span>
            </div>
            <div class="panel-list">
                ${queue.length === 0 && html`<div class="empty">Nothing held right now</div>`}
                ${queue.map(entry => html`
                    <div
                        key=${`${entry.conn}-${entry.direction}`}
                        class=${'list-item tamper-queue-row' + (isSelected(selectedKey, entry) ? ' selected' : '')}
                        onclick=${() => onSelect({ conn: entry.conn, direction: entry.direction })}
                    >
                        <span class="tamper-queue-line">
                            ${pausedEntries?.has(`${entry.conn}:${entry.direction}`) && html`<span class="tamper-paused-dot" title="paused by script">⏸</span>`}
                            #${entry.conn} ·
                            <span class=${dirClass(entry.direction)}>${dirLabel(entry.direction)}</span>
                            · ${entry.chunks} chunk${entry.chunks === 1 ? '' : 's'} · ${entry.length} B ·
                            ${entry.src} ↔ ${entry.dst}
                        </span>
                    </div>
                `)}
            </div>
        </div>
    `
}
