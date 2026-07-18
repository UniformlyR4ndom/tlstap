import { h } from 'preact'
import htm from 'htm'

const html = htm.bind(h)

function isSelected(selectedKey, entry) {
    return selectedKey && selectedKey.conn === entry.conn && selectedKey.direction === entry.direction
}

// The main panel of the Tamper tab: one row per (stream, direction) that currently has
// something held, summarized as chunk count + byte length — not one row per chunk, since
// the new protocol has no more per-chunk ids (a direction's held bytes are one growing,
// editable buffer; see intercept/tamper/buffer.go). Selecting a row is the entry point
// into TamperDetailPanel. No relative "held Xs ago" time here — unlike the old per-chunk
// protocol, stream-list's pendingInfo deliberately carries no timestamp for a buffer as a
// whole (see protocol.go), and it wasn't judged worth new client-side time-tracking just
// to keep a cosmetic display.
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
                            <span class=${entry.direction === 0 ? 'c2s' : 's2c'}>${entry.direction === 0 ? 'C→S' : 'S→C'}</span>
                            · ${entry.chunks} chunk${entry.chunks === 1 ? '' : 's'} · ${entry.length} B ·
                            ${entry.src} ↔ ${entry.dst}
                        </span>
                    </div>
                `)}
            </div>
        </div>
    `
}
