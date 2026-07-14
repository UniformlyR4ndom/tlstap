import { h } from 'preact'
import htm from 'htm'

const html = htm.bind(h)

// Left-hand panel of the Tamper tab: every known stream, with an intercept/watch
// toggle — the only place a watched stream can be escalated into intercept mode (the
// queue list alone only ever shows streams that already have something held).
export default function TamperStreamsList({ streams, onToggleMode }) {
    return html`
        <div class="panel tamper-streams-panel">
            <div class="panel-header">
                Streams
                <span class="badge">${streams.length}</span>
                <span class="tamper-col-label">Intercept</span>
            </div>
            <div class="panel-list">
                ${streams.length === 0 && html`<div class="empty">No active streams</div>`}
                ${streams.map(s => html`
                    <div key=${s.conn} class="list-item tamper-stream-row">
                        <span class="tamper-stream-line">
                            #${s.conn} · <span class="c2s">${s.src}</span> ↔ <span class="s2c">${s.dst}</span>
                        </span>
                        <input
                            type="checkbox"
                            class="tamper-stream-checkbox"
                            checked=${s.intercepting}
                            onchange=${e => onToggleMode(s.conn, e.target.checked)}
                        />
                    </div>
                `)}
            </div>
        </div>
    `
}
