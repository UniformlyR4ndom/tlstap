import { h } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import htm from 'htm'

const html = htm.bind(h)

// Shared chrome for SessionList/StreamList: panel-header (title + count badge + sort-toggle)
// and a sorted, selectable item list. Callers own fetching, per-row content (renderItem), and
// what "empty" means; this owns only the sort-direction state and the header/list markup that
// was otherwise duplicated verbatim between the two.
export default function ListPanel({ title, items, error, emptyMessage, selected, onSelect, renderItem, resetSortKey }) {
    const [desc, setDesc] = useState(false)

    // StreamList resets sort to ascending on session change; SessionList never passes
    // resetSortKey, so this never fires there (matching its original never-reset behavior).
    useEffect(() => { setDesc(false) }, [resetSortKey])

    const sorted = desc ? [...items].reverse() : items

    return html`
        <div class="panel">
            <div class="panel-header">
                ${title}
                <span class="badge">${items.length}</span>
                <span class="sort-toggle" onclick=${() => setDesc(d => !d)} title=${desc ? 'Newest first' : 'Oldest first'}>
                    ${desc ? '▼' : '▲'}
                </span>
            </div>
            <div class="panel-list">
                ${error && html`<div class="error-msg">${error}</div>`}
                ${!error && items.length === 0 && html`<div class="empty">${emptyMessage}</div>`}
                ${sorted.map(item => html`
                    <div
                        key=${item.id}
                        class=${'list-item' + (selected?.id === item.id ? ' selected' : '')}
                        onclick=${() => onSelect(item)}
                    >
                        ${renderItem(item)}
                    </div>
                `)}
            </div>
        </div>
    `
}
