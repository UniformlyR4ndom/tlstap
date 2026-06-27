import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'

const html = htm.bind(h)

export default function GoToPanel({ stream, onGoTo }) {
    const [value, setValue] = useState('')
    const [unit,  setUnit]  = useState('chunks')

    if (!stream) return html`<div class="panel-placeholder">Select a stream first</div>`

    function handleSubmit(e) {
        e?.preventDefault()
        const s = value.trim()
        const n = s.startsWith('0x') || s.startsWith('0X') ? parseInt(s, 16) : parseInt(s, 10)
        if (isNaN(n) || n < 0) return
        onGoTo?.({ value: n, unit })
    }

    return html`
        <form class="goto-form" onsubmit=${handleSubmit}>
            <input
                class="goto-input"
                type="text"
                placeholder="0"
                value=${value}
                oninput=${e => setValue(e.target.value)}
            />
            <select class="goto-select" value=${unit} onchange=${e => setUnit(e.target.value)}>
                <option value="chunks">chunks (total)</option>
                <option value="chunks-c2s">chunks (c→s)</option>
                <option value="chunks-s2c">chunks (s→c)</option>
                <option value="offset-c2s">offset (c→s)</option>
                <option value="offset-s2c">offset (s→c)</option>
            </select>
            <button class="btn" type="submit">Go</button>
        </form>
    `
}
