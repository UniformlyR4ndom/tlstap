import { h } from 'preact'
import { useState } from 'preact/hooks'
import htm from 'htm'
import { DIR_C2S, DIR_S2C } from '../direction.js'

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
                <option value="chunks-c2s">chunks (${DIR_C2S})</option>
                <option value="chunks-s2c">chunks (${DIR_S2C})</option>
                <option value="offset-c2s">offset (${DIR_C2S})</option>
                <option value="offset-s2c">offset (${DIR_S2C})</option>
            </select>
            <button class="btn" type="submit">Go</button>
        </form>
    `
}
