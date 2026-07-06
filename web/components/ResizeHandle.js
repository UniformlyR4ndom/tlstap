import { h } from 'preact'
import { useRef } from 'preact/hooks'
import htm from 'htm'

const html = htm.bind(h)

// A thin draggable divider. `orientation` is 'v' (drag left/right) or 'h' (drag up/down).
// Calls onResize(deltaPx) for each pointer move while dragging; the caller decides sign/clamping.
export default function ResizeHandle({ orientation, onResize }) {
    const draggingRef = useRef(false)

    function onMouseDown(e) {
        if (e.button !== 0) return
        e.preventDefault()
        draggingRef.current = true

        function onMove(ev) {
            if (!draggingRef.current) return
            onResize(orientation === 'v' ? ev.movementX : ev.movementY)
        }
        function onUp() {
            draggingRef.current = false
            document.removeEventListener('mousemove', onMove)
            document.removeEventListener('mouseup', onUp)
        }
        document.addEventListener('mousemove', onMove)
        document.addEventListener('mouseup', onUp)
    }

    return html`<div class=${'resize-handle resize-handle-' + orientation} onMouseDown=${onMouseDown} />`
}
