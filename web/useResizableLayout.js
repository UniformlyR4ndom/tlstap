import { useState } from 'preact/hooks'
import { loadLayout, saveLayoutValue, clamp } from './layout.js'

// Backs every resizable-panel dimension: initializes from the persisted `layout.js` value,
// clamps a ResizeHandle's delta into range, and persists the result. `max` may be a plain
// number or a thunk (`() => number`) re-evaluated on every resize event — needed for the
// panels whose bound is window-relative (e.g. `Math.floor(window.innerHeight * 0.7)`), so a
// browser resize is always picked up at drag-time rather than baked in at whatever render
// happened to create this hook's return value.
export function useResizableLayout(key, { sign = 1, min, max }) {
    const [value, setValue] = useState(() => loadLayout()[key])

    function onResize(delta) {
        setValue(v => {
            const hi = typeof max === 'function' ? max() : max
            const next = clamp(v + sign * delta, min, hi)
            saveLayoutValue(key, next)
            return next
        })
    }

    return [value, onResize]
}
