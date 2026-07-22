import { useState } from 'preact/hooks'
import { loadLayout, saveLayoutValue, clamp } from './layout.js'

// Backs every resizable-panel dimension: reads/clamps/persists via layout.js. `max` may be a
// thunk (`() => number`) for window-relative bounds, evaluated fresh on each resize.
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
