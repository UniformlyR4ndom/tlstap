import { useEffect, useRef } from 'preact/hooks'

// Runs `tick()` every `intervalMs` while `active`; skips starting a new tick if the
// previous one hasn't resolved yet. Cleared when `active` goes false or on unmount.
// `tick` is read fresh from a ref on every fire, so its identity doesn't need to be
// stable across renders (same convention as ResizeHandle.js's onResize).
export function usePoll(active, intervalMs, tick) {
    const tickRef    = useRef(tick)
    const runningRef = useRef(false)
    tickRef.current = tick

    useEffect(() => {
        if (!active) return
        const id = setInterval(async () => {
            if (runningRef.current) return
            runningRef.current = true
            try {
                await tickRef.current()
            } finally {
                runningRef.current = false
            }
        }, intervalMs)
        return () => clearInterval(id)
    }, [active, intervalMs])
}
