import { useEffect } from 'preact/hooks'

// Closes on outside click (mousedown not inside `ref`) or Escape, while `active` is true.
export function useDismissOnOutsideClick(ref, onClose, active = true) {
    useEffect(() => {
        if (!active) return
        const close = e => { if (!ref.current || !ref.current.contains(e.target)) onClose() }
        const onKey = e => { if (e.key === 'Escape') onClose() }
        document.addEventListener('mousedown', close)
        document.addEventListener('keydown', onKey)
        return () => {
            document.removeEventListener('mousedown', close)
            document.removeEventListener('keydown', onKey)
        }
    }, [active])
}
