const STORAGE_KEY = 'tlstap-markers'

export function loadMarkers() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY)
        if (!raw) return []
        const parsed = JSON.parse(raw)
        return Array.isArray(parsed?.markers) ? parsed.markers : []
    } catch {
        return []
    }
}

export function saveMarkers(markers) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ version: 1, markers }))
}

export function makeMarkerId() {
    return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
}
