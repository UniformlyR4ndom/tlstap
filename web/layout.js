const STORAGE_KEY = 'tlstap-layout'
const DEFAULTS = { sidebarWidth: 280, bottomHeight: 160, encdecOptionsWidth: 160, encdecInputHeight: 120, tamperDetailHeight: 300, scriptsListWidth: 220, scriptsLogHeight: 160, framerScriptsListWidth: 220 }

export function loadLayout() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY)
        if (!raw) return { ...DEFAULTS }
        return { ...DEFAULTS, ...JSON.parse(raw) }
    } catch {
        return { ...DEFAULTS }
    }
}

export function saveLayoutValue(key, value) {
    const current = loadLayout()
    current[key] = value
    localStorage.setItem(STORAGE_KEY, JSON.stringify(current))
}

export function clamp(v, lo, hi) {
    return Math.min(Math.max(v, lo), hi)
}
