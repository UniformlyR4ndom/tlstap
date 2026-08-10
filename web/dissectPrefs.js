// localStorage helpers for dissector-script selection — same shape as framerPrefs.js's
// (a global default seeding a stream's first-ever choice, plus a per-stream override that
// then becomes independent of the default), for the same reason: it should survive a page
// reload the way "remember stream position" (App.js, in-memory only) deliberately doesn't.
const KEY = 'tlstap-dissect-prefs'

function load() {
    try {
        const parsed = JSON.parse(localStorage.getItem(KEY))
        return {
            defaultScript: typeof parsed?.defaultScript === 'string' ? parsed.defaultScript : null,
            perStream: parsed?.perStream && typeof parsed.perStream === 'object' ? parsed.perStream : {},
        }
    } catch {
        return { defaultScript: null, perStream: {} }
    }
}

function save(prefs) {
    localStorage.setItem(KEY, JSON.stringify(prefs))
}

function streamKey(session, streamId) {
    return `${session}:${streamId}`
}

export function loadDefaultDissectScript() {
    return load().defaultScript
}

export function saveDefaultDissectScript(name) {
    const prefs = load()
    prefs.defaultScript = name || null
    save(prefs)
}

// Falls back to the default when this stream has no override of its own yet.
export function loadStreamDissectScript(session, streamId) {
    const prefs = load()
    return prefs.perStream[streamKey(session, streamId)] ?? prefs.defaultScript
}

export function saveStreamDissectScript(session, streamId, name) {
    const prefs = load()
    if (name) prefs.perStream[streamKey(session, streamId)] = name
    else delete prefs.perStream[streamKey(session, streamId)]
    save(prefs)
}
