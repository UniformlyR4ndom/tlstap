// localStorage helpers for framer-script selection: a global default (seeds a stream's
// choice the first time it's viewed) and a per-stream override, both surviving a page
// reload — unlike "remember stream position" (App.js), which is deliberately in-memory
// only. Once a stream has its own entry, it's independent of the default from then on.
const KEY = 'tlstap-framer-prefs'

function load() {
    try {
        const parsed = JSON.parse(localStorage.getItem(KEY))
        return {
            defaultScript: typeof parsed?.defaultScript === 'string' ? parsed.defaultScript : null,
            perStream: parsed?.perStream && typeof parsed.perStream === 'object' ? parsed.perStream : {},
            resumeScript: parsed?.resumeScript && typeof parsed.resumeScript === 'object' ? parsed.resumeScript : {},
        }
    } catch {
        return { defaultScript: null, perStream: {}, resumeScript: {} }
    }
}

function save(prefs) {
    localStorage.setItem(KEY, JSON.stringify(prefs))
}

function streamKey(session, streamId) {
    return `${session}:${streamId}`
}

export function loadDefaultFramerScript() {
    return load().defaultScript
}

export function saveDefaultFramerScript(name) {
    const prefs = load()
    prefs.defaultScript = name || null
    save(prefs)
}

// Falls back to the default when this stream has no override of its own yet.
export function loadStreamFramerScript(session, streamId) {
    const prefs = load()
    return prefs.perStream[streamKey(session, streamId)] ?? prefs.defaultScript
}

export function saveStreamFramerScript(session, streamId, name) {
    const prefs = load()
    if (name) prefs.perStream[streamKey(session, streamId)] = name
    else delete prefs.perStream[streamKey(session, streamId)]
    save(prefs)
}

// Separate from perStream above: perStream is "what's selected in the dropdown",
// resumeScript is "what this stream was last successfully framed with" — the two only
// coincide once a Run has actually succeeded. TrafficView.js's stream-reselection effect
// auto-resumes framed view iff loadResumeScript(...) still equals the current
// loadStreamFramerScript(...) for that stream; changing the dropdown selection without
// re-running, or an explicit "Show raw chunks" (which clears this via name=null), makes
// them diverge and falls back to plain raw view — a script is never auto-run against a
// stream it hasn't already been run against at least once.
export function loadResumeScript(session, streamId) {
    return load().resumeScript[streamKey(session, streamId)] ?? null
}

export function saveResumeScript(session, streamId, name) {
    const prefs = load()
    if (name) prefs.resumeScript[streamKey(session, streamId)] = name
    else delete prefs.resumeScript[streamKey(session, streamId)]
    save(prefs)
}
