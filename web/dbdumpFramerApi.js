// REST wrappers for dbdump's framer-script feature: script CRUD plus reading/extending
// the persisted frame index a script produces.
//
// Wire encoding: state/meta are opaque BLOB/TEXT columns server-side, but every caller
// here works with plain JS values for both, which may freely include raw Uint8Arrays
// anywhere in the tree — this module translates to/from the wire shapes those columns
// need (state -> JSON -> UTF-8 bytes -> base64, since the column is a BLOB; meta -> JSON
// text directly, since the column is already TEXT; a nested Uint8Array in either is
// tagged/base64'd only at this boundary — see jsonBytesReplacer/Reviver below). Callers
// never have to encode/decode bytes themselves for either field.
import { fmtAsBase64, parseBase64 } from './format.js'

const BASE = '/api/i/dbdump'

async function checkOk(res) {
    if (!res.ok) {
        let message = res.statusText
        try {
            const body = await res.json()
            if (body.error) message = body.error
        } catch {}
        throw new Error(message)
    }
    return res
}

function post(path, body) {
    return fetch(BASE + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    }).then(checkOk).then(r => r.json())
}

// ── Script storage REST API ────────────────────────────────────────────────────────
// Content is a raw body (always UTF-8 JS text), not JSON/base64-wrapped.

export async function listFramerScripts() {
    const res = await checkOk(await fetch(`${BASE}/scripts`))
    return res.json()
}

export async function getFramerScript(name) {
    const res = await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`))
    return res.text()
}

export async function putFramerScript(name, content) {
    await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/javascript' },
        body: content,
    }))
}

export async function deleteFramerScript(name) {
    await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' }))
}

// ── Frame index REST API ────────────────────────────────────────────────────────────
// key: { session, stream, direction, script, scriptVersion } — scriptVersion is a
// sha256 hex digest of the script's content, computed by the caller.
// listFramesTimeline's key omits direction (it spans both).

function keyBody(key) {
    return {
        session: key.session, stream: key.stream, direction: key.direction,
        script: key.script, script_version: key.scriptVersion,
    }
}

// Like keyBody, but without direction — listFramesTimeline's key spans both.
function timelineKeyBody(key) {
    return { session: key.session, stream: key.stream, script: key.script, script_version: key.scriptVersion }
}

// A script's state/meta may hold a raw Uint8Array anywhere in the tree (e.g. a framer's
// buffered carry bytes) — JSON has no binary type, so the replacer/reviver pair below
// swaps one for a tagged base64 wrapper only at this actual serialization boundary,
// letting script code pass plain Uint8Arrays between calls the rest of the time (no
// per-call encode/decode of its own). BYTES_TAG is chosen unlikely to collide with a
// script's own field names; a state/meta value that happens to be shaped exactly like
// the wrapper would false-positive into bytes on decode — accepted as an edge case.
const BYTES_TAG = '__bytes_base64__'

function jsonBytesReplacer(_key, value) {
    return value instanceof Uint8Array ? { [BYTES_TAG]: fmtAsBase64(value) } : value
}

function jsonBytesReviver(_key, value) {
    return (value && typeof value === 'object' && typeof value[BYTES_TAG] === 'string') ? parseBase64(value[BYTES_TAG]) : value
}

// Exported for direct round-trip testing (dbdumpFramerApi.test.js) — every other export
// here needs a real fetch(), these four are the pure part.
export function encodeMeta(value) {
    return value === undefined || value === null ? null : JSON.stringify(value, jsonBytesReplacer)
}

export function decodeMeta(text) {
    return text == null ? null : JSON.parse(text, jsonBytesReviver)
}

export function encodeState(value) {
    if (value === undefined || value === null) return null
    return fmtAsBase64(new TextEncoder().encode(JSON.stringify(value, jsonBytesReplacer)))
}

export function decodeState(b64) {
    if (b64 == null) return null
    return JSON.parse(new TextDecoder().decode(parseBase64(b64)), jsonBytesReviver)
}

// Returns { processedOffset, state }: how far framing has gotten for key, and the
// framer's own persisted state for resuming. A key with no rows yet is not an error —
// { processedOffset: 0, state: null } just means framing hasn't started for it.
export async function getFrameProgress(key) {
    const res = await post('/frame-progress', keyBody(key))
    return { processedOffset: res.processed_offset, state: decodeState(res.state) }
}

function decodeFrame(f) {
    return { id: f.id, offset: f.offset, length: f.length, meta: decodeMeta(f.meta), direction: f.direction, stid: f.stid, time: f.time }
}

// Returns frames for key with id >= start, ordered by id. n <= 0 means unlimited.
export async function listFrames(key, start, n) {
    const res = await post('/frames', { ...keyBody(key), start, n })
    return res.map(decodeFrame)
}

// Returns frames for key across both directions, ordered by (stid, id) — id is the
// tie-break for multiple frames completing on the same underlying chunk, which is
// routine, not an edge case. n <= 0 means unlimited; for n > 0 the server guarantees the
// returned page never splits a tied-stid group, so `start = last returned frame's stid
// + 1` is always a safe cursor for the next page.
export async function listFramesTimeline(key, start, n) {
    const res = await post('/frames/timeline', { ...timelineKeyBody(key), start, n })
    return res.map(decodeFrame)
}

// Backward counterpart: frames with stid < beforeStid (exclusive), still returned in
// ascending (stid, id) order — same group-boundary-safety guarantee as the forward
// version, mirrored for the reverse walk. See doc/design/hexview-segment-buffer.md.
export async function listFramesTimelineBackward(key, beforeStid, n) {
    const res = await post('/frames/timeline', { ...timelineKeyBody(key), beforeStid, n })
    return res.map(decodeFrame)
}

// Extends key's persisted frame index by one computed batch: expectedProcessedOffset
// must match what's currently stored (0 if framing hasn't started yet) or the call
// throws — the caller is expected to be the only writer for key.
//
// Doesn't use the shared post() helper: a successful append is 204 No Content, and
// post() always calls r.json(), which throws on an empty body.
export async function appendFrames(key, expectedProcessedOffset, frames, newProcessedOffset, newState) {
    await checkOk(await fetch(`${BASE}/frames/append`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            ...keyBody(key),
            expected_processed_offset: expectedProcessedOffset,
            new_frames: frames.map(f => ({ offset: f.offset, length: f.length, meta: encodeMeta(f.meta), stid: f.stid, time: f.time })),
            new_processed_offset: newProcessedOffset,
            new_state: encodeState(newState),
        }),
    }))
}

// Enforces "at most one framing view per stream": deletes every OTHER (script,
// script_version)'s persisted frame/progress data for key's (session, stream), across
// both directions — a rerun of the same (script, script_version) already active for
// this stream is a no-op server-side (its frame_progress survives, so catchUpFramer
// resumes rather than reprocessing). key is timeline-shaped (no direction), matching how
// a "view" is scoped to a whole stream, not one direction.
export async function clearStreamFrames(key) {
    await checkOk(await fetch(`${BASE}/frames/clear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(timelineKeyBody(key)),
    }))
}
