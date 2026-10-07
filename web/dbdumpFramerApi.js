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

// ── Frame index REST API ────────────────────────────────────────────────────────────
// Timeline key: { session, stream, script, scriptVersion } — scriptVersion is a sha256
// hex digest of the script's content, computed by the caller. Every function here except
// listFrames uses this shape: combined mode's frame_progress has no per-direction row to
// begin with (see doc/design/framer-cross-direction-correlation.md), so only listFrames
// (still a per-direction read of the frames table itself) needs a direction to key on.

// listFrames' key adds direction to the timeline shape above.
function keyBody(key) {
    return {
        session: key.session, stream: key.stream, direction: key.direction,
        script: key.script, script_version: key.scriptVersion,
    }
}

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

// Exported for direct round-trip testing (dbdumpFramerApi.test.js) — pure, BASE-
// independent, unlike everything else in this file.
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

// length is a permanent, always-well-defined field (sum(ranges[].length)), not a shim —
// unlike an offset, a total length needs no arbitrary "pick one range" convention to stay
// meaningful regardless of range count, so frameSegmentsCore.js's budget/sizing math
// (selectByBudget) reads it directly rather than recomputing it from ranges itself.
// virtualOffset (frames.virtual_offset) is likewise a genuine, permanent field, passed
// through as-is. Exported for direct testing (dbdumpFramerApi.test.js), same convention
// as encodeMeta/decodeMeta/encodeState/decodeState above.
export function decodeFrame(f) {
    const length = f.ranges.reduce((sum, r) => sum + r.length, 0)
    return { id: f.id, ranges: f.ranges, length, virtualOffset: f.virtual_offset, meta: decodeMeta(f.meta), direction: f.direction, stid: f.stid, time: f.time, seq: f.seq }
}

// createDbDumpFramerApi(dbdumpBasePath) binds the wire calls below to one dbdump
// interceptor instance's own base path — framer routes are nested under it (RegisterRoutes
// always registers at <basePath>/scripts, {basePath}/frames*, ...), so no separate
// discovery is needed for this feature; see api.js's createDbDumpApi for the sibling
// factory covering the rest of dbdump's own REST API.
export function createDbDumpFramerApi(basePath) {
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
        return fetch(basePath + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        }).then(checkOk).then(r => r.json())
    }

    return {
        // ── Script storage REST API ────────────────────────────────────────────────────
        // Content is a raw body (always UTF-8 JS text), not JSON/base64-wrapped.

        async listFramerScripts() {
            const res = await checkOk(await fetch(`${basePath}/scripts`))
            return res.json()
        },

        async getFramerScript(name) {
            const res = await checkOk(await fetch(`${basePath}/scripts/${encodeURIComponent(name)}`))
            return res.text()
        },

        async putFramerScript(name, content) {
            await checkOk(await fetch(`${basePath}/scripts/${encodeURIComponent(name)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/javascript' },
                body: content,
            }))
        },

        async deleteFramerScript(name) {
            await checkOk(await fetch(`${basePath}/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' }))
        },

        // Returns { processedOffset: {c2s, s2c}, state, closed: {c2s, s2c} }: how far a
        // combined-mode framer run has gotten for key (both directions' offset/closed live
        // on one shared row — see doc/design/framer-cross-direction-correlation.md), and the
        // framer's own persisted state for resuming. A key with no rows yet is not an error —
        // { processedOffset: {c2s:0, s2c:0}, state: null, closed: {c2s:false, s2c:false} }
        // just means framing hasn't started for it.
        async getFrameProgress(key) {
            const res = await post('/frame-progress', timelineKeyBody(key))
            return {
                processedOffset: { c2s: res.processed_offset_c2s, s2c: res.processed_offset_s2c },
                state: decodeState(res.state),
                closed: { c2s: res.closed_c2s, s2c: res.closed_s2c },
            }
        },

        // Returns frames for key with id >= start, ordered by id. n <= 0 means unlimited.
        async listFrames(key, start, n) {
            const res = await post('/frames', { ...keyBody(key), start, n })
            return res.map(decodeFrame)
        },

        // Returns frames for key across both directions, ordered by (stid, id) — id is the
        // tie-break for multiple frames completing on the same underlying chunk, which is
        // routine, not an edge case. n <= 0 means unlimited; for n > 0 the server guarantees
        // the returned page never splits a tied-stid group, so `start = last returned frame's
        // stid + 1` is always a safe cursor for the next page.
        async listFramesTimeline(key, start, n) {
            const res = await post('/frames/timeline', { ...timelineKeyBody(key), start, n })
            return res.map(decodeFrame)
        },

        // Backward counterpart: frames with stid < beforeStid (exclusive), still returned in
        // ascending (stid, id) order — same group-boundary-safety guarantee as the forward
        // version, mirrored for the reverse walk. See doc/design/hexview-segment-buffer.md.
        async listFramesTimelineBackward(key, beforeStid, n) {
            const res = await post('/frames/timeline', { ...timelineKeyBody(key), beforeStid, n })
            return res.map(decodeFrame)
        },

        // listFramesTimeline's seq-ordered sibling: frames for key across both directions,
        // ordered by seq (n <= 0 means unlimited) — the server-assigned emission order a
        // combined-mode script actually returned each frame in, which can differ from stid
        // order (e.g. a script holding a request frame until its response is also ready to
        // emit — see doc/design/framer-cross-direction-correlation.md). seq is unique per
        // key by construction, so unlike listFramesTimeline there's no tied-group pagination
        // concern here. Not yet wired into any UI.
        async listFramesBySeq(key, start, n) {
            const res = await post('/frames/by-seq', { ...timelineKeyBody(key), start, n })
            return res.map(decodeFrame)
        },

        // Backward counterpart: frames with seq < beforeSeq (exclusive), still ascending.
        async listFramesBySeqBackward(key, beforeSeq, n) {
            const res = await post('/frames/by-seq', { ...timelineKeyBody(key), beforeSeq, n })
            return res.map(decodeFrame)
        },

        // Extends key's persisted frame index by one computed batch: expectedProcessedOffset
        // ({c2s, s2c}) must match what's currently stored (both 0 if framing hasn't started
        // yet) or the call throws — the caller is expected to be the only writer for key.
        // Each entry of frames carries its own numeric direction, since one combined-mode
        // batch can mix frames from either direction. newProcessedOffset is {c2s, s2c};
        // closed (default {c2s: false, s2c: false}) marks each direction's connection-close
        // signal as delivered — see catchUpFramer in framerRun.js, the only caller that ever
        // sets either true, and always as its own dedicated trailing call (empty frames,
        // offsets unchanged) rather than mixed into an ordinary batch.
        //
        // Doesn't use the shared post() helper: a successful append is 204 No Content, and
        // post() always calls r.json(), which throws on an empty body.
        async appendFrames(key, expectedProcessedOffset, frames, newProcessedOffset, newState, closed = { c2s: false, s2c: false }) {
            await checkOk(await fetch(`${basePath}/frames/append`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...timelineKeyBody(key),
                    expected_processed_offset_c2s: expectedProcessedOffset.c2s,
                    expected_processed_offset_s2c: expectedProcessedOffset.s2c,
                    new_frames: frames.map(f => ({ direction: f.direction, ranges: f.ranges, meta: encodeMeta(f.meta), stid: f.stid, time: f.time })),
                    new_processed_offset_c2s: newProcessedOffset.c2s,
                    new_processed_offset_s2c: newProcessedOffset.s2c,
                    new_state: encodeState(newState),
                    closed_c2s: closed.c2s,
                    closed_s2c: closed.s2c,
                }),
            }))
        },

        // Enforces "at most one framing view per stream": deletes every OTHER (script,
        // script_version)'s persisted frame/progress data for key's (session, stream),
        // across both directions — a rerun of the same (script, script_version) already
        // active for this stream is a no-op server-side (its frame_progress survives, so
        // catchUpFramer resumes rather than reprocessing). key is timeline-shaped (no
        // direction), matching how a "view" is scoped to a whole stream, not one direction.
        async clearStreamFrames(key) {
            await checkOk(await fetch(`${basePath}/frames/clear`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(timelineKeyBody(key)),
            }))
        },
    }
}
