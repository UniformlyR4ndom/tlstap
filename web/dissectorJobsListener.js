import { useEffect, useState } from 'preact/hooks'
import { runDissector } from './dissectRuntime.js'
import { mergeUint8Arrays } from './format.js'

// useDissectorJobsListener(enabled, dbdumpApi, framerApi, dissectApi) — the browser-tab
// side of the dissector-jobs relay (intercept/dbdump/CLAUDE.md's "Framer jobs" section
// covers the shared mechanics; dissectorjobs.go is the dissector-script sibling): lets
// tapctl's `dbdump run-dissector` command run a real dissector script through this tab's
// own already-loaded dissectRuntime.js, the same code path DissectPanel.js's per-frame
// click uses — no separate execution path to keep in sync with the real one.
//
// Deliberately opt-in, independent of useFramerJobsListener's own toggle (framerJobsListener.js)
// — only mounted/enabled while the user has explicitly turned on App.js's own "Remote
// dissector runs" toggle, matching this codebase's convention of keeping the framer and
// dissector systems separate throughout (own stores, own panels, own default-script
// prefs). Returns a connection-status string ('disconnected' | 'connecting' |
// 'connected') for that toggle's own UI to show.
//
// Unlike a framer job, dissection output is never persisted anywhere server-side — there
// is nothing to go inspect afterward the way frames-timeline works for framer jobs — so
// a successful job's result carries the dissector's own FieldNode[] tree directly.
export function useDissectorJobsListener(enabled, dbdumpApi, framerApi, dissectApi) {
    const [status, setStatus] = useState('disconnected')

    useEffect(() => {
        if (!enabled || !dbdumpApi || !framerApi || !dissectApi) {
            setStatus('disconnected')
            return
        }
        setStatus('connecting')

        const conn = dbdumpApi.openDissectorJobs({
            onOpen: () => setStatus('connected'),
            onClose: () => setStatus('disconnected'),
            onError: () => {},
            async onJob(job) {
                try {
                    const [frames, dissectSource] = await Promise.all([
                        framerApi.listFrames({
                            session: job.session, stream: job.stream, direction: job.direction,
                            script: job.framer_script, scriptVersion: job.framer_script_version,
                        }, job.frame_id, 1),
                        dissectApi.getDissectScript(job.dissect_script),
                    ])
                    const frame = frames.find(f => f.id === job.frame_id)
                    if (!frame) {
                        throw new Error(`frame ${job.frame_id} not found for ${job.framer_script} on stream ${job.stream}`)
                    }
                    // A frame is fetched here exactly as frameSegments.js does for the UI's
                    // own frame view — its own ranges, one /byte-ranges call, merged in
                    // range order into one virtual (always 0-based) byte buffer.
                    const ranges = frame.ranges.map(r => ({ offset: r.offset, direction: job.direction, length: r.length }))
                    const parts = await dbdumpApi.fetchByteRanges(job.session, job.stream, ranges)
                    const bytes = parts.length === 1 ? parts[0] : mergeUint8Arrays(parts)
                    // Mirrors TrafficView.js's handleFrameHeaderClick — offset is always 0
                    // for a whole frame (its own virtual concatenation starts at 0; see
                    // frameSegmentsCore.js's module comment).
                    const frameArg = { offset: 0, length: frame.length, direction: job.direction, kind: frame.meta?.kind, meta: frame.meta }
                    const nodes = await runDissector(job.dissect_script, dissectSource, bytes, frameArg)
                    conn.respond(job.job_id, true, { nodes })
                } catch (err) {
                    conn.respond(job.job_id, false, { error: err?.message || String(err) })
                }
            },
        })
        return () => conn.close()
    }, [enabled, dbdumpApi, framerApi, dissectApi])

    return status
}
