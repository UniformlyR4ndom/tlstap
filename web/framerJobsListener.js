import { useEffect, useState } from 'preact/hooks'
import { createFramerRun, streamTlsInfo } from './framerRun.js'

// useFramerJobsListener(enabled, dbdumpApi, framerApi) — the browser-tab side of the
// framer-jobs relay (intercept/dbdump/CLAUDE.md's "dbdump Interceptor" section): lets
// tapctl's `dbdump run-framer` command execute a real framer script through this tab's
// own already-loaded frameRuntime.js/framerRun.js, rather than tapctl needing (or this
// codebase needing to build) any separate script-execution environment.
//
// Deliberately opt-in — only mounted/enabled while the user has explicitly turned on
// App.js's "Remote framer runs" toggle, so a tab never becomes remotely triggerable
// just by being open. Returns a connection-status string ('disconnected' | 'connecting'
// | 'connected') for that toggle's own UI to show.
//
// Runs the exact same catchUpFramer(...) a manual Run click does — no separate
// execution path to keep in sync with the real one. A resolved stream/script pair that
// no longer exists, or a catchUpFramer failure, is reported back over the socket as a
// normal job failure, not a crash here.
export function useFramerJobsListener(enabled, dbdumpApi, framerApi) {
    const [status, setStatus] = useState('disconnected')

    useEffect(() => {
        if (!enabled || !dbdumpApi || !framerApi) {
            setStatus('disconnected')
            return
        }
        setStatus('connecting')
        const { catchUpFramer } = createFramerRun(dbdumpApi, framerApi)

        const conn = dbdumpApi.openFramerJobs({
            onOpen: () => setStatus('connected'),
            onClose: () => setStatus('disconnected'),
            onError: () => {},
            async onJob(job) {
                try {
                    const [streams, content] = await Promise.all([
                        dbdumpApi.getStreams(job.session),
                        framerApi.getFramerScript(job.script),
                    ])
                    const stream = streams.find(s => s.id === job.stream)
                    if (!stream) throw new Error(`stream ${job.stream} not found in session ${job.session}`)
                    await catchUpFramer(job.session, job.stream, job.script, content, stream.end, streamTlsInfo(stream))
                    conn.respond(job.job_id, true)
                } catch (err) {
                    conn.respond(job.job_id, false, err?.message || String(err))
                }
            },
        })
        return () => conn.close()
    }, [enabled, dbdumpApi, framerApi])

    return status
}
