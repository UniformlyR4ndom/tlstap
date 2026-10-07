// REST wrappers for dbdump's dissector-script CRUD — same shape as dbdumpFramerApi.js's
// own script functions (list()->[{name,size}], get(name)->text, put(name,content)->void,
// del(name)->void, the exact shape ScriptsCrudPanel.js expects), just pointed at the
// separate "/dissect/scripts" namespace (its own dissect-scripts-dir store server-side —
// see intercept/dbdump/CLAUDE.md's "Dissector scripts" section). No frame-index-style
// read/extend API here: dissection output is never persisted, so there's nothing beyond
// script storage to wrap.

// createDbDumpDissectApi(dbdumpBasePath) binds these to one dbdump interceptor instance's
// own base path, under its "/dissect" segment — see api.js's createDbDumpApi for the
// sibling factory covering the rest of that instance's REST API.
export function createDbDumpDissectApi(dbdumpBasePath) {
    const basePath = `${dbdumpBasePath}/dissect`

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

    return {
        async listDissectScripts() {
            const res = await checkOk(await fetch(`${basePath}/scripts`))
            return res.json()
        },

        async getDissectScript(name) {
            const res = await checkOk(await fetch(`${basePath}/scripts/${encodeURIComponent(name)}`))
            return res.text()
        },

        async putDissectScript(name, content) {
            await checkOk(await fetch(`${basePath}/scripts/${encodeURIComponent(name)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/javascript' },
                body: content,
            }))
        },

        async deleteDissectScript(name) {
            await checkOk(await fetch(`${basePath}/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' }))
        },
    }
}
