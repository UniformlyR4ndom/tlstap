// REST wrappers for dbdump's dissector-script CRUD — same shape as dbdumpFramerApi.js's
// own script functions (list()->[{name,size}], get(name)->text, put(name,content)->void,
// del(name)->void, the exact shape ScriptsCrudPanel.js expects), just pointed at the
// separate "/dissect/scripts" namespace (its own dissect-scripts-dir store server-side —
// see intercept/dbdump/CLAUDE.md's "Dissector scripts" section). No frame-index-style
// read/extend API here: dissection output is never persisted, so there's nothing beyond
// script storage to wrap.
const BASE = '/api/i/dbdump/dissect'

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

export async function listDissectScripts() {
    const res = await checkOk(await fetch(`${BASE}/scripts`))
    return res.json()
}

export async function getDissectScript(name) {
    const res = await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`))
    return res.text()
}

export async function putDissectScript(name, content) {
    await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/javascript' },
        body: content,
    }))
}

export async function deleteDissectScript(name) {
    await checkOk(await fetch(`${BASE}/scripts/${encodeURIComponent(name)}`, { method: 'DELETE' }))
}
