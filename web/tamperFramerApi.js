// REST CRUD for tamper's framer-script store — a separate scriptstore instance/namespace
// from the interception-script CRUD in tamperApi.js, same shape (raw-body content, no
// JSON/base64 wrapping). See doc/design/tamper-framer.md and intercept/tamper/CLAUDE.md's
// "Script storage" section.

const BASE = '/api/i/tamper/framer'

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
