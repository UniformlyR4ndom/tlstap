// REST CRUD for tamper's framer-script store — a separate scriptstore instance/namespace
// from the interception-script CRUD in tamperApi.js, same shape (raw-body content, no
// JSON/base64 wrapping). See doc/design/tamper-framer.md and intercept/tamper/CLAUDE.md's
// "Script storage" section.

// createTamperFramerApi(tamperBasePath) binds these to one tamper interceptor instance's
// own base path, under its "/framer" segment — see tamperApi.js's createTamperApi for the
// sibling factory covering the rest of that instance's REST/WebSocket API.
export function createTamperFramerApi(tamperBasePath) {
    const basePath = `${tamperBasePath}/framer`

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
    }
}
