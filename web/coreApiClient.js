// Direct-fetch REST clients for core.fs/core.kv (see core/CLAUDE.md), dynamically
// imported inside a Worker — framer's and dissector's own, or tamper's for kv only
// (tamper's fs still goes through scriptRuntime.js's RPC bridge; see its own comment for
// why). baseUrl must be an absolute URL computed on the main thread before the Worker was
// built, same constraint frameRuntime.js's TRANSFORMS_URL et al. already work around: a
// Blob-URL worker's own relative-URL resolution isn't reliable.

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

function encodeSegments(path) {
    return path.split('/').filter(s => s !== '').map(encodeURIComponent).join('/')
}

// { listFiles(path), readFile(path), writeFile(path, bytes), appendFile(path, bytes) } —
// same shape/semantics as coreFsApi.js's own wrappers, just reachable directly from a
// Worker instead of routed through a main-thread RPC bridge.
export function createFsApi(baseUrl) {
    return {
        async listFiles(path = '') {
            const enc = encodeSegments(path)
            const res = await checkOk(await fetch(`${baseUrl}/list${enc ? '/' + enc : ''}`))
            return res.json()
        },
        async readFile(path) {
            const res = await checkOk(await fetch(`${baseUrl}/file/${encodeSegments(path)}`))
            return new Uint8Array(await res.arrayBuffer())
        },
        async writeFile(path, bytes) {
            await checkOk(await fetch(`${baseUrl}/file/${encodeSegments(path)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: bytes,
            }))
        },
        // POST, not PUT: appending isn't idempotent, unlike writeFile above.
        async appendFile(path, bytes) {
            await checkOk(await fetch(`${baseUrl}/file/${encodeSegments(path)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/octet-stream' },
                body: bytes,
            }))
        },
    }
}

// { read(key), write(key, value), readBytes(key), writeBytes(key, bytes), list(prefix?),
// delete(key) } over /api/core/kv (doc/design/core-kv-store.md). read/write JSON-encode
// the value; readBytes/writeBytes pass raw bytes through untouched. Every raw endpoint
// takes key/prefix as a query param, not a JSON body.
export function createKvApi(baseUrl) {
    async function readBytes(key) {
        const res = await checkOk(await fetch(`${baseUrl}/read?key=${encodeURIComponent(key)}`, { method: 'POST' }))
        return new Uint8Array(await res.arrayBuffer())
    }
    async function writeBytes(key, bytes) {
        await checkOk(await fetch(`${baseUrl}/write?key=${encodeURIComponent(key)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/octet-stream' },
            body: bytes,
        }))
    }
    return {
        readBytes,
        writeBytes,
        async read(key) {
            return JSON.parse(new TextDecoder().decode(await readBytes(key)))
        },
        async write(key, value) {
            await writeBytes(key, new TextEncoder().encode(JSON.stringify(value)))
        },
        async list(prefix = '') {
            const res = await checkOk(await fetch(`${baseUrl}/list?prefix=${encodeURIComponent(prefix)}`, { method: 'POST' }))
            return (await res.json()).keys
        },
        async delete(key) {
            await checkOk(await fetch(`${baseUrl}/delete?key=${encodeURIComponent(key)}`, { method: 'POST' }))
        },
    }
}
