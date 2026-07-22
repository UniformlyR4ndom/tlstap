// Triggers a browser download of in-memory content via a throwaway object URL and anchor
// click — the fallback path wherever showSaveFilePicker isn't used/available.
export function downloadBlob(content, filename, mime) {
    const url = URL.createObjectURL(new Blob([content], { type: mime }))
    const a = document.createElement('a')
    a.href = url; a.download = filename
    document.body.appendChild(a); a.click()
    document.body.removeChild(a); URL.revokeObjectURL(url)
}

// Opens the File System Access API's save-file picker. Must be called while a user gesture
// is still active (before any other await) — callers should still gate this on
// `window.showSaveFilePicker` being truthy themselves rather than relying on this rejecting,
// since that same feature check is also what decides whether to fall back to downloadBlob at
// all. Resolves to null if the user dismisses the picker (AbortError) — a silent "nothing to
// do", distinct from any other error, which rethrows so the caller can surface it.
export async function acquireSaveHandle(suggestedName, mime, ext, description) {
    try {
        return await window.showSaveFilePicker({
            suggestedName,
            types: [{ description, accept: { [mime]: [ext] } }],
        })
    } catch (e) {
        if (e.name === 'AbortError') return null
        throw e
    }
}

// Writes content to a handle acquired from acquireSaveHandle.
export async function writeToFileHandle(handle, content, mime) {
    const writable = await handle.createWritable()
    await writable.write(new Blob([content], { type: mime }))
    await writable.close()
}
