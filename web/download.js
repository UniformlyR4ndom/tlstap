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
// is still active; caller must gate on `window.showSaveFilePicker` itself. Resolves to null
// on user-cancel (AbortError); rethrows any other error.
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
