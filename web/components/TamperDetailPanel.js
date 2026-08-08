import { h } from 'preact'
import { useState, useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import HexEditor from './HexEditor.js'
import { peekBuffer } from '../tamperApi.js'
import { mergeUint8Arrays, parseHexdump, parseRaw } from '../format.js'
import { OPERATIONS } from '../transforms.js'
import { dirClass, dirLabel } from '../direction.js'
import { useDismissOnOutsideClick } from '../useDismissOnOutsideClick.js'

const html = htm.bind(h)

// Decodes popover input text per the chosen format. 'hex'/'base64' reuse the Transform
// panel's decode ops (fixed space separator for hex); 'hexdump' has no Transform-panel
// equivalent, so it goes through parseHexdump directly.
function decodeChunkText(text, format) {
    if (format === 'plain') return parseRaw(text)
    const bytes = parseRaw(text)
    if (format === 'hex') return OPERATIONS['hex-decode'].run(bytes, { prefix: '', separator: ' ' })
    if (format === 'base64') return OPERATIONS['base64-decode'].run(bytes, { urlSafe: false })
    if (format === 'hexdump') return parseHexdump(text)
    throw new Error(`unknown format "${format}"`)
}

// Popover for inserting a new chunk at insertAt, either empty or decoded from a
// file/clipboard. Kept separate from ctxMenu (own outside-click/Escape dismissal) since it
// stays open across an async file/clipboard read, unlike ctxMenu's one-shot actions.
function InsertChunkPopover({ x, y, onInsert, onCancel }) {
    const [format, setFormat] = useState('empty') // empty | plain | hex | base64 | hexdump
    const [source, setSource] = useState('clipboard') // clipboard | file
    const [busy,   setBusy]   = useState(false)
    const [error,  setError]  = useState(null)
    const popRef = useRef(null)
    const fileInputRef = useRef(null)

    useDismissOnOutsideClick(popRef, onCancel)

    function addEmpty() {
        onInsert(new Uint8Array(0))
    }

    async function addFromClipboard() {
        setBusy(true); setError(null)
        try {
            onInsert(decodeChunkText(await navigator.clipboard.readText(), format))
        } catch (e) {
            setError(e.message)
        } finally {
            setBusy(false)
        }
    }

    async function addFromFile(file) {
        setBusy(true); setError(null)
        try {
            const bytes = format === 'plain'
                ? new Uint8Array(await file.arrayBuffer())
                : decodeChunkText(await file.text(), format)
            onInsert(bytes)
        } catch (e) {
            setError(e.message)
        } finally {
            setBusy(false)
        }
    }

    return html`
        <div class="ctx-menu tamper-insert-popover" ref=${popRef} style=${{ left: x + 'px', top: y + 'px' }}>
            <div class="tamper-insert-row">
                <label>Format</label>
                <select class="goto-select" value=${format} onchange=${e => setFormat(e.target.value)}>
                    <option value="empty">Empty</option>
                    <option value="plain">Plain</option>
                    <option value="hex">Hex</option>
                    <option value="base64">Base64</option>
                    <option value="hexdump">Hexdump</option>
                </select>
            </div>
            ${format === 'empty'
                ? html`<button class="btn" disabled=${busy} onclick=${addEmpty}>Add Empty Chunk</button>`
                : html`
                    <div class="tamper-insert-row">
                        <label>Source</label>
                        <select class="goto-select" value=${source} onchange=${e => setSource(e.target.value)}>
                            <option value="clipboard">Clipboard</option>
                            <option value="file">File</option>
                        </select>
                    </div>
                    ${source === 'clipboard'
                        ? html`<button class="btn" disabled=${busy} onclick=${addFromClipboard}>Load from Clipboard</button>`
                        : html`
                            <button class="btn" disabled=${busy} onclick=${() => fileInputRef.current?.click()}>Choose File…</button>
                            <input
                                ref=${fileInputRef} type="file" style="display:none"
                                onchange=${e => { const f = e.target.files?.[0]; if (f) addFromFile(f) }}
                            />
                        `}
                `}
            ${error && html`<div class="error-msg">${error}</div>`}
        </div>
    `
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
    return true
}

function chunksEqual(a, b) {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) if (!bytesEqual(a[i], b[i])) return false
    return true
}

// Slices a flat buffer + its chunk-start offsets (as returned by peek) into one Uint8Array
// per chunk. bounds[i]:bounds[i+1] (or :data.length for the last one) — the inverse of
// boundsFromChunks below.
function splitByBounds(data, bounds) {
    const chunks = []
    for (let i = 0; i < bounds.length; i++) {
        const end = i + 1 < bounds.length ? bounds[i + 1] : data.length
        chunks.push(data.subarray(bounds[i], end))
    }
    return chunks
}

// The inverse of splitByBounds: cumulative chunk-start offsets for a chunks[] array, in the
// shape the wire protocol's "bounds" field expects.
function boundsFromChunks(chunks) {
    const bounds = []
    let off = 0
    for (const c of chunks) { bounds.push(off); off += c.length }
    return bounds
}

function totalLength(chunks) {
    return chunks.reduce((n, c) => n + c.length, 0)
}

// Chunks the wire protocol can represent: a non-trailing zero-length chunk would collide
// with its successor's start offset, which the server's strictly-increasing bounds check
// rejects. A user can still leave an empty chunk locally (e.g. as a typing target); it
// just has no effect on the wire if still empty when released.
function nonEmptyChunks(chunks) {
    return chunks.filter(c => c.length > 0)
}

// What chunk-scoped operations (context menu, split) operate on, per view mode.
// Continuous view has no real per-chunk structure, so a right-click's byteIndex is a
// position within the single merged buffer — treated here as one implicit chunk.
function chunksForView(viewMode, chunks) {
    return viewMode === 'continuous' ? [mergeUint8Arrays(chunks)] : chunks
}

// Bottom panel of the Tamper tab: shows the selected direction's whole held buffer
// (fetched via peek, since "held" carries no bytes inline) plus forward/drop/drop-
// connection actions.
//
// Canonical state is chunks: Uint8Array[], one entry per original chunk boundary — not a
// flat array — since split/merge/insert/delete operate on it directly; a flat buffer for
// submission or continuous view is just mergeUint8Arrays(chunks).
//
// Segmented view (default) renders one independent <HexEditor> per chunk; editing one
// block only replaces that entry. Continuous view is a single editor over the merged
// buffer, whose onChange collapses chunks to one entry — editing across former chunk
// boundaries has no well-defined per-chunk meaning, so structure is discarded on edit.
export default function TamperDetailPanel({ entry, onRelease, onDropConnection, paused, onContinue }) {
    const [viewMode,        setViewMode]       = useState('segmented') // 'segmented' | 'continuous'
    const [editMode,        setEditMode]       = useState('insert') // 'insert' | 'overwrite'
    const [chunks,          setChunks]         = useState([])
    const [originalChunks,  setOriginalChunks] = useState([])
    const [loading,         setLoading]        = useState(false)
    const [loadError,       setLoadError]      = useState(null)
    const [busy,            setBusy]           = useState(false)
    const [actionError,     setActionError]    = useState(null)
    // null | { x, y, chunkIndex, byteIndex, totalChunks, chunkLength }. Continuous view is
    // treated as one implicit chunk (index 0 of 1).
    // Enabled/disabled state: Forward only for the first chunk, Split needs an interior
    // byte position, Merge (back)/(front) need a next/previous chunk; Drop and Insert
    // Chunk Before/After have no gating.
    const [ctxMenu, setCtxMenu] = useState(null)
    // null | { x, y, insertAt } — insertAt indexes into chunksForView(viewMode, chunks) at
    // the moment the popover was opened.
    const [insertPopover, setInsertPopover] = useState(null)
    const [settingsOpen, setSettingsOpen] = useState(false)
    const menuRef = useRef(null)
    const selKeyRef = useRef(null)
    const settingsRef = useRef(null)

    // Uses the ref-contains check, not stopPropagation: mousedown fires before click, so an
    // unconditional close would unmount the menu before an item's onClick fires.
    useDismissOnOutsideClick(menuRef, () => setCtxMenu(null), !!ctxMenu)
    useDismissOnOutsideClick(settingsRef, () => setSettingsOpen(false), settingsOpen)

    function openChunkMenu(chunkIndex, info) {
        const target = chunksForView(viewMode, chunks)
        setCtxMenu({
            x: info.x, y: info.y, chunkIndex, byteIndex: info.index,
            totalChunks: target.length, chunkLength: target[chunkIndex].length,
        })
    }

    // Right-click fallback for padding outside HexEditor's own .hexed-container (which
    // already handles clicks landing inside it) — opens with byteIndex: null, same as a
    // click inside the editor that missed every byte.
    function handleBlockContextMenu(e, chunkIndex) {
        if (e.target.closest('.hexed-container')) return
        e.preventDefault()
        openChunkMenu(chunkIndex, { index: null, x: e.clientX, y: e.clientY })
    }

    // Splits target[chunkIndex] into two entries at byteIndex. In continuous view this
    // also collapses any prior multi-chunk structure into just the two new pieces (the
    // same edit-discards-structure rule a plain byte edit there already follows).
    function splitChunk(chunkIndex, byteIndex) {
        setChunks(cs => {
            const target = chunksForView(viewMode, cs)
            const chunk = target[chunkIndex]
            const before = chunk.subarray(0, byteIndex)
            const after = chunk.subarray(byteIndex)
            return [...target.slice(0, chunkIndex), before, after, ...target.slice(chunkIndex + 1)]
        })
        setCtxMenu(null)
    }

    // Merges adjacent target[a]/target[b] into one entry. Shared by Merge (back)
    // (a=chunkIndex, b=chunkIndex+1) and Merge (front) (a=chunkIndex-1, b=chunkIndex).
    function mergeChunks(a, b) {
        setChunks(cs => {
            const target = chunksForView(viewMode, cs)
            const merged = mergeUint8Arrays([target[a], target[b]])
            return [...target.slice(0, a), merged, ...target.slice(b + 1)]
        })
        setCtxMenu(null)
    }

    // Removes target[chunkIndex] entirely — a pure local edit, unlike Forward (which must
    // hit the server for a partial release). No sibling requirement, so this can empty
    // chunks[] entirely.
    function dropChunk(chunkIndex) {
        setChunks(cs => {
            const target = chunksForView(viewMode, cs)
            return [...target.slice(0, chunkIndex), ...target.slice(chunkIndex + 1)]
        })
        setCtxMenu(null)
    }

    // Closes ctxMenu first — only one floating panel should be up at a time.
    function openInsertPopover(insertAt, x, y) {
        setCtxMenu(null)
        setInsertPopover({ x, y, insertAt })
    }

    // Splices a new chunk into target at insertAt — same in-place splice shape as
    // split/merge/drop above.
    function insertChunk(insertAt, bytes) {
        setChunks(cs => {
            const target = chunksForView(viewMode, cs)
            return [...target.slice(0, insertAt), bytes, ...target.slice(insertAt)]
        })
        setInsertPopover(null)
    }

    function load(conn, direction) {
        setLoading(true)
        setLoadError(null)
        peekBuffer(conn, direction)
            .then(buf => {
                const loaded = splitByBounds(buf.data, buf.bounds)
                setChunks(loaded)
                setOriginalChunks(loaded)
            })
            .catch(err => setLoadError(err.message))
            .finally(() => setLoading(false))
    }

    // A selection change always reloads. The same selection's live chunks/length changing
    // only auto-reloads if nothing's been edited yet — an edited-and-stale buffer instead
    // surfaces the banner below and waits for an explicit refresh.
    useEffect(() => {
        setActionError(null)
        if (!entry) {
            selKeyRef.current = null
            setChunks([])
            setOriginalChunks([])
            setLoadError(null)
            return
        }

        const key = `${entry.conn}-${entry.direction}`
        if (key !== selKeyRef.current) {
            selKeyRef.current = key
            setChunks([])
            setOriginalChunks([])
            setLoadError(null)
            load(entry.conn, entry.direction)
            return
        }

        if (!loading && entry.length !== totalLength(originalChunks) && chunksEqual(chunks, originalChunks)) {
            load(entry.conn, entry.direction)
        }
    }, [entry?.conn, entry?.direction, entry?.length, entry?.chunks])

    const edited = !chunksEqual(chunks, originalChunks)
    const stale = !!(entry && entry.length !== totalLength(originalChunks))

    function act(action) {
        if (!entry || busy) return
        setBusy(true)
        setActionError(null)
        // releaseChunks/bounds just describe chunks[] as it stands now, regardless of view
        // mode. nonEmptyChunks strips any still-empty chunk first, since the wire protocol
        // can't represent one.
        const submit = nonEmptyChunks(chunks)
        const opts = {
            action,
            releaseChunks: edited ? submit.length : originalChunks.length,
            edited,
            prefixLength: edited ? totalLength(originalChunks) : 0,
            bounds: edited ? boundsFromChunks(submit) : [],
        }
        onRelease(entry.conn, entry.direction, opts, edited ? mergeUint8Arrays(submit) : undefined)
            .catch(err => setActionError(err.message))
            .finally(() => setBusy(false))
    }

    // Forwards just the first chunk, leaving the rest held. Reuses act()'s edited/
    // prefixLength/bounds computation (always describes the whole current buffer) — the
    // server applies that edit first, then releases releaseChunks of the result.
    function forwardFirstChunk() {
        if (!entry || busy) return
        const target = chunksForView(viewMode, chunks)
        // Also skips leading empty chunks: a still-empty target[0] contributes no bounds
        // entry of its own, so dropCount must match what releaseChunks below actually covers.
        let dropCount = 1
        while (dropCount < target.length && target[dropCount - 1].length === 0) dropCount++
        const remaining = target.slice(dropCount)
        const submit = nonEmptyChunks(chunks)
        // In continuous view the single synthetic entry already is everything, so this
        // releases everything (same count act() would use); in segmented view it's 1 chunk
        // of the filtered sequence.
        const releaseChunks = viewMode === 'continuous'
            ? (edited ? submit.length : originalChunks.length)
            : Math.min(1, submit.length)
        setBusy(true)
        setActionError(null)
        const opts = {
            action: 'forward',
            releaseChunks,
            edited,
            prefixLength: edited ? totalLength(originalChunks) : 0,
            bounds: edited ? boundsFromChunks(submit) : [],
        }
        onRelease(entry.conn, entry.direction, opts, edited ? mergeUint8Arrays(submit) : undefined)
            .then(() => {
                // Optimistic local update to the known remainder, instead of waiting on the
                // resync that follows a release — the auto-refresh effect only fires when
                // unedited, so without this the panel would keep showing the just-forwarded
                // chunk until that round-trip completes.
                setChunks(remaining)
                setOriginalChunks(remaining)
            })
            .catch(err => setActionError(err.message))
            .finally(() => setBusy(false))
        setCtxMenu(null)
    }

    // "Continue" (only shown while paused): commits any pending edit as an edit-only hold
    // (releaseChunks: 0) and hands control back to the script's suspended ctx.pause() call,
    // instead of releasing to the wire. Mirrors forwardFirstChunk's optimistic local
    // update on success, for the same reason.
    function handleContinue() {
        if (!entry || busy) return
        const submit = nonEmptyChunks(chunks)
        setBusy(true)
        setActionError(null)
        const opts = {
            action: 'forward',
            releaseChunks: 0,
            edited,
            prefixLength: edited ? totalLength(originalChunks) : 0,
            bounds: edited ? boundsFromChunks(submit) : [],
        }
        onContinue(entry.conn, entry.direction, opts, edited ? mergeUint8Arrays(submit) : undefined)
            .then(() => {
                setChunks(submit)
                setOriginalChunks(submit)
            })
            .catch(err => setActionError(err.message))
            .finally(() => setBusy(false))
    }

    function dropConnection() {
        if (!entry || busy) return
        setBusy(true)
        setActionError(null)
        onDropConnection(entry.conn, entry.direction)
            .catch(err => setActionError(err.message))
            .finally(() => setBusy(false))
    }

    if (!entry) {
        return html`<div class="tamper-detail-panel"><div class="placeholder">Select a held buffer</div></div>`
    }

    const actionsDisabled = busy || loading || !!loadError || originalChunks.length === 0
    // A split at position 0 or the chunk's own length would produce a zero-length chunk,
    // which the server rejects — both edge positions are excluded here.
    const canSplit = !!ctxMenu && ctxMenu.byteIndex != null &&
        ctxMenu.byteIndex > 0 && ctxMenu.byteIndex < ctxMenu.chunkLength

    return html`
        <div class="tamper-detail-panel">
            <div class="tamper-detail-toolbar">
                <span class="tamper-detail-title">
                    #${entry.conn} · <span class=${dirClass(entry.direction)}>${dirLabel(entry.direction)}</span>
                    · ${entry.chunks} chunk${entry.chunks === 1 ? '' : 's'} · ${entry.length} B
                    ${paused && html`<span class="tamper-paused-tag">⏸ paused by script</span>`}
                </span>
                <button
                    class="btn" disabled=${busy || loading || !!loadError}
                    onclick=${e => openInsertPopover(chunksForView(viewMode, chunks).length, e.clientX, e.clientY)}
                >New Chunk…</button>
                ${paused
                    ? html`<button class="btn btn-continue" disabled=${busy || loading || !!loadError} onclick=${handleContinue}>▶ Continue</button>`
                    : html`
                        <button class="btn" disabled=${actionsDisabled} onclick=${() => act('forward')}>Forward</button>
                        <button class="btn" disabled=${actionsDisabled} onclick=${() => act('drop')}>Drop</button>
                        <button class="btn" disabled=${busy || loading} onclick=${dropConnection}>Drop Connection</button>
                    `}
                <div class="tamper-settings-wrap" ref=${settingsRef}>
                    <button
                        class="btn btn-icon" title="Settings"
                        onclick=${() => setSettingsOpen(o => !o)}
                    >
                        <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19.14,12.94c0.04-0.3,0.06-0.61,0.06-0.94c0-0.32-0.02-0.64-0.07-0.94l2.03-1.58c0.18-0.14,0.23-0.41,0.12-0.61 l-1.92-3.32c-0.12-0.22-0.37-0.29-0.59-0.22l-2.39,0.96c-0.5-0.38-1.03-0.7-1.62-0.94L14.4,2.81c-0.04-0.24-0.24-0.41-0.48-0.41 h-3.84c-0.24,0-0.43,0.17-0.47,0.41L9.25,5.35C8.66,5.59,8.12,5.92,7.63,6.29L5.24,5.33c-0.22-0.08-0.47,0-0.59,0.22L2.74,8.87 C2.62,9.08,2.66,9.34,2.86,9.48l2.03,1.58C4.84,11.36,4.8,11.69,4.8,12s0.02,0.64,0.07,0.94l-2.03,1.58 c-0.18,0.14-0.23,0.41-0.12,0.61l1.92,3.32c0.12,0.22,0.37,0.29,0.59,0.22l2.39-0.96c0.5,0.38,1.03,0.7,1.62,0.94l0.36,2.54 c0.05,0.24,0.24,0.41,0.48,0.41h3.84c0.24,0,0.44-0.17,0.47-0.41l0.36-2.54c0.59-0.24,1.13-0.56,1.62-0.94l2.39,0.96 c0.22,0.08,0.47,0,0.59-0.22l1.92-3.32c0.12-0.22,0.07-0.47-0.12-0.61L19.14,12.94z M12,15.6c-1.98,0-3.6-1.62-3.6-3.6 s1.62-3.6,3.6-3.6s3.6,1.62,3.6,3.6S13.98,15.6,12,15.6z" /></svg>
                    </button>
                    ${settingsOpen && html`
                        <div class="tamper-settings-panel">
                            <label class="tamper-auto-toggle">
                                <input
                                    type="checkbox"
                                    checked=${viewMode === 'continuous'}
                                    onchange=${e => setViewMode(e.target.checked ? 'continuous' : 'segmented')}
                                />
                                Continuous view
                            </label>
                            <div class="tamper-settings-row">
                                <label>Hex editor mode</label>
                                <select class="goto-select" value=${editMode} onchange=${e => setEditMode(e.target.value)}>
                                    <option value="insert">Insert</option>
                                    <option value="overwrite">Overwrite</option>
                                </select>
                            </div>
                        </div>
                    `}
                </div>
                ${actionError && html`<span class="error-msg">${actionError}</span>`}
            </div>
            ${edited && stale && html`
                <div class="tamper-stale-banner">
                    ${entry.length} B now held server-side (showing ${totalLength(originalChunks)} B) — refreshing will discard your edit.
                    <button class="btn" onclick=${() => load(entry.conn, entry.direction)}>Refresh</button>
                </div>
            `}
            ${loading && html`<div class="placeholder">Loading…</div>`}
            ${loadError && html`<div class="error-msg">${loadError}</div>`}
            ${!loading && !loadError && chunks.length === 0 && html`
                <div class="placeholder">Nothing left in this buffer — Forward/Drop or New Chunk… from the toolbar, or Refresh to resync.</div>
            `}
            ${!loading && !loadError && chunks.length > 0 && (viewMode === 'continuous'
                ? html`
                    <${HexEditor}
                        bytes=${mergeUint8Arrays(chunks)}
                        onChange=${newBytes => setChunks([newBytes])}
                        onContextMenu=${info => openChunkMenu(0, info)}
                        direction=${entry.direction}
                        overwrite=${editMode === 'overwrite'}
                        style="flex: 1; min-height: 0;"
                    />
                `
                : html`
                    <div class="tamper-chunks-list">
                        ${chunks.map((chunk, i) => html`
                            <div key=${i} class="tamper-chunk-block" onContextMenu=${e => handleBlockContextMenu(e, i)}>
                                <div class="tamper-chunk-header">Chunk ${i + 1} · ${chunk.length} B</div>
                                <${HexEditor}
                                    bytes=${chunk}
                                    onChange=${slice => setChunks(cs => cs.map((c, idx) => idx === i ? slice : c))}
                                    onContextMenu=${info => openChunkMenu(i, info)}
                                    direction=${entry.direction}
                                    overwrite=${editMode === 'overwrite'}
                                    style="flex: none; overflow-y: visible; min-height: 0;"
                                />
                            </div>
                        `)}
                    </div>
                `)}
            ${ctxMenu && html`
                <div class="ctx-menu" ref=${menuRef} style=${{ left: ctxMenu.x + 'px', top: ctxMenu.y + 'px' }}>
                    <div class="ctx-item" onClick=${() => dropChunk(ctxMenu.chunkIndex)}>Drop</div>
                    <div
                        class=${'ctx-item' + (ctxMenu.chunkIndex === 0 && !busy && !paused ? '' : ' ctx-item-disabled')}
                        onClick=${() => { if (ctxMenu.chunkIndex === 0 && !busy && !paused) forwardFirstChunk() }}
                    >Forward</div>
                    <div class="ctx-sep"></div>
                    <div
                        class=${'ctx-item' + (canSplit ? '' : ' ctx-item-disabled')}
                        onClick=${() => { if (canSplit) splitChunk(ctxMenu.chunkIndex, ctxMenu.byteIndex) }}
                    >Split</div>
                    <div
                        class=${'ctx-item' + (ctxMenu.chunkIndex < ctxMenu.totalChunks - 1 ? '' : ' ctx-item-disabled')}
                        onClick=${() => { if (ctxMenu.chunkIndex < ctxMenu.totalChunks - 1) mergeChunks(ctxMenu.chunkIndex, ctxMenu.chunkIndex + 1) }}
                    >Merge (back)</div>
                    <div
                        class=${'ctx-item' + (ctxMenu.chunkIndex > 0 ? '' : ' ctx-item-disabled')}
                        onClick=${() => { if (ctxMenu.chunkIndex > 0) mergeChunks(ctxMenu.chunkIndex - 1, ctxMenu.chunkIndex) }}
                    >Merge (front)</div>
                    <div class="ctx-sep"></div>
                    <div
                        class="ctx-item"
                        onClick=${() => openInsertPopover(ctxMenu.chunkIndex, ctxMenu.x, ctxMenu.y)}
                    >Insert Chunk Before</div>
                    <div
                        class="ctx-item"
                        onClick=${() => openInsertPopover(ctxMenu.chunkIndex + 1, ctxMenu.x, ctxMenu.y)}
                    >Insert Chunk After</div>
                </div>
            `}
            ${insertPopover && html`
                <${InsertChunkPopover}
                    x=${insertPopover.x} y=${insertPopover.y}
                    onInsert=${bytes => insertChunk(insertPopover.insertAt, bytes)}
                    onCancel=${() => setInsertPopover(null)}
                />
            `}
        </div>
    `
}
