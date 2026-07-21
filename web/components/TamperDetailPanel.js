import { h } from 'preact'
import { useState, useEffect, useRef } from 'preact/hooks'
import htm from 'htm'
import HexEditor from './HexEditor.js'
import { peekBuffer } from '../tamperApi.js'
import { mergeUint8Arrays, parseHexdump } from '../format.js'
import { OPERATIONS } from '../transforms.js'

const html = htm.bind(h)

// Decodes popover input text per the chosen format. 'hex'/'base64' reuse the Transform
// panel's own (tested) decode ops rather than re-implementing hex/base64 parsing here —
// 'hex' passes a fixed space separator (no prefix) since that op's separator stripping
// already treats contiguous or whitespace-joined hex identically once whitespace is
// collapsed. 'hexdump' has no Transform-panel equivalent (it isn't a general encode/decode
// op, just this popover's way to round-trip HexDump's own "Copy as hexdump" output), so it
// goes through format.js's parseHexdump directly.
function decodeChunkText(text, format) {
    if (format === 'plain') return new TextEncoder().encode(text)
    const bytes = new TextEncoder().encode(text)
    if (format === 'hex') return OPERATIONS['hex-decode'].run(bytes, { prefix: '', separator: ' ' })
    if (format === 'base64') return OPERATIONS['base64-decode'].run(bytes, { urlSafe: false })
    if (format === 'hexdump') return parseHexdump(text)
    throw new Error(`unknown format "${format}"`)
}

// Toolbar/context-menu popover for inserting a new chunk at insertAt (an index into
// chunksForView(viewMode, chunks) — see the call sites below), either empty or decoded
// from a file/clipboard in one of four text formats. Kept as its own small floating panel
// (not folded into ctxMenu) since — unlike Drop/Split/Merge/Forward, which are one-shot
// instant actions — this needs to stay open across a format pick, a possible source pick,
// and an async file-read/clipboard-read before finally calling onInsert, so it needs its
// own independent outside-click/Escape dismissal instead of ctx-menu's fire-and-close one.
function InsertChunkPopover({ x, y, onInsert, onCancel }) {
    const [format, setFormat] = useState('empty') // empty | plain | hex | base64 | hexdump
    const [source, setSource] = useState('clipboard') // clipboard | file
    const [busy,   setBusy]   = useState(false)
    const [error,  setError]  = useState(null)
    const popRef = useRef(null)
    const fileInputRef = useRef(null)

    useEffect(() => {
        const close = e => { if (!popRef.current || !popRef.current.contains(e.target)) onCancel() }
        const onKey = e => { if (e.key === 'Escape') onCancel() }
        document.addEventListener('mousedown', close)
        document.addEventListener('keydown', onKey)
        return () => {
            document.removeEventListener('mousedown', close)
            document.removeEventListener('keydown', onKey)
        }
    }, [])

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

// Chunks the wire protocol can actually represent. A zero-length chunk carries no bytes, so
// it can never get its own valid bounds entry — buffer.go's validBounds requires bounds to be
// strictly increasing, and a zero-length chunk's start offset is identical to whatever comes
// right after it (it added nothing to move the offset forward), so anything but a *trailing*
// zero-length chunk collides with its successor and gets the whole release rejected as "the
// buffer has changed". Filtering here is a no-op on the actual byte stream — merging an empty
// chunk contributes nothing either way — so it's applied everywhere chunks[] feeds a release:
// boundsFromChunks, mergeUint8Arrays, and the releaseChunks counts in act()/forwardFirstChunk.
// A user can still create and leave an empty chunk locally (e.g. as an insertion point to type
// new bytes into directly via its own HexEditor block, which is the primary reason to want one
// at all) — it simply has no effect on the wire if it's still empty by the time Forward/Drop is
// actually clicked.
function nonEmptyChunks(chunks) {
    return chunks.filter(c => c.length > 0)
}

// What chunk-scoped operations (context menu, split) actually operate on, per view mode.
// Continuous view displays mergeUint8Arrays(chunks) as one editor with no real per-chunk
// structure visible, so a right-click's byteIndex is a position within *that* merged
// buffer, not within chunks[0] alone — treating it as a single implicit chunk here is what
// makes "index 0 of 1" the correct target both for menu-gating (already done) and for
// actually performing a split. Segmented view's chunks already are that structure, so this
// is just chunks unchanged.
function chunksForView(viewMode, chunks) {
    return viewMode === 'continuous' ? [mergeUint8Arrays(chunks)] : chunks
}

// Bottom panel of the Tamper tab: shows the currently-selected direction's whole held
// buffer (fetched on demand via peek, since "held" never carries bytes inline), plus the
// forward/drop/drop-connection actions that release it.
//
// Canonical state is chunks: Uint8Array[] — one entry per original chunk boundary, not a
// flat byte array — since that's what both view modes below are ultimately a projection
// of, and what the chunk-editing operations (split/merge/create/delete — see
// splitChunk/mergeChunks/dropChunk/insertChunk below) operate on directly. A flat buffer
// for submission or the continuous view is always just mergeUint8Arrays(chunks); the
// reverse (bytes -> chunks) needs bounds, which is why peek's bounds are threaded all the
// way through here now instead of being reduced to a bare chunk count.
//
// **Segmented view** (default) renders one independent <HexEditor> per chunk, fed that
// chunk's own byte slice — HexEditor always renders offsets relative to whatever bytes it's
// given starting at 0, so per-chunk local offsets and the "restart at each boundary" look
// fall out for free, with zero changes to HexEditor.js itself. Editing inside one block only
// ever replaces that one entry of chunks[]; the others (and their own HexEditor instances,
// each with independent cursor state) are untouched.
//
// **Continuous view** is the single flat editor this panel used to always show: one
// <HexEditor> over mergeUint8Arrays(chunks), whose onChange collapses chunks down to a
// single entry — editing across what were chunk boundaries has no well-defined
// per-chunk meaning yet (real boundary editing is still future work), so continuous mode
// deliberately discards structure on edit rather than guessing.
export default function TamperDetailPanel({ entry, onRelease, onDropConnection, paused, onContinue }) {
    const [viewMode,        setViewMode]       = useState('segmented') // 'segmented' | 'continuous'
    const [chunks,          setChunks]         = useState([])
    const [originalChunks,  setOriginalChunks] = useState([])
    const [loading,         setLoading]        = useState(false)
    const [loadError,       setLoadError]      = useState(null)
    const [busy,            setBusy]           = useState(false)
    const [actionError,     setActionError]    = useState(null)
    // null | { x, y, chunkIndex, byteIndex, totalChunks, chunkLength }. Continuous view has
    // no real per-chunk structure to target, so it's treated as a single implicit chunk
    // (index 0 of 1) for menu purposes — Forward is trivially enabled (it is the first
    // chunk) and both Merge items are trivially disabled (no siblings), which is the
    // correct answer for "the whole buffer" anyway.
    //
    // All items are implemented (see dropChunk/splitChunk/forwardFirstChunk/mergeChunks/
    // openInsertPopover below). Enabled/disabled state: Forward only for the first chunk
    // (release is always a front-aligned prefix), Split needs a real interior byte position
    // (not the two edges, which would produce a zero-length chunk), Merge (back)/(front)
    // need a next/previous chunk to merge with; Drop and Insert Chunk Before/After have no
    // gating at all — unlike Merge, Drop needs no sibling (so it can remove the last
    // remaining chunk too), and inserting a new chunk boundary never requires one either.
    const [ctxMenu, setCtxMenu] = useState(null)
    // null | { x, y, insertAt } — insertAt indexes into chunksForView(viewMode, chunks) at
    // the moment the popover was opened (from the toolbar button, appending at the end, or
    // from a context-menu "Insert Chunk Before/After"). See InsertChunkPopover above.
    const [insertPopover, setInsertPopover] = useState(null)
    const menuRef = useRef(null)
    const selKeyRef = useRef(null)

    // Dismiss context menu on outside click or Escape. Deliberately *not* HexDump.js's exact
    // pattern (a bare document "mousedown" -> close): mousedown fires before click, so an
    // unconditional close there would unmount the menu before a click on one of its own
    // items ever reaches it — invisible as long as every item's only effect was closing the
    // menu anyway (indistinguishable from the listener doing it), but a real bug once an
    // item does something else, caught here by Split silently not firing. Only treat a
    // mousedown as "outside" if it didn't land inside the menu itself; each item's own
    // onClick is what closes the menu after (optionally) doing its real work.
    useEffect(() => {
        if (!ctxMenu) return
        const close = e => {
            if (menuRef.current && menuRef.current.contains(e.target)) return
            setCtxMenu(null)
        }
        const onKey = e => { if (e.key === 'Escape') setCtxMenu(null) }
        document.addEventListener('mousedown', close)
        document.addEventListener('keydown', onKey)
        return () => {
            document.removeEventListener('mousedown', close)
            document.removeEventListener('keydown', onKey)
        }
    }, [!!ctxMenu])

    function openChunkMenu(chunkIndex, info) {
        const target = chunksForView(viewMode, chunks)
        setCtxMenu({
            x: info.x, y: info.y, chunkIndex, byteIndex: info.index,
            totalChunks: target.length, chunkLength: target[chunkIndex].length,
        })
    }

    // Right-click fallback for the segmented view's per-chunk block: HexEditor only reports
    // a context-menu event for clicks landing inside its own .hexed-container (see
    // HexEditor.js's handleContextMenu), so a right-click on the chunk header — or any other
    // padding within the block that isn't the editor itself — used to fall through to the
    // browser's default menu instead of this one. Bails out when the click already landed
    // inside .hexed-container, since HexEditor's own onContextMenu already handled that case
    // (with a real byteIndex when the click hit an actual byte); this only ever fires for the
    // remainder of the block, so it always opens with byteIndex: null, same as a click inside
    // the editor that missed every byte.
    function handleBlockContextMenu(e, chunkIndex) {
        if (e.target.closest('.hexed-container')) return
        e.preventDefault()
        openChunkMenu(chunkIndex, { index: null, x: e.clientX, y: e.clientY })
    }

    // Splits chunksForView(viewMode, chunks)[chunkIndex] into two entries at byteIndex,
    // replacing it in place. In continuous view this also collapses whatever multi-chunk
    // structure existed before the split into just the two new pieces — the same "an edit
    // discards prior structure" rule continuous mode's plain byte edits already follow (see
    // the module doc comment), just via a split instead of a byte insert/delete.
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

    // Merges chunksForView(viewMode, chunks)[a] and [b] (adjacent, a === b - 1) into one
    // entry. Shared by both Merge (back) (a = chunkIndex, b = chunkIndex + 1) and Merge
    // (front) (a = chunkIndex - 1, b = chunkIndex) — merging is direction-agnostic, only
    // which pair of neighboring indices is being joined differs between the two menu items.
    function mergeChunks(a, b) {
        setChunks(cs => {
            const target = chunksForView(viewMode, cs)
            const merged = mergeUint8Arrays([target[a], target[b]])
            return [...target.slice(0, a), merged, ...target.slice(b + 1)]
        })
        setCtxMenu(null)
    }

    // Removes chunksForView(viewMode, chunks)[chunkIndex] entirely — a pure local edit, like
    // Split/Merge and unlike Forward (which has to hit the server, since only it can do a
    // partial release). Unlike Merge, there's no sibling requirement, so this can remove the
    // last remaining chunk too, leaving chunks empty; the toolbar's Forward/Drop (submitting
    // that as a full-buffer edit to nothing) or a Refresh (discarding it) are what resolve
    // that state, same as any other edit.
    function dropChunk(chunkIndex) {
        setChunks(cs => {
            const target = chunksForView(viewMode, cs)
            return [...target.slice(0, chunkIndex), ...target.slice(chunkIndex + 1)]
        })
        setCtxMenu(null)
    }

    // Opens InsertChunkPopover targeting insertAt (an index into chunksForView(viewMode,
    // chunks) as it stands right now). Closes ctxMenu too, since "Insert Chunk Before/After"
    // are themselves ctxMenu items — only one of the two floating panels should ever be up.
    function openInsertPopover(insertAt, x, y) {
        setCtxMenu(null)
        setInsertPopover({ x, y, insertAt })
    }

    // Splices a newly-created chunk into chunksForView(viewMode, chunks) at insertAt — same
    // splice-in-place shape as splitChunk/mergeChunks/dropChunk above, so an insert made
    // while in continuous view lands in the underlying array the same way a Split there
    // would, just displayed merged until the view is switched back to segmented.
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

    // Selection changes always (re)load from scratch. Staying on the same selection but
    // seeing its live chunks/length change (a new "held" push arrived, reflected via
    // TamperView's resync-on-every-event stream-list) only auto-reloads if nothing's
    // been edited yet — silently replacing an in-progress edit would be a real way to
    // lose work, so an edited-and-stale buffer instead surfaces the banner below and
    // waits for an explicit refresh.
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
        // Continuous-mode edits already collapsed chunks down to a single entry (see the
        // module doc comment); segmented-mode edits preserve however many entries chunks[]
        // currently has. Either way releaseChunks/bounds just describe chunks[] as it stands
        // now — no special-casing needed between the two view modes here. nonEmptyChunks
        // strips any still-empty chunk (e.g. one created via New Chunk/Insert and never typed
        // into) before that description is built, since the wire protocol can't represent one.
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

    // Forwards just the first chunk in chunksForView(viewMode, chunks) — the same "first" the
    // Forward menu item's chunkIndex === 0 gate already checks — leaving the rest still held.
    // Reuses act()'s exact edited/prefixLength/bounds computation (always describing the
    // *whole* current buffer, never a hand-picked partial prefix): the server applies that
    // full-buffer edit first, then releases only releaseChunks of the result, so this needs
    // no bookkeeping about which original bytes ended up in "chunk 0" even after a Merge
    // pulled in a neighbor — the edit already fully describes the new structure regardless of
    // how it was built locally. The one difference from a plain act('forward') is
    // releaseChunks: in continuous view chunksForView's single synthetic entry already *is*
    // everything, so "release its first chunk" has to mean every raw chunk (submit.length or
    // originalChunks.length, exactly what act() itself would release) — segmented view's
    // chunksForView is chunks unchanged, so there releaseChunks is 1 chunk of the *filtered*
    // sequence (see nonEmptyChunks): if target[0] itself is a still-empty chunk (possible if
    // the user right-clicks one directly — chunkIndex === 0 doesn't require non-empty), it
    // contributes no bounds entry at all, so "1 filtered chunk" actually covers it plus
    // whatever real chunk follows it; dropCount below mirrors that same coalescing on the
    // local (raw) side so `remaining` stays exactly what the server has left.
    function forwardFirstChunk() {
        if (!entry || busy) return
        const target = chunksForView(viewMode, chunks)
        let dropCount = 1
        while (dropCount < target.length && target[dropCount - 1].length === 0) dropCount++
        const remaining = target.slice(dropCount)
        const submit = nonEmptyChunks(chunks)
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
                // Optimistic local update to the known remainder, rather than waiting on the
                // resync TamperView's onRelease chain triggers: without this, the panel would
                // keep showing the just-forwarded first chunk (and, if this action was itself
                // an edit, "edited" would stay true relative to the now-stale originalChunks)
                // until that round-trip completes, which the auto-refresh effect can't correct
                // on its own since it only fires when unedited.
                setChunks(remaining)
                setOriginalChunks(remaining)
            })
            .catch(err => setActionError(err.message))
            .finally(() => setBusy(false))
        setCtxMenu(null)
    }

    // "Continue" (only shown while paused, in place of Forward/Drop/Drop Connection):
    // commits any pending edit as an edit-only hold (releaseChunks: 0 — TamperView's
    // onContinue forces this regardless of what's passed here) and hands control back to
    // the script's suspended ctx.pause() call, rather than releasing anything to the wire.
    // Mirrors forwardFirstChunk's optimistic local update on success, for the same reason:
    // without it, the buffer would still compare "edited" against a now-stale
    // originalChunks until some unrelated event happens to trigger a resync, and briefly
    // show the (misleading, since nothing external changed) stale-edit banner.
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
    // A split at position 0 or at the chunk's own length would produce a zero-length
    // chunk — bounds the server's validBounds rejects outright (bounds must be strictly
    // increasing), so those two edge positions are excluded here alongside "no byte
    // position was targeted at all".
    const canSplit = !!ctxMenu && ctxMenu.byteIndex != null &&
        ctxMenu.byteIndex > 0 && ctxMenu.byteIndex < ctxMenu.chunkLength

    return html`
        <div class="tamper-detail-panel">
            <div class="tamper-detail-toolbar">
                <span class="tamper-detail-title">
                    #${entry.conn} · <span class=${entry.direction === 0 ? 'c2s' : 's2c'}>${entry.direction === 0 ? 'C→S' : 'S→C'}</span>
                    · ${entry.chunks} chunk${entry.chunks === 1 ? '' : 's'} · ${entry.length} B
                    ${paused && html`<span class="tamper-paused-tag">⏸ paused by script</span>`}
                </span>
                <label class="tamper-auto-toggle">
                    <input
                        type="checkbox"
                        checked=${viewMode === 'continuous'}
                        onchange=${e => setViewMode(e.target.checked ? 'continuous' : 'segmented')}
                    />
                    Continuous view
                </label>
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
