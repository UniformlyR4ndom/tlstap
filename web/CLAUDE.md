# tlstap web frontend (`web/`)

Implementation notes for the web UI, loaded automatically when working under this
directory. See the root `CLAUDE.md` for where this fits into the wider architecture —
`ApiProvider`/REST API mechanics ("REST API" section), the `dbdump` interceptor whose
REST API `api.js` consumes (`intercept/dbdump/CLAUDE.md`), and the `tamper` interceptor
whose control/watch WebSocket API and script-storage/fs-root REST APIs back the Tamper
tab and "Scripted interception" below (`intercept/tamper/CLAUDE.md`).

Served at `/ui/` by the API HTTP server. No build step — uses vendored ES modules loaded via an importmap.

**Technology:** Preact 10.25.4 + htm 3.1.1, vendored under `web/vendor/`. The importmap in `index.html` maps bare specifiers (`preact`, `preact/hooks`, `htm`) to the vendored files so the Preact hooks module (which imports bare `"preact"`) resolves correctly.

**Layout:** Header bar (title + refresh button) → top-level tab bar (**Analysis** / **Tamper**, `App.js`'s `view` state) → for Analysis: menu bar → sidebar (sessions + streams) + main area (traffic view) + collapsible bottom panel; for Tamper: see "Tamper tab" below, an entirely separate layout with no sidebar/bottom-panel reuse.

**Menu bar (`App.js`, `index.html`):**
- `App.js` owns `openMenu` (null | `'view'`), `globalOffset` (bool, default `true`), and `rememberPosition` (bool, default `false`).
- A `mousedown` listener on `document` (active only while a menu is open) closes the menu when clicking outside `.menubar`.
- One menu: **View** → **Global offset** toggle, **View mode** (Single stream / Combined streams), **Remember stream position** toggle.
- `globalOffset` is passed down: `App` → `TrafficView`/`CombinedView` → `HexDump` → `HexRow`.
- **Remember stream position** (single-stream view only): while on, `App.js` remembers the byte offset/direction at the top of the viewport per stream, in-memory only, keyed by `` `${session}:${id}` `` (stream `id` is only unique within a session). `selectStream(s)` looks up a saved position and jumps to it with `align: 'top'` instead of a plain `setStream(s)`; re-clicking the already-selected stream is a no-op. Switching **View mode** away and back doesn't auto-restore — only reselecting via the Streams list does.

**Refresh (`App.js`):** the header's `↺` button (`.btn-refresh`) increments `refreshKey`, a plain counter threaded into `SessionList`, `StreamList`, `TrafficView`, and `CombinedView`; each re-fetches whatever it owns when the value changes.

**Jump to top / jump to bottom (`App.js`, `.btn-icon`):** two icon buttons placed left of
Refresh. `App.js` owns `viewJumpRef = useRef({jumpToTop: () => {}, jumpToBottom: () => {}})`,
passed as `jumpRef` to both `TrafficView`/`CombinedView` (mounted mutually-exclusively under
`viewMode`); each registers `jumpRef.current = { jumpToTop, jumpToBottom }` in a
dependency-array-free effect. The buttons call `viewJumpRef.current.jumpToTop()`/
`.jumpToBottom()`; the actual work lives in `useChunkBuffer.js` (see below) as a genuine
`reloadFrom` of the chunk buffer, not a scroll over already-loaded rows.

**Central live poll (`App.js`):**
- One `usePoll(true, POLL_INTERVAL_MS, tick)` call (`usePoll.js`, 500ms) is the single source of live-ness for the whole Analysis view — `SessionList`, `StreamList`, and whichever of `TrafficView`/`CombinedView` is mounted all react to its output rather than polling themselves.
- Each tick calls `getLatest(params)` (`api.js`), building `params` from current selection: `{session: session.id}` if a session is selected, plus `stream: stream.id` only when `viewMode === 'single'` and a stream is selected too. The raw `{latest_session_id, latest_sgid, streams_version, latest_stid}` response is stored as-is in a `latest` state object and passed down as four separately-named props: `latestSessionId` (`SessionList`), `streamsVersion` (`StreamList`), `latestStid` (`TrafficView`), `latestSgid` (`CombinedView`).
- `tick`'s closure captures `session`/`stream`/`viewMode` fresh from each render (`usePoll.js` reassigns `tickRef.current` unconditionally every render), so the poll always acts on the current selection with no separate ref-syncing.
- A failed `getLatest` call is silently swallowed; the next tick just retries. Each downstream consumer's own "did this number change" comparison treats an unchanged `latest` as a no-op, so a missed tick is invisible.

**Bottom panel (`App.js`):**
- `bottomTab` state: `null` (collapsed) | `'goto'` | `'search'` | `'extract'` | `'transform'`.
- `selectBottomTab(name)`: sets tab; does not toggle (panel only collapses via the `▼` button at the right of the tab bar).
- Tab bar contains: **Goto**, **Search**, **Extract**, **Transform**, and a collapse button (`▼`) on the right.
- Content area (`.bottom-content`, resizable — see "Resizable panels" below) renders `GoToPanel`, `SearchPanel`, `ExtractPanel`, or `TransformPanel` based on `bottomTab`.
- A `ResizeHandle` (`orientation="h"`) sits at the top edge of `.bottom-panel`, shown only while `bottomTab` is set (nothing to resize when collapsed).

**Session/stream list panels (`ListPanel.js`, `SessionList.js`, `StreamList.js`):**
- `ListPanel.js` is the shared panel chrome: `<${ListPanel} title items error? emptyMessage selected onSelect renderItem resetSortKey? />`. It owns the `desc` sort state (default `false` = ascending/oldest first), the `▼`/`▲` toggle button, the count badge, the sorted/mapped item list, and the empty-state line (`error`, if truthy, takes priority over `emptyMessage`). Callers own fetching the data and each item's row markup via `renderItem(item)`.
- `SessionList.js` fetches via `getSessions()` and never passes `resetSortKey`. `StreamList.js` fetches via `getStreams(session.id)` and passes `resetSortKey=${session?.id}`, which resets `desc` to `false` on session change without affecting a plain refresh.
- Both re-fetch whenever `refreshKey` changes, in addition to their own natural triggers (mount / session change) — this is what makes the Refresh button pick up newly-initiated streams and updated end-times/byte-counts.
- **Reacting to the central live poll**: `SessionList.js` takes a `latestSessionId` prop, `StreamList.js` a `streamsVersion` prop. Each owns a `lastSeenIdRef`/`lastSeenVersionRef` and two effects: a **seed effect** (keyed on its own natural triggers) that fetches and sets the baseline ref from the prop's current value without depending on the prop itself, and a **poll-reaction effect** (keyed on the prop) that re-fetches only on a genuine difference from the baseline. Seeding from the already-available prop value (rather than an extra round trip) is what keeps the next poll tick from spuriously re-fetching what the seed effect just fetched.

**Duration formatting:** `fmtDuration(start, end)` (`format.js`) — for finished streams (`end` set) formats `end - start`; for ongoing streams formats `Date.now() - start` and appends `" (ongoing)"`, e.g. `12.34s (ongoing)`.

**Resizable panels (`ResizeHandle.js`, `layout.js`, `useResizableLayout.js`):**
- `ResizeHandle.js` is a generic draggable divider: `<${ResizeHandle} orientation="v"|"h" onResize=${deltaPx => ...} />`. On `mousedown` it attaches document-level `mousemove`/`mouseup` listeners for the drag; each `mousemove` calls `onResize(ev.movementX)` (`v`) or `onResize(ev.movementY)` (`h`). The caller owns the resulting size state, clamping, and sign convention (a handle placed *after* the sized element treats a positive delta as "grow"; placed *before*, negative is "grow"). `onResize` is read fresh from props at `mousedown` time, never memoized.
- `layout.js`: `loadLayout()` / `saveLayoutValue(key, value)` read/write one `localStorage` key (`tlstap-layout`) holding `{ sidebarWidth, markersWidth, bottomHeight, encdecOptionsWidth, encdecInputHeight, tamperDetailHeight, scriptsListWidth, scriptsLogHeight }`, merged with defaults on load. Also exports `clamp(v, lo, hi)`, used by the hook below and standalone by `TransformPanel.js`.
- `useResizableLayout(key, { sign = 1, min, max })` is what every panel below calls: reads `loadLayout()[key]` for the initial value, applies `clamp(v + sign * delta, min, max)` on each `onResize(delta)`, calls `saveLayoutValue(key, next)`, and returns `[value, onResize]`. `max` may be a plain number or a thunk (`() => number`) — the three window-relative panels pass `() => Math.floor(window.innerHeight * 0.7)` so the bound is re-read at drag time rather than baked in at render time.
- **Sidebar** (`App.js`): `useResizableLayout('sidebarWidth', { min: 180, max: 600 })` (default 280), handle between `.sidebar` and `.main`.
- **Bottom panel** (`App.js`): `useResizableLayout('bottomHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })` (default 160), handle at the top of `.bottom-panel` (only rendered while a tab is open).
- **Markers panel** (`TrafficView.js`): `useResizableLayout('markersWidth', { sign: -1, min: 150, max: 500 })` (default 240), handle between `HexDump`/`HexEditor` and `MarkersPanel` (only rendered while not collapsed); width passed down as a `width` prop to `MarkersPanel`, applied via inline style on `.markers-side`.
- **Transform panel** (`TransformPanel.js`): `useResizableLayout('encdecOptionsWidth', { min: 100, max: 400 })` (default 160, handle between the options column and the input/output column) and `useResizableLayout('encdecInputHeight', { min: 30, max: 2000 })` (default 120, handle between the input and output areas).
- **Tamper detail panel** (`TamperView.js`): `useResizableLayout('tamperDetailHeight', { sign: -1, min: 120, max: () => Math.floor(window.innerHeight * 0.7) })` (default 300), handle above `.tamper-detail-wrap`, same sign convention as the bottom panel's handle (also placed before the sized element).
- **Tamper scripts sub-tab** (`TamperScriptsPanel.js`): `useResizableLayout('scriptsListWidth', { min: 150, max: 500 })` (default 220, handle between the script list and editor) and `useResizableLayout('scriptsLogHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })` (default 160, handle above the log panel).
- All of the above apply their size via inline `style` (not fixed CSS) so the persisted value always wins.

**Outside-click/Escape dismissal (`useDismissOnOutsideClick.js`):**
- `useDismissOnOutsideClick(ref, onClose, active = true)`: while `active`, attaches document-level `mousedown`/`keydown` listeners — `mousedown` calls `onClose()` unless the click landed inside `ref.current`, `keydown` calls `onClose()` on `Escape` — removed on cleanup. `active` defaults to `true` for a popover only ever mounted while shown; callers that stay mounted pass their own boolean.
- Used by `TransformPanel.js`'s algorithm menu, `TamperDetailPanel.js`'s `ctxMenu`, and `InsertChunkPopover`.
- **`HexDump.js`'s context menu is a deliberate non-user**: it has no ref of its own, so its `.ctx-menu` container instead calls `onMouseDown={e => e.stopPropagation()}` to keep an inside click from reaching its own document-level close listener.
- The ref-contains check matters because `mousedown` fires before `click`: an unconditional close-on-any-mousedown would unmount a menu before a click on one of its own items ever reaches it.

**Virtual scroll (`HexDump.js`):**
- Exports `ROW_HEIGHT = 22`. Constants: `BUFFER = 8` (overdraw rows), `PREFETCH_FRACTION = 0.1`.
- Props: `rows`, `onScrollEnd`, `scrollAdjust`, `adjustVersion`, `scrollTo`, `scrollToVersion`, `globalOffset`, `onSetMarker`, `onClearMarker`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`, `onViewportChange`, `markers`.
- Encoding helpers imported from `../format.js` (not defined locally).
- Flattens all loaded chunks into a flat `rows[]` array: one `{type:'header'}` row + N `{type:'hex'}` rows per chunk.
- A `ResizeObserver` tracks container height; `onScroll` tracks `scrollTop`. Visible window is `[startIdx, endIdx)`. Inner div height = `rows.length * ROW_HEIGHT`; top/bottom spacer divs fill the rest.
- **Prefetch trigger** (`scrollend` event): fires `onScrollEnd(1)` when fewer than `rows.length * PREFETCH_FRACTION` rows remain below the viewport; `onScrollEnd(-1)` when fewer remain above.
- **Scroll correction** (`useLayoutEffect([adjustVersion])`): applies signed `scrollAdjust` to `scrollTop` synchronously before paint. Negative = scroll up (after front eviction); positive = scroll down (after prepend).
- **Absolute scroll** (`useLayoutEffect([scrollToVersion])`): clamps `scrollTo` to `[0, el.scrollHeight - el.clientHeight]` and sets both `scrollTop` and internal `scrollTop` state to that clamped value, synchronously before paint; `scrollToVersion` must change to trigger even if `scrollTo` is unchanged. Used by jump-to — the clamp is what lets `jumpToBottom()` pass a deliberately-oversized `scrollTo` and land exactly at the end without knowing the viewport height.
- **Global/local offset**: `HexRow` displays `row.offset` (stream-global byte offset) when `globalOffset` is true, or `row.localOffset` (offset within the chunk, resets to 0 at each chunk start) when false.
- **Byte selection**: `sel` state `{direction, start, end}` (byte offsets, inclusive). `onMouseDown` starts selection; `onMouseMove` extends it if same direction as anchor; document-level `mouseup` ends drag. Per-byte `<span data-off=N data-dir=D>` elements carry `.sel-hl` class when highlighted. Selection is scoped to one direction (cannot drag across c2s/s2c boundary).
- **Byte markers**: `markedC2S` / `markedS2C` — `Set<offset>` derived from `markers` prop. Marked bytes receive `.hex-byte-marked` / `.asc-byte-marked` CSS classes.
- **Chunk header** format: `[+T.TTTs] [#stid] DIRECTION  #chunkId  N B` (stid shown when present; stream number shown in CombinedView). A `⋯ ` prefix (plus a `title` tooltip) marks a `row.continued` header — the byte-budgeted segment buffer's loaded window doesn't start at the segment's own offset, so the real header is further up, out of the loaded range (only possible in `TrafficView.js`'s frame mode today, for a still-growing huge frame).
- **Context menu** (right-click on a hex row or chunk header):
  - Copy as hex / ASCII / hexdump / base64 — copies chunk bytes (header click) or selection/chunk bytes (row click).
  - Separator, then (when right-clicking a hex byte and extract props present):
    - **Set selection (range)** — only when a selection is active; sets both From and To offsets in the Extract tab.
    - **Set selection start** — sets the From offset in the Extract tab.
    - **Set selection end** — sets the To offset in the Extract tab.
  - Separator, then **Set marker** / **Clear marker** — toggles based on whether the byte is already marked.

**Editable hex grid (`HexEditor.js`):**
- Small, non-virtualized hex/ASCII editor (all rows render directly), unlike the read-only, virtualized `HexDump.js`. Reuses `HexDump.js`'s `ROW_HEIGHT` for visual consistency only; otherwise independent.
- Controlled component: `<${HexEditor} bytes=${Uint8Array} onChange=${bytes => ...} readOnly? style? direction? onContextMenu? overwrite? />`.
- `onContextMenu` (optional): fires `{index, x, y}` on right-click instead of rendering any menu itself (`index` null if the click didn't land on a real byte/insertion cell) — the component stays menu-agnostic; only `TamperDetailPanel.js` uses this today.
- **Cursor model**: `cursor = { index, area }` — `index` is a byte position `0..bytes.length` (insertion point before that byte), `area` is `'hex'`/`'ascii'`. `pendingNibble` holds a single typed hex character awaiting its pair; cleared by Backspace, arrow movement, Tab, or clicking elsewhere.
- **Typing inserts by default; `overwrite` prop (bool, default falsy) switches every mutating path except Backspace/Delete to overwrite:**
  - Hex column: only `[0-9a-fA-F]` accepted (modifier-guarded so shortcuts aren't swallowed); two nibbles combine into one byte.
  - ASCII column: any printable keystroke produces one byte (`charCodeAt(0) & 0xFF`).
  - Backspace/Delete remove a byte and shift subsequent bytes regardless of `overwrite` (which only affects how a typed/pasted byte lands, not removal).
  - Arrow keys move by one byte (Up/Down by a row = 16 bytes); Home/End/Ctrl+Home/End jump within/across the buffer; Tab toggles `area`; click sets the cursor directly.
  - Paste is filtered per the active column's rules and applied in one `onChange` call.
  - Every mutating path funnels its produced bytes through `(overwrite ? overwriteBytes : insertBytes)(bytes, index, newBytes)`: `insertBytes` shifts everything at/after `index` forward; `overwriteBytes` writes in place, growing the buffer only if the write runs past the current end — which makes "cursor at end" append under both with no special-casing.
- Row layout mirrors `fmtAsHexdump`'s conventions (16 bytes/row, 8-hex-digit offset, `|ascii|` column) via `.hexed-*` CSS classes, kept separate from `HexDump.js`'s `.hex-*` classes.
- A synthetic trailing cell (`byte === null`) at `bufferLength` lets the cursor be positioned after the last byte when the last row isn't full; an empty buffer gets exactly one row holding just that cell; a buffer whose length is a nonzero multiple of 16 gets no extra row for it.
- `readOnly` prop: every mutating path becomes a no-op; navigation still works. Used for `TransformPanel`'s output panel.

**Chunk buffer hook (`useChunkBuffer.js`) — `CombinedView.js`'s only remaining consumer**
**(`TrafficView.js` migrated off it entirely — see "Byte-budgeted segment buffer" below):**
- Backs `CombinedView.js`'s windowed/paginated chunk buffer — initial load, forward/backward
  scroll-driven eviction, and refresh top-up. Keyed by session/`sgid`.
- `useChunkBuffer({ entity, refreshKey, openStream, fetchPage, getId, buildRows, isClosed, latestId })`
  → `{ display, loading, error, setError, handleScrollEnd, reloadFrom, displayRef, jumpToTop, jumpToBottom }`.
  `entity` is the current session; `openStream` is `openSgidStream` (`api.js`);
  `fetchPage(ws, entity, startId, n)` wraps entity-specific fetch args; `buildRows` stays
  caller-owned and is only invoked by the hook; `isClosed(entity)` is optional
  (`CombinedView.js` omits it); `latestId` is optional too — a plain number from `App.js`'s
  central poll, not a function the hook calls itself.
- `display = {rows, scrollAdjust, adjustVersion, scrollTo, scrollToVersion}` — single state
  object for atomic render.
- `BATCH = 50` chunks per request (exported); `MAX_BUFFERED_CHUNKS = BATCH * 2`
  (100) soft-caps how many chunks the refresh path may hold at once; `countChunks(rows)` counts
  `header` rows to measure occupancy against it.
- Refs owned by the hook: `nextIdRef` (exclusive upper bound of buffer), `prevIdRef` (id of
  first chunk in buffer), `hasMoreRef`, `loadingMoreRef`, `generationRef` (increments on entity
  change/`reloadFrom`, checked after every `await` to abort stale fetches), `entityRef`, `wsRef`
  (single WS connection per entity), `displayRef`, `hasMountedRef`.
- **`reloadFrom(startId, { computeExtra })`**: opens a fresh connection, fetches one `BATCH`
  window from `startId`, builds rows, replaces `display` — merging in `computeExtra(rows)` if
  given. The entity-change effect calls `reloadFrom(0)` on mount/swap; that's the hook's only
  caller today (`CombinedView.js` has no `jumpTo`-driven jump effect — see below).
- **`handleScrollEnd(scrollDir)`** (stable `useCallback([])`):
  - **Forward** (1): fetches next `BATCH` from `nextIdRef`, appends rows, evicts front half at
    the nearest chunk-header boundary, updates `prevIdRef`, sets negative `scrollAdjust`.
  - **Backward** (-1): fetches chunks before `prevIdRef`, prepends rows, evicts back half,
    updates `nextIdRef`/`hasMoreRef`, sets positive `scrollAdjust`.
- **`topUp()`** (hook-internal): skips if no entity, `isClosed?.(entity)`, a scroll-triggered
  load is already in flight, or the buffer has no spare room (`MAX_BUFFERED_CHUNKS -
  countChunks(...) <= 0`); otherwise fetches exactly that much room from `nextIdRef.current`
  onward. Unlike `handleScrollEnd`, it never evicts and never touches `scrollAdjust` — new rows
  append straight to the end of `display.rows`, which is what makes a top-up visually silent
  when the new data isn't on screen. Goes inert once the cap is hit until a forward scroll frees
  room. Called from both places below.
- **Refresh top-up**: a `useEffect` keyed on `refreshKey` (no-op on initial mount) calls
  `topUp()` on every tick — the Refresh-button path.
- **Live-poll reaction**: `useEffect(() => { if (latestId != null && latestId >= nextIdRef.current)
  topUp() }, [latestId])` — no fetching/interval of its own; `latestId` arrives already fetched
  from `App.js`'s central poll, so a tick with nothing new costs one shared indexed query
  server-side and zero chunk fetches. `dbdump`'s chunk writes are themselves flushed at most
  once/second, so polling faster narrows the average wait but doesn't beat the next flush.
- **`jumpToTop()` / `jumpToBottom()`** (back `App.js`'s header buttons): both a genuine
  `reloadFrom`. `jumpToTop()` is `reloadFrom(0, {computeExtra: () => ({scrollTo: 0,
  scrollToVersion})})`. `jumpToBottom()` is a no-op if `latestId` is unset/`-1`; otherwise it
  fetches a `BATCH`-sized window ending at `latestId` and sets `scrollTo:
  Number.MAX_SAFE_INTEGER` — `HexDump.js`'s scroll-to effect clamps that to the DOM's real
  range, landing exactly at the end without either view tracking its own viewport height.
  `scrollToVersion` in both is `(displayRef.current.scrollToVersion ?? 0) + 1` rather than a
  separate counter — same convention `useByteBuffer.js` below uses, where it matters more
  directly (`TrafficView.js`'s own jump effect writes into that hook's identical field
  through a different path; two independent counters could otherwise coincide on the same
  value and make `HexDump.js` miss a jump).

**Byte-budgeted segment buffer (`useByteBuffer.js`, `byteBufferCore.js`, `chunkSegments.js`,
`frameSegments.js`, `frameSegmentsCore.js`) — backs all of `TrafficView.js` now (both raw
and frame mode); `CombinedView.js` is the only view still on `useChunkBuffer.js` above:**

Full design: [`doc/design/hexview-segment-buffer.md`](../doc/design/hexview-segment-buffer.md).
Replacement for the chunk buffer hook above, built to bound memory for an arbitrarily huge
single frame (frame mode used to load a frame's entire byte span in one shot — see that
document's "What problem this solves"). Per the design doc's "Migration plan", frame mode
went first (the one with the actual defect), then raw-chunk mode (a mechanical port, as
expected — same hook, `chunkSegments.js` in place of `frameSegments.js`, entity is the real
`stream` object rather than a synthetic one). Both are done and live-verified; observed
bonus from the byte-budget replacing the old item-count one: the browser's scrollbar thumb
size now stays roughly consistent regardless of how a stream happened to be chunked, rather
than varying with chunk size, except in degenerate cases where the segment-count cap (not
the byte cap) ends up binding. `CombinedView.js` (step 4 of the migration plan) remains
undecided — deliberately left open until this size/complexity was visible in practice, per
that plan; still on `useChunkBuffer.js`/`buildRows` as documented above.
`useChunkBuffer.js` itself isn't touched until nothing references it.

- **`byteBufferCore.js`** (pure, no Preact import — kept separately testable with Node's
  plain test runner via `byteBufferCore.test.js`, the same reason `format.js`/
  `transforms/*.js` stay framework-free): the `Segment`/`SegmentWindow` model, `buildRows`
  (the shared row-builder frame mode now uses in place of the deleted `frameBuildRows` —
  `relTime` is unconditional, since `segment.time` is always present for both entity
  types; `ChunkHeader` in `HexDump.js` no longer special-cases a missing one), `evict`
  (byte-budgeted, row-aligned mid-segment trimming — fixes the tied-`stid`-group eviction
  gap the old chunk-count model had), `fillToTarget` (the quantized fill loop driving an
  adapter's `fillForward`/`fillBackward` toward a target, with generation-based
  cancellation between quanta).
- **`useByteBuffer.js`**: the Preact hook wrapping that core — same external contract as
  `useChunkBuffer.js` above (`display`, `loading`, `error`, `setError`, `handleScrollEnd`,
  `reloadFrom`, `displayRef`, `jumpToTop`, `jumpToBottom`), so migrating a view onto it is
  meant to be a small change. Caller props shrink to `{entity, refreshKey, openConnection,
  fillForward, fillBackward, isClosed, latestId}` — no `fetchPage`/`getId`/`buildRows`,
  since pagination is now the adapter's own concern and row-building is shared.
- **Adapters** — one per entity type, each implementing `openConnection`/`fillForward`/
  `fillBackward` against `/segments` (see `intercept/dbdump/CLAUDE.md`'s "WebSocket
  `/segments` protocol"):
  - **`chunkSegments.js`**: a thin, direct mapping — every returned window is already
    fully loaded, since `/segments` delivers a chunk's metadata and bytes together in one
    exchange. Tested via a fake connection handle (`chunkSegments.test.js`), sidestepping
    `openSegmentsStream()`'s real `WebSocket`/`location` dependency.
  - **`frameSegments.js`** / **`frameSegmentsCore.js`**: metadata via `/frames/timeline`
    (`dbdumpFramerApi.js`'s `listFramesTimeline`/`listFramesTimelineBackward`), bytes via
    the same `/segments` chunk mode uses (the same offset→stid resolution `api.js`'s
    `fetchDirectionChunks` does today). Split the same way `useByteBuffer.js`/
    `byteBufferCore.js` is: `frameSegmentsCore.js` holds the pure selection/range math —
    `selectByBudget` (accumulate whole frames until the budget would be exceeded; a
    single oversized first candidate is still included, but only partially, and nothing
    further is added that round) and the forward/backward anchor asymmetry in
    `initialWindowRange` (a huge frame's first partial load anchors at the segment's
    *start* when opened while scrolling forward into it, so later extension grows
    `loadedEnd`; anchors at the segment's *end* when opened scrolling backward into it, so
    later extension shrinks `loadedStart` instead — in both cases the loaded window grows
    toward whatever's already visible) — tested directly (`frameSegmentsCore.test.js`).
    `frameSegments.js` is the thin async glue calling the real REST/WS endpoints,
    including `sliceFrameBytes` — now the only copy; `TrafficView.js`'s own was deleted
    once frame mode moved onto this adapter.

**`TrafficView.js`-specific layer on top of its raw-mode `useByteBuffer.js` instance**
(frame mode's own layer is documented in "Framer scripts" below):
- Props: `stream`, `globalOffset`, `jumpTo`, `markers`, `onAddMarker`, `onRemoveMarker`, `onUpdateMarkerLabel`, `onMarkerJumpRequest`, `onImportMarkers`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`, `onLeaveStream`, `jumpRef`.
- `jumpRef`: a ref `App.js` owns; a dependency-array-free effect keeps it pointed at the
  raw-mode hook's current `jumpToTop`/`jumpToBottom` every render (frame mode has its own
  instance but doesn't feed `jumpRef` — see "Framer scripts" below). `CombinedView.js` has
  the identical effect over its own (`useChunkBuffer.js`) hook.
- `handleSetMarker` / `handleClearMarker` are local (not lifted); `onSetExtractStart/End/Range` are forwarded directly to `HexDump`.
- `totalBytes` (the ↑/↓ byte counters in the meta bar) is `TrafficView.js`-only state, independent of either hook's `display`, mirrored via its own small effect on `stream?.id`.
- **Jump effect** (`useEffect([jumpTo?.version])`, no `CombinedView.js` equivalent, and not
  wired to frame mode): resolves `jumpTo` to a target stid, then calls the raw-mode hook's
  `reloadFrom`. A local `cancelled` flag (set in the effect's cleanup) guards the resolution
  step against a stale jump firing after a newer one has superseded it — the hook's own
  `generationRef` only protects `reloadFrom`'s internal async work, not this caller-side step.
  - `chunks` unit: `targetStid = jumpTo.value`.
  - `chunks-c2s` / `chunks-s2c`: `POST /chunk-stid` resolves per-direction `id` → `stid`.
  - `offset-c2s` / `offset-s2c`: `POST /byte-stid` resolves byte offset → `stid`, also recording `targetByteOffset`/`targetDirection`.
  - Calls `reloadFrom(max(0, targetStid - FILL_TARGET_SEGMENTS/2), { computeExtra })` —
    `FILL_TARGET_SEGMENTS` (from `useByteBuffer.js`) plays the same centering role `BATCH`
    played before this view's migration — where `computeExtra` scans the freshly-built rows
    for the target row (byte-offset jumps match both direction and offset range, since
    c2s/s2c offsets both start at 0) and returns `{scrollTo, scrollToVersion: jumpTo.version}`
    — centered by default, or placed at the very top when `jumpTo.align === 'top'` (marker
    jumps, remembered-position restore).
  - A resolution failure calls the hook's `setError` directly, since `reloadFrom` is never reached.
- **Leave effect** (`useEffect([stream?.id])`, save side of "Remember stream position"): its
  cleanup resolves the row at `Math.floor(scrollTopRef.current / ROW_HEIGHT)` in
  `displayRef.current.rows`, scanning forward past any `'header'` row to the next `'hex'`
  row, and calls `onLeaveStream(leavingStream, {direction, offset})` if one was found.
  `scrollTopRef`/`viewHeightRef` are stashed by `handleViewportChange` on every scroll/resize tick.

**`CombinedView.js`-specific layer on top of `useChunkBuffer.js`:** almost none — no markers, no
extract-selection, no `totalBytes`, no `jumpTo`-driven jump effect. It has the `jumpRef`
registration effect described above, and is the only place `scrollTo`/`scrollToVersion` get
threaded to `<HexDump>` at all.

**Goto panel (`GoToPanel.js`):**
- Text input (accepts decimal or `0x`-prefixed hex).
- Unit select (option values / labels): `chunks` / "chunks (total)", `chunks-c2s` / "chunks (c→s)", `chunks-s2c` / "chunks (s→c)", `offset-c2s` / "offset (c→s)", `offset-s2c` / "offset (s→c)".
- No separate direction dropdown — direction is encoded in the unit choice.
- Shows "Select a stream first" placeholder when no stream selected.
- `onGoTo({value: N, unit})` is called on submit (Enter or button click).

**Search panel (`SearchPanel.js`):**
- Props: `session`, `stream`, `onJump`.
- Shows "Select a session first" placeholder when no session selected.
- Form fields: pattern input (monospace, dynamic placeholder), format select, direction select (`both` / `c→s` / `s→c`), **Contiguous** checkbox, stream number input (empty = all streams in session).
- Format select options and encoding behaviour:
  - `ascii` — unescape `\n \r \t \\` then UTF-8 encode; sent as base64.
  - `utf16le` / `utf16be` — encode string with `DataView.setUint16`; sent as base64.
  - `hex` — accepts `0xff 0x00`, `\xff\x00`, `ff00`, space/comma-separated; sent as base64.
  - `regex` — sent as raw text with `pattern_encoding: "regex"`; no base64.
- All non-regex formats are always sent as base64 (`pattern_encoding: "base64"`).
- Results list: match count header + scrollable rows showing stream id, direction (coloured), hex offset. Clicking a row calls `onJump({streamId, direction, offset})`.
- `App.js` wires `onJump` → `handleSearchJump`: finds the stream in `streamList`, switches to it if needed (sets `stream` state), then sets `jumpTo` with unit `offset-c2s` or `offset-s2c`.
- `streamList` state in `App.js` is populated via `StreamList`'s `onLoad` prop (called after each fetch).

**`format.js` (shared encoding/formatting helpers):**
- `fmtAsRaw(bytes)` / `parseRaw(text)` — UTF-8 decode (non-fatal) / encode.
- `fmtAsBase64(bytes)` — standard base64 string.
- `fmtAsHex(bytes)` — lowercase hex string (no separators).
- `fmtAsAscii(bytes)` — printable ASCII, `.` for non-printable.
- `fmtAsHexdump(bytes, baseOffset)` — `xxd`-style: `OOOOOOOO  gg gg … gg  gg gg … gg  |ascii|` per 16-byte line.
- `parseHexdump(text)` — inverse of `fmtAsHexdump`: parses that same format back into bytes, ignoring the offset and `|ascii|` columns (both derived/lossy) and reading only the hex byte tokens between them; lenient about spacing. Covered by `format.test.js`.
- `parseHexBytes(text, label, validLengths?)` — parses an optionally `0x`-prefixed hex string into bytes, with an optional byte-length check; used by the Transform panel's encryption/MAC ops (`transforms/encryption.js`, `transforms/mac.js`) to parse key/IV/nonce/AAD fields.
- `bytesFromWordArray(wordArray)` — unpacks a crypto-js `WordArray`-shaped object into a `Uint8Array`; used by `transforms/hash.js`, `transforms/encryption.js`, `transforms/mac.js`.
- `fmtUintHex(n, width)` / `parseUintField(text, label, width)` — fixed-width `0x`-hex formatting/parsing for a single integer param (`0x`/decimal/bare-hex accepted); used by `transforms/checksum.js`'s CRC variant fields.
- `parseIntInRange(value, min, max, label)` — rounds and range-validates a numeric param; used by `transforms/basic.js`'s Base-N `base` field.
- `mergeUint8Arrays(arrays)` — concatenates an array of `Uint8Array`s into one.
- `fmtByteSize(n)` — human-readable byte count (`B`/`KB`/`MB`; negative `n` formats as `'?'`, for a not-yet-known total). Used by `HexDump.js` (chunk header) and `TrafficView.js` (stream meta bar).
- `fmtDuration(start, end)` — see "Duration formatting" below.
- `fmtRelTime(ms, base)` — formats a chunk timestamp relative to a stream/session start as `"+T.TTTs"`. Used by `TrafficView.js`'s and `CombinedView.js`'s `buildRows`.
- Imported by `HexDump.js`, `ExtractPanel.js`, `transforms.js`, `TamperDetailPanel.js`, and others. **Any new top-level `.js` file under `web/` must be added to the `//go:embed` directive in `web/server.go` explicitly** — same for a new `transforms/*.js` category module, listed there by name (test files must not be, so they're never pulled into the binary).

**Extract panel (`ExtractPanel.js`):**
- Props (all controlled from `App.js`): `session`, `stream`, `direction` (string `'0'`/`'1'`), `from` (string), `to` (string), `onDirectionChange`, `onFromChange`, `onToChange`.
- Local state: `format` (`'raw'`|`'base64'`|`'hex'`|`'hexdump'`), `method` (`'file'`|`'clipboard'`), `working`, `status`.
- Shows "Select a stream first" placeholder when no stream selected.
- `parseOffset(s)`: accepts decimal or `0x`/`0X`-prefixed hex; returns `null` on invalid input.
- `fetchRange(session, stream, dir, fromOffset, toOffset)`: fetches the covering chunks via `api.js`'s `fetchDirectionChunks` (see below), then trims to exact byte boundaries and merges — the resolve-offsets-to-stids/fetch/filter-by-direction part is shared with `framerRun.js`'s catch-up fetch, factored out once that became a second real caller.
- **Extract button is `type="button"` with `onclick` handler** — NOT a form submit. This is required for `showSaveFilePicker` (Chrome/Edge File System Access API): the browser only grants a file-picker dialog from a direct click event, not from a form `submit` event.
- For file method: `acquireFileHandle(format)` (thin wrapper over `download.js`'s shared `acquireSaveHandle`, see below) is called **before** `fetchRange` to preserve the transient user activation; Chrome consumes activation on the first relevant `await`.
- Fallback for browsers without `showSaveFilePicker` (Firefox): uses an anchor-click download; status message notes "no save dialog in this browser".
- File extensions/MIME: raw → `.bin`/`application/octet-stream`, base64 → `.b64`/`text/plain`, hex → `.hex`/`text/plain`, hexdump → `.txt`/`text/plain`.
- `App.js` extract state: `extractDir` (useState `'0'`), `extractFrom`, `extractTo` (both useState `''`).
  - `handleSetExtractStart(direction, offset)`: sets dir+from as `'0x'+hex`, opens extract tab.
  - `handleSetExtractEnd(direction, offset)`: sets dir+to as `'0x'+hex`, opens extract tab.
  - `handleSetExtractRange(direction, fromOffset, toOffset)`: sets all three, opens extract tab.
  - Direction/from/to are always overwritten from the chunk that was right-clicked.

**Transform panel (`TransformPanel.js`, `transforms.js`):**
- Layout: resizable options column (`.encdec-options`, left) + input/output column (`.encdec-io`, right), split by `ResizeHandle`s.
- **Canonical state is `bytes: Uint8Array`**: text mode derives the `<textarea>`'s value from `bytes` each render (never stored back except via its own `oninput`), so toggling Hexdump view off/on never loses data even with invalid UTF-8 (a warning line appears when the decode is lossy); hexdump mode operates on `bytes` directly via `<${HexEditor}>`.
- **Steps** (`steps: [{id, op, label, params}]`), built from the `+` button's dropdown (`transforms.js`'s `ALGORITHM_SECTIONS`, subsections rendered as a nested indent level). An algorithm with no matching `OPERATIONS` entry renders `[TODO]` and isn't clickable. `addStep` seeds `params` from each param's `default`, including ones hidden by `showIf`. Step rows are HTML5-draggable for reordering.
- **Per-step parameters** (`renderStepParam`): `param.type` is `'number'` (clamped to `min`/`max`), `'boolean'`, `'select'`, or `'text'`.
- **Conditional/derived params**: `showIf: (params) => boolean` hides a param row; `onSet: (value, params) => partialParams`, run when that param changes, merges extra param changes alongside the edited key — e.g. `crc16`/`crc32`'s `variant` select both reveals `poly`/`init`/`refin`/`refout`/`xorout` under `Custom` and copies a chosen preset's values into them otherwise.
- **Execution is manual** (`handleGo`, `async` so it can `await` each step): runs `bytes` through `steps` via `OPERATIONS[step.op].run(current, step.params)`. A thrown error halts the pipeline (`outputError` shown in red); on success `outputHexdumpView` defaults to `!isPrintable(outputBytes)`.
- **Output panel** mirrors the input's Hexdump-view checkbox: hex view reuses `<${HexEditor} readOnly=${true} />`, text view is a read-only derived `<textarea>`.

**`transforms.js` + `transforms/*` (operation registry + algorithm catalog):**

Operations are implemented in per-category modules under `transforms/`; `transforms.js` itself only aggregates them into the two exports `TransformPanel.js` consumes, plus the still-unimplemented placeholder catalog entries. Category grouping (which file an op lives in) is independent of UI grouping (which section/subsection it appears under in the menu) — e.g. `transforms/numbers.js`'s two catalog arrays both feed the `Numeric` section's `Encode`/`Decode` subsections.

- **Category module contract** (e.g. `transforms/basic.js`, `transforms/numbers.js`): each exports
  - `OPERATIONS` — object keyed by op id, each entry `{ label, params?, run(bytes, params) }`. `run` returns the transformed `Uint8Array` or throws a plain `Error` with a human-readable message (caught by `TransformPanel`'s `handleGo`).
  - one or more plain catalog arrays of `{ label, op }`, named for the UI slot(s) they feed (e.g. `ENCODE_ALGORITHMS`/`DECODE_ALGORITHMS`).
  - All other helpers/tables (e.g. `HEX_SEPARATOR_CHARS`, `NUMBER_TYPES`) are private to the module.
- **`transforms.js`**:
  - `OPERATIONS`: merges every category module's `OPERATIONS` into one registry.
  - `ALGORITHM_SECTIONS`: catalog grouped into UI sections — `Basic` (subsections `Encode`/`Decode`, sourced from `transforms/basic.js`), `Numeric` (subsections `Encode`/`Decode`, sourced from `transforms/numbers.js`'s two catalog arrays), `Compression` (subsections `Compress`/`Uncompress`, each concatenating `transforms/compression.js`'s and `transforms/zip.js`'s algorithm arrays — two category modules feeding the same UI subsection), `Checksum` (sourced from `transforms/checksum.js`'s `CHECKSUM_ALGORITHMS`), `Encryption` (subsections `Encrypt`/`Decrypt`, sourced from `transforms/encryption.js`'s `ENCRYPT_ALGORITHMS`/`DECRYPT_ALGORITHMS`), `Hash` (sourced from `transforms/hash.js`'s `HASH_ALGORITHMS`) — and `MAC` (sourced from `transforms/mac.js`'s `MAC_ALGORITHMS`; flat like `Hash`, not split into subsections, since HMAC has no inverse operation any more than hashing does). Each leaf is `{ label, op }`.
  - **`[E]`/`[D]` label prefixing**: `sectionPrefix(name)` (exported) returns `'[E] '`/`'[D] '` for any section/subsection name that **starts with** `"Encode"`/`"Decode"` — this covers `Basic > Encode/Decode` and `Numeric > Encode/Decode` uniformly, while `Encrypt`/`Decrypt` and `Compress`/`Uncompress` are deliberately excluded (they don't match the `Encode`/`Decode` prefix test). Catalog entries (`ALGORITHM_SECTIONS`) keep plain, unprefixed `label`s — the menu shows just the algorithm name, since the Encode/Decode grouping is already visible from the section/subsection header. `TransformPanel.js`'s `renderAlgoItem(entry, prefix)` applies `sectionPrefix(...)` only when constructing the label stored on a step (`addStep`), so the prefix appears in the step chain but not the selection menu.
  - Algorithms within each (sub)section are sorted alphabetically by plain `label` — applying the same fixed prefix to every entry in a group never changes their relative order, so sorting doesn't need to account for it.
- **Implemented operations:**
  - `hex-encode`/`hex-decode` (`transforms/basic.js`): `prefix` (None/`0x`/`\x`) and `separator` (text, default Space) combine independently, e.g. `\x48,\x65`.
  - `base64-encode`/`base64-decode` (`transforms/basic.js`): `urlSafe` boolean (default `false`).
  - `octal-encode`/`octal-decode` (`transforms/basic.js`): 3-digit zero-padded octal per byte, space-separated.
  - `basen-encode`/`basen-decode` (`transforms/basic.js`): `base` param (2–64, default 64); arbitrary-base big-integer encoding via `BigInt`, Base58-style leading-zero handling.
  - `encnum-*`/`decnum-*` (`transforms/numbers.js`; 14 fixed-width integer types, big/little endian): decode requires the exact byte width; encode validates range; 64-bit types use `BigInt` throughout.
  - `gzip-compress`/`gzip-decompress`, `deflate-compress`/`deflate-decompress`, `zlib-compress`/`zlib-decompress` (`transforms/compression.js`, via `fflate`'s sync functions, no params, `run()` returns a plain `Uint8Array`): `deflate-*` is raw DEFLATE; `zlib-*` is the zlib-wrapped format (Node's `zlib.deflateSync` is this format, not raw DEFLATE).
  - `zip-compress`/`zip-decompress` (`transforms/zip.js`, via `fflate`'s `zipSync`/`unzipSync`): `zip-compress` has a `filename` param; `zip-decompress` has an `entry` param (empty = auto-extract if exactly one entry, otherwise throws listing available names).
  - `md2`/`md4`/`ntlm`/`md5`/`sha1`/`sha224`/`sha256`/`sha384`/`sha512`/`whirlpool` (`transforms/hash.js`, no params): MD5/SHA-1/SHA-2 family via vendored `crypto-js`; MD2/MD4 hand-rolled (no established JS library covers them); NTLM is `md4(UTF-16LE(text))`; Whirlpool via vendored `hash-wasm` (WASM-backed), lazily warmed up via `warmupWhirlpool()` — its first call anywhere returns a `Promise<Uint8Array>`, every call after that a plain one.
  - `crc16`/`crc32`/`adler32` (`transforms/checksum.js`, output as raw big-endian bytes): CRC16/CRC32 share one hand-rolled Williams/Rocksoft-model core (`crcCompute`, parameterized by `width`/`poly`/`init`/`refin`/`refout`/`xorout`); a `variant` select offers named presets (CCITT-FALSE, ARC, MODBUS, ... / CRC-32, CRC-32C, BZIP2, MPEG-2) plus `Custom`, which reveals those fields directly and lets a preset's values seed them. Adler-32 is unrelated to the CRC model and hand-rolled separately, no params.
  - `aes-encrypt`/`aes-decrypt`, `des-encrypt`/`des-decrypt`, `3des-encrypt`/`3des-decrypt`, `rc4-encrypt`/`rc4-decrypt`, `salsa20-encrypt`/`salsa20-decrypt`, `chacha20-encrypt`/`chacha20-decrypt`, `xor-encrypt`/`xor-decrypt` (`transforms/encryption.js`; key/IV/nonce/AAD as hex-digit-pair text): AES (CBC/CTR/ECB/CFB/OFB/GCM) and Salsa20/ChaCha20 via vendored `@noble/ciphers`; DES/TripleDES/RC4 via vendored `crypto-js`; XOR hand-rolled. Each block cipher is one catalog entry with a `mode` select (AES: all six modes; DES/3DES: all but GCM); `iv`/`nonce`/`padding`/`aad` show/hide per mode via `showIf`. CTR/CFB/OFB are forced to no padding regardless of the (hidden) `padding` param, since the underlying libraries would otherwise pad these stream-like modes' output unconditionally. AES-OFB is hand-rolled (`aesOfbTransform`, standard NIST SP 800-38A construction) since `@noble/ciphers` has no OFB export. AES-GCM's tag is appended to the ciphertext; an auth failure is rewrapped as a clearer message. Salsa20/ChaCha20/XOR are self-inverse and share one function per pair; RC4 needs distinct wrappers since crypto-js's decrypt requires a `CipherParams` wrapper.
  - `hmac-md5`/`hmac-sha1`/`hmac-sha224`/`hmac-sha256`/`hmac-sha384`/`hmac-sha512` (`transforms/mac.js`, one `key` param each): HMAC over the SHA-1/SHA-2 family plus MD5 via vendored `crypto-js`; no key-length validation (HMAC is defined for any key length). MD2/MD4/NTLM/Whirlpool are excluded (not standard HMAC constructions, or no HMAC helper available).

**Testing (`transforms/*.test.js`, `format.test.js`):**
- Unit tests live alongside their source (e.g. `transforms/numbers.test.js`), using Node's built-in `node:test` + `node:assert/strict`. `web/package.json` (`"type": "module"`, scoped to `web/`) exists solely so Node treats these as ES modules — it doesn't affect the browser, which uses the importmap instead. Run via `npm test` or `node --test` (both from `web/`; prefer the no-args form, which recurses `*.test.js` discovery).
- Neither `package.json` nor any `*.test.js` file is embedded into the binary (see the `format.js` embed note above).
- Each category module's tests check known vectors (cross-checked against Node's `crypto`/`zlib` or an independent reference implementation before use), round-trips, boundary/error cases, and that distinguishing parameters (mode, variant, key size, ...) actually change the output.

**Markers panel (`MarkersPanel.js`):**
- Props: `markers[]`, `onRemove`, `onUpdateLabel`, `onJump`, `onImport(markers[])`, `collapsed`, `onToggle`, `width` (px, applied as inline style on `.markers-side`; see "Resizable panels" above — not used when `collapsed`).
- `collapsed` renders a vertical strip (`◀ Markers`); expanded renders the full side panel.
- Marker rows: show `[streamId] direction  0xOFFSET` + inline editable label. Click row → `onJump`; `×` → `onRemove`.
- **Import/export** (bottom bar of expanded panel): `[clipboard ▾] [Import] [Export]` + status line.
  - File format: deflate-compressed JSON, base64-encoded, extension `.tlstap-markers`. Content is the raw `tlstap-markers` localStorage JSON (`{ version: 1, markers: [{id, session, stream, direction, offset, label?}] }`).
  - `compress(str)` / `decompress(b64)`: use `CompressionStream`/`DecompressionStream` with `'deflate'` (Chrome 80+, Firefox 113+, Safari 16.4+).
  - Export to file: `download.js`'s shared `acquireSaveHandle` called **before** `compress()` to preserve user activation; falls back to anchor download.
  - Import from file: programmatic `<input type="file" accept=".tlstap-markers,.txt">` click (no activation constraint on read).
  - Import replaces all markers (`onImport` prop wired to `setMarkers` in `App.js`).
  - `parseImport(text)`: validates JSON has `markers` array with required typed fields; returns `null` on invalid data.
- `onImport` prop is threaded: `App.js (setMarkers) → TrafficView (onImportMarkers) → MarkersPanel (onImport)`.

**`api.js`:**
- `openStidStream()` → `{ fetch(sessionId, streamId, start, n), close() }`: persistent WS to `/stid-stream`.
- `openSgidStream()` → `{ fetch(session, start, n), close() }`: persistent WS to `/sgid-stream`.
- `getSessions()`, `getStreams(sessionId)`, `getChunkList(sessionId, streamId)`.
- `getLatest({session, stream} = {})`: POST `/latest` — `App.js`'s central live poll; both fields optional/independent, omitted entirely when falsy/nullish rather than sent as `0`/`null`. See "Central live poll" above and `intercept/dbdump/CLAUDE.md`'s `/latest` entry.
- `getChunkStid(sessionId, streamId, direction, id)`: POST `/chunk-stid`.
- `getByteStid(sessionId, streamId, direction, offset)`: POST `/byte-stid`.
- `searchText(req)`: POST `/search-text`; `req` is the full request object.
- `fetchDirectionChunks(sessionId, streamId, direction, fromOffset, toOffset?)`: resolves
  `fromOffset` (and `toOffset`, if given) to stids via `getByteStid`, fetches that range
  via `openStidStream`, filters down to `direction` (stid is direction-agnostic — chunks
  of both directions share the counter). `toOffset` omitted means "everything up to the
  current end" (`n: 0`, unlimited). Two callers: `ExtractPanel.js`'s `fetchRange` (bounded,
  trims to exact bytes and merges into one buffer) and `framerRun.js`'s catch-up fetch
  (unbounded, keeps chunks separate — a framer's `frame()` is called once per raw chunk).
- `openSegmentsStream()` → `{ fetchForward(session, stream, afterStid, maxSegments,
  maxBytes), fetchBackward(session, stream, beforeStid, maxSegments, maxBytes), close() }`:
  persistent WS to `/segments` (see `intercept/dbdump/CLAUDE.md`'s "WebSocket `/segments`
  protocol"). Not `openStidStream`/`openChunkStream`-based — `/segments` answers one
  request with exactly one response (one metadata text frame + one binary frame), not a
  per-item stream, so this has its own message-pairing state machine. Each resolves to
  `{ segments: [{stid, segmentId, direction, time, offset, length, data}, ...],
  reachedEnd }`; `splitSegments` (module-private) reconstructs each segment's own
  zero-copy `Uint8Array` view from the one combined binary frame using each entry's own
  (non-cumulative) `length`, walked in array order. Backs `chunkSegments.js`/
  `frameSegments.js` (see "Byte-budgeted segment buffer" below) — not yet called from any
  view.

**Tamper tab (`TamperView.js`, `TamperStreamsList.js`, `TamperQueueList.js`, `TamperDetailPanel.js`, `tamperApi.js`):**

Deliberately a separate top-level tab from Analysis: the two have fundamentally different
shapes (Analysis is a virtualized browse of long, mostly-static history; Tamper is a
small, constantly-draining live decision queue). Scoped to a single proxy's `tamper`
instance (canonical `/api/i/tamper/...`), same simplification `tapctl` makes.

- **Layout** (`TamperView.js`, top to bottom): toolbar (connection status, manual
  Reconnect button — no auto-retry — "Auto-intercept new connections" checkbox, manual
  Refresh button) → body (`TamperStreamsList` fixed-width left panel + `TamperQueueList`
  flex:1 right panel) → `ResizeHandle` (orientation `h`) → `TamperDetailPanel` (bottom,
  resizable height via `layout.js`'s `tamperDetailHeight`, same pattern as `bottomHeight`).
- **State model — full resync on every push event, not incremental patching.** `TamperView`
  holds `streams` (the latest `stream-list` array) as the single source of truth;
  `stream-created`/`stream-terminated`/`held` all just trigger a fresh `listStreams()` call
  rather than hand-patching local state, since `list-streams`'s `pending` array is already
  a complete snapshot. `handleRelease`/`handleDropConnection` also resync after their own
  successful call (a `drop` produces no push event at all, so without this the queue would
  keep showing an already-released buffer).
- `queue` is derived (`useMemo`) from `streams`: one entry per `(conn, direction)` with
  something held, summarized as `{chunks, length}` (not one entry per chunk — see
  `intercept/tamper/protocol.go`'s `pendingInfo`), sorted by `conn`/`direction`.
  `selectedKey` is kept valid by an effect keyed on `queue`: if the selected buffer fell
  out (released, timed out, stream gone) or nothing is selected, it auto-selects the new
  first item — both the initial selection and the post-release auto-advance.
- **`tamperApi.js`**: `openTamperControl(handlers)` wraps the single control WebSocket.
  Replies are matched **by `type`, not by "the next message in"** — the server can
  interleave a push event with the `ok`/`error`/`stream-list` reply to whatever command
  was just sent. `ok`/`error` resolve or reject the one in-flight command promise;
  `held`/`stream-created`/`stream-terminated` always route to their handler; `stream-list`
  does both. Returns `{ setAutoIntercept, setMode, listStreams, release, dropConnection,
  close }`; `release(conn, direction, opts, editedBytes?)` mirrors the server's combined
  edit+release command (`opts: {action, releaseChunks, edited, prefixLength, bounds}`),
  sending the JSON command then the binary frame when `opts.edited` is set.
  `dropConnection(conn, direction)` is a separate command, matching the backend split.
- **`peekBuffer(conn, direction, offset?, length?)`**: a direction's held bytes are
  fetched via a short-lived `/watch` connection per selection (open → `peek` → collect
  reply → close), not a persistent per-stream socket. The server always replies with
  exactly one `pending`+binary pair (or a single `error` for an invalid direction) — a
  direction with nothing held is a normal zero-length reply. `TamperDetailPanel` always
  fetches the whole buffer; slicing exists in the wire protocol but isn't used here.
- **`listFs`/`readFs`/`writeFs`/`appendFs`**: plain REST wrappers over `fs.go`'s endpoints,
  not WebSocket-based (fs-root access has no relation to the control connection's
  lifecycle). `path` segments are percent-encoded individually (`encodeFsPath`) so literal
  slashes survive as separators. `appendFs` sends `POST` (non-idempotent); everything else
  here is `GET`/`PUT`.
- **`TamperStreamsList.js`**: one row per stream (conn/src/dst) with an intercept/watch
  checkbox calling `setMode` — the only place a watched stream can be escalated into
  intercept mode.
- **`TamperQueueList.js`**: one row per `(conn, direction)` with something held — chunk
  count + byte length. Click sets `selectedKey`.
- **`TamperDetailPanel.js`**: placeholder when nothing selected; otherwise fetches the
  whole buffer via `peekBuffer` in an effect keyed on `[entry.conn, entry.direction,
  entry.length, entry.chunks]`, plus **Forward** / **Drop** / **Drop Connection** / **New
  Chunk…** and a cog-icon **Settings** button. Settings (dismissed via
  `useDismissOnOutsideClick`, same mechanism as `ctxMenu`) holds the **Continuous view**
  toggle (default off — segmented) and a **Hex editor mode** select (`editMode`,
  `'insert'`/`'overwrite'`) forwarded as the `overwrite` prop to every editable
  `<${HexEditor}>` this panel renders.
  - **Canonical state is `chunks: Uint8Array[]`, not a flat byte array** — one entry per
    original chunk boundary. Both view modes are projections of it: `splitByBounds(data,
    bounds)` builds it from a `peek` reply, `mergeUint8Arrays(chunks)` flattens it back for
    submission or the continuous view, `boundsFromChunks(chunks)` derives the wire
    `bounds` field — this is what makes split/merge/drop/insert straightforward array
    splices on `chunks`.
  - **Segmented view (default)** renders one independent `<${HexEditor}>` per entry of
    `chunks`, each fed just that chunk's own byte slice with a `.tamper-chunk-header`
    above it — offsets come out chunk-local for free since `HexEditor.js` already renders
    relative to whatever `bytes` it's given. Editing inside one block only replaces that
    one entry of `chunks`.
  - **Continuous view** is a single flat editor over `mergeUint8Arrays(chunks)`, whose
    `onChange` collapses `chunks` down to one entry — editing across former chunk
    boundaries has no well-defined per-chunk meaning, so structure is discarded on edit
    rather than guessed at.
  - **Release submission doesn't care which view mode was used** —
    `releaseChunks: edited ? chunks.length : originalChunks.length`, `bounds: edited ?
    boundsFromChunks(chunks) : []`. This toolbar path always releases everything currently
    in `chunks`; releasing just the first one is the context menu's per-chunk Forward
    (`forwardFirstChunk`), not a toolbar affordance.
  - **Live updates vs. not clobbering an in-progress edit:** the selected entry's live
    `chunks`/`length` double as a staleness signal (`TamperView` already resyncs `streams`
    on every push event). A `selKeyRef` distinguishes a genuine selection change (always
    reload) from the same selection's data changing (auto-reloads only if the buffer is
    still unedited); otherwise a `.tamper-stale-banner` offers "Refresh (discards your edit)".
  - A single Forward/Drop pair compares `chunks` against `originalChunks` to decide
    `edited`. Buttons disable while a release is in flight, while loading, on a load
    error, or when nothing is left to act on. **Drop Connection** is separate, calling
    `onDropConnection` directly — connection-scoped, not buffer-scoped.
  - **Per-chunk context menu** (`ctxMenu`, right-click within a chunk's block): Drop /
    Forward / Split / Merge (front/back) / Insert Chunk Before / Insert Chunk After,
    following `heldBuffer`'s structural constraints (Forward only for chunk 0, Split only
    at an interior byte position, Merge only when the neighbor exists). All are pure local
    edits to `chunks` except **Forward** (`forwardFirstChunk`), which releases just chunk 0
    over the network, leaving the rest held.
  - **Creating a chunk** (`insertChunk`/`InsertChunkPopover`): the toolbar's **New
    Chunk…** button or the context menu's Insert Before/After open the same popover — pick
    a Format (`Empty`/`Plain`/`Hex`/`Base64`/`Hexdump`) and, if not `Empty`, a Source
    (`Clipboard`/`File`). Hex/Base64 decoding reuses the Transform panel's
    `OPERATIONS['hex-decode']`/`['base64-decode']`; Hexdump goes through `format.js`'s
    `parseHexdump()`.

**Scripted interception (`scriptRuntime.js`, `TamperScriptsPanel.js`, `ScriptEditor.js`) —
"Scripts" sub-tab:** runs one user script in a Web Worker as a programmatic stand-in for a
human clicking around `TamperQueueList`/`TamperDetailPanel`. Entirely a frontend feature —
nothing on the Go side executes a script (see `intercept/tamper/CLAUDE.md`'s "Script
storage" section). `TamperView` has a second-level tab bar (**Intercept** / **Scripts**);
only one is mounted at a time, but the running script, its log, and paused entries are
lifted to `TamperView` so they survive switching away and back.

For the full `tamper`/`ctx` script-facing API (every method, params, examples),
architecture, and execution semantics (event coalescing, pause/continue, error
handling, worked examples), see [`doc/interceptor/tamper.md`](../doc/interceptor/tamper.md).
This section is implementation notes only:

- **Loading**: `BOOTSTRAP` (the Worker's actual entry point) and the script are two
  separate Blobs, not one concatenated file, so a script syntax error can't prevent
  `BOOTSTRAP` from initializing `self.tamper`/`self.onmessage`/error listeners; each Blob
  ends with its own `//# sourceURL=...` for correct DevTools stack traces.
- **RPC bridge**: most `tamper.*` methods (`peek`/`release`/`dropConnection`/
  `setIntercept`/`listStreams`, all of `fs.*`) post a `call` message to the main thread
  (`createScriptRuntime`'s `handlers`), which performs the real operation and posts back
  a `result` — the Worker has no direct network access from a Blob URL.
- **`tamper.transform.*`/`tamper.encode.*`/`tamper.decode.*` are the exception**: they run
  directly inside the Worker (`BOOTSTRAP` dynamically imports `transforms.js`/`format.js`
  by absolute URL), synchronous once a `ready` flag flips after that import finishes — a
  script's own hook handlers never observe them as unpopulated; a call made at the
  script's own top level before that returns a `Promise` instead.
- **Per-connection event serialization**: all events for one `conn` go through a per-conn
  FIFO queue; different `conn`s run independently. Consecutive still-queued `onReceive`
  entries for the same `(conn, direction)` are coalesced into one dispatch.
- **Pause/Continue**: `ctx.pause()` suspends until a human clicks Continue in the
  Intercept sub-tab; if the connection terminates while paused, the pending promise is
  rejected immediately so the per-conn queue can still advance.
- **Error handling**: a syntax error in the script's own source kills the Worker
  permanently (reported, then `stop()`); an exception thrown inside a handler is caught
  per-event without stopping the Worker. Losing the control connection also stops the script.
- **`TamperScriptsPanel.js`** is CRUD over the REST script store plus Run/Stop wired to
  the lifted runtime state.
- **Log panel** (Download/Clear, or **"Logged to `<filename>`"** in place of Download when
  `log-file` is configured) — see `doc/interceptor/tamper.md`'s "Logging" section for the
  persistence/"Skip browser log" behavior.
- **`ScriptEditor.js`** wraps a CodeMirror 6 `EditorView` (syntax highlighting, bracket
  matching, folding, `tamper.*`/`ctx.*` autocompletion via `@codemirror/lang-javascript`'s
  `scopeCompletionSource` — vendored into `codemirror.module.js`, see that file's header —
  run against never-called mirror objects rather than the real API surface). Semi-controlled,
  same contract shape as `HexEditor.js`: `<${ScriptEditor} value onChange loadVersion
  readOnly? />` — `value` is only pushed back into CodeMirror when the caller bumps
  `loadVersion`, never inferred from `value` changing on its own. `readOnly` is applied
  through a `Compartment` rather than a remount.

**Framer scripts (`dbdumpFramerApi.js`, `frameRuntime.js`, `framerRun.js`,
`framerPrefs.js`, plus `App.js`'s View-menu entry and `TrafficView.js`'s "Framer"
control):** reassembles a stream direction's raw chunks into logical frames via a
user-authored script, persisting the result server-side (dbdump's
`frames`/`frame_progress` tables — see `intercept/dbdump/CLAUDE.md`'s "Framer scripts"
section) so a stream can be viewed partitioned by frame instead of by raw chunk at
near-zero repeat cost once cached. Full design in
[`doc/design/packet-dissector.md`](../doc/design/packet-dissector.md).

Frame view merges both directions into one scroll, the same way the raw-chunk view
already does via `chunks.stid` — see `intercept/dbdump/CLAUDE.md`'s "Framer scripts"
section ("Cross-direction interleaving") for the backend half (`frames.stid`,
`listFramesTimeline`, why ties are routine and how pagination avoids splitting one).
Known gaps here (buffer-trimming eviction not group-aware, large-frame byte-payload
pagination, no empty state for zero-result frame view) are tracked in the root
`CLAUDE.md`'s TODO section, not repeated here.

Confirmed working end-to-end in a real browser (2026-08-05) against
`examples/dbdump/framer/tls-framer.js`, a TLS record-layer framer — real frames
rendered, merged/interleaved across both directions.

- **Script contract**: a plain top-level `function frame(state, chunk)`, no registration
  call — unlike tamper's `tamper.register(hook, fn)`, there's only one hook, so a bare
  global function is simpler and matches the (not-yet-built) dissector stage's `dissect`
  convention (see the design doc). `chunk` is `{offset, length, direction, data}` — one raw
  chunk, in stream order, for the one direction being framed; `direction` (`'c2s'`/`'s2c'`,
  `direction.js`'s `dirToStr` — same convention `scriptRuntime.js` uses for its own
  script-facing API) is fixed for the whole run but carried on every chunk anyway, so a
  script covering both sides of an asymmetric protocol (one script, run once per
  direction) can branch on it. Returns `{frames, state}` (or nothing,
  to mean "no new frames, state unchanged"); each frame is `{offset, length, meta?}`.
  `state`/`meta` are always plain JSON-serializable JS values from the script's point of
  view — a script never sees bytes or base64 for either, even though `frame_progress.state`
  is a BLOB column and `frames.meta` is TEXT (`dbdumpFramerApi.js` encodes/decodes both at
  the wire boundary: `state` → JSON → UTF-8 bytes → base64 for the BLOB; `meta` → JSON text
  directly, since the column is already TEXT).
- **`frameRuntime.js`** runs the script in a Worker via the same two-Blob-plus-`sourceURL`
  loading technique `scriptRuntime.js` uses (see that file's header comment) — but
  **not** that file's IIFE-wrapping of the script Blob: the framer contract looks
  `frame` up by *name* (`typeof frame`/`frame(...)`, unlike tamper's side-effecting
  `tamper.register(...)`), and an IIFE would trap the script's `function frame(...)`
  declaration in its own local scope instead of the global one BOOTSTRAP looks it up
  in — always failing with "framer script must define a top-level function named
  'frame'" regardless of the script's actual content (a real bug this shipped with
  briefly; fixed by dropping the wrapper entirely, safe since BOOTSTRAP's own internals
  are already scoped inside its own separate IIFE).
- No RPC bridge: a framer script is a pure function over bytes
  already fetched onto the main thread, so there's no `peek`/`release`/network access from
  inside the Worker at all, unlike tamper's scripted interception. The only messages are a
  batch/ack cycle: `runFramer(scriptName, scriptSource, initialState, chunks, onBatch)`
  posts every chunk in one message; the Worker loops over them calling `frame()`, and posts
  a `{frames, state, processedOffset}` batch back every `BATCH_FRAMES` (500) frames or
  `BATCH_BYTES` (2 MB) processed, whichever comes first (plus a final batch, even if
  empty, so a trailing state-only advance still persists) — `onBatch` must return a
  Promise, and the Worker waits for it to resolve (`{kind:'continue'}`) before computing
  the next batch. This is what lets the caller apply backpressure and stop immediately
  (nothing further computed) if a batch fails to persist. A script that never defines
  `frame`, or throws, rejects `runFramer`'s promise; so does an `onBatch` rejection (e.g. a
  409 from `appendFrames`) — in every case the Worker is torn down immediately, not asked
  to wind down gracefully.
- **`framerRun.js`**'s `catchUpFramer(sessionId, streamId, direction, scriptName,
  scriptSource)` (plain scalar ids, matching every other `api.js` wrapper — not whole
  session/stream objects) is the orchestration: fetches `frame-progress` (how far framing has
  gotten, plus the framer's own persisted `state`) and `/chunklist`'s length for the target
  direction; if already caught up, resolves immediately having fetched nothing further.
  Otherwise fetches the missing tail via `api.js`'s `fetchDirectionChunks` (unbounded — see
  its own entry above) and runs it through `runFramer`, tagging each returned frame with
  the `stid` *and* `time` of whichever raw chunk contains its last byte (a frame has no
  timestamp of its own, since it's computed, not captured) before calling `appendFrames`
  after each batch with a running `expectedOffset` tracker. `scriptVersion` (sha256 hex of
  `scriptSource`, via `sha256Hex` — also exported) is computed once per call, not passed
  in, so every caller derives it identically. Idempotent and safe to call repeatedly —
  `TrafficView.js`'s live-tailing effect (below) calls it again on every central-poll
  tick while a stream with an active framer is still growing.
- **`framerPrefs.js`**: two `localStorage`-backed preferences, deliberately **not** the
  same in-memory-only mechanism "remember stream position" uses (App.js) — these survive
  a reload. `loadDefaultFramerScript`/`saveDefaultFramerScript` (one global default,
  driven by the View menu's new "Default framer" entry) and
  `loadStreamFramerScript`/`saveStreamFramerScript` (per-`session:streamId` override;
  reading falls back to the default when a stream has no override of its own yet — once
  it does, the two are independent).
- **`TrafficView.js`'s "Framer" control** (in the stream meta bar) and the frame-view
  toggle:
  - `frameState`: `'raw'` | `'framing'` | `'framed'` — **never persisted**, always starts
    at `'raw'` on a stream (re)selection; only the *script selection* survives that (via
    `framerPrefs.js`). Entering `'framed'` is always an explicit "Run" click (never
    automatic just from picking a script) — **blocking**: the raw view stays up, "Run"
    shows "Framing…" and is disabled, until `catchUpFramer` resolves for both directions
    (`Promise.all`) or throws. On success the picked script is also persisted as this
    stream's override; on failure, `frameState` falls back to `'raw'` and the message
    surfaces via a `.error-msg` banner at the top of `.traffic-body`, above the hex view.
  - Once `'framed'`, both directions are shown merged in one scroll (see
    `intercept/dbdump/CLAUDE.md`'s "Cross-direction interleaving" note for the backend
    half); "Show raw chunks" returns to `'raw'` without discarding anything (the
    raw-mode hook's own data was never torn down — only which of the two is rendered
    changes).
  - **Raw and frame mode run on two separate `useByteBuffer.js` instances** — see
    "Byte-budgeted segment buffer" above for the hook and its two adapters
    (`chunkSegments.js` for raw mode, `frameSegments.js` for frame mode); frame mode was
    the first migrated onto it, per that design doc's migration plan, raw mode followed.
    The frame-mode `entity` is a synthetic object (`{id: "streamId:scriptVersion", end,
    start, session, streamId, script, scriptVersion}`, `null` while not in frame view —
    the hook treats a `null` entity as "nothing to show" either way) rather than a real
    stream/session pair, unlike raw mode's (the real `stream` object); `start`
    (`stream.start`, added for the frame-mode migration) feeds `buildRows`' `relTime`
    calc. No `openStream`/`fetchPage`/`getId`/`buildRows` props for either instance —
    this file's old per-mode `fetchPage`/`getId`/`buildRows` (raw) and
    `frameFetchPage`/`frameGetId`/`frameBuildRows`/`openNullStream`/`sliceFrameBytes`
    (frame) are all gone, replaced by the two adapters' own
    `openConnection`/`fillForward`/`fillBackward` (see above).
  - **`ChunkHeader`'s `relTime` is unconditional** now (no longer the conditional-empty
    special case frame-view rows used to need) — `frames.time` is always populated, so
    `byteBufferCore.js`'s shared `buildRows` always sets it. See the "Chunk header" bullet
    under "Virtual scroll" above for the `⋯` continued-segment marker this migration also
    added to `HexDump.js`.
  - **Live-tailing (eager)**: a `useEffect` keyed on `latestStid` (the same prop the raw
    view already reacts to) calls `catchUpFramer` again for both directions whenever
    frame view is active, then bumps a `frameRefreshKey` fed into the frame-mode hook's
    own `refreshKey` — reusing its existing unconditional top-up path rather than
    inventing a `latestId`-style mechanism for frames (no per-stream "latest frame id" is
    available from `App.js`'s central poll the way `latestStid` already is for chunks).
    Best-effort: a transient failure here is swallowed and retried next tick, since a
    real failure was already surfaced by the initial Run.
  - Markers/extract-selection context-menu items are omitted in frame view (`HexDump.js`
    already hides those context-menu sections when their callback props are omitted) —
    a deliberate v1 scope cut, not a limitation of the offsets themselves (which are
    still real absolute stream offsets and would work if wired up later).
- **`App.js`**: fetches `listFramerScripts()` once (on mount and on Refresh — the same
  list backs both the View menu's "Default framer" entry and every `TrafficView`'s own
  per-stream picker), and owns the "Default framer" menu entry itself (a `<select>`
  inside a `.menu-item`, not the usual checkmark-toggle shape every other entry uses).
  Scripts must be added via `curl`/`tapctl` against dbdump's `/scripts` endpoints — no
  in-app editor yet (see the root `CLAUDE.md`'s TODO section).
