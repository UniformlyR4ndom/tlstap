# tlstap web frontend (`web/`)

Implementation notes for the web UI, loaded automatically when working under this
directory. See the root `CLAUDE.md` for where this fits into the wider architecture —
`ApiProvider`/REST API mechanics ("REST API" section), the `dbdump` interceptor whose
REST API `api.js` consumes (`intercept/dbdump/CLAUDE.md`), the `tamper` interceptor whose
control/watch WebSocket API and script-storage REST API back the Tamper tab and
"Scripted interception" below (`intercept/tamper/CLAUDE.md`), and the `core.fs`/`core.kv`
core services backing every script runtime's `fs.*`/`kv.*` (`core/CLAUDE.md`).

Served at `/ui/` by the API HTTP server. No build step — uses vendored ES modules loaded via an importmap.

**Technology:** Preact 10.25.4 + htm 3.1.1, vendored under `web/vendor/`. The importmap in `index.html` maps bare specifiers (`preact`, `preact/hooks`, `htm`) to the vendored files so the Preact hooks module (which imports bare `"preact"`) resolves correctly.

**Layout:** Insecure-context banner (below) → header bar (title + refresh button) → top-level tab bar (**Analysis** / **Tamper**, `App.js`'s `view` state) → for Analysis: menu bar → sidebar (sessions + streams) + main area (traffic view) + collapsible bottom panel; for Tamper: see "Tamper tab" below, an entirely separate layout with no sidebar/bottom-panel reuse.

**Insecure-context banner (`App.js`):** a plain `!window.isSecureContext` check (no state
— the value can't change during a session), shown above the header, in both tabs, while
true. `isSecureContext` is `false` whenever the page is served over plain HTTP to
anything other than `localhost`/`127.0.0.1` — several features the UI relies on
(`crypto.subtle`, used by `framerRun.js`'s `sha256Hex` for framer script versioning;
`showSaveFilePicker`/clipboard writes) are unavailable or throw outside a secure context,
so this exists to make that failure mode legible instead of a confusing runtime error the
first time one of those is used. No dismiss button — the condition doesn't change while
the tab is open, so hiding it would just mean the user forgets why something later fails.

**Menu bar (`App.js`, `index.html`):**
- `App.js` owns `openMenu` (null | `'view'`), `globalOffset` (bool, default `true`), `sizeFormat` (`'size'` | `'count'`, default `'size'`), `pinHeader` (bool, default `true`), and `rememberPosition` (bool, default `false`).
- A `mousedown` listener on `document` (active only while a menu is open) closes the menu when clicking outside `.menubar`.
- One menu: **View** → **Global offset** toggle, **View mode** (Single stream / Combined streams), **Size** / **Byte count** (chunk header banner's `sizeFormat`), **Pin header when scrolled past** toggle (`pinHeader`), **Remember stream position** toggle, **Remote framer runs** toggle (see "Remote framer job listener" below), **Remote dissector runs** toggle (see "Remote dissector job listener" below, an independent opt-in from the framer one), **Default framer** select, **Default dissector** select.
- `globalOffset`/`sizeFormat`/`pinHeader` are each passed down: `App` → `TrafficView`/`CombinedView` → `HexDump` (→ `HexRow` for `globalOffset` specifically).
- **Remember stream position** (single-stream view only): while on, `App.js` remembers the byte offset/direction at the top of the viewport per stream, in-memory only, keyed by `` `${session}:${id}` `` (stream `id` is only unique within a session). `selectStream(s)` looks up a saved position and jumps to it with `align: 'top'` instead of a plain `setStream(s)`; re-clicking the already-selected stream is a no-op. Switching **View mode** away and back doesn't auto-restore — only reselecting via the Streams list does.

**Refresh (`App.js`):** the header's `↺` button (`.btn-refresh`) increments `refreshKey`, a plain counter threaded into `SessionList`, `StreamList`, `TrafficView`, and `CombinedView`; each re-fetches whatever it owns when the value changes.

**Jump to top / bottom / next segment / previous segment (`App.js`, `.btn-icon`):** four
icon buttons placed left of Refresh. `App.js` owns `viewJumpRef =
useRef({jumpToTop: () => {}, jumpToBottom: () => {}})`, passed as `jumpRef` to both
`TrafficView`/`CombinedView` (mounted mutually-exclusively under `viewMode`); each
registers `jumpRef.current = {...}` in a dependency-array-free effect. `jumpToTop`/
`jumpToBottom` are a genuine `reloadFrom`/backward reload of the buffer, not a scroll over
already-loaded rows — `useByteBuffer.js` for `TrafficView.js` (both raw and frame mode),
`useChunkBuffer.js` for `CombinedView.js`. **`jumpToNextSegment`/`jumpToPrevSegment` are
`TrafficView.js`-only** (`useByteBuffer.js`, see below) — `CombinedView.js`'s registration
doesn't provide them, so those two buttons are `disabled=${viewMode !== 'single'}` and
called via `viewJumpRef.current.jumpToNextSegment?.()` (optional chaining, since Combined
view's own `jumpRef.current` object simply lacks the key rather than providing a no-op).

**Central live poll (`App.js`):**
- One `usePoll(true, POLL_INTERVAL_MS, tick)` call (`usePoll.js`, 500ms) is the single source of live-ness for the whole Analysis view — `SessionList`, `StreamList`, and whichever of `TrafficView`/`CombinedView` is mounted all react to its output rather than polling themselves.
- Each tick calls `getLatest(params)` (`api.js`), building `params` from current selection: `{session: session.id}` if a session is selected, plus `stream: stream.id` only when `viewMode === 'single'` and a stream is selected too. The raw `{latest_session_id, latest_sgid, streams_version, latest_stid}` response is stored as-is in a `latest` state object and passed down as four separately-named props: `latestSessionId` (`SessionList`), `streamsVersion` (`StreamList`), `latestStid` (`TrafficView`), `latestSgid` (`CombinedView`).
- `tick`'s closure captures `session`/`stream`/`viewMode` fresh from each render (`usePoll.js` reassigns `tickRef.current` unconditionally every render), so the poll always acts on the current selection with no separate ref-syncing.
- A failed `getLatest` call is silently swallowed; the next tick just retries. Each downstream consumer's own "did this number change" comparison treats an unchanged `latest` as a no-op, so a missed tick is invisible.

**Bottom panel (`App.js`):**
- `bottomTab` state: `null` (collapsed) | `'goto'` | `'markers'` | `'search'` | `'extract'` | `'transform'` | `'framing'`.
- `selectBottomTab(name)`: sets tab; does not toggle (panel only collapses via the `▼` button at the right of the tab bar).
- Tab bar contains: **Goto**, **Markers**, **Search**, **Extract**, **Transform**, **Framing**, and a collapse button (`▼`) on the right.
- Content area (`.bottom-content`, resizable — see "Resizable panels" below) renders `GoToPanel`, `MarkersPanel`, `SearchPanel`, `ExtractPanel`, `TransformPanel`, or `FramingPanel` based on `bottomTab` — see "Markers panel" and "Framing panel" below for the latter two.
- A `ResizeHandle` (`orientation="h"`) sits at the top edge of `.bottom-panel`, shown only while `bottomTab` is set (nothing to resize when collapsed).

**Session/stream list panels (`ListPanel.js`, `SessionList.js`, `StreamList.js`):**
- `ListPanel.js` is the shared panel chrome: `<${ListPanel} title items error? emptyMessage selected onSelect renderItem resetSortKey? />`. It owns the `desc` sort state (default `false` = ascending/oldest first), the `▼`/`▲` toggle button, the count badge, the sorted/mapped item list, and the empty-state line (`error`, if truthy, takes priority over `emptyMessage`). Callers own fetching the data and each item's row markup via `renderItem(item)`.
- `SessionList.js` fetches via `getSessions()` and never passes `resetSortKey`. `StreamList.js` fetches via `getStreams(session.id)` and passes `resetSortKey=${session?.id}`, which resets `desc` to `false` on session change without affecting a plain refresh.
- Both re-fetch whenever `refreshKey` changes, in addition to their own natural triggers (mount / session change) — this is what makes the Refresh button pick up newly-initiated streams and updated end-times/byte-counts.
- **Reacting to the central live poll**: `SessionList.js` takes a `latestSessionId` prop, `StreamList.js` a `streamsVersion` prop. Each owns a `lastSeenIdRef`/`lastSeenVersionRef` and two effects: a **seed effect** (keyed on its own natural triggers) that fetches and sets the baseline ref from the prop's current value without depending on the prop itself, and a **poll-reaction effect** (keyed on the prop) that re-fetches only on a genuine difference from the baseline. Seeding from the already-available prop value (rather than an extra round trip) is what keeps the next poll tick from spuriously re-fetching what the seed effect just fetched.

**Duration formatting:** `fmtDuration(start, end)` (`format.js`) — for finished streams (`end` set) formats `end - start`; for ongoing streams formats `Date.now() - start` and appends `" (ongoing)"`, e.g. `12.34s (ongoing)`.

**Resizable panels (`ResizeHandle.js`, `layout.js`, `useResizableLayout.js`):**
- `ResizeHandle.js` is a generic draggable divider: `<${ResizeHandle} orientation="v"|"h" onResize=${deltaPx => ...} />`. On `mousedown` it attaches document-level `mousemove`/`mouseup` listeners for the drag; each `mousemove` calls `onResize(ev.movementX)` (`v`) or `onResize(ev.movementY)` (`h`). The caller owns the resulting size state, clamping, and sign convention (a handle placed *after* the sized element treats a positive delta as "grow"; placed *before*, negative is "grow"). `onResize` is read fresh from props at `mousedown` time, never memoized.
- `layout.js`: `loadLayout()` / `saveLayoutValue(key, value)` read/write one `localStorage` key (`tlstap-layout`) holding `{ sidebarWidth, bottomHeight, encdecOptionsWidth, encdecInputHeight, tamperDetailHeight, scriptsListWidth, scriptsLogHeight, framerScriptsListWidth, dissectPanelWidth, dissectScriptsListWidth }`, merged with defaults on load. Also exports `clamp(v, lo, hi)`, used by the hook below and standalone by `TransformPanel.js`.
- `useResizableLayout(key, { sign = 1, min, max })` is what every panel below calls: reads `loadLayout()[key]` for the initial value, applies `clamp(v + sign * delta, min, max)` on each `onResize(delta)`, calls `saveLayoutValue(key, next)`, and returns `[value, onResize]`. `max` may be a plain number or a thunk (`() => number`) — the three window-relative panels pass `() => Math.floor(window.innerHeight * 0.7)` so the bound is re-read at drag time rather than baked in at render time.
- **Sidebar** (`App.js`): `useResizableLayout('sidebarWidth', { min: 180, max: 600 })` (default 280), handle between `.sidebar` and `.main`.
- **Bottom panel** (`App.js`): `useResizableLayout('bottomHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })` (default 160), handle at the top of `.bottom-panel` (only rendered while a tab is open). The Markers/Framing bottom tabs (below) have no resizable dimension of their own — they're sized entirely by this one, like every other bottom tab.
- **Transform panel** (`TransformPanel.js`): `useResizableLayout('encdecOptionsWidth', { min: 100, max: 400 })` (default 160, handle between the options column and the input/output column) and `useResizableLayout('encdecInputHeight', { min: 30, max: 2000 })` (default 120, handle between the input and output areas).
- **Tamper detail panel** (`TamperView.js`): `useResizableLayout('tamperDetailHeight', { sign: -1, min: 120, max: () => Math.floor(window.innerHeight * 0.7) })` (default 300), handle above `.tamper-detail-wrap`, same sign convention as the bottom panel's handle (also placed before the sized element).
- **Tamper scripts sub-tab** (`TamperScriptsPanel.js`): `useResizableLayout('scriptsListWidth', { min: 150, max: 500 })` (default 220, handle between the script list and editor) and `useResizableLayout('scriptsLogHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })` (default 160, handle above the log panel).
- **Framer Scripts sub-tab** (`FramerScriptsPanel.js`, via `ScriptsCrudPanel.js`): `useResizableLayout('framerScriptsListWidth', { min: 150, max: 500 })` (default 220) — same key shape as tamper's `scriptsListWidth` but its own persisted value, since the two script lists are independent. No log-height key here — `FramerLogPanel.js` is a separate bottom tab (Framing's own "Log" sub-tab), not a panel nested inside the Scripts sub-tab the way tamper's is.
- **Dissect Scripts tab** (`DissectScriptsPanel.js`, via `ScriptsCrudPanel.js`): `useResizableLayout('dissectScriptsListWidth', { min: 150, max: 500 })` (default 220) — same pattern as the framer's own, independent persisted value.
- **Tamper Framer Scripts sub-tab** (`TamperFramerScriptsPanel.js`, via `ScriptsCrudPanel.js`): `useResizableLayout('tamperFramerScriptsListWidth', { min: 150, max: 500 })` (default 220) — same pattern again, its own independent persisted value (distinct from dbdump's `framerScriptsListWidth` above, a different feature entirely — see "Tamper framer scripts" below).
- **Dissect panel** (`TrafficView.js`): `useResizableLayout('dissectPanelWidth', { sign: -1, min: 200, max: 800 })` (default 300), handle between `.hexdump-wrap` and `.dissect-panel` — placed *before* the sized element (the panel sits on the right), same sign convention as the bottom panel's and tamper detail panel's own handles above. `max` is larger than every other width panel's own fixed cap (500–600) since a single unscrolled `fmtAsHexdump` line (see `DissectPanel.js`'s multi-line value rendering, under "Dissector scripts" below) needs ~600px+ of monospace width on its own.
- All of the above apply their size via inline `style` (not fixed CSS) so the persisted value always wins.

**Outside-click/Escape dismissal (`useDismissOnOutsideClick.js`):**
- `useDismissOnOutsideClick(ref, onClose, active = true)`: while `active`, attaches document-level `mousedown`/`keydown` listeners — `mousedown` calls `onClose()` unless the click landed inside `ref.current`, `keydown` calls `onClose()` on `Escape` — removed on cleanup. `active` defaults to `true` for a popover only ever mounted while shown; callers that stay mounted pass their own boolean.
- Used by `TransformPanel.js`'s algorithm menu, `TamperDetailPanel.js`'s `ctxMenu`, and `InsertChunkPopover`.
- **`HexDump.js`'s context menu is a deliberate non-user**: it has no ref of its own, so its `.ctx-menu` container instead calls `onMouseDown={e => e.stopPropagation()}` to keep an inside click from reaching its own document-level close listener.
- The ref-contains check matters because `mousedown` fires before `click`: an unconditional close-on-any-mousedown would unmount a menu before a click on one of its own items ever reaches it.

**Virtual scroll (`HexDump.js`):**
- Exports `ROW_HEIGHT = 22`. Constants: `BUFFER = 8` (overdraw rows), `PREFETCH_FRACTION = 0.1`.
- Props: `rows`, `onScrollEnd`, `scrollAdjust`, `adjustVersion`, `scrollTo`, `scrollToVersion`, `globalOffset`, `onSetMarker`, `onClearMarker`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`, `onViewportChange`, `markers`, `sizeFormat`, `pinHeader`, `onHeaderClick`, `selectedHeaderKey`, `highlightRange` (the last three back the dissector panel — see "Dissector scripts" below).
- Encoding helpers imported from `../format.js` (not defined locally).
- Flattens all loaded chunks into a flat `rows[]` array: one `{type:'header'}` row + N `{type:'hex'}` rows per chunk.
- A `ResizeObserver` tracks container height; `onScroll` tracks `scrollTop`. Visible window is `[startIdx, endIdx)`. Inner div height = `rows.length * ROW_HEIGHT`; top/bottom spacer divs fill the rest.
- **Prefetch trigger** (`scrollend` event): fires `onScrollEnd(1)` when fewer than `rows.length * PREFETCH_FRACTION` rows remain below the viewport; `onScrollEnd(-1)` when fewer remain above.
- **Scroll correction** (`useLayoutEffect([adjustVersion])`): applies signed `scrollAdjust` to `scrollTop` synchronously before paint. Negative = scroll up (after front eviction); positive = scroll down (after prepend).
- **Absolute scroll** (`useLayoutEffect([scrollToVersion])`): clamps `scrollTo` to `[0, el.scrollHeight - el.clientHeight]` and sets both `scrollTop` and internal `scrollTop` state to that clamped value, synchronously before paint; `scrollToVersion` must change to trigger even if `scrollTo` is unchanged. Used by jump-to — the clamp is what lets `jumpToBottom()` pass a deliberately-oversized `scrollTo` and land exactly at the end without knowing the viewport height.
- **Global/local offset**: for chunk mode, `HexRow` displays `row.offset` (real
  stream-global byte offset) when `globalOffset` is true, or `row.localOffset` (offset
  within the chunk, resets to 0 at each chunk start) when false — `segment.offset` is a
  real per-direction position there, always.
  - **Frame mode addresses a frame entirely in its own virtual space instead — `row.offset`
    is not a real stream position there at all**, for any frame regardless of range count
    (see `frameSegmentsCore.js`'s module comment and `intercept/dbdump/CLAUDE.md`'s
    `frames.virtual_offset` note): `buildFrameWindow` always sets `segment.offset = 0`, so
    `localBase = loadedStart - segment.offset` degenerates to `loadedStart` itself — `row.offset`
    and `row.localOffset` become numerically identical (both the position within the
    frame's own 0-based concatenation of `ranges`), and byte identity (`byteOff = offset +
    i`, driving selection and dissector highlighting) is virtual too. This is fine, not a
    regression: `TrafficView.js`'s frame-mode `HexDump` instance already passes
    `markers=${[]}` and omits every marker/extract prop entirely (a real, pre-existing v1
    scope cut, not something this changed), and dissector highlighting/`collectChunkBytes`
    (`HexDump.js`) already derive their own base position from `row.offset` directly, so
    they inherit virtual addressing automatically and stay internally consistent with no
    separate change needed. `globalOffset` shows `row.virtualOffset ?? row.offset` — the
    per-direction *cross-frame* running total (`segment.virtualOffset`, present only for
    frame-mode segments — `chunkSegments.js` never sets it, so chunk mode's `??` always
    falls through to its own real `offset`) plus the within-frame virtual position, i.e.
    `segment.virtualOffset + localBase + off` — computed in `buildRows` with no
    frame/chunk-mode branching of its own. `??`, not `||`, since a direction's very first
    frame legitimately has `virtualOffset: 0`.
- **Byte selection**: `sel` state `{direction, start, end}` (byte offsets, inclusive). `onMouseDown` starts selection; `onMouseMove` extends it if same direction as anchor; document-level `mouseup` ends drag. Per-byte `<span data-off=N data-dir=D>` elements carry `.sel-hl` class when highlighted. Selection is scoped to one direction (cannot drag across c2s/s2c boundary).
- **External highlight** (`highlightRange` prop, `null | {direction, start, end}`, inclusive like `sel`): driven from outside `HexDump.js` itself, not by any mouse interaction inside it — rendered via its own `.range-hl` class alongside (not replacing) `.sel-hl`/marker classes, so a byte under more than one at once shows all of them. Two independent sources feed it, one per `HexDump` instance: `TrafficView.js`'s frame-mode instance gets `dissectHighlight`, set by clicking a field node in `DissectPanel.js` (see "Dissector scripts" below); its raw-mode instance gets `searchHighlight`, set from a search-result jump's `jumpTo.highlight` (see "Search panel" below).
- **Byte markers**: `markedC2S` / `markedS2C` — `Set<offset>` derived from `markers` prop. Marked bytes receive `.hex-byte-marked` / `.asc-byte-marked` CSS classes.
- **Chunk header** format: `[+T.TTTs] [#stid] DIRECTION  #chunkId  N B` (stid shown when present; stream number shown in CombinedView), where the size field is `fmtByteSize`'s or `fmtByteCount`'s output depending on the `sizeFormat` prop (`'size'`/`'count'`, App.js's View-menu toggle — see "Menu bar" above). A `⋯ ` prefix (plus a `title` tooltip) marks a `row.continued` header — the byte-budgeted segment buffer's loaded window doesn't start at the segment's own offset, so the real header is further up, out of the loaded range (only possible in `TrafficView.js`'s frame mode today, for a still-growing huge frame).
- **Pinned header** (`pinHeader` prop, App.js's View-menu toggle, default on): when the chunk header for whatever row sits at the very top of the viewport has itself been scrolled above it, a second copy is rendered pinned to the top via `position: sticky` inside a zero-height wrapper (`.chunk-hdr-pinned-wrap` — contributes no height to the flow, so it doesn't perturb `topSpacer`/`scrollHeight` math elsewhere) — `.chunk-hdr-pinned`'s own class adds an opaque background/shadow/border so it reads as floating above the rows scrolling underneath, plus a `▲ ` prefix and a distinct tooltip. `headerRowIdxs` (`useMemo`, keyed on `rows`) + a binary search (`lastHeaderIdxAtOrBefore`) finds it in O(log n) rather than scanning back through however many rows the current segment has. Clicking it calls `scrollToRow` to jump back to the real header; its own `onContextMenu` stops propagation so a right-click there doesn't get misattributed to whatever row is underneath at that screen position (the container's context-menu handler maps click position to a row via `scrollTop`, which doesn't account for the pinned banner's fixed on-screen position).
- **Frame selection for dissection** (`onHeaderClick`/`selectedHeaderKey` props, frame mode only — `TrafficView.js` is the only caller that passes them): a plain (non-pinned) header row's `onClick` calls `onHeaderClick(row, collectChunkBytes(idx))` — reuses the same `collectChunkBytes` the right-click "copy as hex" menu already computes, so no second byte-collection implementation exists. `headerKey(row)` (`` `${row.direction}:${row.chunkId}` ``, unique within one direction/frame-mode entity) compared against `selectedHeaderKey` adds `.chunk-hdr-selected`; `onClick` being set at all adds `.chunk-hdr-clickable` (cursor). The pinned header keeps its own separate `onClick` (`scrollToRow`) unconditionally — the two behaviors don't share one element. See "Dissector scripts" below.
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
Bounds memory for an arbitrarily huge single frame/chunk via a byte budget (not an item
count) — the scrollbar thumb size stays roughly consistent regardless of how a stream
happened to be chunked, except when the segment-count cap (not the byte cap) binds.
`chunkSegments.js` (raw-chunk mode) and `frameSegments.js` (frame mode) are the two
adapters; entity is the real `stream` object for raw-chunk mode, a synthetic one for
frame mode. `CombinedView.js` remains on `useChunkBuffer.js`/`buildRows`, unmigrated — see
root `CLAUDE.md`'s TODO; `useChunkBuffer.js` itself isn't touched until nothing
references it.

- **`byteBufferCore.js`** (pure, no Preact import — kept separately testable with Node's
  plain test runner via `byteBufferCore.test.js`, the same reason `format.js`/
  `transforms/*.js` stay framework-free): the `Segment`/`SegmentWindow` model, `buildRows`
  (the shared row-builder frame mode now uses in place of the deleted `frameBuildRows` —
  `relTime` is unconditional, since `segment.time` is always present for both entity
  types; `ChunkHeader` in `HexDump.js` no longer special-cases a missing one), `evict`
  (byte-budgeted, row-aligned mid-segment trimming — fixes the tied-`stid`-group eviction
  gap the old chunk-count model had), `idsAtStid` (every segment id already loaded at a
  given stid, scanning inward from whichever buffer edge is being extended — a stid can
  hold more than one segment, a tied group, so an adapter requerying that stid needs the
  whole set, not just the most recently finished one, to avoid re-surfacing an
  already-consumed sibling as "new"), `fillToTarget` (the quantized fill loop driving an
  adapter's `fillForward`/`fillBackward` toward a target, with generation-based
  cancellation between quanta; optional trailing `mustReachStid` param keeps it looping —
  using full `WINDOW_STEP`/`SEGMENT_STEP` quanta rather than the shrinking, potentially
  negative remaining-budget clamp `selectByBudget` can't handle — past `targetBytes`/
  `targetSegments` until a segment with that stid is actually loaded, bounded by
  `MAX_BUFFERED_BYTES`/`MAX_BUFFERED_SEGMENTS` regardless so an unreachable target can't
  grow the buffer without limit; backs `TrafficView.js`'s jump effect, see below),
  `windowIndexAtRow`/`rowIndexOfWindow` (row↔segment-index
  lookups over `windows`, using the same per-window row-span math `buildRows` does — back
  `useByteBuffer.js`'s `jumpToNextSegment`/`jumpToPrevSegment`, the same role
  `HexDump.js`'s own `headerRowIdxs` binary search plays for its pinned-header feature,
  just exposed at the level that can also decide to fetch).
- **`useByteBuffer.js`**: the Preact hook wrapping that core — same external contract as
  `useChunkBuffer.js` above (`display`, `loading`, `error`, `setError`, `handleScrollEnd`,
  `reloadFrom`, `displayRef`, `jumpToTop`, `jumpToBottom`, plus `jumpToNextSegment`/
  `jumpToPrevSegment` and `reloadCenteredOn` — see below), so migrating a view onto it is
  meant to be a small change. Caller props shrink to `{entity, refreshKey, openConnection,
  fillForward, fillBackward, isClosed, latestId, hasPendingJump}` — no `fetchPage`/`getId`/
  `buildRows`, since pagination is now the adapter's own concern and row-building is
  shared. `hasPendingJump` (optional, only `TrafficView.js`'s raw-mode instance passes it)
  makes the "reload from stid 0 on entity change" effect skip itself for the one render
  where a caller-owned jump is about to load this same entity instead — see the jump
  effect's own note below for why.
- **`reloadCenteredOn(targetStid, {computeExtra})`**: what a jump-to-stid caller uses
  instead of `reloadFrom` — one backward `fillToTarget` ending just before `targetStid`
  (leading context, capped at half the normal fill target) and one forward `fillToTarget`
  starting *at* it (`mustReachStid: targetStid` as a defensive backstop only — the very
  first candidate a forward fill from `targetStid-1` sees already *is* `targetStid`, so
  this resolves in essentially one round trip per direction), run concurrently via
  `Promise.all`, merged into one `windows` array once both settle. Exists because
  `reloadFrom`'s own boundary-plus-walk-forward shape doesn't fit a jump: centering via a
  segment-count-computed start (`targetStid - FILL_TARGET_SEGMENTS/2`, clamping to 0 for
  anything not deep into the stream) can be genuinely far from the target in *byte* terms
  for realistic chunk sizes, turning a jump into a long chain of `WINDOW_STEP`-sized
  quanta just to reach it — even though the server resolves a query at any stid directly
  (an indexed `WHERE stid >= start` lookup) with no need to walk through everything
  before it.
- **`reloadInFlightRef`**: true for a `reloadFromBoundary`/`reloadCenteredOn` call's whole
  span (cleared in its `finally`, only if still the current generation) — distinct from
  `loadingMoreRef`'s narrower "an incremental top-up/scroll-fill is in flight" meaning,
  which both of those explicitly set `false` at their own start (a full reload isn't an
  incremental one). `topUp()` checks both: without this, a live-poll tick or Refresh click
  landing in a reload's async gap reads `windowsRef.current` as the reload's momentarily-
  empty `[]`, fetches its own small forward-from-0 result under the reload's own (not yet
  superseded) generation, and can commit *after* the reload's own final `setDisplay` —
  silently overwriting its correct rows with a bogus one while leaving its
  `scrollTo`/`scrollToVersion` pointing at a row that's no longer there. Most likely to
  bite when jumping around in a stream that's still actively growing.
- **`jumpToNextSegment(currentRowIndex)`/`jumpToPrevSegment(currentRowIndex)`**: jump to
  the segment right after/before whatever row the caller says the viewport is currently
  showing (`TrafficView.js` derives this from its own `scrollTopRef`, see above — the hook
  has no scroll-position awareness of its own). Already-loaded neighbor
  (`windowIndexAtRow`/`rowIndexOfWindow` locate it): instant, `scrollTo`/`scrollToVersion`
  only, no fetch. Not loaded yet: `fetchAndJump` asks for exactly one more segment via
  `fillToTarget` (`targetSegments: 1`, `targetBytes: Infinity` — segment count alone ends
  the fetch, not a byte budget) and scrolls to it once it arrives. Passes a *synthetic*
  stand-in for the current edge segment, reported as fully loaded via `isWindowFull`
  regardless of its real state, so a tied-aware adapter (`frameSegments.js`) treats it as
  settled and looks for what comes next/before instead of extending its own byte range —
  jumping past a still-loading huge segment shouldn't have to wait for it to finish first
  (`idsAtStid`, called inside `fillToTarget`, still sees the segment's real entry in the
  actual `windows` array passed alongside the stand-in, so a tied sibling at the same stid
  is still found rather than mistaken for "already past"). `isWindowFull`'s own
  end-boundary-only limitation (root `CLAUDE.md`'s TODO section) doesn't affect this —
  `fetchAndJump` wants exactly that "treat as settled" behavior anyway.
- **Adapters** — one per entity type, each implementing `openConnection`/`fillForward`/
  `fillBackward`. Both built on two dumb, shared REST primitives — see
  `intercept/dbdump/CLAUDE.md`'s "POST `/byte-ranges`"/"POST `/chunks/timeline`" sections
  for the full wire format: `fetchByteRanges` (`api.js`) for
  arbitrary byte-range fetching (no frame-awareness, no dedup — two entries may
  legitimately reference overlapping/identical bytes, resolved independently), and a
  metadata-only timeline listing per entity type (`listChunksTimeline`/
  `listChunksTimelineBackward` for chunks, the pre-existing `listFramesTimeline`/
  `listFramesTimelineBackward` for frames). `openConnection` is now a no-op stub for both
  adapters (no real connection to open) — kept only for the adapter contract's shape and
  so a fake can be injected in place of `api.js`'s real network calls in tests.
  - **`chunkSegments.js`**: lists candidates via `listChunksTimeline`/
    `listChunksTimelineBackward`, applies `selectByBudget` client-side (the same function
    frame mode uses — no second, server-side copy of the budget discipline the way the old
    `/segments` handler had), then fetches each selected chunk's own `(offset, length)` via
    `fetchByteRanges`. Every returned window is still always fully loaded — a chunk row's
    data is one complete, immutable blob, so its own declared range can never come back
    short — but `resumeWindow`/`excludeIds` are now genuinely unused and dropped from the
    adapter's params entirely (chunks never tie on `stid`). Tested via a fake handle
    (`chunkSegments.test.js`) implementing `listChunksTimeline`/`listChunksTimelineBackward`/
    `fetchByteRanges`, sidestepping `api.js`'s real `fetch()` calls.
  - **`frameSegments.js`** / **`frameSegmentsCore.js`**: metadata via `/frames/timeline`
    (`dbdumpFramerApi.js`'s `listFramesTimeline`/`listFramesTimelineBackward`), bytes via
    `fetchByteRanges`. **A frame is addressed entirely in its own virtual coordinate
    space, not real stream positions** — see `frameSegmentsCore.js`'s module comment and
    the "Global/local offset" note above: a frame is its own independent, always-
    contiguous 0-based concatenation of its `ranges`, regardless of how many it has or
    where they physically sit (two frames' real ranges may legitimately overlap; each is
    fetched/rendered fully independently, matching `/byte-ranges`' own no-dedup design).
    This is what lets `byteBufferCore.js`'s generic offset/length arithmetic
    (`buildRows`, `isWindowFull`, etc.) keep working completely unmodified for a
    multi-range frame — `SegmentWindow.segment.offset` is simply always `0` for a
    frame-mode window (`buildFrameWindow`), never a real position. `virtualRangeToReal`
    is the one function that maps a virtual sub-window back onto the real
    `(offset, length)` spans actually needed to fetch it (one entry per real range it
    overlaps — a single-range frame always yields exactly one, byte-identical to a direct
    real request); `frameSegments.js`'s `fetchFrameWindows`/`extendResumeWindow` batch
    every included/extending frame's own real entries into one `/byte-ranges` call and
    concatenate each frame's own slice of the response (`mergeUint8Arrays`, skipped for
    the common single-entry case) into one virtual bytes buffer per frame. No offset→stid
    resolution and no covering-whole-chunk over-fetch either way (`sliceFrameBytes`/
    `fetchDirectionRange`/`getByteStid` are gone entirely — a byte-range fetch can name an
    arbitrary span itself now, unlike the old `/segments`, which only ever served whole
    raw chunks).

    Split the same way `useByteBuffer.js`/`byteBufferCore.js` is: `frameSegmentsCore.js`
    holds the pure selection/range math — `selectByBudget` (accumulate whole frames until
    the budget would be exceeded, by `f.length` — a permanent, always-well-defined
    `sum(ranges[].length)`, not itself shimmed; a single oversized first candidate is
    still included, but only partially, and nothing further is added that round) and the
    forward/backward anchor asymmetry in `initialWindowRange` (now anchored at the
    frame's own virtual `0`/`f.length` rather than a real position — a huge frame's first
    partial load anchors at the segment's *start* when opened while scrolling forward
    into it, so later extension grows `loadedEnd`; anchors at the segment's *end* when
    opened scrolling backward into it, so later extension shrinks `loadedStart` instead —
    in both cases the loaded window grows toward whatever's already visible), and
    `excludeAlreadyLoaded` (drops every id in a given set from a `stid`-inclusive
    `/frames/timeline` fetch, turning it back into "only what's genuinely new") — tested
    directly (`frameSegmentsCore.test.js`, including a dedicated `virtualRangeToReal`
    suite: single/multi-range windows, a window spanning a real-range boundary, one fully
    inside a non-first range). `frameSegments.js` is the thin async glue calling the real
    REST endpoints, now also tested directly via a fake handle (`frameSegments.test.js`)
    covering the `/byte-ranges` call shape for included/oversized/extend-resume cases,
    including multi-range fetch/concatenation and cross-range extension specifically —
    `rangesByDirection` (the old per-direction-batched byte-range computation) was deleted
    as dead code once each frame started requesting its own range independently.
    `fillForward`/`fillBackward` query `/frames/timeline` inclusively (not the usual
    exclusive "+1" cursor) whenever `resumeWindow` is given, since a tied-stid group's
    members can't all be resolved in one round — `excludeIds` (from `idsAtStid`, above)
    plus `excludeAlreadyLoaded` turn that back into an exclusive-feeling result without
    ever losing a sibling to the boundary stid being passed and never revisited.

**`TrafficView.js`-specific layer on top of its raw-mode `useByteBuffer.js` instance**
(frame mode's own layer is documented in "Framer scripts" below):
- Props: `stream`, `globalOffset`, `jumpTo`, `markers`, `onAddMarker`, `onRemoveMarker`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`, `onLeaveStream`, `jumpRef`. `markers`/`onAddMarker`/`onRemoveMarker` are only for `HexDump.js`'s per-byte marker highlighting and its right-click Set/Clear marker items — the marker *list* itself lives in the Analysis bottom panel's Markers tab (`MarkersPanel.js`, owned directly by `App.js`), not here.
- `jumpRef`: a ref `App.js` owns; a dependency-array-free effect keeps it pointed at
  whichever hook's `jumpToTop`/`jumpToBottom`/`jumpToNextSegment`/`jumpToPrevSegment` is
  actually on screen — the raw-mode instance normally, the frame-mode instance while
  `inFrameView` (see "Framer scripts" below; frame mode's hook is given the same
  `latestStid` prop as raw mode's, purely so its own `jumpToBottom` has a boundary to fill
  backward from — a frame's own `stid` is always that of the raw chunk containing its last
  byte, so `latestStid` is a valid upper bound for "the end" of the frame timeline too).
  `jumpToNextSegment`/`jumpToPrevSegment` are wrapped in a local zero-arg closure here that
  reads `Math.floor(scrollTopRef.current / ROW_HEIGHT)` at call time (same ref/math the
  leave-effect below already uses) and forwards it to the hook, which doesn't track the
  viewport's scroll position itself — this keeps `App.js`'s buttons on the same zero-arg
  call signature as `jumpToTop`/`jumpToBottom`. `CombinedView.js` has the identical
  effect over its own (`useChunkBuffer.js`) hook, with no frame-mode counterpart to
  switch between.
- `handleSetMarker` / `handleClearMarker` are local (not lifted); `onSetExtractStart/End/Range` are forwarded directly to `HexDump`.
- `totalBytes` (the ↑/↓ byte counters in the meta bar) is `TrafficView.js`-only state, independent of either hook's `display`, mirrored via its own small effect on `stream?.id`.
- **Jump effect** (`useEffect([jumpTo?.version])`, no `CombinedView.js` equivalent, and not
  wired to frame mode): resolves `jumpTo` to a target stid, then calls the raw-mode hook's
  `reloadCenteredOn` (not `reloadFrom` — see that function's own doc comment). A local
  `cancelled` flag (set in the effect's cleanup) guards the resolution step against a stale
  jump firing after a newer one has superseded it — the hook's own `generationRef` only
  protects `reloadCenteredOn`'s internal async work, not this caller-side step.
  `reportError(message)` (effect-local) is every failure path's single exit: calls the
  `onJumpError` prop with `(jumpTo, message)` when `jumpTo.source` is set (routes to that
  source's own UI — currently just Goto, see `GoToPanel.js`'s `error` prop above), else
  falls back to the hook's own `setError` (the top-of-view banner search-result/marker
  jumps still use — their own target is always real/already-found, so nothing there
  validates it client-side).
  - `chunks` unit: `targetStid = jumpTo.value` directly — no resolution call, so
    `latestStid` (already available, the same prop the raw-mode hook's live-poll reaction
    uses) is checked client-side instead: `jumpTo.value > latestStid` reports an error and
    returns before touching `reloadCenteredOn`, skipped only if `latestStid` itself isn't
    known yet (`null`/`< 0`).
  - `chunks-c2s` / `chunks-s2c`: same pre-check, against `POST /chunklist`'s per-direction
    `latest0`/`latest1` instead (not already available as a prop, so this unit alone pays
    for the extra round trip even on success) — keeps the error message in the same
    phrasing as the other two units rather than surfacing `/chunk-stid`'s own 404 text
    (`"chunk not found"`) verbatim.
  - `offset-c2s` / `offset-s2c`: validated against `stream.length0`/`length1` (whichever
    matches direction) before calling `POST /byte-stid` at all — that endpoint resolves to
    the *last* chunk rather than 404ing for an offset past what's captured so far, so
    without this check a too-large/stale typed offset lands at the top of that chunk's
    window instead of failing outright. On failure neither `/byte-stid` nor
    `reloadCenteredOn` is called and `display` is left untouched. `stream.length0`/
    `length1` only refresh on the poll/Refresh (not per keystroke), so a just-captured
    legitimate offset can trip this on an actively-growing stream — an accepted,
    narrow false-positive trade against silently mis-landing.
  - Calls `reloadCenteredOn(targetStid, { computeExtra })`, where `computeExtra` scans the
    freshly-built rows for the target row (byte-offset jumps match both direction and
    offset range, since c2s/s2c offsets both start at 0) and returns `{scrollTo,
    scrollToVersion: jumpTo.version}` — centered by default, or placed at the very top when
    `jumpTo.align === 'top'` (marker jumps, remembered-position restore). With `pinHeader`
    on, a top-aligned byte target lands one row lower, since the pinned header covers the
    top row; the remembered-position capture on stream leave skips that covered row to
    match, so save/restore round-trips without drifting.
  - **`hasPendingJump`** (passed into the raw-mode `useByteBuffer` instance, computed each
    render as `jumpTo.version !== lastJumpVersionRef.current`): a jump that also switches
    `stream` (e.g. a search result in a different stream) changes `entity` and `jumpTo` in
    the same commit, so `useByteBuffer`'s own "reload from stid 0 on entity change" effect
    and this jump effect both fire — the former runs first (registered earlier in hook
    order) and, needing only one round trip against the jump's two (resolve offset, then
    reload), can commit last and strand the view at the top. `hasPendingJump` tells that
    effect to skip its own reload and leave the jump effect as the sole loader for that
    entity; `lastJumpVersionRef.current` is set at the top of the jump effect itself so the
    flag is true for exactly the one render with a genuinely unprocessed jump.
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
- Unit select (option values / labels): `chunks` / "chunks (total)", `chunks-c2s` / "chunks (c→s)", `chunks-s2c` / "chunks (s→c)", `offset-c2s` / "offset (c→s)", `offset-s2c` / "offset (s→c)". The unit lives in `App.js` (`gotoUnit`; props `unit`, `onUnitChange`) so it survives tab switches; the typed value is local and resets.
- No separate direction dropdown — direction is encoded in the unit choice.
- Shows "Select a stream first" placeholder when no stream selected.
- `onGoTo({value: N, unit})` is called on submit (Enter or button click).
- **`error` prop** (string or null, rendered as an `.error-msg` line below the form):
  `App.js`'s own `gotoError` state, set by `handleJumpError` when `TrafficView.js`'s jump
  effect reports a failure for a jump `handleGoTo` tagged `source: 'goto'` — shown here
  instead of the hex view's generic top-of-view banner (every other jump source stays on
  that banner; see the jump effect's own note in "Jump effect" below for why only Goto's
  target can be wrong to begin with). `handleGoTo` clears it optimistically on every new
  attempt, so a fixed/different value that succeeds silently drops the old message.

**Search panel (`SearchPanel.js`):**
- Props: `session`, `stream`, `onJump`, `searchState`, `onSearchStateChange(patch)`.
- Form values and results live in `App.js` (`searchState`, initialized from `SearchPanel.js`'s `INITIAL_SEARCH_STATE`, merged via `updateSearchState`), so they survive bottom-tab and Analysis/Tamper switches (in memory only — lost on page reload). Only `searching`/`error` are local. `results` is `{session, list}`; the panel shows it only while `session` is the same object, and `App.js` clears it whenever `session` changes (which also covers a dbdump instance switch).
- Shows "Select a session first" placeholder when no session selected.
- Form fields: pattern input (monospace, dynamic placeholder), format select, direction select (`both` / `c→s` / `s→c`), **Contiguous** checkbox, stream number input (empty = all streams in session).
- Format select options and encoding behaviour:
  - `ascii` — unescape `\n \r \t \\` then UTF-8 encode; sent as base64.
  - `utf16le` / `utf16be` — encode string with `DataView.setUint16`; sent as base64.
  - `hex` — accepts `0xff 0x00`, `\xff\x00`, `ff00`, space/comma-separated; sent as base64.
  - `regex` — sent as raw text with `pattern_encoding: "regex"`; no base64.
- All non-regex formats are always sent as base64 (`pattern_encoding: "base64"`).
- Results list: match count header + scrollable rows showing stream id, direction (coloured), hex offset. Clicking a row calls `onJump({streamId, direction, offset, length})` — `length` (bytes matched, from the backend's `SearchMatch.length`) is passed straight through, undecoded.
- `App.js` wires `onJump` → `handleSearchJump`: finds the stream in `streamList`, switches to it if needed (sets `stream` state), builds a `{direction, start: offset, end: offset + length - 1}` highlight range, and calls `jumpToOffset` with it — `jumpToOffset`'s optional `highlight` param rides along on the `jumpTo` object it builds (`jumpTo.highlight`) as the one extra field distinguishing a search-originated jump from every other kind (Goto, marker jump, remembered-position restore), all of which simply omit it. `TrafficView.js`'s jump effect picks it up into local `searchHighlight` state, fed to the raw-mode `HexDump` as its `highlightRange` prop (see "Virtual scroll"'s "External highlight" note above) — reset alongside `dissectHighlight` on stream (re)selection.
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
- `fmtByteSize(n)` — human-readable byte count (`B`/`KB`/`MB`; negative `n` formats as `'?'`, for a not-yet-known total). Used by `HexDump.js` (chunk header, when `sizeFormat === 'size'`) and `TrafficView.js` (stream meta bar, unconditionally).
- `fmtByteCount(n)` — byte count with thousands separators, e.g. `"2,733 B"` (negative `n` formats as `'?'`, same convention as `fmtByteSize`). Used by `HexDump.js`'s chunk header when `sizeFormat === 'count'`.
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
- **State lives in `App.js`** (`transformState`, initialized from `INITIAL_TRANSFORM_STATE`; props `transformState`, `onTransformStateChange(prev => next)`), so input, steps, output and collapsed menu sections survive bottom-tab and Analysis/Tamper switches (in memory only — lost on page reload). The panel's `field(key)` builds `useState`-style setters over it (value or updater). Transient UI state (`menuOpen`, `dragOverId`, `HexEditor`'s cursor) stays local.
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
  - All other helpers/tables (e.g. `HEX_SEPARATOR_CHARS`) are private to the module.
    `transforms/numbers.js` is the one exception: `NUMBER_TYPES` (the type table) and
    `decodeNumberValue`/`encodeNumberValue` (the pure bytes↔number core `numberDecode`/
    `numberEncode` below wrap) are exported for `transformWorkerApi.js`'s `number.*`
    surface — see "Scripted interception"'s `tamper.number.*`/`framer.number.*` note.
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
  - `encnum-*`/`decnum-*` (`transforms/numbers.js`; 14 fixed-width integer types, big/little endian): decode requires the exact byte width; encode validates range; 64-bit types use `BigInt` throughout. Decodes to/encodes from decimal *text* (as `Uint8Array`), matching every other op's bytes-in/bytes-out contract — for a real number/bigint instead, see `tamper.number.*`/`framer.number.*` in "Scripted interception".
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

**Markers panel (`MarkersPanel.js`) — "Markers" Analysis bottom-panel tab:**
- A bottom tab, positioned right after Goto (`Goto | Markers | Search | ...`) — moved out of
  `TrafficView.js`'s side panel so the traffic view's right edge is free for a future frame
  dissector panel (`doc/design/packet-dissector.md`). `App.js` renders it directly off state
  it already owns (`markers`, `removeMarker`, `updateMarkerLabel`, `handleMarkerJumpRequest`,
  `setMarkers`) — no lifting needed, unlike the Framing tab's log (markers were already
  centrally owned).
- Props: `session`, `markers[]`, `onRemove`, `onUpdateLabel`, `onJump`, `onImport(markers[])`.
  "Select a session first" placeholder when no session selected (same convention as
  `SearchPanel.js`). Session-scoped, not stream-scoped: shows every marker in the current
  session across all its streams (`markers.filter(m => m.session === session.id)`) — a
  marker's own stream is shown per row since more than one can appear here.
- Marker rows (`.markers-tab-row`/`.mtab-*`, a single-line table row — replaced the old
  side panel's multi-line card layout, a better fit for a wide/short bottom panel):
  session, stream, direction, offset, an inline-editable label (double-click to edit), and
  `×` (`onRemove`). A single click anywhere else on the row jumps (`onJump`), like a
  `SearchPanel.js` result row; the label input and `×` stop propagation. Jumping doesn't
  collapse the bottom panel.
- **Import/export** (bottom bar): `[clipboard ▾] [Import] [Export]` + status line.
  - File format: deflate-compressed JSON, base64-encoded, extension `.tlstap-markers`. Content is the raw `tlstap-markers` localStorage JSON (`{ version: 1, markers: [{id, session, stream, direction, offset, label?}] }`).
  - `compress(str)` / `decompress(b64)`: use `CompressionStream`/`DecompressionStream` with `'deflate'` (Chrome 80+, Firefox 113+, Safari 16.4+).
  - Export to file: `download.js`'s shared `acquireSaveHandle` called **before** `compress()` to preserve user activation; falls back to anchor download.
  - Import from file: programmatic `<input type="file" accept=".tlstap-markers,.txt">` click (no activation constraint on read).
  - Import replaces all markers (`onImport` prop wired to `setMarkers` in `App.js`).
  - `parseImport(text)`: validates JSON has `markers` array with required typed fields; returns `null` on invalid data.

**`api.js`:**
- `errorMessage(r)`: extracts a failed response's `{"error": "..."}` body (falling back to
  `r.statusText` if the body isn't JSON) — every throw in this file goes through it (or
  `okJson`, which wraps it), matching the `checkOk`-shaped helper every other API client
  in this codebase already has (`coreApiClient.js`, `tamperApi.js`, ...), so a thrown
  message is always the server's own text, not a raw JSON blob.
- `openStidStream()` → `{ fetch(sessionId, streamId, start, n), close() }`: persistent WS to `/stid-stream`.
- `openSgidStream()` → `{ fetch(session, start, n), close() }`: persistent WS to `/sgid-stream`.
- `openFramerJobs(handlers)` → `{ respond(jobId, ok, error?), close() }`: persistent WS to `/framer-jobs` — the browser-tab side of the remote framer-job relay (`intercept/dbdump/CLAUDE.md`'s "Framer jobs" section), pushed one `{onOpen, onClose, onError, onJob(job)}` handler set at open time, same shape as `tamperApi.js`'s `openTamperControl`. See "Remote framer job listener" below for the caller.
- `openDissectorJobs(handlers)` → `{ respond(jobId, ok, extra), close() }`: persistent WS to `/dissector-jobs` — `openFramerJobs`'s dissector-script sibling (`intercept/dbdump/CLAUDE.md`'s "Dissector jobs" section); `respond`'s `extra` is merged into the result message (`{nodes}` on success, `{error}` on failure) rather than a plain `error?` param, since a dissector job's success payload actually carries data. See "Remote dissector job listener" below for the caller.
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
- `fetchByteRanges(sessionId, streamId, ranges)`: POST `/byte-ranges` (binary request/
  response — see `intercept/dbdump/CLAUDE.md`'s "POST `/byte-ranges`" section for the full
  wire format). `ranges` is `[{offset, direction, length}, ...]`; resolves to a
  same-length, same-order `Uint8Array[]`, each possibly shorter than requested (never an
  error — see that section). Encoding/decoding the binary wire format itself lives in
  `byteRangesCore.js` (pure, Node-testable — `encodeByteRangesRequest`/
  `decodeByteRangesResponse`), imported here; `fetchByteRanges` is just the `fetch()` call
  wrapping it. An empty `ranges` is a no-op (no request sent). Backs both
  `chunkSegments.js` and `frameSegments.js` (see "Byte-budgeted segment buffer" below).
- `listChunksTimeline(sessionId, streamId, start, n)` / `listChunksTimelineBackward(sessionId,
  streamId, beforeStid, n)`: POST `/chunks/timeline` — raw-chunk metadata listing, mirroring
  `dbdumpFramerApi.js`'s `listFramesTimeline`/`listFramesTimelineBackward` shape minus any
  script key. No server-side budget selection (see `intercept/dbdump/CLAUDE.md`'s "POST
  `/chunks/timeline`" section) — callers apply their own (`chunkSegments.js` uses
  `frameSegmentsCore.js`'s `selectByBudget`, same as frame mode).
- `openSegmentsStream()`/`splitSegments` — superseded by the two above, unreferenced by
  any adapter; dead code pending removal (root `CLAUDE.md`'s TODO).

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
  `tamper.fs.*`/`tamper.kv.*` (Scripts sub-tab only, not this REST/WebSocket layer) are
  `coreApiClient.js`, not `tamperApi.js` — see "Scripted interception" below.
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

**Scripted interception (`scriptRuntime.js`, `TamperScriptsPanel.js`, `ScriptsCrudPanel.js`,
`ScriptEditor.js`) — "Scripts" sub-tab:** runs one user script in a Web Worker as a programmatic stand-in for a
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
- **RPC bridge**: `peek`/`release`/`dropConnection`/`setIntercept`/`listStreams` post a
  `call` message to the main thread (`createScriptRuntime`'s `handlers`), which performs
  the real operation (all of it live-connection-scoped, needing the main thread's own
  state) and posts back a `result`. `fs.*`/`kv.*` don't need this — see the dedicated
  bullet below.
- **`tamper.transform.*`/`tamper.encode.*`/`tamper.decode.*`/`tamper.number.*` are the
  exception**: they run directly inside the Worker (`BOOTSTRAP` dynamically imports
  `transforms.js`/`format.js` by absolute URL), synchronous once a `ready` flag flips
  after that import finishes — a script's own hook handlers never observe them as
  unpopulated; a call made at the script's own top level before that returns a `Promise`
  instead. The op-id-to-JS-name mapping behind `transform.<category>.*` (`camelCaseOpId`,
  the per-category grouping) and `number.decode<Type>`/`encode<Type>` (`capitalizeTypeId`,
  driven by `transforms/numbers.js`'s `NUMBER_TYPES`) are shared with `frameRuntime.js`'s
  equivalent surface via `transformWorkerApi.js`, since both mappings must stay identical
  between the two — each runtime supplies its own per-entry function body (Promise-wrapped
  here; see "Framer scripts" below for why `framer.*`'s is plain sync instead).
  `number.*` is deliberately a separate namespace from `transform.*`: every
  `transform.<category>.*` op speaks `Uint8Array` in and out (the same convention the
  Transform panel's step pipeline relies on — `transforms/numbers.js`'s own
  `decnum-*`/`encnum-*` ops, exposed there as `transform.numeric.*`, decode to/from a
  *decimal-text* `Uint8Array`, not a number, for exactly that reason), whereas
  `number.decode<Type>` returns a real number (`bigint` for the 64-bit types, per
  `DataView`'s own `getBigInt64`/`getBigUint64`) and `number.encode<Type>` takes one —
  useful for a script parsing a binary length/count field, where `transform.numeric.*`
  would mean round-tripping through decimal text just to get back to a number. Both share
  the same pure core (`decodeNumberValue`/`encodeNumberValue`, `transforms/numbers.js`),
  re-exported through `transforms.js` for the Worker's dynamic import; `numberDecode`/
  `numberEncode` (the `OPERATIONS['decnum-*'/'encnum-*']` implementations) are thin
  decimal-text wrappers around those same two functions, so the Transform panel's own
  behavior is untouched by any of this.
- **`tamper.fs.*`/`tamper.kv.*`** (`coreApiClient.js`) — `core/fs`/`core/kv` access (see
  `core/CLAUDE.md`), the same method shapes `framer.fs.*`/`kv.*` and `dissector.fs.*`/
  `kv.*` expose (see "Framer scripts" below for the full method list and error
  convention). Bypass the RPC bridge above entirely — a real `fetch()` straight from the
  Worker, with an absolute base URL baked in at Worker-build time to sidestep a Blob-URL
  worker's unreliable relative-URL resolution — but are still `whenReady`-gated the same
  way `transform.*`/`number.*` are, so a script can reference either from anywhere
  (including its own top level) without special-casing "not ready yet" itself; a call made
  before ready just returns a pending `Promise`, same as `transform.*`'s own convention.
  `peek`/`release`/etc. still use the RPC bridge above — only `fs.*`/`kv.*` bypass it.
  Browser-verified: write/read/list/delete/readBytes/writeBytes round-trips from a
  script's top level, with zero RPC handlers wired up on the `createScriptRuntime` caller
  side.
- **Per-connection event serialization**: all events for one `conn` go through a per-conn
  FIFO queue; different `conn`s run independently. Consecutive still-queued `onReceive`
  entries for the same `(conn, direction)` are coalesced into one dispatch.
- **Pause/Continue**: `ctx.pause()` suspends until a human clicks Continue in the
  Intercept sub-tab; if the connection terminates while paused, the pending promise is
  rejected immediately so the per-conn queue can still advance.
- **Error handling**: a syntax error in the script's own source kills the Worker
  permanently (reported, then `stop()`); an exception thrown inside a handler is caught
  per-event without stopping the Worker. Losing the control connection also stops the script.
- **`ScriptsCrudPanel.js`** is the generic list+editor CRUD chrome (script list with
  `+ New`, `ScriptEditor.js` instance, Save/Reload/Delete toolbar) extracted out of what
  used to be `TamperScriptsPanel.js` monolithically — shared with the Analysis tab's
  framer-script editor (`FramerScriptsPanel.js`, see "Framer scripts" below), and matches
  what `doc/design/packet-dissector.md`'s "Script storage" section anticipated for a
  future dissector script store too. Props: `className` (root class — a caller-specific
  CSS variant, since this component's root sits in different flex contexts per caller;
  see that file's own CSS comments), `list`/`get`/`put`/`del` (REST CRUD functions,
  `tamperApi.js`'s and `dbdumpFramerApi.js`'s script functions are byte-for-byte this same
  shape), `completions` (passed straight through to `ScriptEditor.js`), `refreshSignal`,
  `listWidthKey` (a `layout.js` key, since each caller needs its own persisted list width),
  and two optional render-prop extension points: `controls(selectedName, source)` (tamper
  supplies Run/Stop; framer supplies nothing — CRUD only, see "Framer scripts" below for
  why) and `rowDecoration(scriptName)` (tamper supplies the ● running-dot; framer supplies
  nothing).
- **`TamperScriptsPanel.js`** is now a thin wrapper around `ScriptsCrudPanel.js`: owns
  `TAMPER_COMPLETION_SHAPE`/`CTX_COMPLETION_SHAPE` (moved here from `ScriptEditor.js`,
  see below), supplies tamper's REST functions/`controls`/`rowDecoration`, and keeps its
  own log panel (Download/Clear, or **"Logged to `<filename>`"** in place of Download when
  `log-file` is configured — see `doc/interceptor/tamper.md`'s "Logging" section for the
  persistence/"Skip browser log" behavior) as a sibling below `ScriptsCrudPanel.js`, wired
  to the lifted runtime state exactly as before this extraction.
- **`ScriptEditor.js`** wraps a CodeMirror 6 `EditorView` (syntax highlighting, bracket
  matching, folding, autocompletion via `@codemirror/lang-javascript`'s
  `scopeCompletionSource` — vendored into `codemirror.module.js`, see that file's header —
  run against never-called mirror objects rather than the real API surface). Semi-controlled,
  same contract shape as `HexEditor.js`: `<${ScriptEditor} value onChange loadVersion
  completions readOnly? />` — `value` is only pushed back into CodeMirror when the caller
  bumps `loadVersion`, never inferred from `value` changing on its own. `readOnly` is
  applied through a `Compartment` rather than a remount. `completions` (an object passed
  straight to `scopeCompletionSource`, e.g. `{tamper: TAMPER_COMPLETION_SHAPE, ctx:
  CTX_COMPLETION_SHAPE}` or `{framer: FRAMER_COMPLETION_SHAPE}`) is baked into the editor
  once at mount, not reactive to later changes — no caller needs that, since one
  `ScriptEditor.js` instance is tied to one script *type* for its whole lifetime. The
  mirror-shape objects themselves now live with their own caller (`TamperScriptsPanel.js`,
  `FramerScriptsPanel.js`) rather than hardcoded in `ScriptEditor.js` — they're
  caller-specific config, not editor internals.

**Tamper framer scripts (`tamperFramerApi.js`, `TamperFramerScriptsPanel.js`, plus
`scriptRuntime.js`'s composition/`onFrame` mechanism above) — "Framer Scripts" sub-tab:**
lets a separately-selected, separately-stored `frame(state, chunk)` script reassemble
live traffic into frames for the interception script's `onFrame` hook, mirroring dbdump's
own framer feature closely enough for scripts to be portable between the two, but
otherwise unrelated (live/editable vs. read-only/persisted — see
[`doc/design/tamper-framer.md`](../doc/design/tamper-framer.md) for the full
rationale). Script-author-facing reference (contract, hook, examples):
[`doc/interceptor/tamper.md`](../doc/interceptor/tamper.md)'s "Framer scripts" section —
this is implementation notes only.

- **Storage**: its own `scriptstore.Store` instance, nested under `/api/i/tamper/framer`
  (`framer-scripts-dir` config field) — a distinct namespace from both tamper's own
  interception `scripts-dir` and dbdump's framer scripts-dir; see
  `intercept/tamper/CLAUDE.md`'s "Script storage" section. `tamperFramerApi.js` is
  `tamperApi.js`'s script CRUD section verbatim, pointed at the new base — same shape
  `ScriptsCrudPanel.js`'s `list/get/put/del` props already expect.
- **`TamperFramerScriptsPanel.js`** is a thin CRUD-only wrapper around
  `ScriptsCrudPanel.js` (own `TAMPER_FRAMER_COMPLETION_SHAPE`:
  `transform/encode/decode/number/fs/kv/log` — unlike dbdump's own
  `FRAMER_COMPLETION_SHAPE`, tamper's framer scripts get `fs`/`kv` too, for parity with
  every other runtime — no `ctx`-like namespace, a framer script has no hooks), rendered
  under `TamperView.js`'s third sub-tab ("Intercept / Scripts / Framer Scripts") — a
  sibling of the Scripts sub-tab, not nested inside it, since running happens from the
  Scripts sub-tab's own picker (below), not here.
- **Selection**: `TamperScriptsPanel.js`'s `controls` render-prop gains a `.framer-controls`
  dropdown (same shape as `TrafficView.js`'s own dbdump framer picker) next to Run/Stop,
  disabled while a script is running (composition is fixed at Run time — Stop to change).
  `TamperView.js` owns the selection as plain non-persisted `useState` (no per-stream
  dimension the way dbdump's `framerPrefs.js` needs — one script runs at a time, not one
  per stream) and its own `onFramerScriptUpdated` control-handler case (a distinct
  `framer-script-updated` push event, since it comes from a distinct store) refreshing
  the list. `TamperView.js`'s `onRun` handler (`handleRunScript`) fetches the selected
  framer's current source before calling `scriptRuntimeRef.current.start(name, source,
  framerName, framerSource)` — mirroring `TrafficView.js`'s own `handleRunFramer`'s
  `getFramerScript` fetch.
- **Worker mechanics** live in `scriptRuntime.js`'s `BOOTSTRAP` (documented above, under
  "Scripted interception") — no separate runtime module the way `frameRuntime.js` is a
  separate file from `scriptRuntime.js` for dbdump/tamper's interception scripts
  respectively: the framer script's Blob is loaded into the *same* Worker as the
  interception script, un-wrapped (its `frame` must resolve as a bare global — mirrors
  `frameRuntime.js`'s own convention — vs. the interception script's IIFE-wrapped Blob,
  unchanged). `handleOnFrame`/`resolveFramerClose` are the two new dispatch paths `pump()`
  routes to (instead of `handleOnReceive`) purely based on `typeof frame === 'function'`,
  decided entirely inside the Worker — no new wire event type, no backend changes.
  `chunk.data` is only the bytes not yet fed to `frame()` (tracked via each direction's
  `lastRemaining` cache, whose *length* — not a separate counter — is what makes this
  possible, since a fresh `peek()` always returns `lastRemaining ++ whatever's newly
  arrived`); a single `frame()` call is expected to resolve every currently-extractable
  frame itself (mirroring dbdump's own contract, where `chunk.data` is one new raw chunk,
  never the whole accumulated buffer) — `handleOnFrame` doesn't loop calling `frame()`
  repeatedly within one dispatch. Each extracted frame gets its own `makeCtx(...)`
  instance (unmodified — a `live:false` opts flag, described next, was the only addition
  needed) seeded with just that frame's byte range; its `release`/`drop` map directly onto
  the *existing* `release` wire message (`prefixLength: frame.length, bounds:[0],
  releaseChunks:1`) with no backend awareness of "frames" required at all, since
  `heldBuffer`'s `bounds` were already a purely client-owned, arbitrary re-segmentation of
  the buffer (the same mechanism a human's split/merge context-menu action already uses).
- **Close handling (`resolveFramerClose`)** exists because a fresh `peek`/`release` is
  actually impossible once `stream-terminated` arrives — `ConnectionTerminated`
  (`intercept/tamper/tamper.go`) deletes the stream from `i.streams` and closes both
  `heldBuffer`s *before* sending that event, and `lookupHeld` (`api.go`) resolves via that
  same now-empty map. So close handling works entirely from the client-cached
  `lastRemaining` tail instead: the framer gets one final `closed:true` call with empty
  `data` (mirroring dbdump's identical convention — its own `state` already has
  everything), and whatever that call still doesn't resolve into a frame is dispatched to
  `onFrame` as one synthetic final frame (`meta:null`). Every frame produced during close
  handling carries `final:true` and a `live:false` ctx — `makeCtx`'s `commit()` skips the
  wire `release` call entirely when `live` is false, sharing 100% of the real ctx's
  buffer/edit bookkeeping (`get`/`set`/`append`) rather than a parallel implementation, so
  `release`/`drop`/`pause` are safe no-ops instead of touching a connection that no longer
  exists server-side. `pump()`'s `onClose` branch guards each direction's
  `resolveFramerClose` call independently (its own try/catch) so one direction's framer
  throwing can't prevent the other direction's handling, the interception script's own
  `onClose`, or `frameState`/`lastRemaining` cleanup from running.
- **State persistence is incremental, not batched**: both `frameState` (the framer
  script's own opaque `state`, combined-mode-shared across both directions) and
  `lastRemaining` are updated immediately after each individual frame is processed, not
  once at the end of a `frame()` call's whole `frames` array — so a later frame's handler
  throwing mid-batch can't roll back bookkeeping for frames already released to the wire
  earlier in the same batch.
- **No server-side persistence at all** (unlike dbdump's `frames`/`frame_progress`
  tables) — a tamper framer's `state` lives only in the running script's Worker for the
  connection's lifetime, discarded on stream end or Stop; nothing here ever crosses a
  JSON boundary the way dbdump's `jsonBytesReplacer`/`jsonBytesReviver` handle for its
  persisted BLOB/TEXT columns.
- Verified via a throwaway Node smoke test (not committed, same convention as every other
  example script's own verification): simulates a Worker environment enough to run the
  real assembled `BOOTSTRAP`+script+framer source (captured via the real `start()` call
  path) against a mock peek/release "server," exercising multi-chunk carry, multiple
  frames resolved from one call, forward/drop actions with correct wire `prefixLength`/
  `bounds`, and both close-handling cases (a framer resolving the tail vs. the synthetic
  `meta:null` fallback). Not yet verified end-to-end in a real browser.

**Framer scripts (`dbdumpFramerApi.js`, `frameRuntime.js`, `framerRun.js`,
`framerPrefs.js`, plus `App.js`'s View-menu entry and `TrafficView.js`'s "Framer"
control):** reassembles a stream's raw chunks into logical frames via a user-authored
script, persisting the result server-side (dbdump's `frames`/`frame_progress` tables —
see `intercept/dbdump/CLAUDE.md`'s "Framer scripts" section) so a stream can be viewed
partitioned by frame instead of by raw chunk at near-zero repeat cost once cached. Full
design in [`doc/design/packet-dissector.md`](../doc/design/packet-dissector.md).

**Combined mode**: a script runs **once per `(stream, script)`**, not once per direction
— one shared script instance and one shared `state`, fed both directions' chunks merged
into one chronological (`stid`-ordered) sequence. See
[`doc/design/framer-cross-direction-correlation.md`](../doc/design/framer-cross-direction-correlation.md)
for the full design/rationale (why this replaces the original one-instance-per-direction
model, the ordering guarantee it relies on, and the rejected per-direction-snapshot
alternative). Frame view merges both directions into one scroll, the same way the
raw-chunk view already does via `chunks.stid` — see `intercept/dbdump/CLAUDE.md`'s
"Framer scripts" section ("Cross-direction interleaving") for the backend half
(`frames.stid`, `listFramesTimeline`, why ties are routine and how pagination avoids
splitting one). Known gaps here (buffer-trimming eviction not group-aware, large-frame
byte-payload pagination, no empty state for zero-result frame view) are tracked in the
root `CLAUDE.md`'s TODO section, not repeated here.

Browser-verified, including combined mode, against `tls-framer.js`, `http2-framer.js`
(HPACK decoding via `framer.hpack` below), and `length-prefix-framer.js` over a real
two-way ~18.6MB/direction capture (multi-megabyte frame, clean close both directions).

- **Script contract**: a plain top-level `function frame(state, chunk)`, no registration
  call — unlike tamper's `tamper.register(hook, fn)`, there's only one hook, so a bare
  global function is simpler and matches the dissector stage's own `dissect` convention
  (see the design doc). `chunk` is `{offset, length, direction, data}` — one raw chunk,
  in true chronological (`stid`) order across **both** directions (combined mode, above);
  `direction` (`'c2s'`/`'s2c'`, `direction.js`'s `dirToStr` — same convention
  `scriptRuntime.js` uses for its own script-facing API) now varies call to call within
  one run, rather than being fixed for it, since chunks from both directions interleave
  through the single merged sequence — a script correlating the two (e.g. HTTP/1's
  request/response pairing) keeps its own per-direction sub-state inside the one shared
  `state` (e.g. `state.c2s`/`state.s2c`), the same pattern `tls-framer.js`/
  `http2-framer.js` both use even though neither actually needs correlation. `offset` is
  always relative to `chunk.direction`'s own byte stream, same as before. The *last* call
  for a given direction may instead carry `chunk.closed = true` with empty `data` — a
  synthetic signal that *that* direction's connection has closed, for a script that needs
  to flush anything whose length is implicit in connection close (e.g. an HTTP/1 response
  with neither `Content-Length` nor chunked `Transfer-Encoding`); see `catchUpFramer`
  below for exactly when this fires — both directions' close signals are delivered within
  the same run, interleaved into the merged sequence once each direction's own real
  backlog is exhausted. `chunk.tls` is `null` for a plain-mode proxy or a not-yet-upgraded
  `detecttls` connection, else `{sni, alpn, version, cipherSuite}` from the downstream TLS
  handshake — constant for the whole run, carried per-chunk the same way, e.g. to let one
  script pick HTTP/1.1 vs h2 framing off `chunk.tls?.alpn`. Returns `{frames, state}` (or
  nothing, to mean "no new frames, state unchanged"); each frame is
  `{ranges: [{offset, length}], meta?}` — an ordered list of byte ranges, not a single
  `{offset, length}` pair (see `intercept/dbdump/CLAUDE.md`'s schema notes) — most scripts
  emit exactly one range per frame, but `http1-framer.js`'s WebSocket reassembly emits
  more than one for a fragmented message (see its "Framer scripts" section below). A
  frame is addressed by consumers as its own 0-based virtual concatenation of `ranges`,
  never real stream positions — see `frameSegmentsCore.js`'s module comment and the
  "Byte-budgeted segment buffer" section above. **Not** tagged with a direction by the
  script itself;
  `frameRuntime.js` tags each returned frame with whichever chunk's `frame()` call
  produced it (see below), since a frame always belongs to the direction it was parsed
  from. `state`/`meta` are plain JS values from the script's point of view, and may freely
  include a raw `Uint8Array` anywhere in the tree (e.g. a framer's buffered carry bytes
  between calls) — a script never has to encode/decode bytes itself for either, even
  though `frame_progress.state` is a BLOB column and `frames.meta` is TEXT
  (`dbdumpFramerApi.js` encodes/decodes both at the wire boundary: `state` → JSON → UTF-8
  bytes → base64 for the BLOB; `meta` → JSON text directly, since the column is already
  TEXT; either JSON pass swaps a nested `Uint8Array` for a tagged base64 wrapper via a
  replacer/reviver pair — `jsonBytesReplacer`/`jsonBytesReviver`, `dbdumpFramerApi.js` —
  only at that one actual serialization boundary, not on every call). Prefer keeping
  buffered bytes as a plain `Uint8Array` across calls rather than encoding it yourself
  every time: `state` is passed in-memory between consecutive `frame()` calls within one
  Worker run (and survives the Worker→main-thread `postMessage` hop via structured clone,
  which also carries `Uint8Array` natively) with no serialization in between — only
  `appendFrames`'s actual wire write (once per `runFramer` batch, not once per chunk)
  needs the tagged/base64'd form, and that now happens automatically. Use `.slice()`,
  not `.subarray()`, when computing what to carry forward — a view would keep the whole
  (possibly much larger) accumulated buffer alive in memory for as long as the carry is
  held. Tested directly in `dbdumpFramerApi.test.js`.
- **`dbdumpFramerApi.js`'s `decodeFrame`** decodes a wire frame into `{id, ranges, length,
  virtualOffset, meta, direction, stid, time, seq}` — `length` (`sum(ranges[].length)`)
  and `virtualOffset` (the wire's `virtual_offset`, per-direction — see
  `intercept/dbdump/CLAUDE.md`'s `frames.virtual_offset` note and the "Global/local
  offset" bullet above) are both genuine, permanent fields, not derived shims. `TrafficView.js`/
  `DissectPanel.js` build their own independent `frame.offset` from `collectChunkBytes`'s
  `baseOffset` rather than reading a decoded frame's fields directly. Exported (alongside
  `encodeMeta`/`decodeMeta`/`encodeState`/`decodeState`) and tested in
  `dbdumpFramerApi.test.js`, for both single- and multi-range input.
- **A global `framer` object** exposes the same transform framework tamper scripts get,
  under `framer.transform.<category>.*`/`framer.encode.{hex,base64,hexdump}`/
  `framer.decode.{hex,base64,hexdump}`/`framer.number.decode<Type>`/`encode<Type>` —
  mirroring `tamper.*`'s shape (see "Scripted interception" above, including *why*
  `number.*` is a separate namespace from `transform.*`) minus the `tamper` prefix,
  sharing its naming via `transformWorkerApi.js`. Unlike `tamper.*`, every `framer.*` call
  is **plain synchronous, never a Promise**: `runScript` (unlike tamper's live event
  dispatch) only starts once explicitly told to via the Worker's `'run'` message, so it
  simply awaits the `transforms.js`/`format.js` module import (plus Whirlpool warmup)
  finishing *before* ever calling `frame()`, rather than gating each call behind a `ready`
  flag the way tamper must. A script's own top level, outside `frame()`, has no such
  guarantee and shouldn't reference `framer.*` there. Both example scripts
  (`examples/dbdump/framer/*.js`) use `framer.encode.hex` to add a hex preview of the
  offending header bytes to their "implausible length" error — useful when a framer is
  misapplied to the wrong protocol (see the "framer never finished" discussion this
  followed from) — and `framer.number.decodeU32be`/`decodeU16be` to parse their own
  length-prefix fields as real numbers, in place of a hand-rolled bit-shift.
- **`framer.log(...args)`** posts `{kind: 'log', args, direction}` — `direction` is
  whichever chunk's `frame()` call was executing at the time (`currentDirection`,
  BOOTSTRAP-scoped, set at the top of each loop iteration, numeric like `frames.direction`
  rather than `chunk.direction`'s own `'c2s'`/`'s2c'` string), since combined mode has no
  single fixed direction for the run to fall back on. `runFramer`'s optional `onLog`
  param is called with `(direction, args)` directly — `catchUpFramer` forwards it through
  unchanged (no wrapping needed, unlike the pre-combined-mode version which had to inject
  its own fixed per-call direction). `TrafficView.js` formats args via `format.js`'s
  `fmtLogArgs` (shared with tamper's identical need, moved out of `TamperView.js`'s
  previously-local `formatLogArgs`) and lifts each line to `App.js` via
  `onFramerLog(direction, text, level)` — see "Framing panel" below for where those lines
  end up.
- **`framer.hpack.decode(bytes, table)`** — decode-only HPACK (RFC 7541), for an HTTP/2
  framer script decoding HEADERS/PUSH_PROMISE/CONTINUATION header blocks. Lives in its own module,
  `hpackDecode.js` (a flat top-level file, not under `transforms/` — it's not a
  context-free "run this on some bytes" operation the Transform panel could sensibly
  offer, and isn't part of the shared tamper/framer/dissector transform framework
  `transform`/`number`/`encode`/`decode` above draw from), dynamically imported
  alongside `transforms.js`/`format.js` in the same `modulesReady` `Promise.all`. Not
  exposed to dissector scripts (`dissectRuntime.js`) at all: HPACK's dynamic table is
  connection/direction-scoped, cumulative across every HEADERS/CONTINUATION frame in
  order — exactly what a framer script's persisted `state` already provides room for (a
  script keeps it in its own per-direction sub-state, e.g. `state.c2s.hpackTable`, the
  same as `http2-framer.js` does), and exactly what a dissector script's deliberate lack
  of cross-frame state (see "Dissector scripts" below) can't. `table` is the previous
  call's returned table, or `undefined`/`null` for a direction's first header block; the
  script threads it back in via its own `state`, the same way it already threads a
  byte-carry buffer. Reassembling
  HEADERS+CONTINUATION frames into one complete block before calling this is also the
  script's own job — `hpackDecode.js` only ever decodes one already-complete block per
  call, no partial-parse state of its own. Throws on malformed input (bad integer/Huffman
  encoding, out-of-range table index) rather than a silent best-effort decode, matching
  the other example framers' "implausible length" error convention. Unit-tested directly
  (`hpackDecode.test.js`, Node's test runner, not run in a Worker) against RFC 7541
  Appendix C's own official worked examples (integer encoding; request/response header
  blocks with and without Huffman coding; dynamic-table eviction under a constrained
  max size) plus structural checks on the Huffman table itself (forms a complete,
  prefix-free code). Also browser-verified via `http2-framer.js` against real captured
  HTTP/2 traffic.
- **`framer.fs.*`/`framer.kv.*`** (`coreApiClient.js`) — `core/fs`/`core/kv` access (see
  `core/CLAUDE.md`), the same method shapes `tamper.fs.*`/`tamper.kv.*` and
  `dissector.fs.*`/`dissector.kv.*` expose, so a script doesn't need different syntax per
  runtime: `fs.listFiles(path)`/`readFile(path)`/`writeFile(path, bytes)`/
  `appendFile(path, bytes)`; `kv.read(key)`/`write(key, value)` (JSON-encoded)/
  `readBytes(key)`/`writeBytes(key, bytes)` (raw)/`list(prefix?)`/`delete(key)`. Unlike
  every other `framer.*` surface, these are real network calls — always a Promise, always
  needs awaiting — which is also why `frame(state, chunk)` itself is now always `await`ed
  by `runScript` below (harmless for a plain sync `frame`). Rejects with a plain `Error`
  on any non-2xx response (`core/fs`/`core/kv` collapse "not found" and "service not
  configured" into the same status code, so there's exactly one failure idiom to handle,
  not two). Browser-verified: write/read/list/delete round-trips for both `fs`/`kv`,
  including a deleted key's `read` correctly rejecting.
- **`frameRuntime.js`** runs the script in a Worker via the same two-Blob-plus-`sourceURL`
  loading technique `scriptRuntime.js` uses (see that file's header comment) — but
  **not** that file's IIFE-wrapping of the script Blob: the framer contract looks
  `frame` up by *name* (`typeof frame`/`frame(...)`, unlike tamper's side-effecting
  `tamper.register(...)`), and an IIFE would trap the script's `function frame(...)`
  declaration in its own local scope instead of the global one BOOTSTRAP looks it up
  in — always failing with "framer script must define a top-level function named
  'frame'" regardless of the script's actual content. No wrapper is needed here since
  BOOTSTRAP's own internals are already scoped inside their own separate IIFE.
- No RPC bridge: a framer script is a pure function over bytes already fetched onto the
  main thread, so there's no `peek`/`release`/live-connection access from inside the
  Worker at all, unlike tamper's scripted interception — `framer.fs.*`/`kv.*` above are a
  direct `fetch()`, not a bridged call, and don't change this. The only *postMessage*
  traffic is a batch/ack cycle: `runFramer(scriptName, scriptSource, initialState,
  initialProcessedOffset, chunks, onBatch, onLog?)` posts every chunk in one message
  (`initialProcessedOffset` is `{c2s, s2c}` — the caller's own current progress per
  direction, seeded so a batch that hasn't yet touched one direction still reports that
  direction's already-correct offset rather than 0); the Worker loops over them calling
  `frame()`, tagging each returned frame with the numeric direction of whichever chunk
  produced it, and posts a `{frames, state, processedOffset}` batch back every
  `BATCH_FRAMES` (500) frames or `BATCH_BYTES` (2 MB) processed, whichever comes first
  (plus a final batch, even if empty, so a trailing state-only advance still persists) —
  `processedOffset` in that batch is `{c2s, s2c}`, only the touched direction's value
  actually advancing. `onBatch` must return a Promise, and the Worker waits for it to
  resolve (`{kind:'continue'}`) before computing the next batch. This is what lets the
  caller apply backpressure and stop immediately (nothing further computed) if a batch
  fails to persist. A script that never defines `frame`, or throws, rejects `runFramer`'s
  promise; so does an `onBatch` rejection (e.g. a 409 from `appendFrames`) — in every case
  the Worker is torn down immediately, not asked to wind down gracefully.
- **`framerRun.js`**'s `catchUpFramer(sessionId, streamId, scriptName, scriptSource,
  streamEnd, tlsInfo, onLog?)` (plain scalar ids, matching every other `api.js` wrapper —
  not whole session/stream objects; no `direction` param — combined mode's key spans both;
  `streamEnd` is the stream's own `end` field, `0` while ongoing — same convention
  `TrafficView.js`'s `isClosed(stream)` and `chunkSegments.js`'s own `end` prop already
  use; `tlsInfo` is `framerRun.js`'s own `streamTlsInfo(stream)` (moved here from
  `TrafficView.js` once `framerJobsListener.js` below needed it too — a manual Run and a
  remote-triggered one must derive it identically) — `null`, or `{sni, alpn,
  version, cipherSuite}` from the stream's downstream TLS handshake, attached as
  `chunk.tls` on every chunk built below, constant for the run) is the orchestration:
  fetches `frame-progress` (both directions' processed offset, the framer's own shared
  persisted `state`, and whether each direction's close signal was already delivered) and
  `/chunklist`'s lengths for both directions; if both close signals were already
  delivered, or (nothing new for either direction *and* the stream hasn't closed),
  resolves immediately having fetched nothing further.
  Otherwise resolves each direction's own starting point via `api.js`'s `getByteStid`
  (skipped for a direction with zero bytes ever captured, since `/byte-stid` 404s with no
  chunks to floor-resolve against) and fetches everything from the earliest of the two
  onward, merged across both directions in one `openStidStream()` call (unfiltered,
  unbounded — reusing the same underlying mechanism `fetchDirectionChunks` already
  wrapped for the pre-combined-mode per-direction fetch, rather than a new endpoint; see
  the design doc's "Open, not yet decided" note, resolved this way). Runs the merged
  result through `runFramer` (one shared instance, both directions), tagging each
  returned frame with the `stid` *and* `time` of whichever raw chunk **in that frame's own
  direction's sequence** contains its last byte (via a per-direction `chunkAtOffset`
  cursor — deliberately independent of the order the script actually returned the frame
  in; see `frames.seq` in `intercept/dbdump/CLAUDE.md` for that separate, emission-order
  concept) — a frame has no timestamp of its own, since it's computed, not captured —
  before calling `appendFrames` after each batch with a running `{c2s, s2c}`
  `expectedOffset` tracker. `scriptVersion` (sha256 hex of `scriptSource`, via
  `sha256Hex` — also exported) is computed once per call, not passed in, so every caller
  derives it identically. Idempotent and safe to call repeatedly — `TrafficView.js`'s
  live-tailing effect (below) calls it again on every central-poll tick while a stream
  with an active framer is still growing. `onLog`, if given, is passed straight through to
  `runFramer` unchanged — `runFramer`'s own `onLog(direction, args)` already carries the
  right per-call direction now that one run spans both (see the `framer.log` bullet
  above), so `catchUpFramer` no longer needs to wrap it with a fixed direction of its own.
  - **Connection-close signal**: once `streamEnd` is nonzero, for each direction not
    already marked closed, `runFramer`'s `chunks` array gets one extra synthetic entry
    appended — `{offset: totalLength, length: 0, direction, data: new Uint8Array(0),
    closed: true}` — interleaved in wherever that direction's own real backlog ends (in
    practice both land at the very end of the merged sequence, since a full catch-up run
    processes both directions all the way to the true end). Each direction's own starting
    point is always resolved (see above) even when it has no new backlog of its own —
    floor-lookup naturally resolves to that direction's last real chunk, which is exactly
    what's needed so a frame the script emits on that direction's synthetic call can still
    resolve a real `stid`/`time` via `chunkAtOffset`. Once `runFramer` resolves — meaning
    every batch, including whichever one(s) carried a synthetic chunk, already persisted
    via an ordinary `appendFrames(..., closed: {c2s: false, s2c: false})` call — one
    dedicated trailing `appendFrames(key, expectedOffset, [], expectedOffset, finalState,
    {c2s: true, s2c: true})` call marks `frame_progress.closed_c2s`/`closed_s2c`, so a
    later call short-circuits instead of ever redelivering either signal (needed because
    `TrafficView.js`'s live-tailing effect keeps re-polling on every central-poll tick
    regardless of whether the stream has closed). Both flags are always set together in
    this one call — the two directions share a single TCP connection and thus a single
    `stream.end`, so there's no scenario where only one has actually closed. A frame
    emitted from a synthetic call for a direction that captured **zero bytes ever** has no
    real chunk for that direction's `chunkAtOffset` to resolve against and throws — an
    accepted edge case (surfaces as an ordinary framer-run error), not worth guarding
    since it only arises from a script emitting a frame that references no real data.
- **`framerPrefs.js`**: `localStorage`-backed preferences, deliberately **not** the same
  in-memory-only mechanism "remember stream position" uses (App.js) — these survive a
  reload. `loadDefaultFramerScript`/`saveDefaultFramerScript` (one global default, driven
  by the View menu's "Default framer" entry); `loadStreamFramerScript`/
  `saveStreamFramerScript` (per-`session:streamId` override — what's selected in the
  dropdown; reading falls back to the default when a stream has no override of its own
  yet — once it does, the two are independent); `loadResumeScript`/`saveResumeScript`
  (per-`session:streamId`, separate map — what this stream was *last successfully framed
  with*, set on a successful Run and cleared by "Show raw chunks"; see
  `TrafficView.js`'s auto-resume note below for how the two interact).
- **`TrafficView.js`'s "Framer" control** (in the stream meta bar) and the frame-view
  toggle:
  - `frameState`: `'raw'` | `'framing'` | `'framed'` — not itself persisted, but the
    stream-reselection effect auto-resumes `'framed'` when `framerPrefs.js`'s
    `loadResumeScript(...)` still equals the script currently selected for this stream
    (`loadStreamFramerScript(...)`) — i.e. this exact stream was actually successfully
    framed with this exact script before, not merely "a script happens to be selected"
    (an inherited global default the user never ran here doesn't qualify — a framer is
    never auto-run against a stream it has no established business with). When it
    doesn't match (never run, script changed since, or an explicit "Show raw chunks" —
    which clears `resumeScript` — happened since), `frameState` resets to `'raw'` as
    before and a Run click is required. `runFramerFor(scriptName, targetStream)` is the
    one function both the auto-resume path and the button's `handleRunFramer` call
    (explicit args, not read from `framerSelected`/`stream` closure state, since the
    auto-resume call fires from inside the very effect that's still updating
    `framerSelected` for the newly-selected stream) — **blocking**: the raw view stays
    up, "Run" shows "Framing…" and is disabled, until the single `catchUpFramer` call
    (combined mode — one call now covers both directions, unlike the pre-combined-mode
    `Promise.all` of two) resolves or throws. It computes `scriptVersion` (`sha256Hex`)
    and calls `clearStreamFrames` (`dbdumpFramerApi.js`) *before* that call — enforces
    "at most one framing view per stream" (see `intercept/dbdump/CLAUDE.md`'s
    `clearStreamFrames`) on every run, not just a script edit/delete; a rerun of the
    already-active `(script, version)` is a no-op there, so `catchUpFramer` still resumes
    rather than reprocessing — this is also what makes auto-resume cheap when nothing
    changed and correctly a full reprocess when the script was edited since, with no
    separate client-side version comparison needed. On success the picked script is
    persisted as both this stream's override and its `resumeScript`; on failure
    (including the clear itself), `frameState` falls back to `'raw'` (`resumeScript` is
    left untouched on failure — a transient failure resuming an established framing
    shouldn't un-establish it) and the message surfaces via a `.error-msg` banner at the
    top of `.traffic-body`, above the hex view. `streamGenRef` (bumped once per stream
    (re)selection) guards every state-applying step in `runFramerFor` against a stream
    switch superseding it while it's still in flight — needed once auto-resume can fire
    on every switch, not just an occasional manual click.
  - Once `'framed'`, both directions are shown merged in one scroll (see
    `intercept/dbdump/CLAUDE.md`'s "Cross-direction interleaving" note for the backend
    half); "Show raw chunks" returns to `'raw'` without discarding anything (the
    raw-mode hook's own data was never torn down — only which of the two is rendered
    changes) and clears `resumeScript` for this stream (see above).
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
    view already reacts to) calls `catchUpFramer` again (one call, both directions)
    whenever frame view is active, then bumps a `frameRefreshKey` fed into the frame-mode hook's
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

**"Framing" Analysis bottom-panel tab (`FramingPanel.js`, `FramerScriptsPanel.js`,
`FramerLogPanel.js`):** groups the in-app framer-script editor and a running script's log
under one tab, **Scripts**/**Log** as sub-tabs — same shape as the Tamper tab's own
Intercept/Scripts split (`TamperView.js`'s `subTab`). Positioned after Transform in the
bottom-tab bar (`Goto | Markers | Search | Extract | Transform | Framing`).

- **`FramingPanel.js`** owns just the sub-tab switch (`subTab`: `'scripts'` | `'log'`,
  local, resets to `'scripts'` on remount — nothing here needs to survive switching away
  from the Framing tab, unlike tamper's Scripts sub-tab whose running script/log *do*
  survive switching away, since framer has no persistent "currently running" concept
  the way tamper does). `frameLog`/`onClearFrameLog` are passed through from `App.js`
  (see below) since that data needs to survive switching *sub-tabs* here without
  resetting; `refreshSignal` is `App.js`'s existing header-refresh counter, reused as-is.
- **`FramerScriptsPanel.js`** is a thin wrapper around `ScriptsCrudPanel.js` (see
  "Scripted interception" above): dbdump's script REST functions, a new
  `FRAMER_COMPLETION_SHAPE` (mirrors `TAMPER_COMPLETION_SHAPE`'s `transform`/`number`
  generation from the same `OPERATIONS_BY_CATEGORY`/`camelCaseOpId`/`NUMBER_TYPES`/
  `capitalizeTypeId` inputs, plus `encode`/`decode`/`log` — no `fs`, no RPC methods, no
  `ctx`-equivalent, since a framer script has none of those), no `controls`/
  `rowDecoration` — CRUD only. Running still happens from `TrafficView.js`'s own
  meta-bar "Run" button (tied to a specific stream), not from this panel — a second
  "run" trigger here would need its own stream-picker, duplicating that. Root class
  `.framer-scripts-view` — `height: 100%` rather than `.tamper-scripts-main`'s `flex: 1`,
  since it sits inside `.framing-body` (a `flex: 1` region under the sub-tab bar) rather
  than a flex-column ancestor the way tamper's version does (see `index.html`'s CSS
  comments on both classes).
- **`FramerLogPanel.js`**: `<${FramerLogPanel} lines onClear />`, `lines` is
  `[{direction, text, level}]`. Reuses tamper's log CSS (`.tamper-scripts-log-body`,
  `.tamper-log-line`/`.tamper-log-${level}`) since the rendering is identical; only the
  root layout class (`.framer-log-panel`, `height: 100%` for the same reason
  `.framer-scripts-view` is) is new. Each line is prefixed `[c2s]`/`[s2c]` (or nothing,
  for a `direction: null` script-level failure) since both directions' `catchUpFramer`
  calls log concurrently and would otherwise interleave indistinguishably. A Download
  button (reusing `download.js`'s `downloadBlob`) writes plain text with the direction
  prefix and an `[ERROR]` marker for error lines, since neither the tag styling nor the
  bracket-prefix layout survives into a downloaded file.
- **`App.js`** owns `frameLog` (capped array, `FRAME_LOG_LIMIT = 500`, same cap tamper's
  `scriptLog` uses) and `handleFramerLog`/`handleFramerLogReset`, wired into
  `TrafficView.js` as `onFramerLog(direction, text, level)`/`onFramerLogReset()`.
  `frameLog` is scoped to whichever stream is currently selected: `TrafficView.js`'s own
  stream-switch reset effect (the one that already resets `frameState`/
  `frameScriptRunning` — see above) also calls `onFramerLogReset`, since a framer run has
  no continuity across a stream switch the way tamper's proxy-wide running script does.
  `handleRunFramer`'s `catch` block calls `onFramerLog(null, e.message, 'error')` in
  addition to setting `frameError` — the existing banner stays the immediate/prominent
  signal; the Log tab becomes a persistent trail that includes that same failure, not
  just successful runs.

**Remote framer job listener (`framerJobsListener.js`):** lets `tapctl dbdump run-framer`
(see `tapctl/CLAUDE.md`) trigger a real framer run through this tab, over the relay
`intercept/dbdump/CLAUDE.md`'s "Framer jobs" section documents server-side. Runs the
*exact same* `catchUpFramer(...)` a manual Run click calls — no separate execution path
to keep in sync with the real one, and no server-side script execution exists or is
being added; this is purely a dispatch mechanism from a CLI call to a tab that already
has the real code loaded. Browser-verified 2026-09-08 (see the dbdump-side note for what
was exercised).

- **`useFramerJobsListener(enabled, dbdumpApi, framerApi)`**: a plain hook, mounted
  unconditionally in `App.js` (independent of stream/session selection — a job names its
  own session/stream, unrelated to whatever's currently on screen) but only opens the
  `openFramerJobs` connection while `enabled` is true. Returns `'disconnected'` |
  `'connecting'` | `'connected'` for the toggle's own status text.
  - **Deliberately opt-in** — `App.js`'s View-menu "Remote framer runs" checkbox
    (default off, not persisted — same as every other View-menu toggle except the two
    `*Prefs.js`-backed script selects). A tab never becomes remotely triggerable just by
    being open; the checkbox's own row shows live connection status (`● connected` /
    `connecting…` / `○ disconnected`) next to it, and — unlike every sibling toggle in
    that menu — clicking it does *not* close the menu, so that status is actually visible
    to watch change right after toggling on.
  - **On a job**: resolves the target stream (`dbdumpApi.getStreams(job.session)`,
    matched by `job.stream`) and the script's current content
    (`framerApi.getFramerScript(job.script)`) concurrently, then calls `catchUpFramer`
    exactly as `TrafficView.js`'s own manual Run does, using the shared
    `streamTlsInfo` (see above). Any failure along the way — stream not found, unknown
    script (a real `getFramerScript` 404), or `catchUpFramer` itself throwing — is caught
    and reported back as an ordinary job failure (`conn.respond(job.job_id, false,
    err.message)`), never left to throw unhandled in the hook.
  - **No persistence of its own**: this hook doesn't track which jobs it has handled or
    keep any state across renders beyond the connection itself — `intercept/dbdump/
    CLAUDE.md`'s relay is what tracks in-flight jobs, and `frames`/`frame_progress` (via
    the ordinary `appendFrames` calls inside `catchUpFramer`) are what actually persist.

**Dissector scripts (`dissectRuntime.js`, `dbdumpDissectApi.js`, `dissectPrefs.js`,
`DissectPanel.js`, `DissectScriptsPanel.js`) — done, feature-complete for v1:** produces a
labeled field-tree breakdown of one frame's bytes, à la Wireshark's packet-details pane.
Full design (field node schema, `dissect(bytes, frame)` contract) in
[`doc/design/packet-dissector.md`](../doc/design/packet-dissector.md); backend script
storage in `intercept/dbdump/CLAUDE.md`'s "Dissector scripts" section.

Browser-verified against `examples/dbdump/dissect/http2-dissector.js` — field tree
renders, clicking a field highlights the corresponding hex-view bytes.

- **Script contract**: a plain top-level `function dissect(bytes, frame)`, sync or async —
  always `await`ed by `runScript` below (so a script that needs `dissector.fs.*`/`kv.*`
  can just await them inline; harmless for a plain sync `dissect`) — looked up by name,
  same convention as the framer's `frame(state, chunk)`, and for the same reason
  (`dissectRuntime.js`'s `buildScriptSource` isn't IIFE-wrapped, same as
  `frameRuntime.js`'s). Returns `FieldNode[]` — top-level siblings, not one wrapping root.
  Unlike a framer script, there's no `state` threaded across calls (dissection has no
  cross-frame memory) and no batch/ack cycle (one call, one result) — `dissectRuntime.js`
  spins up a fresh Worker per call rather than reusing one across frames, since dissection
  is on-demand per selected frame, not a running process; revisit only if per-click
  Worker-startup cost turns out to matter in practice.
- **A global `dissector` object** exposes the same transform framework framer/tamper
  scripts get, under `dissector.transform.<category>.*`/`dissector.encode.{hex,base64,
  hexdump}`/`dissector.decode.{hex,base64,hexdump}`/`dissector.number.decode<Type>`/
  `encode<Type>` — mirroring `framer.*`'s shape (see "Framer scripts" above) and its
  always-synchronous convention, via the same shared `transformWorkerApi.js`. Named
  `dissector`, not `dissect`, specifically so it can't collide with the script's own
  top-level `function dissect(...)` declaration. Lets a script report a node's `content`
  for something that isn't a direct frame slice (e.g. a decompressed sub-payload via
  `dissector.transform.compression.zlibDecompress(bytes)`, base64-encoded for `content`
  via `dissector.encode.base64(...)`) without a second formatting implementation. Also
  exposes `dissector.fs.*`/`kv.*` (`coreApiClient.js`) — the same method shapes
  `framer.fs.*`/`kv.*` and `tamper.fs.*`/`kv.*` expose (see "Framer scripts" above for the
  full method list and error convention); real network calls, so unlike the transform
  surface above these always return a Promise. A plausible use: a dissector correlating
  bytes against a crypto key another script derived and stashed via `kv.write` on a
  different connection/stream. Browser-verified: `fs`/`kv` round-trips from inside a
  `dissect()` call.
- **No RPC bridge, no live-connection access from inside the Worker at all** — a dissector
  script is a pure function over bytes the main thread already has (the design doc's
  "Execution model" section is explicit that only the two-Blob-plus-`sourceURL` loading
  trick is worth carrying over from `scriptRuntime.js`/`frameRuntime.js`; not worth
  factoring into shared code across three call sites, per this repo's duplication policy —
  same conclusion each of the three independently reaches for that trick).
  `dissector.fs.*`/`kv.*` above are a direct `fetch()`, not a bridged call, and don't
  change this.
- **`runDissector(scriptName, scriptSource, bytes, frame)`** posts one `{kind: 'run',
  bytes, frame}` message; the Worker calls `dissect(bytes, frame)` after `modulesReady`
  resolves and posts back `{kind: 'result', nodes}` or `{kind: 'error', message}`. Rejects
  if the script throws, never defines `dissect`, or `dissect` doesn't return an array —
  the last case is checked explicitly (`Array.isArray`) rather than silently coerced to
  `[]`, matching this codebase's fail-loud convention for a contract violation.
- **`dbdumpDissectApi.js`** — `listDissectScripts`/`getDissectScript`/
  `putDissectScript`/`deleteDissectScript`, byte-for-byte the same shape as
  `dbdumpFramerApi.js`'s own script functions, pointed at `/api/i/dbdump/dissect/scripts`
  instead of `/api/i/dbdump/scripts` — the exact shape `ScriptsCrudPanel.js` expects
  (`list`/`get`/`put`/`del` props), so a future `DissectScriptsPanel.js` can wrap it the
  same way `FramerScriptsPanel.js` wraps the framer's own functions (see "Scripted
  interception" above). No frame-index-style read/extend functions here — dissection
  output is never persisted, so there's nothing beyond script CRUD to wrap.
- **`dissectPrefs.js`** — `localStorage`-backed script-selection persistence, a straight
  mirror of `framerPrefs.js` (global default + per-stream override, own storage key
  `tlstap-dissect-prefs`): `loadDefaultDissectScript`/`saveDefaultDissectScript` (driven
  by the View menu's "Default dissector" entry, next to "Default framer") and
  `loadStreamDissectScript`/`saveStreamDissectScript` (per-`session:streamId`, falling
  back to the default until a stream has its own override).
- **`DissectPanel.js`** — the field-tree side panel, `TrafficView.js`'s right edge, frame
  view only (see "Frame selection for dissection" under "Virtual scroll" above for how a
  frame becomes `selectedFrame`). Runs `dissect()` in an effect keyed on
  `[selectedFrame?.key, dissectorSelected]` — re-fetches the script's current content via
  `getDissectScript` on every run rather than caching it, so an edit made in the "Dissect"
  bottom tab (below) takes effect on the very next frame click with no separate reload
  step, unlike the framer's cached `frameScriptRunning`. Placeholders for "no frame
  selected yet" / "no script chosen"; a thrown/malformed result surfaces as an
  `.error-msg` banner, not a crash.
  - **`resolveValue(node, frameBytes)`** turns a node's `content` or `offset`/`length`
    (mutually exclusive, per the schema) into `{text, bytes}`: an `offset`/`length` node
    slices `frameBytes` directly; a `content` string is treated as base64 *only* when
    `display-hint` is present (undecorated string content renders as-is — a script's own
    already-formatted label); a `content` number/bool renders via `String(...)`,
    `display-hint` ignored. `display-hint` is one of `format.js`'s own formatter names
    (`ascii`/`hex`/`hexdump`/`base64`/`raw`), defaulting to `hex` when byte-shaped but
    unhinted. **Wrapped in try/catch** — a bad base64 `content` (or any other malformed
    node) renders as an inline `(invalid: ...)` value instead of throwing mid-render, since
    this codebase has no error boundary to catch it. A non-object array entry gets the
    same treatment one level up, in `FieldNode` itself.
  - **`FieldNode`** (recursive): local `expanded` state per instance (default expanded,
    resets on remount — no persistence, matching `HexEditor.js`'s cursor not persisting
    across remounts). Only a node with both `offset` and `length` is clickable
    (`.dissect-node-clickable`) — clicking translates its frame-relative range to an
    absolute one (`frameOffset + node.offset`, inclusive end) and calls `onNodeClick`,
    forwarded unchanged through every recursion level from the top-level list's own
    closure (which is where `selectedFrame.frame.direction` actually gets attached — a
    node itself carries no direction, since it's implicit in whichever frame is selected).
  - **A multi-line value** (`text.includes('\n')` — in practice only a `hexdump`-hinted
    field spanning more than one `fmtAsHexdump` line) skips the inline
    `.dissect-node-value` span and renders instead as its own `<${HexdumpValue}>` block
    on the line(s) below the label row: a `white-space: pre` block that scrolls both
    ways (`overflow: auto`) rather than shrinking `fmtAsHexdump`'s fixed 16-bytes/line
    layout to fit — horizontally when the panel's narrower than one xxd line, vertically
    past a fixed `max-height` (`.dissect-node-hexdump`, ~8 lines) that keeps the block
    compact regardless of the field's real size, the field tree's own compactness
    mechanism (not the line cap below). Separately, `MAX_HEXDUMP_LINES` (512, i.e. 8KB)
    is a hard cap on how many lines are ever rendered at all — a DOM-size guard against a
    pathologically large script-decoded field (e.g. a decompressed body), surfaced as a
    trailing `… N more bytes` note only once actually hit; the full bytes stay reachable
    via the context menu's own Copy as hexdump regardless, since that operates on the
    untruncated `bytes` rather than this display text. Shares `handleClick`/
    `handleContextMenu` with the row itself, so the block is clickable (highlights in the
    main hex view) and right-clickable exactly like a single-line value.
  - Props: `selectedFrame` (`TrafficView.js`'s `{key, frame, bytes}` or `null`),
    `dissectScripts`, `dissectorSelected`, `onDissectorSelect`, `onNodeClick(direction,
    start, end)`.
- **`DissectScriptsPanel.js`** — thin `ScriptsCrudPanel.js` wrapper, byte-for-byte the
  same shape as `FramerScriptsPanel.js` (own `DISSECTOR_COMPLETION_SHAPE`, generated the
  same way from `OPERATIONS_BY_CATEGORY`/`NUMBER_TYPES`, minus `log` — a dissector script
  has no equivalent). CRUD only, no `controls`/`rowDecoration` — a dissector script runs
  on-demand per selected frame from `DissectPanel.js`, not from here.
- **"Dissect" Analysis bottom-panel tab** (`App.js`): positioned after "Framing"
  (`Goto | Markers | Search | Extract | Transform | Framing | Dissect`). Unlike
  `FramingPanel.js`, no Scripts/Log sub-tab split — `DissectScriptsPanel.js` is the
  entire tab content directly, since there's no running-script log to show alongside the
  editor (errors surface inline in `DissectPanel.js` itself, per-frame).
- **`TrafficView.js`'s own state**: `selectedFrame`/`dissectHighlight`/
  `dissectorSelected` (see the doc comment directly above `handleFrameHeaderClick` in
  that file) are all reset together on a stream switch, on `handleShowRawChunks` (leaving
  frame view), and at the start of `handleRunFramer` (a fresh run's `clearStreamFrames`
  can invalidate a previously-selected frame's key) — `dissectorSelected` alone survives
  a stream switch, reloaded from `dissectPrefs.js` like `framerSelected` is from
  `framerPrefs.js`. `dissectPanelWidth` (`layout.js`) is not stream-scoped, same as every
  other resizable-panel width in this codebase.

**Remote dissector job listener (`dissectorJobsListener.js`):** the "Remote framer job
listener" section's dissector-script sibling — lets `tapctl dbdump run-dissector` (see
`tapctl/CLAUDE.md`) trigger a real dissection through this tab, over the relay
`intercept/dbdump/CLAUDE.md`'s "Dissector jobs" section documents server-side. Runs the
*exact same* `runDissector(...)` (`dissectRuntime.js`) a per-frame click in
`DissectPanel.js` calls — no separate execution path. Independent opt-in from the framer
listener (own `remoteDissectorJobs` state, own "Remote dissector runs" View-menu toggle,
own connection) — kept separate rather than folding both job kinds into one relay/toggle,
matching this codebase's consistent framer/dissector-are-separate-systems precedent (own
stores, own panels, own default-script prefs). Browser-verified 2026-09-08 alongside the
framer listener.

- **`useDissectorJobsListener(enabled, dbdumpApi, framerApi, dissectApi)`**: same shape
  as `useFramerJobsListener` (mounted unconditionally in `App.js`, only connects while
  `enabled`), returning the same three-state status string.
- **On a job**: unlike a framer job, there's no framer script to fetch or run here — the
  target frame is already fully computed and persisted. Fetches the exact frame
  (`framerApi.listFrames({...key}, job.frame_id, 1)`, verified against the returned
  `id` — a mismatch or empty result means "frame not found," reported as an ordinary job
  failure) and the dissector script's current content (`dissectApi.getDissectScript`)
  concurrently, then its bytes via `dbdumpApi.fetchByteRanges` over the frame's own
  `ranges` (merged in range order via `format.js`'s `mergeUint8Arrays` when there's more
  than one — the same primitive `frameSegments.js` uses for the UI's own frame view, not
  a second implementation of it), then calls `runDissector` with a `frame` argument
  shaped like `TrafficView.js`'s `handleFrameHeaderClick` builds one (`offset: 0` — always
  the start of a frame's own virtual concatenation, per `frameSegmentsCore.js`'s module
  comment — `length`, `direction`, `kind: meta?.kind`, `meta`).
- **Result carries data, not just ok/error**: `conn.respond(jobId, ok, extra)`'s `extra`
  is merged into the wire message — `{nodes}` on success (the dissector's own
  `FieldNode[]` tree, nothing persisted for `tapctl` to go query afterward the way a
  framer job's frames are), `{error}` on failure. `api.js`'s `openDissectorJobs` is the
  thin WS wrapper this hook opens, mirroring `openFramerJobs`'s shape with that one
  payload difference.
