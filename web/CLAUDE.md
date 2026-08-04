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
- `App.js` owns `openMenu` (null | `'view'`) and `globalOffset` (bool, default `true`).
- A `mousedown` listener on `document` (active only while a menu is open) closes the menu when clicking outside the `.menubar` element.
- Currently one menu: **View** → **Global offset** toggle and **View mode** (Single stream / Combined streams), each a separate separator-delimited group. The checkmark (✓) uses `.menu-check` styled with `var(--accent)`.
- `globalOffset` is passed down: `App` → `TrafficView`/`CombinedView` → `HexDump` → `HexRow`.

**Refresh (`App.js`):**
- The header's `↺` button (`.btn-refresh` — icon-only, ~34×30px, no label) increments `refreshKey` (a plain counter) on click.
- `refreshKey` is threaded into `SessionList`, `StreamList`, `TrafficView`, and `CombinedView`; each re-fetches whatever it owns when the value changes (see their respective sections below).
- There used to be an Auto-Refresh toggle (View menu) that just clicked this button on a 1s timer; removed once the central live poll below made it fully redundant — every field the toggle used to keep fresh is already covered by the poll's counters.

**Central live poll (`App.js`):**
- One `usePoll(true, POLL_INTERVAL_MS, tick)` call (`usePoll.js`, 500ms) is the single source of live-ness for the whole Analysis view — `SessionList`, `StreamList`, and whichever of `TrafficView`/`CombinedView` is mounted all react to its output rather than polling themselves. This replaced an earlier per-component design (each of those four independently called its own cheap-check endpoint every tick) once `intercept/dbdump` gained a single consolidated endpoint for exactly this purpose — see "`/latest`" in its `CLAUDE.md`.
- Each tick calls `getLatest(params)` (`api.js`), building `params` from current selection: `{session: session.id}` if a session is selected, plus `stream: stream.id` only when `viewMode === 'single'` and a stream is selected too (`CombinedView` has no use for `latest_stid`, so it's left out server-side rather than fetched and ignored). The raw `{latest_session_id, latest_sgid, streams_version, latest_stid}` response is stored as-is in a `latest` state object (field names kept snake_case, matching the wire response directly — no camelCase translation layer) and passed down as four separately-named props: `latestSessionId` (`SessionList`), `streamsVersion` (`StreamList`), `latestStid` (`TrafficView`), `latestSgid` (`CombinedView`).
- `tick`'s closure captures `session`/`stream`/`viewMode` fresh from each render (per `usePoll.js`'s contract — `tickRef.current = tick` is reassigned unconditionally every render, not gated behind a dependency array), so there's no separate ref-syncing needed for the poll to always act on the current selection.
- A failed `getLatest` call (network hiccup, mid-restart of the proxy process — see `intercept/dbdump/CLAUDE.md`'s "Async write buffer" for why sub-second polling doesn't imply sub-second data anyway) is silently swallowed; the next tick just retries. Each downstream consumer's own "did this number change" comparison (below) naturally treats an unchanged `latest` as a no-op, so a missed tick is invisible rather than disruptive.

**Bottom panel (`App.js`):**
- `bottomTab` state: `null` (collapsed) | `'goto'` | `'search'` | `'extract'` | `'transform'`.
- `selectBottomTab(name)`: sets tab; does not toggle (panel only collapses via the `▼` button at the right of the tab bar).
- Tab bar contains: **Goto**, **Search**, **Extract**, **Transform**, and a collapse button (`▼`) on the right.
- Content area (`.bottom-content`, resizable — see "Resizable panels" below) renders `GoToPanel`, `SearchPanel`, `ExtractPanel`, or `TransformPanel` based on `bottomTab`.
- A `ResizeHandle` (`orientation="h"`) sits at the top edge of `.bottom-panel`, shown only while `bottomTab` is set (nothing to resize when collapsed).

**Session/stream list panels (`ListPanel.js`, `SessionList.js`, `StreamList.js`):**
- `ListPanel.js` is the shared panel chrome: `<${ListPanel} title items error? emptyMessage selected onSelect renderItem resetSortKey? />`. It owns the `desc` sort state (default `false` = ascending/oldest first), the `▼`/`▲` toggle button in the panel header, the count badge, the sorted/mapped item list (`key`/`selected`-class/`onclick` wrapper), and the empty-state line (`error`, if passed and truthy, takes priority over `emptyMessage`). Callers own fetching the data, deciding what `error`/`emptyMessage` should say, and each item's actual row markup via `renderItem(item)`.
- `SessionList.js` fetches via `getSessions()`, tracks its own `error` state, and never passes `resetSortKey` — matching its original never-reset-on-its-own sort behavior.
- `StreamList.js` fetches via `getStreams(session.id)` (guarded on `!session`) and passes `resetSortKey=${session?.id}`, which `ListPanel.js` watches via its own effect to reset `desc` back to `false` on session change (kept as a `ListPanel`-internal effect, separate from the fetch effect, so a refresh doesn't reset sort order).
- Both `SessionList.js` and `StreamList.js` re-fetch (`getSessions()` / `getStreams()`) whenever `refreshKey` changes, in addition to their own natural triggers (mount / session change) — this is what makes the Refresh button pick up newly-initiated streams and updated end-times/byte-counts in the sidebar.
- **Reacting to the central live poll** (`App.js`'s `latest` state — see "Central live poll" above; each component here is a pure consumer, no polling of its own): `SessionList.js` takes a `latestSessionId` prop, `StreamList.js` a `streamsVersion` prop. Each owns a `lastSeenIdRef`/`lastSeenVersionRef` and two effects with the same shape:
  - **Seed effect**, keyed on its own natural triggers (`SessionList.js`: `[refreshKey]`; `StreamList.js`: `[session?.id, refreshKey]`) — does the real fetch (`load()`), and also sets `lastSeen*Ref.current = <the prop's current value>`. Deliberately *reads* the prop without depending on it (only the entity/refresh change should reset the baseline; the prop moving on its own is the next effect's job) — same "read fresh, not a dependency" convention `ResizeHandle.js`'s `onResize` uses.
  - **Poll-reaction effect**, keyed on `[latestSessionId]` / `[streamsVersion]` — compares the incoming value against `lastSeen*Ref.current`; only on a genuine difference does it update the ref and re-run `load()`.
  - Seeding from the prop's already-available value (rather than an extra network round trip) means the very next poll tick can't spuriously see a stale baseline and re-trigger a redundant fetch of what the seed effect's own `load()` just fetched — the value being seeded from *is* what the next tick will be compared against.
  - `SessionList.js` previously had no live-poll equivalent at all (new sessions were Refresh-only); it now gets one for free from the same `latestSessionId` prop, no session/stream scoping needed since it's a global counter (see `intercept/dbdump/CLAUDE.md`'s `/latest`).

**Duration formatting:**
- `fmtDuration(start, end)` (`format.js`, used by `StreamList.js` and `TrafficView.js`) — for finished streams (`end` set) formats `end - start`; for ongoing streams (`end` falsy) formats `Date.now() - start` the same way and appends `" (ongoing)"`, e.g. `12.34s (ongoing)`. Re-renders (including ones triggered by Refresh) naturally advance this since it's computed fresh each render.

**Resizable panels (`ResizeHandle.js`, `layout.js`, `useResizableLayout.js`):**
- `ResizeHandle.js` is a generic draggable divider: `<${ResizeHandle} orientation="v"|"h" onResize=${deltaPx => ...} />`. On `mousedown` it attaches document-level `mousemove`/`mouseup` listeners for the duration of the drag (removed on `mouseup`); each `mousemove` calls `onResize(ev.movementX)` (orientation `v`) or `onResize(ev.movementY)` (orientation `h`). The caller owns the resulting size state, clamping and sign convention (a handle placed *after* the sized element in DOM order treats a positive delta as "grow"; a handle placed *before* it treats a negative delta as "grow"). `onResize` is only ever read fresh from props at `mousedown` time (never captured in an effect's dependency array), so its identity doesn't need to be stable across renders — nothing memoizes it, deliberately.
- `layout.js`: `loadLayout()` / `saveLayoutValue(key, value)` — reads/writes a single `localStorage` key (`tlstap-layout`) holding `{ sidebarWidth, markersWidth, bottomHeight, encdecOptionsWidth, encdecInputHeight, tamperDetailHeight, scriptsListWidth, scriptsLogHeight }`, merged with defaults on load (same pattern as `markers.js`). Also exports `clamp(v, lo, hi)`, used both by the hook below and standalone by `TransformPanel.js` (for a step param's numeric bound, unrelated to layout).
- `useResizableLayout(key, { sign = 1, min, max })` (`useResizableLayout.js`) is what every panel below actually calls — it's the one place that reads `loadLayout()[key]` for the initial value, applies `clamp(v + sign * delta, min, max)` on each `onResize(delta)`, and calls `saveLayoutValue(key, next)`, returning `[value, onResize]` (mirrors `useState`'s tuple shape). `max` may be a plain number or a thunk (`() => number`) — the three window-relative panels (bottom panel, tamper detail panel, scripts log panel) pass `() => Math.floor(window.innerHeight * 0.7)` so the bound is re-read at drag-time from whatever `window.innerHeight` currently is, not baked in at whatever render created the hook's return value (there's no `resize` listener anywhere forcing a re-render on browser-window resize, so a plain number captured at render time could go stale between an actual window resize and the next unrelated re-render).
- **Sidebar** (`App.js`): `useResizableLayout('sidebarWidth', { min: 180, max: 600 })` (default 280), handle between `.sidebar` and `.main`.
- **Bottom panel** (`App.js`): `useResizableLayout('bottomHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })` (default 160), handle at the top of `.bottom-panel` (only rendered while a tab is open).
- **Markers panel** (`TrafficView.js`): `useResizableLayout('markersWidth', { sign: -1, min: 150, max: 500 })` (default 240), handle between `HexDump`/`HexEditor` and `MarkersPanel` (only rendered while not collapsed); width passed down as a `width` prop to `MarkersPanel`, applied via inline style on `.markers-side`.
- **Transform panel** (`TransformPanel.js`): `useResizableLayout('encdecOptionsWidth', { min: 100, max: 400 })` (default 160, handle between the options column and the input/output column) and `useResizableLayout('encdecInputHeight', { min: 30, max: 2000 })` (default 120, handle between the input and output areas).
- **Tamper detail panel** (`TamperView.js`): `useResizableLayout('tamperDetailHeight', { sign: -1, min: 120, max: () => Math.floor(window.innerHeight * 0.7) })` (default 300), handle above `.tamper-detail-wrap`, same sign convention as the bottom panel's handle (also placed before the sized element).
- **Tamper scripts sub-tab** (`TamperScriptsPanel.js`): `useResizableLayout('scriptsListWidth', { min: 150, max: 500 })` (default 220, handle between the script list and editor) and `useResizableLayout('scriptsLogHeight', { sign: -1, min: 80, max: () => Math.floor(window.innerHeight * 0.7) })` (default 160, handle above the log panel).
- All of the above apply their size via inline `style` (not fixed CSS) so the persisted value always wins.

**Outside-click/Escape dismissal (`useDismissOnOutsideClick.js`):**
- `useDismissOnOutsideClick(ref, onClose, active = true)`: while `active`, attaches document-level `mousedown`/`keydown` listeners — `mousedown` calls `onClose()` unless the click landed inside `ref.current` (`ref.current.contains(e.target)`), `keydown` calls `onClose()` on `Escape` — and removes both on cleanup. `active` defaults to `true` for a popover that's only ever mounted while shown (no gating needed); callers that stay mounted with a nullable open/closed state pass their own boolean.
- Used by `TransformPanel.js`'s algorithm menu (`useDismissOnOutsideClick(toolbarRef, () => setMenuOpen(false), menuOpen)`) and `TamperDetailPanel.js`'s `ctxMenu` (`useDismissOnOutsideClick(menuRef, () => setCtxMenu(null), !!ctxMenu)`) and `InsertChunkPopover` (`useDismissOnOutsideClick(popRef, onCancel)`) — the three sites that already shared this exact `ref.contains(e.target)` mechanism before the hook existed.
- **`HexDump.js`'s context menu is a deliberate non-user of this hook.** It has no ref of its own to check containment against; instead its `.ctx-menu` container calls `onMouseDown={e => e.stopPropagation()}` so an inside click never reaches its own unconditional document-level `mousedown` → close listener. The two mechanisms both prevent the same failure mode (see next bullet) but aren't drop-in compatible — folding `HexDump.js` in would mean giving it a ref and deciding whether the now-redundant `stopPropagation` can be dropped, not a pure mechanical extraction, so it was left as its own documented outlier.
- **Why the ref-contains check matters, not just "any dismiss listener works":** `mousedown` fires before `click`, so an *unconditional* close-on-any-mousedown would unmount a menu before a click on one of its own items ever reaches it. This is invisible when every item's only effect is closing the menu anyway, but a real bug once an item does something else — this was caught in practice by `TamperDetailPanel.js`'s **Split** action silently not firing before its dismiss handler was written with the containment check.

**Virtual scroll (`HexDump.js`):**
- Exports `ROW_HEIGHT = 22`. Constants: `BUFFER = 8` (overdraw rows), `PREFETCH_FRACTION = 0.1`.
- Props: `rows`, `onScrollEnd`, `scrollAdjust`, `adjustVersion`, `scrollTo`, `scrollToVersion`, `globalOffset`, `onSetMarker`, `onClearMarker`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`, `onViewportChange`, `markers`.
- Encoding helpers imported from `../format.js` (not defined locally).
- Flattens all loaded chunks into a flat `rows[]` array: one `{type:'header'}` row + N `{type:'hex'}` rows per chunk.
- A `ResizeObserver` tracks container height; `onScroll` tracks `scrollTop`. Visible window is `[startIdx, endIdx)`. Inner div height = `rows.length * ROW_HEIGHT`; top/bottom spacer divs fill the rest.
- **Prefetch trigger** (`scrollend` event): fires `onScrollEnd(1)` when fewer than `rows.length * PREFETCH_FRACTION` rows remain below the viewport; `onScrollEnd(-1)` when fewer remain above.
- **Scroll correction** (`useLayoutEffect([adjustVersion])`): applies signed `scrollAdjust` to `scrollTop` synchronously before paint. Negative = scroll up (after front eviction); positive = scroll down (after prepend).
- **Absolute scroll** (`useLayoutEffect([scrollToVersion])`): sets `scrollTop = scrollTo` synchronously before paint. Used by jump-to. `scrollToVersion` must change to trigger even if `scrollTo` value is the same.
- **Global/local offset**: `HexRow` displays `row.offset` (stream-global byte offset) when `globalOffset` is true, or `row.localOffset` (offset within the chunk, resets to 0 at each chunk start) when false.
- **Byte selection**: `sel` state `{direction, start, end}` (byte offsets, inclusive). `onMouseDown` starts selection; `onMouseMove` extends it if same direction as anchor; document-level `mouseup` ends drag. Per-byte `<span data-off=N data-dir=D>` elements carry `.sel-hl` class when highlighted. Selection is scoped to one direction (cannot drag across c2s/s2c boundary).
- **Byte markers**: `markedC2S` / `markedS2C` — `Set<offset>` derived from `markers` prop. Marked bytes receive `.hex-byte-marked` / `.asc-byte-marked` CSS classes.
- **Chunk header** format: `[+T.TTTs] [#stid] DIRECTION  #chunkId  N B` (stid shown when present; stream number shown in CombinedView).
- **Context menu** (right-click on a hex row or chunk header):
  - Copy as hex / ASCII / hexdump / base64 — copies chunk bytes (header click) or selection/chunk bytes (row click).
  - Separator, then (when right-clicking a hex byte and extract props present):
    - **Set selection (range)** — only when a selection is active; sets both From and To offsets in the Extract tab.
    - **Set selection start** — sets the From offset in the Extract tab.
    - **Set selection end** — sets the To offset in the Extract tab.
  - Separator, then **Set marker** / **Clear marker** — toggles based on whether the byte is already marked.

**Editable hex grid (`HexEditor.js`):**
- Small, non-virtualized hex/ASCII editor (all rows render directly — no windowing), unlike the read-only `HexDump.js` which is built for large captured-traffic streams. Reuses `HexDump.js`'s exported `ROW_HEIGHT` constant for visual consistency only; otherwise fully independent.
- Controlled component: `<${HexEditor} bytes=${Uint8Array} onChange=${bytes => ...} readOnly? style? direction? onContextMenu? />`.
- `onContextMenu` (optional): fires `{index, x, y}` on right-click instead of rendering any menu itself — `index` is the byte position under the cursor (`null` if the click didn't land on a real byte or the trailing insertion cell, e.g. a filler cell or empty space), `x`/`y` are `e.clientX`/`e.clientY` for positioning. HexEditor stays completely generic/menu-agnostic (it's shared with `TransformPanel`, which has no notion of what a menu here would mean) — ownership of the menu's content and behavior lives entirely with the caller; only `TamperDetailPanel.js` passes this prop today, see below.
- **Cursor model**: `cursor = { index, area }` — `index` is a byte position `0..bytes.length` (an insertion point *before* that byte, like a text cursor), `area` is `'hex'` or `'ascii'`. `pendingNibble` holds a single typed hex character awaiting its pair (shown as a half-entered `hexed-pending` cell); cleared by Backspace, arrow movement, Tab, or clicking elsewhere.
- **Typing inserts, never overwrites** (this is the "arbitrary insertion/deletion" requirement it was built for):
  - Hex column: only `[0-9a-fA-F]` accepted (guarded against `Ctrl`/`Cmd`/`Alt` so shortcuts like Ctrl+C aren't swallowed, even though `c`/`d`/`e`/`f` are valid hex chars); two nibbles combine into one inserted byte, cursor advances by one byte.
  - ASCII column: any single printable keystroke inserts one byte (`charCodeAt(0) & 0xFF`), same modifier guard.
  - Backspace removes the byte before the cursor (or just cancels a pending nibble); Delete removes the byte at the cursor; both shift subsequent bytes.
  - Arrow keys move by one byte (Up/Down by one row = 16 bytes); Home/End jump to row start/end, Ctrl+Home/End to buffer start/end; Tab toggles `area` at the same `index`; click on any byte/char cell sets the cursor directly.
  - Paste: clipboard text is filtered per the active column's rules (hex chars paired up in the hex column; every character mapped to a byte in the ASCII column) and inserted in one `onChange` call.
- Row layout mirrors `fmtAsHexdump`'s conventions (16 bytes/row, 8-hex-digit offset, `|ascii|` column) via `.hexed-*` CSS classes — deliberately distinct from `HexDump.js`'s `.hex-*` classes so nothing is shared/at risk between the two components.
- A synthetic trailing cell (`byte === null`) exists at `bufferLength` within the last row so the cursor can be positioned after the last byte, whenever that row isn't already completely full. An empty buffer gets exactly one row (holding just that synthetic cell) since the normal per-row loop produces none. When the buffer length is a non-zero exact multiple of 16, no extra row is added purely to hold the cursor — that would render as an empty hexdump line with no bytes on it; the cursor position past the last byte is still reachable (e.g. via arrow keys), just without a dedicated rendered cell to click on in that one case.
- `readOnly` prop: every mutating path (hex/ASCII insert, Backspace, Delete, paste) becomes a no-op; navigation (arrows/Home/End/Tab) and click-to-position still work. Used for `TransformPanel`'s output panel so it can reuse the same grid without being editable.

**Chunk buffer hook (`useChunkBuffer.js`), shared by `TrafficView.js` and `CombinedView.js`:**
- Backs both views' windowed/paginated chunk buffer — initial load, forward/backward
  scroll-driven eviction, and refresh top-up — previously duplicated near-verbatim
  between the two files (see the TODO section's history for the pre-unification shape).
  `TrafficView.js` is keyed by stream/`stid`; `CombinedView.js` by session/`sgid`; a raw
  fetched chunk and a header row built from it always carry the same id field name
  within a given caller, so one `getId(obj)` accessor works on both shapes.
- `useChunkBuffer({ entity, refreshKey, openStream, fetchPage, getId, buildRows, isClosed, latestId })`
  → `{ display, loading, error, setError, handleScrollEnd, reloadFrom }`. `entity` is the
  current stream or session (or null); `openStream` is `openStidStream`/`openSgidStream`
  (`api.js`, same `() => {fetch, close}` shape either way); `fetchPage(ws, entity, startId, n)`
  wraps whatever entity-specific args `ws.fetch(...)` needs (`TrafficView.js`:
  `stream.session`/`stream.id`; `CombinedView.js`: just `session.id`); `buildRows(chunks,
  startMs)` stays caller-owned (row shape genuinely differs — `CombinedView.js` adds a
  `stream` field per row) and is only ever *invoked* by the hook, not defined in it;
  `isClosed(entity)` is optional — `TrafficView.js` passes `s => !!s.end` so refresh
  top-up (and the live-poll reaction below) stops once a stream closes, `CombinedView.js`
  omits it (a session has no such concept); `latestId` is optional too — see "Live-poll
  reaction" below — a plain number from `App.js`'s central poll (`TrafficView.js`:
  `latestStid`; `CombinedView.js`: `latestSgid`), not a function the hook calls itself.
- `display = {rows, scrollAdjust, adjustVersion, scrollTo, scrollToVersion}` — single
  state object for atomic render, prevents split-render glitch.
- `BATCH = 50` chunks fetched per request (exported, since `TrafficView.js`'s jump-to —
  see below — needs it too, to center the fetched window the same way `reloadFrom` does);
  `MAX_BUFFERED_CHUNKS = BATCH * 2` (100) is a soft cap on how many chunks the refresh
  path is allowed to hold in the buffer at once; `countChunks(rows)` counts `header` rows
  to measure current occupancy against it.
- Refs owned by the hook: `nextIdRef` (exclusive upper bound of buffer), `prevIdRef` (id
  of first chunk in buffer), `hasMoreRef`, `loadingMoreRef`, `generationRef` (increments
  on each entity change or `reloadFrom` call; captured at async start and checked after
  every `await` to abort stale fetches), `entityRef`, `wsRef` (single WS connection per
  entity), `displayRef`, `hasMountedRef`.
- **`reloadFrom(startId, { computeExtra })`**: opens a fresh connection (closing any
  previous one), fetches one `BATCH` window starting at `startId`, builds rows, and
  replaces `display` with the result — merging in `computeExtra(rows)`'s return value if
  given. The entity-change effect calls `reloadFrom(0)` on mount/entity swap with no
  extras; `TrafficView.js`'s jump-to effect (below) is the only other caller, passing a
  non-zero `startId` and a `computeExtra` that scans the freshly-built rows for the
  target row's pixel offset.
- **`handleScrollEnd(scrollDir)`** (stable `useCallback([])`):
  - **Forward** (scrollDir=1): fetches next `BATCH` from `nextIdRef`, appends rows,
    evicts front half at nearest chunk-header boundary, updates `prevIdRef`, sets
    negative `scrollAdjust`.
  - **Backward** (scrollDir=-1): fetches `n = prevIdRef - start` chunks before
    `prevIdRef`, prepends rows, evicts back half, updates `nextIdRef`/`hasMoreRef`, sets
    positive `scrollAdjust`.
  - `findChunkBoundaryNearHalf(rows, fallback)` (hook-internal): scans forward from
    midpoint for a `header` row, falls back to scanning backward.
- **`topUp()`** (hook-internal function, not a `useCallback`): skip if no entity,
  `isClosed?.(entity)` is true, a scroll-triggered load is already in flight
  (`loadingMoreRef.current`), or the buffer has no spare room (`room =
  MAX_BUFFERED_CHUNKS - countChunks(...) <= 0`, checked via `displayRef` so it doesn't
  need `display` in a dependency array). Otherwise it fetches exactly `room` chunks from
  `nextIdRef.current` onward. Unlike `handleScrollEnd`, this path **never evicts and
  never touches `scrollAdjust`/`adjustVersion`** — new rows are appended straight to the
  end of `display.rows`. Since virtualization only cares about total row count, appending
  below the viewport doesn't move anything already on screen; this is what makes a
  top-up visually silent when new data isn't currently visible. Once the cap is hit,
  top-up goes inert until the user scrolls forward (which evicts via the normal path and
  frees up room). Same `generationRef`/`loadingMoreRef` race-safety pattern as
  `handleScrollEnd`. Called from both places below.
- **Refresh top-up**: a `useEffect` keyed on `refreshKey` (guarded by `hasMountedRef` so
  the initial mount is a no-op) calls `topUp()` unconditionally on every tick — this is
  the Refresh-button path.
- **Live-poll reaction**: a plain `useEffect(() => { if (latestId != null && latestId >=
  nextIdRef.current) topUp() }, [latestId])` — no fetching, no interval, no `isClosed`/
  `loadingMoreRef` check here, since `topUp()` already guards on all of that itself. The
  hook does no polling of its own; `latestId` arrives already fetched, from `App.js`'s
  single central poll (see its "Central live poll" section) via `getLatest()`
  (`intercept/dbdump`'s consolidated `/latest` endpoint — see its `CLAUDE.md`), which is
  what makes a poll tick with nothing new cost one shared indexed query server-side and
  zero chunk fetches, rather than one query per mounted view. This is what actually keeps
  the currently-open view live without the user touching Refresh.
  Note: `dbdump`'s chunk writes are themselves buffered and flushed at most once/second
  (see its `CLAUDE.md`'s "Async write buffer"), so polling faster than that narrows the
  average wait but doesn't make new data appear before the next flush.
  (This hook previously polled itself, one `usePoll.js` call per mounted view, each hitting
  its own cheap-check endpoint — collapsed into `App.js`'s single poll once `/latest`
  existed to serve every consumer from one request; see `usePoll.js`'s own header comment
  for why it's a thin, reusable `setInterval` wrapper regardless of caller count.)

**`TrafficView.js`-specific layer on top of the hook:**
- Props: `stream`, `globalOffset`, `jumpTo`, `markers`, `onAddMarker`, `onRemoveMarker`, `onUpdateMarkerLabel`, `onMarkerJumpRequest`, `onImportMarkers`, `onSetExtractStart`, `onSetExtractEnd`, `onSetExtractRange`.
- `handleSetMarker` / `handleClearMarker` are local (not lifted); `onSetExtractStart/End/Range` are forwarded directly to `HexDump`.
- `totalBytes` (the ↑/↓ byte counters in the meta bar) is `TrafficView.js`-only state,
  independent of the hook's `display` — its own small effect mirrors it on `stream?.id`.
- **Jump effect** (`useEffect([jumpTo?.version])`, no `CombinedView.js` equivalent):
  resolves `jumpTo` to a target stid, then calls the hook's `reloadFrom`. A local
  `cancelled` flag (set in the effect's cleanup) guards the resolution step itself against
  a stale jump calling `reloadFrom` after a newer jump has already superseded it — the
  hook's own `generationRef` only protects `reloadFrom`'s internal async work, not this
  caller-side resolution step that happens before `reloadFrom` is even called.
  - `chunks` unit: `targetStid = jumpTo.value`
  - `chunks-c2s` / `chunks-s2c`: calls `POST /chunk-stid` to resolve per-direction `id` → `stid`
  - `offset-c2s` / `offset-s2c`: calls `POST /byte-stid` to resolve byte offset → `stid`; also records `targetByteOffset` and `targetDirection` (0/1, derived from the unit)
  - Calls `reloadFrom(max(0, targetStid - BATCH/2), { computeExtra })`, where
    `computeExtra` scans the freshly-built rows: for byte-offset jumps finds the hex row
    matching **both** `row.direction === targetDirection` and `row.offset <=
    targetByteOffset < row.offset + row.bytes.length` (the direction check matters
    because c2s/s2c offsets both start at 0 independently, so byte ranges collide across
    directions); otherwise finds the header row with `row.stid === targetStid` — then
    returns `{scrollTo, scrollToVersion: jumpTo.version}`. Default (Goto/Search jumps)
    centers the row in the viewport (`targetRowPx - viewHeight/2`); if `jumpTo.align ===
    'top'` (set only by marker jumps — see `App.js`'s `handleMarkerTabJump`/
    `handleStreamLoad`), the row is instead placed at the very top of the viewport
    (`scrollTo = targetRowPx` directly).
  - A resolution failure (the `getChunkStid`/`getByteStid` call itself throwing) calls
    the hook's `setError` directly, since `reloadFrom` is never reached in that case.
- `buildRows(chunks, streamStart)`: each hex row carries both `offset` (global stream byte offset) and `localOffset` (byte offset within the chunk).

**`CombinedView.js`-specific layer on top of the hook:** none beyond the hook call and
the `<HexDump>` render — no jump-to, no markers, no extract-selection, no `totalBytes`.

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
- Imported by `HexDump.js` (context menu copy, chunk header size), `ExtractPanel.js` (extraction encoding), `transforms.js` (`fmtAsBase64` for the Base64 encode operation), `TamperDetailPanel.js` (`parseHexdump`/`mergeUint8Arrays`, for the Hexdump-format chunk-creation popover — see "Creating a chunk" under the Tamper tab section below), and others. **Must be listed in the `//go:embed` directive in `web/server.go` — any new top-level `.js` file added under `web/` must be added there explicitly.** The same applies to `transforms/*.js`: `web/server.go` lists each category source file individually (`transforms/basic.js`, `transforms/numbers.js`, `transforms/hash.js`, ...) rather than embedding the `transforms` directory wholesale — this is deliberate, so that `web/package.json` (Node test tooling, see "Testing" below) and any `transforms/*.test.js` file are never pulled into the binary. Any new category module must be added to that embed line by name; test files must not be.

**Extract panel (`ExtractPanel.js`):**
- Props (all controlled from `App.js`): `session`, `stream`, `direction` (string `'0'`/`'1'`), `from` (string), `to` (string), `onDirectionChange`, `onFromChange`, `onToChange`.
- Local state: `format` (`'raw'`|`'base64'`|`'hex'`|`'hexdump'`), `method` (`'file'`|`'clipboard'`), `working`, `status`.
- Shows "Select a stream first" placeholder when no stream selected.
- `parseOffset(s)`: accepts decimal or `0x`/`0X`-prefixed hex; returns `null` on invalid input.
- `fetchRange(session, stream, dir, fromOffset, toOffset)`: resolves both offsets to stids via parallel `getByteStid` calls, fetches `endStid - startStid + 1` chunks via `openStidStream`, filters by direction, trims to exact byte boundaries.
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
- Layout: resizable options column (`.encdec-options`, left) + input/output column (`.encdec-io`, right), split by `ResizeHandle`s — see "Resizable panels" above.
- **Canonical state is `bytes: Uint8Array`**, regardless of which input view is active:
  - Text mode: the `<textarea>`'s displayed value is *derived* each render via `new TextDecoder('utf-8', {fatal:false}).decode(bytes)` — never stored back into `bytes` except via its own `oninput` (`setBytes(new TextEncoder().encode(value))`). This means toggling "Hexdump view" off and back on without typing never loses data, even if the decoded text contains `�` (U+FFFD, from invalid UTF-8) — a warning line (`.encdec-warning`) appears near the checkbox when that's the case, since typing while it's shown *would* bake in the loss.
  - Hexdump mode: `<${HexEditor} bytes=${bytes} onChange=${setBytes} />` operates on `bytes` directly, no text serialization involved.
- **Steps** (`steps: [{id, op, label, params}]`), built from the `+` button's dropdown menu:
  - The menu (`algo-menu`) is generated from `transforms.js`'s `ALGORITHM_SECTIONS`; sections can have `subsections` (rendered as a nested indent level) or a flat `algorithms` list.
  - An algorithm entry whose `op` has no matching `OPERATIONS` registration renders with a `[TODO]` suffix (`.algo-menu-item-todo`) and isn't clickable — every catalogued section (Basic, Numeric, Compression, Checksum, Encryption, Hash) is now fully implemented, so this fallback isn't currently exercised by anything, but stays in place for whenever a new algorithm is catalogued ahead of its `OPERATIONS` entry landing.
  - `addStep(op, label)` seeds `params` from the op's `params` definitions' `default` values — including params hidden by `showIf` (below), since `addStep` doesn't filter by it; a hidden param still needs a sane default in case it's revealed later (e.g. by switching a `crc16`/`crc32` step to `Custom`).
  - Step rows are `draggable="true"` (HTML5 DnD) for reordering: `dragIdRef` holds the dragged id, `dragOverId` state highlights the hovered row (`.encdec-step-drag-over`), and `handleDrop` splices the dragged step to the target's index.
  - **Per-step parameters** (`renderStepParam`): `param.type` is `'number'` (`<input type=number>`, clamped to `min`/`max` via `updateStepParam`), `'boolean'` (checkbox), `'select'` (`<select>` populated from `param.options: [{value,label}]`), or `'text'` (plain `<input type=text>`, e.g. `zip-compress`'s `filename` / `zip-decompress`'s `entry`) — only `'number'` values get coerced/clamped; boolean/select/text values pass through as-is.
  - **Conditional/derived params** (`showIf`, `onSet` — generic hooks on a param definition, optional and unused by every param predating `checksum.js`): `showIf: (params) => boolean` skips rendering that param row when false (filtered in the params-mapping loop, alongside `renderStepParam`). `onSet: (value, params) => partialParams`, invoked from `updateStepParam` when that param's own value changes, is merged into the step's params alongside the changed key — this is what lets `crc16`/`crc32`'s `variant` select both reveal the `poly`/`init`/`refin`/`refout`/`xorout` fields only under `Custom` (their `showIf`) and copy a chosen preset's values into those same fields otherwise (`variant`'s `onSet`), so they always reflect whatever's actually in effect and `Custom` starts from a sensible seed. See `transforms/checksum.js`'s `makeCrcParams`.
- **Execution is manual** (`handleGo`, a "Go" button — not live, and `async` so it can `await` each step): runs `bytes` through `steps` in order via `await OPERATIONS[step.op].run(current, step.params)`. `run()` returns a plain `Uint8Array` for nearly every op — including Compression, via `fflate`'s sync functions — except Whirlpool, which returns a `Promise<Uint8Array>` on its very first call in the page's lifetime (lazily warming up a WASM hasher) and a plain `Uint8Array` on every call after that; `await` on a plain value just resolves immediately, so both cases work uniformly. A thrown/rejected error halts the pipeline immediately: `outputBytes = null`, `outputError = "<step label>: <message>"`, shown in red (`.encdec-output-error`) in place of any output. On success, `outputBytes` is set and `outputHexdumpView` is defaulted to `!isPrintable(outputBytes)` (printable = every byte in `0x20–0x7e` or `\t`/`\n`/`\r`) — the checkbox is a normal manual toggle after that, until the next Go.
- **Output panel** mirrors the input's Hexdump-view checkbox, but its hex view reuses `<${HexEditor} readOnly=${true} />` on `outputBytes` (same grid as the input, not a separate plain-text rendering); its text view is a read-only `<textarea>` derived from `outputBytes` the same way the input's text mode is derived from `bytes`.

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
  - `hex-encode`/`hex-decode` (`transforms/basic.js`): two orthogonal params — `prefix` (`select`: None, `0x`, `\x` — default None), a literal string prepended to every byte (e.g. `0x48 0x65...` / `\x48\x65...`), and `separator` (`text`, default Space), a literal string joined between bytes, empty for no separator at all (e.g. `4865...`). The two combine freely (e.g. prefix `\x` + separator `,` → `\x48,\x65`) — this replaced an earlier single `separator` enum (None/`0x`/`\x`/`,`/`;`/`:`/Space/`\n`) that conflated the per-byte-prefix and join-separator concepts into one field. Decode strips the configured prefix (if any) and separator (if any) via plain `split(...).join('')`, then collapses any remaining incidental whitespace before the existing hex-digit-pair parsing/validation.
  - `base64-encode`/`base64-decode` (`transforms/basic.js`): `urlSafe` boolean param (default `false`). Encode swaps `+`/`/` for `-`/`_` and strips trailing `=` padding; decode reverses the substitution and restores correct padding (based on length mod 4) before `atob`.
  - `octal-encode`/`octal-decode` (`transforms/basic.js`): each byte as 3-digit zero-padded octal, space-separated.
  - `basen-encode`/`basen-decode` (`transforms/basic.js`): `base` param (`number`, 2–64, default 64). Arbitrary-base big-integer encoding via `BigInt`; alphabet is the first *N* characters of the standard base64 char ordering (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`); leading zero bytes are preserved as leading zero-symbol characters (same convention as Base58).
  - `encnum-*`/`decnum-*` (`transforms/numbers.js`; 14 types: `Int8`/`UInt8`, `Int16`/`UInt16`/`Int32`/`UInt32`/`Int64`/`UInt64` each big/little endian — see `NUMBER_TYPES`): decode requires the exact byte width for the type (throws otherwise) and outputs the decimal text representation (`-` prefix for negatives) via `DataView`; encode parses decimal text back into the fixed-width binary form, validating it's a plain integer and in range for the type. 64-bit types use `getBigInt64`/`setBigInt64`/`BigInt` throughout to avoid precision loss.
  - `gzip-compress`/`gzip-decompress`, `deflate-compress`/`deflate-decompress` (`transforms/compression.js`): built on the vendored `fflate`'s synchronous `gzipSync`/`gunzipSync`/`deflateSync`/`inflateSync` — no params. `run()` returns a plain `Uint8Array`, not a `Promise` (this used to go through `CompressionStream`/`DecompressionStream`, which are inherently stream-based/async; switching to `fflate`'s sync functions is what let `tamper.transform.*` — see the "Scripted interception" section below — become fully synchronous). Decode errors (fflate throws its own short message, e.g. `"invalid gzip data"`/`"unexpected EOF"`) are re-thrown as `invalid <format> data: <detail>` for a consistent message shape across both formats.
  - `zip-compress`/`zip-decompress` (`transforms/zip.js`, via the vendored `fflate` library's `zipSync`/`unzipSync` — synchronous, no `Promise` needed): `zip-compress` has a `filename` text param (default `data.bin`) naming the archive's single entry. `zip-decompress` has an `entry` text param (default `''` = auto): if the archive has exactly one entry it's extracted automatically; otherwise (zero or multiple entries) it throws, listing the available entry names, rather than guessing which one the user wants — the pipeline is single-blob-in/single-blob-out, so a multi-entry archive has no single correct output without the user picking one.
  - `md2`/`md4`/`ntlm`/`md5`/`sha1`/`sha224`/`sha256`/`sha384`/`sha512`/`whirlpool` (`transforms/hash.js`; no params on any of them): MD5/SHA1/SHA224/SHA256/SHA384/SHA512 run through the vendored `crypto-js` (`../vendor/crypto-js.module.js`) via `WordArray.create(bytes)` in / `bytesFromWordArray()` out. MD2 and MD4 are hand-rolled directly from RFC 1319/1320 (no well-established JS library covers these legacy algorithms) — cross-checked against an independent implementation's source and RFC test vectors before use; NTLM is just `md4(UTF-16LE(text))`, where `text` is the input bytes decoded as UTF-8 (consistent with `SearchPanel.js`'s `utf16le` search format). Whirlpool runs through the vendored `hash-wasm` (`../vendor/hash-wasm-whirlpool.module.js`, WASM-backed) instead of being hand-rolled, since it's the one algorithm where a hand-written S-box/MDS-matrix implementation was judged too error-prone to trust without a reference. Rather than hash-wasm's async `whirlpool()` convenience function, this uses its lower-level `createWhirlpool()` hasher factory: a `Promise<IHasher>` resolved once (memoized module-level, `warmupWhirlpool()` exported so a caller — `scriptRuntime.js`'s Worker bootstrap, see "Scripted interception" below — can force that one-time cost up front) whose `.init()/.update()/.digest('binary')` are synchronous and reusable thereafter. `run()` therefore returns a plain `Uint8Array` on every call except the very first one anywhere in the page's lifetime (absent an explicit `warmupWhirlpool()`), which returns a `Promise<Uint8Array>` instead — the one op in this module that's ever async.
  - `crc16`/`crc32`/`adler32` (`transforms/checksum.js`; output is the checksum's raw big-endian bytes, same convention as the hash digests above): CRC16/CRC32 share one hand-rolled generic core, `crcCompute`, implementing the Williams/Rocksoft CRC model (`width`/`poly`/`init`/`refin`/`refout`/`xorout`) that every named CRC variant is defined against — hand-rolled rather than vendored (unlike Whirlpool above) since the algorithm is a short, unambiguous bit-shift-and-XOR loop, not error-prone enough to justify a dependency; a `polycrc` (npm) evaluation during development confirmed correctness of the same reference values but was passed over because its single `reflect` flag can't express `refin ≠ refout`, which this module's `Custom` variant needs to expose independently. Both ops take a `variant` select param (`CRC16_PRESETS`: CCITT-FALSE, ARC, MODBUS, XMODEM, KERMIT, USB; `CRC32_PRESETS`: CRC-32, CRC-32C, BZIP2, MPEG-2) plus `Custom`, which reveals `poly`/`init`/`xorout` (`text`, parsed by `parseUintField` — accepts `0x`-prefixed hex, bare hex with no prefix at all as long as it contains a letter a–f (otherwise it's ambiguous with decimal), or plain decimal; a pure-digit string is always read as decimal, preserving whatever an already-typed value meant) and `refin`/`refout` (`boolean`) via `showIf`/`onSet` (see above) — selecting a named variant instead copies its five parameters into those same fields so they always reflect what's in effect. Adler-32 (RFC 1950) is unrelated to the CRC model and hand-rolled separately, no params. All preset check-values were cross-checked against Python's `zlib.crc32`/`zlib.adler32` (for the two variants zlib covers directly) and an independent from-scratch Python reimplementation of the same parameter model (for every other named variant) before use.
  - `aes-encrypt`/`aes-decrypt`, `des-encrypt`/`des-decrypt`, `3des-encrypt`/`3des-decrypt`, `rc4-encrypt`/`rc4-decrypt`, `salsa20-encrypt`/`salsa20-decrypt`, `chacha20-encrypt`/`chacha20-decrypt`, `xor-encrypt`/`xor-decrypt` (`transforms/encryption.js`; key/IV/nonce/AAD fields are hex-digit-pair text — byte strings rather than single integer constants like checksum.js's `poly`/`init`/`xorout`, so there's no decimal fallback to worry about, but an optional leading `0x`/`0X` is still accepted and stripped/ignored the same way, for a consistent rule across every hex input field in the Transform panel): AES (CBC/CTR/ECB/CFB/OFB/GCM) and Salsa20/ChaCha20 come from the vendored `@noble/ciphers` (`../vendor/noble-ciphers/`); DES/TripleDES/RC4 come from the vendored `crypto-js` (now also covering ciphers, not just hashing — see the Dependencies entry below); XOR is hand-rolled (a repeating-key XOR has no meaningful "library" question, same reasoning as CRC/Adler-32). Each block cipher is **one catalog entry with a `mode` select param** (`inHeader: true`, next to the step title) rather than one entry per mode — AES offers CBC/CTR/GCM/ECB/CFB/OFB, DES/3DES offer all but GCM (GCM has no standard/supported pairing with DES — crypto-js has no GCM support at all regardless, which is exactly why AES doesn't use it). `key`/`iv`/`nonce`/`padding`/`aad` all use `row`/`rowLabel`/`showIf` (see above) to reveal only the fields relevant to the selected mode: `iv` for every mode except ECB (which has none at all) and GCM (which uses `nonce` instead), `nonce` (+ optional `aad`, empty-string default = none) for GCM, `padding` (`select`: PKCS7/No padding) for CBC/ECB only — the two true block modes that need one. **CTR/CFB/OFB are forced to `PadNoPadding` internally regardless of the (hidden) `padding` param's leftover value** — crypto-js's `BlockCipher._doFinalize` applies `cfg.padding` unconditionally with no per-mode special-casing, so leaving the default in place would silently pad these stream-like modes' output. AES's `disablePadding` option (native to `@noble/ciphers`' `cbc()`/`ecb()`) serves the same role there; CFB needs no such flag at all since `@noble/ciphers`' `cfb()` has no padding concept in its API to begin with. **AES-OFB is the one hand-rolled piece**: `@noble/ciphers` has no OFB export (confirmed by reading its source, not assumed), so `aesOfbTransform` builds it from noble's own `ecb()` primitive via the standard NIST SP 800-38A construction (`keystream_0 = E(IV)`, `keystream_i = E(keystream_{i-1})`, ciphertext = plaintext XOR keystream) — no cryptographic design of our own, just orchestrating an already-audited block encryption in a well-known way, cross-checked against Node's `aes-*-ofb` in `encryption.test.js`; a fresh `ecb()` instance is constructed per keystream block since every `@noble/ciphers` cipher instance is deliberately single-use (a second `.encrypt()` call on the same instance throws, as a misuse guard). `parseHexBytes(text, label, validLengths?)` is the shared key/IV parsing/validation helper (strips an optional leading `0x`/`0X` before validating; odd-length/invalid-hex/wrong-length all throw clear errors); AES/Salsa20/ChaCha20 key and IV/nonce lengths are left for `@noble/ciphers` itself to validate (it already throws an equally clear error) — only the crypto-js-backed DES (8-byte key/IV) and TripleDES (16 or 24-byte key, 8-byte IV; the also-accepted-by-crypto-js degenerate 8-byte-key case is deliberately rejected here since it's never actually 3 distinct keys) enforce lengths locally, since crypto-js itself is far less strict. AES-GCM's `encrypt()`/`decrypt()` operate on ciphertext with the 16-byte tag **appended at the end** (both `@noble/ciphers`' own convention and Node's `crypto.createCipheriv`'s effective format once its separately-reported `getAuthTag()` is appended); a tag-mismatch or wrong-AAD decrypt throws `@noble/ciphers`' own `"invalid ghash tag"` error, rewrapped here as a clearer `"AES-GCM authentication failed: ..."` message. Salsa20/ChaCha20/RC4/XOR are all self-inverse (XOR-keystream constructions) — `salsa20-encrypt`/`salsa20-decrypt` and `chacha20-encrypt`/`chacha20-decrypt` share one literal transform function each (matching `@noble/ciphers`' single-call, no separate encrypt/decrypt API), and `xor-encrypt`/`xor-decrypt` share one hand-rolled one; RC4 still needs distinct encrypt/decrypt wrapper code despite being self-inverse too, since crypto-js's `.decrypt()` requires the ciphertext wrapped in a `CipherParams` object (via `CipherParams.create({ciphertext: ...})`) while `.encrypt()` takes a raw `WordArray` directly. ChaCha20 specifically uses `@noble/ciphers`' RFC 8439 `chacha20` export (32-byte key, 12-byte nonce, 4-byte counter) — not `chacha20orig` (the original 8-byte-nonce DJB variant).
  - `hmac-md5`/`hmac-sha1`/`hmac-sha224`/`hmac-sha256`/`hmac-sha384`/`hmac-sha512` (`transforms/mac.js`; flat list like `Hash`, one `key` param each — `text`, `wide`, hex bytes with the same optional-`0x`-prefix convention as `encryption.js`'s `parseHexBytes`, duplicated privately in this module rather than shared, matching the project's per-module-private-helper convention): HMAC over each hash algorithm already in `hash.js`'s SHA-1/SHA-2 family plus MD5 — the six that see real-world use as MACs (JWT `HS256`, AWS SigV4, webhook signatures) — via the vendored `crypto-js` (a third extension of the same bundle already backing `hash.js` and `encryption.js`; no new dependency). No key-length validation: HMAC is defined for any key length (RFC 2104 pads short keys and hashes down long ones internally), so `key` only needs to be non-empty. MD2/MD4/NTLM are excluded (not a real/standardized/commonly-used HMAC construction — NTLM in particular has its own different MAC-like protocol uses, not "HMAC with NTLM plugged in"); Whirlpool is excluded too (would need hand-rolling the generic HMAC construction ourselves, since the vendored hash-wasm bundle is hash-only with no HMAC helper, for a niche algorithm not judged worth it). **Extending the vendored `crypto-js.module.js` a third time required care with import order**: crypto-js's `md5.js`/`sha1.js`/etc. each define their own `CryptoJS.HmacMD5 = Hasher._createHmacHelper(MD5)` (etc.) at their own top level, and that call only succeeds once `hmac.js` (which defines `_createHmacHelper` on `Hasher`) has already run — so the entry file's `import './hmac.js'` had to move *before* the hash algorithm imports, not simply appended after them like the cipher-mode additions were; verified directly (all six `HmacXXX` exports checked for `typeof === 'function'`) rather than assumed.

**Testing (`transforms/*.test.js`, `format.test.js`):**
- Unit tests for category modules live alongside their source (e.g. `transforms/numbers.test.js` tests `transforms/numbers.js`), using Node's built-in `node:test` + `node:assert/strict` — no external test dependency. `format.test.js` (top-level, alongside `format.js`) follows the same convention for `parseHexdump`: round-trips against `fmtAsHexdump` (default and non-zero base offset, empty input), whitespace leniency, and rejection of a missing `|ascii|` column or an odd-length hex token.
- `web/package.json` (`"type": "module"`, scoped to `web/` only) exists solely so Node treats these `.js` files as ES modules; it does not affect the browser, which resolves modules via the `index.html` importmap instead. Run the suite with `npm test` (from `web/`) or `node --test` (from `web/`, relying on Node's default recursive `*.test.js` discovery — passing an explicit directory path like `node --test transforms` does *not* recurse the same way, so prefer the no-args form).
- Neither `package.json` nor any `*.test.js` file is listed in `web/server.go`'s `//go:embed` directive, so they're never compiled into the binary or served — see the embed note below.
- `transforms/numbers.test.js` covers all 14 integer types: fixed known-byte-vector checks (independent of round-tripping, so a symmetric encode/decode bug can't hide), boundary round-trips, byte-length validation, out-of-range/non-integer rejection, and BE/LE byte-order cross-checks.
- `transforms/compression.test.js` covers gzip/deflate round-trips (including empty input), that compression actually shrinks repetitive input, malformed-input rejection (via `assert.throws`, not `assert.rejects` — these ops are synchronous), a fixed known-vector gzip buffer (pre-calculated via Node's `zlib.gzipSync`, a different implementation than `fflate`'s sync functions under test), and that gzip/deflate framing is mutually non-interchangeable.
- `transforms/zip.test.js` covers the default-filename round-trip, that `zip-compress`'s `filename` param controls the actual archive entry name (checked via the vendored `unzipSync` directly, independent of `zip-decompress`), auto-extraction of single-entry archives, name-based entry selection from multi-entry archives, the multi-entry/unknown-entry/malformed-input error messages, all imported from `../vendor/fflate.module.js` by relative path for the same reason `zip.js` itself does.
- `transforms/hash.test.js` covers all 10 hash ops against known test vectors, each independently cross-checked before use: RFC 1319/1320 Appendix A's full test-string suite for MD2/MD4 (empty, `"a"`, `"abc"`, `"message digest"`, the lowercase alphabet); MD5 gets the same suite's `"message digest"`/alphabet strings too (it shares RFC 1319/1320/1321's identical test strings), all against Node's `crypto.createHash`; SHA1/SHA224/SHA256 additionally get FIPS's classic three-block `"abcdbcdecdefdefg..."` vector and SHA384/512 their own two-block equivalent, also against Node; Whirlpool gets the canonical NESSIE/ISO empty/`"abc"` vectors plus `"message digest"`/alphabet ones cross-checked directly against the vendored hash-wasm output (a WASM-compiled implementation, independent of any JS reimplementation risk). Beyond known vectors: the well-known empty and `"password"` NTLM vectors, NTLM differing from a plain MD4 of the same bytes, fixed-digest-length checks across short and long input, and different input producing a different digest for every op (guards against a constant/broken implementation). Its `runHex()` helper always `await`s the op's `run()` result so the same test code covers both the always-synchronous ops and Whirlpool's first-call-only-async (WASM warmup) one uniformly.
- `transforms/checksum.test.js` covers every `CRC16_PRESETS`/`CRC32_PRESETS` variant against the standard CRC "check" input (`"123456789"`) and a second string, both cross-checked against `zlib.crc32` (directly, for the CRC-32 preset) or an independent reference implementation (the other variants) — see `checksum.js`'s header comment; Adler-32 against `zlib.adler32`; empty-input results for each width; big-endian output byte-length; that a `Custom` step supplied with a preset's own five parameters (in `0x`-hex, bare-hex-with-no-prefix, and plain-decimal form) reproduces that preset's output exactly, proving `Custom` and the presets share one code path; that a pure-digit bare string is read as decimal rather than silently reinterpreted as hex (guards against already-typed values changing meaning); invalid/out-of-range `Custom` parameter text and an unknown `variant` name both throwing; and that CRC-32 and CRC-32C differ on identical input (guards against a silently-ignored `poly`).
- `transforms/encryption.test.js` covers every cipher/mode combination with fixed known-vector checks cross-checked against an independent implementation before use — AES CBC/CTR/ECB/CFB/OFB/GCM (128/192/256-bit keys, GCM with and without AAD) against Node's `crypto.createCipheriv`/`getAuthTag` (including the hand-rolled OFB construction, verified byte-for-byte against Node's `aes-*-ofb`); DES against the widely-published classic textbook vector (via a CBC-with-zero-IV single block, mathematically identical to plain ECB) plus round-trip-only coverage of ECB/CFB/OFB (no independent oracle for single DES beyond that one vector); TripleDES (both 16- and 24-byte keys) against Node's `des-ede-cbc`/`des-ede3-cbc` and, for ECB/CFB/OFB, `des-ede3-ecb`/`des-ede3-cfb`/`des-ede3-ofb`; RC4 against RFC 6229's keystream vector plus the classic `"Secret"`/`"Attack at dawn"` vector; ChaCha20 against Node's bare `chacha20` cipher (16-byte IV = 4-byte zero counter || 12-byte nonce, RFC 8439's initial-counter-0 convention); Salsa20 (both 16- and 32-byte keys, spanning more than one 64-byte block to also exercise counter increment) against an independent from-spec Python reimplementation of the Salsa20 core, the same discipline `hash.test.js`'s MD2/MD4 vectors used. Beyond known vectors: round-trips across every mode/key-size combination, AES-GCM tampered-ciphertext and mismatched-AAD rejection, all of AES's CBC/ECB/CFB/OFB differing pairwise on identical input and DES's CBC-vs-CTR differing (guards against a silently-ignored `mode` param), CBC "no padding" round-tripping only block-aligned input and rejecting non-aligned input, ECB needing no IV at all, the degenerate 8-byte TripleDES key being rejected despite crypto-js itself accepting it, invalid key/IV/nonce lengths and malformed hex throwing clear errors across the shared `parseHexBytes` helper, an optional `0x`/`0X` prefix being accepted and ignored (matching `checksum.test.js`'s equivalent check for `parseUintField`), and direct assertions on each mode's `showIf`-driven field visibility (IV hidden only for ECB, padding shown only for CBC/ECB) for both the AES and DES/3DES param sets.
- `transforms/mac.test.js` covers RFC 2202 (HMAC-MD5/SHA1) and RFC 4231 (HMAC-SHA224/256/384/512) Test Cases 1 and 2 — Test Case 1 uses each algorithm's own correct key length from its respective RFC table (16 bytes for MD5, 20 for the rest; an earlier draft of the test mixed these up and silently got the wrong HMAC-MD5 value, since HMAC's key handling depends on block size — a reminder of why every vector here was independently cross-checked against Node's `crypto.createHmac` rather than trusted from memory alone), Test Case 2 uses one uniform key across all six. Beyond known vectors: different keys producing different MACs on identical input, different messages producing different MACs under the same key, empty message with a real key still producing a valid MAC, empty key rejected, malformed hex (odd-length/invalid characters) rejected and embedded whitespace tolerated (exercised once via HMAC-SHA256 rather than repeated per algorithm, matching `encryption.test.js`'s economical-single-representative convention), the optional `0x`/`0X` key prefix accepted and ignored, and fixed per-algorithm output length regardless of input length.

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

**Tamper tab (`TamperView.js`, `TamperStreamsList.js`, `TamperQueueList.js`, `TamperDetailPanel.js`, `tamperApi.js`):**

Deliberately a separate top-level tab from Analysis rather than integrated into
`TrafficView`/`HexDump.js` — the two have fundamentally different shapes (Analysis is a
virtualized browse of a long, mostly-static history; Tamper is a small,
constantly-draining live decision queue), and dbdump should normally sit *before*
`tamper` in a proxy's interceptor chain to record untouched originals, so "edit" has no
natural place inside the history-browsing view anyway. Scoped to a single proxy's
`tamper` instance (canonical `/api/i/tamper/...`), same simplification `tapctl` makes.

- **Layout** (`TamperView.js`, top to bottom): toolbar (connection status, manual
  Reconnect button — no auto-retry, to avoid hammering the one-control-connection-at-
  a-time limit — "Auto-intercept new connections" checkbox, manual Refresh button) →
  body (`TamperStreamsList` fixed-width left panel + `TamperQueueList` flex:1 right
  panel) → `ResizeHandle` (orientation `h`) → `TamperDetailPanel` (bottom, resizable
  height via `layout.js`'s `tamperDetailHeight`, same pattern as `bottomHeight`).
- **State model — full resync on every push event, not incremental patching.**
  `TamperView` holds `streams` (the array from the latest `stream-list`) as the single
  source of truth; `stream-created`/`stream-terminated`/`held` all just trigger a fresh
  `listStreams()` call rather than hand-patching local state, since `list-streams`'s
  `pending` array is already a complete, correct snapshot — simpler and far less
  bug-prone than incremental diffing, at the cost of one small extra round-trip per
  event (irrelevant at debug-tool traffic volumes). `handleRelease`/`handleDropConnection`
  **also** resync after their own successful call, not just on server-pushed events — a
  `drop` produces no further traffic and therefore no push event at all, so without this
  the queue would keep showing an already-released buffer until something unrelated
  happened to trigger a resync (`.then(res => { resync(); return res })` chained onto the
  call).
- `queue` is derived (`useMemo`) from `streams`:
  `streams.flatMap(s => s.pending.map(p => ({...p, conn: s.conn, src: s.src, dst: s.dst})))`
  — one entry per `(conn, direction)` that currently has *something* held, summarized as
  `{chunks, length}`, **not** one entry per chunk (the new protocol has no more per-chunk
  ids — see `intercept/tamper/protocol.go`'s `pendingInfo`). Sorted by `conn`/`direction`
  for a stable order; the old "oldest held first" sort relied on a per-chunk `time` that
  `pendingInfo` deliberately no longer carries at the buffer-summary level (see
  `TamperQueueList.js` below). `selectedKey` (`{conn, direction}` or `null`) is kept valid
  by an effect keyed on `queue`: if the selected buffer fell out of the queue (fully
  released, timed out, stream gone) or nothing is selected yet, it auto-selects the new
  first item — this is both the initial selection and the Burp-style post-release
  auto-advance the tab is meant to provide, with no separate "advance" code path needed.
- **`tamperApi.js`**: `openTamperControl(handlers)` wraps the single control
  WebSocket. Replies are matched **by `type`, not by "the next message in"** — the
  server can interleave a push event (`held`, etc.) with the `ok`/`error`/`stream-list`
  reply to whatever command was just sent, since pushes originate from a different
  goroutine than command replies (`intercept/tamper/api.go`'s `controlWriteMu`
  serializes writes but not their relative order). `ok`/`error` resolve or reject the
  one in-flight command promise (`sendCommand` only ever allows one at a time);
  `held`/`stream-created`/`stream-terminated` always route to their handler regardless
  of an in-flight command; `stream-list` does both — updates `onStreamList` *and*
  resolves a pending promise, since every `stream-list` is inherently a reply to
  `list-streams` (never pushed unsolicited). Returns `{ setAutoIntercept, setMode,
  listStreams, release, dropConnection, close }`; `release(conn, direction, opts,
  editedBytes?)` mirrors the server's combined edit+release command directly — `opts` is
  `{action, releaseChunks, edited, prefixLength, bounds}` — sending the JSON command then
  the binary frame immediately after when `opts.edited` is set, mirroring `tapctl`'s
  `cmdTamperRelease` exactly. `dropConnection(conn, direction)` is a separate command, not
  a `release` action value, matching the backend split.
- **`peekBuffer(conn, direction, offset?, length?)`**: a direction's held bytes are
  fetched via a **short-lived** `/watch` connection per selection (open → `peek` →
  collect reply → close), not a persistent per-stream socket — matches the point-in-time
  nature of inspecting whatever's currently selected in `TamperDetailPanel`, and avoids
  managing idle sockets for streams the user isn't looking at. Unlike the old per-chunk
  `peekChunk`, the server always replies with exactly one `pending`+binary pair (or a
  single `error` for an invalid direction) — a direction with nothing held is a normal
  zero-length reply, not an error — so there's no more reply-loop/"chunk not found"
  branch to handle. `TamperDetailPanel` always calls it with no offset/length (fetch the
  whole buffer); the parameters exist because the wire protocol supports slicing, not
  because this UI currently uses it.
- **`listFs`/`readFs`/`writeFs`/`appendFs`**: plain REST wrappers over `fs.go`'s
  endpoints (see `intercept/tamper/CLAUDE.md`'s "Filesystem access" section) — not
  WebSocket-based like the rest of this file, since fs-root access has no relation to
  the control connection's lifecycle. `path` is always slash-separated; each segment is
  percent-encoded individually (`encodeFsPath`) rather than the whole path, so literal
  slashes survive as separators through to the server's `{path...}` wildcard route
  instead of being escaped into `%2F`. `appendFs` sends `POST`, matching
  `handleFsAppend`'s non-idempotent-verb reasoning (see `intercept/tamper/CLAUDE.md`) —
  everything else here is `GET`/`PUT`.
- **`TamperStreamsList.js`**: one row per stream (conn/src/dst) with an intercept/watch
  checkbox calling `setMode` — the only place a watched stream can be escalated into
  intercept mode; the queue alone only ever shows streams that already have something
  held. Untouched by the per-chunk → per-buffer protocol change (never touched the
  per-chunk shape to begin with).
- **`TamperQueueList.js`**: one row per `(conn, direction)` with something held —
  chunk count + byte length, no more relative "Xs ago" time (dropped along with the old
  per-chunk `time` field; not judged worth new client-side time-tracking machinery just
  to keep a cosmetic display). Click sets `selectedKey`.
- **`TamperDetailPanel.js`**: placeholder when nothing selected; otherwise fetches the
  *whole* buffer via `peekBuffer` in an effect keyed on `[entry.conn, entry.direction,
  entry.length, entry.chunks]`, plus **Forward** / **Drop** / **Drop Connection** / **New
  Chunk…** and a **Continuous view** toggle (default off — segmented).
  - **Canonical state is `chunks: Uint8Array[]`, not a flat byte array** — one entry per
    original chunk boundary. Both view modes are projections of it: `splitByBounds(data,
    bounds)` builds it from a `peek` reply, `mergeUint8Arrays(chunks)` (from `format.js`)
    flattens it back for submission or the continuous view, `boundsFromChunks(chunks)`
    derives the wire `bounds` field. This is what makes split/merge/drop/insert (see the
    context menu below) straightforward array splices on `chunks`.
  - **Segmented view (default)** renders one independent `<${HexEditor}>` per entry of
    `chunks`, each fed just that chunk's own byte slice with a small `.tamper-chunk-header`
    ("Chunk N · M B") above it. This is the "restart the hex view at each boundary" look —
    and it falls out for free with **zero changes to `HexEditor.js`**: it already always
    renders offsets relative to whatever `bytes` it's given, starting at 0, so handing each
    instance a slice automatically makes offsets chunk-local, and each instance naturally
    gets its own independent cursor/`pendingNibble` state just by being a separate
    component instance. Editing inside one block only ever replaces that one entry of
    `chunks` (`cs.map((c, idx) => idx === i ? slice : c)`); the others are untouched.
  - **Continuous view** is the single flat editor this panel used to always show:
    `<${HexEditor} bytes=${mergeUint8Arrays(chunks)} onChange=${...} />`, whose `onChange`
    collapses `chunks` down to `[newBytes]` — a single entry. Editing across what were
    chunk boundaries has no well-defined per-chunk meaning (real boundary editing is still
    future work), so continuous mode deliberately discards structure on edit rather than
    guessing how to redistribute it.
  - **Release submission doesn't care which view mode was used** — `releaseChunks: edited
    ? chunks.length : originalChunks.length`, `bounds: edited ? boundsFromChunks(chunks) :
    []`. Continuous-mode edits already reduced `chunks.length` to `1`; segmented-mode
    edits preserve however many entries `chunks` still has. No branching on `viewMode`
    needed at submit time. This toolbar path always releases *everything* currently in
    `chunks`; releasing just the first one (leaving the rest held) is the context menu's
    per-chunk Forward (`forwardFirstChunk`, below), not a toolbar affordance.
  - **Live updates vs. not clobbering an in-progress edit:** since `TamperView` already
    resyncs `streams` on every push event, the selected entry's live `chunks`/`length`
    double as a staleness signal for free, with no separate event plumbing needed. The
    effect distinguishes a genuine selection change (always reload) from the same
    selection's `length`/`chunks` changing (a new `held` arrived) via a `selKeyRef` — for
    the latter, it only auto-reloads if the buffer is still unedited (`chunksEqual(chunks,
    originalChunks)`); if the user has started editing, silently replacing their buffer
    would be a real way to lose work, so instead a `.tamper-stale-banner` appears with an
    explicit "Refresh (discards your edit)" button.
  - A single Forward/Drop pair (no separate edited/unedited buttons) compares `chunks`
    against `originalChunks` to decide `edited`. Buttons disable while a release is in
    flight, while loading, on a load error, or when `originalChunks.length === 0` (nothing
    to act on yet/anymore); a rejection is shown inline rather than silently doing nothing.
    **Drop Connection** is a separate button calling `onDropConnection` directly — it needs
    no bytes/edit state at all, matching the backend's `drop-connection` being
    connection-scoped, not buffer-scoped.
  - **Per-chunk context menu** (`ctxMenu` state, right-click within a chunk's block):
    Drop / Forward / Split / Merge (front/back) / Insert Chunk Before / Insert Chunk
    After. Enabled/disabled state follows `heldBuffer`'s own structural constraints —
    Forward only for chunk 0 (release is always a front-aligned prefix), Split only at an
    interior byte position (an edge split would produce a zero-length chunk, rejected by
    the server's `validBounds`), Merge only when the relevant neighbor exists. All are
    pure local edits to the `chunks` array (splice-in-place via `dropChunk`/`splitChunk`/
    `mergeChunks`) except **Forward** (`forwardFirstChunk`), the one case needing a
    network round-trip — it releases just chunk 0 via the same edit/release computation
    the toolbar's Forward/Drop uses, leaving the rest held. Continuous view has no real
    chunk structure and is treated as a single implicit chunk for menu purposes. Menu
    dismissal is gated on a `menuRef` (mousedown outside it closes the menu) rather than a
    bare document-level `mousedown` handler, since the latter would unmount the menu
    before a click on one of its own items ever reaches it.
  - **Creating a chunk** (`insertChunk`/`InsertChunkPopover`): the toolbar's **New
    Chunk…** button or the context menu's Insert Before/After open the same popover —
    pick a Format (`Empty` | `Plain` | `Hex` | `Base64` | `Hexdump`) and, if not `Empty`,
    a Source (`Clipboard` | `File`). Hex/Base64 decoding reuses the Transform panel's own
    `OPERATIONS['hex-decode']`/`['base64-decode']`; Hexdump goes through `format.js`'s
    `parseHexdump()`.

**Scripted interception (`scriptRuntime.js`, `TamperScriptsPanel.js`) — "Scripts"
sub-tab:** runs one user script in a Worker as a programmatic stand-in for a human
clicking around `TamperQueueList`/`TamperDetailPanel`. Entirely a frontend feature —
nothing on the Go side executes a script (see `scripts.go`, documented in
`intercept/tamper/CLAUDE.md`'s "Script storage" section). `TamperView` has a
second-level tab bar (**Intercept** / **Scripts**, `.tamper-subtabs`); only one is mounted
at a time, but the running script, its log, and which entries are script-paused are
lifted to `TamperView` so they survive switching away and back.

**Script-facing API surface** (defined by `BOOTSTRAP`, loaded as its own Blob — the Worker's
actual entry point — which then `importScripts()`s the script's own separate Blob into that
same global scope; see `scriptRuntime.js`'s header comment and "Error handling" below for why
they're two Blobs rather than one concatenated file):

```js
tamper.register('onConnect', (conn) => { ... })   // conn: { conn, src, dst }
tamper.register('onReceive', (ctx) => { ... })      // fired for newly-held data, either direction — see "Per-connection event serialization" below for the exact firing guarantee
tamper.register('onClose',   (conn) => { ... })      // same shape as onConnect

tamper.peek(conn, direction)                     // raw escape hatch — direction is always 'c2s' | 's2c'
tamper.release(conn, direction, opts, editedBytes)  // mirrors the wire protocol directly
tamper.dropConnection(conn, direction)
tamper.setIntercept(conn, intercepting)
tamper.listStreams()
tamper.log(...args)

tamper.fs.listFiles(path)          // -> [{name, dir, size}]; path '' lists fs-root itself
tamper.fs.readFile(path)           // -> Uint8Array
tamper.fs.writeFile(path, bytes)   // bytes: Uint8Array; overwrites
tamper.fs.appendFile(path, bytes)  // appends, creating the file if it doesn't exist yet

tamper.transform.<category>.<function>(bytes, params)  // -> Uint8Array (Promise<Uint8Array> only if called before the script has finished loading — see below)
// categories: basic, numeric, compression, checksum, encryption, mac, hash
// e.g. tamper.transform.hash.md5(bytes), tamper.transform.encryption.aesEncrypt(bytes, {mode:'gcm', key, nonce, aad})

tamper.encode.hex(bytes, params)      // -> string; params: {prefix, separator}, both default '' (plain contiguous hex)
tamper.encode.base64(bytes, params)   // -> string; params: {urlSafe}, default false
tamper.encode.hexdump(bytes, baseOffset)  // -> string (xxd-style); baseOffset default 0

tamper.decode.hex(text, params)       // -> Uint8Array; same params as tamper.encode.hex
tamper.decode.base64(text, params)    // -> Uint8Array; same params as tamper.encode.base64
tamper.decode.hexdump(text)           // -> Uint8Array
```

`register` only accepts these three hook names; a hook can be registered more than once,
all handlers `await`ed in registration order.

`tamper.fs.*` (see `intercept/tamper/CLAUDE.md`'s "Filesystem access" section) is
routed through the same postMessage RPC bridge as every other `tamper.*` call, even
though its actual transport
(`tamperApi.js`'s `listFs`/`readFs`/`writeFs`/`appendFs`) is a plain REST fetch, not the
control WebSocket. This is a deliberate uniformity choice, not a technical requirement
of REST itself: the Worker never does network I/O directly anywhere in this file, and a
Worker spun up from a Blob URL has no well-defined page origin to resolve a relative
`fetch()` against — routing through the main thread sidesteps relying on
browser-specific blob-URL fetch behavior. Rejects if `fs-root` isn't configured
server-side (surfaces the REST API's `501` as a rejected promise). `appendFile` is a
real server-side append (`fs.go`'s `Append`, opened with `O_APPEND`), not a client-side
read-modify-write — the latter would race across different connections' independently
scheduled `onReceive` handlers (see "Per-connection event serialization" below), risking
lost data from whichever append lost the race.

**`tamper.transform.*`** exposes every implemented Transform-panel operation (see the "Transform
panel" section above — `transforms.js`'s `OPERATIONS`, covering Basic/Numeric/Compression/
Checksum/Encryption/MAC/Hash) to scripts, one flat function per op id regardless of how the UI
groups Encode/Decode/Encrypt/Decrypt/Compress/Uncompress into subsections — that grouping is a
menu-presentation concern with no bearing on a script-facing API. Sourced from `transforms.js`'s
`OPERATIONS_BY_CATEGORY` (a grouping kept deliberately separate from the UI-oriented
`ALGORITHM_SECTIONS`, built for this API alone), grouped under the UI's category *names*, not its
module filenames — `numeric`, not `numbers.js` (a rename left for a future pass). Function names
are a mechanical camelCase of the op id (`hmac-sha256` -> `hmacSha256`), with one necessary
exception: `3des-encrypt`/`3des-decrypt` would camelCase to `3desEncrypt`, invalid as a
dot-accessed property name (an identifier can't start with a digit), so those two are spelled out
as `tripleDesEncrypt`/`tripleDesDecrypt` instead (`scriptRuntime.js`'s
`TRANSFORM_NAME_OVERRIDES`). `params` is passed straight through to `OPERATIONS[op].run(bytes,
params)` unchanged — exactly the same params object shape `TransformPanel.js` itself builds and
sends to `run()`, since the UI-only param metadata (`label`, `default`, `showIf`, `row`/
`rowLabel`, `inHeader`) is consumed only by the panel's own rendering, never by `run()`.

Unlike every other `tamper.*` call, this does **not** go through the `postMessage` RPC bridge —
it runs `OPERATIONS[opId].run(bytes, params)` directly inside the Worker, no main-thread round
trip. `BOOTSTRAP` dynamically imports `transforms.js` by its real absolute URL (`TRANSFORMS_URL`,
computed once on the main thread as `new URL('./transforms.js', import.meta.url).href` and
spliced into `BOOTSTRAP`) — a *relative* specifier is what can't resolve from a Blob-URL worker,
not an absolute one, so `transforms.js`'s own relative imports into `transforms/*`/`vendor/*`
resolve correctly once given its real URL. This is only viable because every `OPERATIONS` entry
is now synchronous (see the Transform panel's Compression/Whirlpool entries above for how each
got there) — a script author never needs to remember which ops are the exception. `self.tamper.
transform = {...}` is generated the same way as before (`buildTransformApiSource()`, built once
when `scriptRuntime.js` loads, spliced into `BOOTSTRAP`), except each generated function now
calls a `callTransform(opId, bytes, params)` helper defined inside `BOOTSTRAP` instead of posting
an RPC `call`. No new privilege is exposed here beyond convenience: a script already has full
read/write access to the bytes in question via `ctx`/`tamper.peek`/`tamper.release`.

**`tamper.encode.*`/`tamper.decode.*`** are a smaller, separate convenience layer for the common
case of turning a buffer into a loggable/matchable string and back — as opposed to
`tamper.transform.*`, whose every op is deliberately bytes-in/bytes-out so Transform-panel steps
can chain. `hex`/`base64` are thin wrappers around the same `OPERATIONS['hex-encode']`/
`['hex-decode']`/`['base64-encode']`/`['base64-decode']` used by `tamper.transform.basic.*`
(`TextEncoder`/`TextDecoder` at the string/bytes boundary, same `params` shape — see the "Transform
panel" section's `hex-encode`/`hex-decode` entry above for `prefix`/`separator`), so there's exactly
one implementation of each codec; unsupplied params default to the most common case (`prefix: ''`,
`separator: ''` for hex — a plain contiguous string, `urlSafe: false` for base64), merged with any
explicit `params` the same way `addStep`'s param defaults work in the UI. `hexdump` has no
`OPERATIONS`/Transform-panel entry to wrap at all (see the "Transform panel" section's note on this
gap), so `tamper.encode.hexdump`/`tamper.decode.hexdump` call `format.js`'s `fmtAsHexdump`/
`parseHexdump` directly instead — both are already string in/out, so no `TextEncoder`/`TextDecoder`
step is needed there. `format.js` is dynamically imported by `BOOTSTRAP` the same way
`transforms.js` is (`FORMAT_URL`, computed identically to `TRANSFORMS_URL`), gated on the same
`ready` flag described below.

**Bootstrap sequencing (why `tamper.transform.*`/`tamper.encode.*`/`tamper.decode.*` are
synchronous in practice, not just in principle):** `BOOTSTRAP`'s outer IIFE stays synchronous —
`self.tamper`, `self.onmessage`, and the `error`/`unhandledrejection` listeners are all wired up
immediately — and only *after* that does a trailing `async` IIFE dynamically import both
`TRANSFORMS_URL` and `FORMAT_URL` in parallel and `await` `warmupWhirlpool()` (see the Transform
panel's Whirlpool entry above), then flips a module-level `ready` flag. `pump()` — the function
that dispatches queued `onConnect`/`onReceive`/`onClose` events to the script's registered
handlers — checks `ready` first and simply declines to run until it's true; events still queue
normally via `self.onmessage` in the meantime (nothing is dropped or reordered), and the trailing
IIFE calls `pump()` for every queued `conn` once `ready` flips. The practical effect: a script's
own hook handlers never observe `OPERATIONS`/`FORMAT` as unpopulated, so every
`tamper.transform.*`/`tamper.encode.*`/`tamper.decode.*` call made from inside
`onConnect`/`onReceive`/`onClose` is genuinely synchronous — no `await`, no `Promise` wrapper. A
shared `whenReady(fn)` helper (`fn` called immediately if `ready`, otherwise chained onto the one
`readyPromise`) backs `callTransform()` and the six `callEncode*`/`callDecode*` functions alike;
its `ready` check exists only for the one case this doesn't cover: a script calling one of these
functions at its own top level, outside any hook, which can run before the import/warmup has
finished — that gets a `Promise` instead of a crash, `await`-compatible like the general
convention elsewhere in this API. A thrown/rejected error propagates back as a rejected promise
either way.

**`ctx` (passed to `onReceive`)** is a local working-copy wrapper built on top of
`peek`/`release`:

```js
ctx.conn / ctx.direction / ctx.newLength
ctx.get()                      // -> Uint8Array, local, no network
ctx.set(bytes, start?, end?)   // Python-slice-assignment style; covers insert/delete too
ctx.append(bytes)
await ctx.release(n?)          // release first n bytes (default: everything); remainder stays held
await ctx.drop(n?)              // same, discarding instead of forwarding
await ctx.pause()                // see below
ctx.log(...args)                  // like tamper.log, auto-prefixed with a connection/time summary
```

`release`/`drop`/`pause` **must be `await`ed** — there's no internal auto-serialization,
so an un-awaited `ctx.pause()` immediately followed by `ctx.release()` races (the release
can complete before the pause's suspend logic even runs). If a handler mutates the buffer
(`set`/`append`) but returns without an explicit release/drop/pause, the framework
auto-commits the remainder as an edit-only hold, so nothing is silently lost. `release`/
`drop` are always prefix-based (never an arbitrary interior range), matching the backend's
own constraint (`heldBuffer.performAction`, documented in `intercept/tamper/CLAUDE.md`).

Direction is `'c2s'`/`'s2c'` everywhere in this surface; the numeric `0`/`1` used by the
rest of the wire protocol is translated only at `scriptRuntime.js`'s main-thread boundary
(`dirToStr`/`dirFromStr`).

**Per-connection event serialization:** all events for one `conn` (both directions, plus
`onConnect`/`onClose`) go through a per-conn FIFO queue — the next event only dispatches
once every handler for the previous one (including any `ctx.pause()` suspension) has
resolved. Different `conn`s run fully independently.

**`onReceive` firing guarantee — coalesced, not strictly one-per-chunk:** a `held`
notification only ever means "go look at the buffer again," and TCP itself gives no
guarantee about how incoming data is chunked into physical reads in the first place — so
there is nothing meaningful tied to any individual notification, only to the buffer state
a dispatch actually observes via `ctx.get()`. `scriptRuntime.js`'s `pump()` therefore
coalesces **consecutive still-queued** `onReceive` entries for the same `(conn,
direction)` into a single dispatch, rather than running one after another: once
accumulation on the Go side (near-instant) outpaces how fast a dispatch can round-trip
(peek, decide, release), several notifications routinely pile up for the same direction
before the first one even starts — without coalescing, only that first dispatch finds
anything to do (whatever accumulated by then), and every one behind it is a redundant
round trip that finds an already-drained, empty buffer. Coalescing merges those trailing,
otherwise-empty round trips into one. It never reorders anything relative to an
interleaved other-direction/other-`conn` event — only entries adjacent in the same
per-conn queue, for the same direction, are ever merged, so a genuinely interleaved
sequence still dispatches every distinct state in order. Merged entries sum their
lengths, so `ctx.newLength` still means "how many new bytes since the last dispatch," not
just one physical chunk's own size.

The practical guarantee this leaves scripts with: **at least one `onReceive` will
eventually see the complete, not-yet-processed buffer** (`ctx.get()` always reflects
everything held at that instant, coalesced or not) — just not necessarily one dispatch
per notification. In practice this only *reduces* redundant empty dispatches, it doesn't
eliminate them entirely: the very first notification of a fresh burst (arriving into an
idle queue) can never be pre-merged with anything not yet queued at that instant, and —
since Go-side accumulation typically outpaces the round trip — that first dispatch
usually drains everything by the time its own `peek()` resolves, leaving one merged
trailing dispatch behind it that often still finds nothing left. A script that wants to
suppress that entirely can add `if (ctx.get().length === 0) return` at the top of its
`onReceive` handler.

**Custom state across invocations is not `ctx`'s job — use closures instead.** `ctx` is
rebuilt from scratch by `handleOnReceive` on every `onReceive` dispatch (a fresh object
literal from `makeCtx`, never reused or frozen), so a field a handler sets on it
(`ctx.foo = ...`) is gone the moment the handler returns — there is no per-stream `ctx`
that persists across chunks. Since one script instance runs in one Worker for its whole
lifetime (until Stop/Restart, a syntax/runtime error, or the control connection dropping
— see "Error handling" below), any variable declared at the script's top level is an
ordinary JS closure that *does* survive across every future invocation, with no
framework support needed:

```js
const perStream = new Map()  // keyed by conn — this is "per-stream" storage
tamper.register('onConnect', c => perStream.set(c.conn, { requestCount: 0 }))
tamper.register('onReceive', ctx => { perStream.get(ctx.conn).requestCount++ })
tamper.register('onClose', c => perStream.delete(c.conn))

let totalBytesSeen = 0  // a bare top-level variable is shared across *all* streams
tamper.register('onReceive', ctx => { totalBytesSeen += ctx.get().length })
```

Two caveats worth knowing, not framework gaps: this state is memory-only (gone on
Stop/Restart/error/disconnect — `tamper.fs.*` above is the mechanism for anything that
needs to survive that); and while a plain increment like `totalBytesSeen` above is safe
(the Worker is single-threaded), a read-modify-write that spans an `await` (e.g.
`ctx.pause()`) can interleave with another connection's handler resuming in between,
since different `conn`s run on independent queues (see "Per-connection event
serialization" above) — not a data race, just async interleaving to design around.

**Pause / Continue:** `ctx.pause()` commits any pending edit, then suspends until a human
clicks "Continue" in the Intercept sub-tab (`TamperDetailPanel`'s toolbar swaps to a
single Continue button while paused; editing stays available, since pausing is a
review/edit checkpoint, not a release gate). Control returns to the *script*, not to a
release — it typically does `ctx.get()` to see the human's edits, then `ctx.release()`.
If the connection terminates while a script is suspended in `ctx.pause()`, `TamperView`
rejects the pending pause immediately (not routed through the queued `onClose`), so the
per-conn queue can still advance and `onClose` still fires.

**Connection caching for `onClose`:** the wire's `stream-terminated` only carries a
numeric `conn`, but `onClose` gets the same `{conn, src, dst}` shape `onConnect` does —
cached in `scriptRuntime.js`'s `connMeta` map from `onConnect`, looked up and deleted on
`onClose`. A stream already open before the script started falls back to `{conn}` alone.

**Error handling:** a syntax error in the script's own source kills the Worker permanently
— reported (with a full stack trace naming the actual failing script file, see "Loading and
stack-trace naming" below) and treated as an explicit `stop()`. This used to fall out
incidentally of `worker.onerror` firing because BOOTSTRAP and the script were one
concatenated parse unit — a script syntax error meant *nothing*, including BOOTSTRAP's own
`self.tamper`/`self.onmessage`/error listeners, ever ran. Now that they're two separate
Blobs (see below), BOOTSTRAP always finishes initializing regardless of whether the script
does, so this is instead caught explicitly around the `importScripts()` call that loads the
script and reported as a `'fatal'` message (`scriptRuntime.js`'s `handleWorkerMessage`),
which `createScriptRuntime` turns into the same `stop()` call — same observable outcome,
explicit mechanism instead of an incidental one. An exception thrown *inside* a handler is
still just caught per-event and reported without stopping the Worker — the queue moves on.
All three paths (`'error'`, `'fatal'`, a handler-local catch) render into the same log
panel, `'fatal'` and a handler's own catch both under `level: 'error'`. Losing the control
connection also stops the running script.

**Loading and stack-trace naming:** BOOTSTRAP and the script are two separate Blobs, not one
concatenated file. BOOTSTRAP's own Blob is the Worker's actual entry point — after wiring up
`self.tamper`/`self.onmessage`/the error listeners, it synchronously `importScripts()`s the
script's Blob into that same global scope (`importScripts`, unlike an ES module import, runs
the imported code in the *same* scope as the caller, not a separate module namespace — the
script still sees the bare `tamper` global exactly as if everything were one file; nothing
about how a script is written changes). Each Blob ends with its own `//# sourceURL=...`
magic comment (`scriptRuntime.js`'s `buildWorkerSource`/`buildScriptSource`) — `BOOTSTRAP`'s
own Blob as `tamper-bootstrap.js`, the script's Blob as its own name (sanitized to end in
`.js`) — so DevTools/stack traces show a real, correctly-line-numbered file name for
whichever side actually failed, instead of one opaque `blob:http://.../<uuid>` URL covering
both.

**`TamperScriptsPanel.js`** is CRUD over the REST script store (`listScripts`/
`getScript`/`putScript`/`deleteScript`) plus Run/Stop wired to the lifted runtime state
above.

**Log panel** (Download / Clear, or **"Logged to `<filename>`"** in place of Download
when the `tamper` interceptor is configured with `log-file` — see above): every
`tamper.log`/`ctx.log` call is also pushed to the server over the control WebSocket
(`{"type":"script-log", level, text}`) for optional persistence, independent of a
**"Skip browser log"** checkbox (shown only when `log-file` is active) that lets large
output skip the in-memory copy while still reaching the file.

**`ScriptEditor.js`** wraps a CodeMirror 6 `EditorView` for the script body (syntax
highlighting, bracket matching, folding — no tamper-specific autocompletion; an earlier
custom `tamper.*`/`ctx.*` completion source caused a reproducible editor freeze and was
removed entirely). Semi-controlled, same contract shape as `HexEditor.js`:
`<${ScriptEditor} value onChange loadVersion readOnly? />`. `value` seeds the initial doc
and is only ever pushed back into CodeMirror when the caller bumps `loadVersion`
(`TamperScriptsPanel.js` does this on script load/switch/Reload) — **not** inferred from
`value` changing on its own. An earlier version tried exactly that (comparing `value`
against the last text the component itself had emitted, to distinguish "external change"
from "our own edit echoing back") and is fundamentally racy: CodeMirror processes
keystrokes synchronously and immediately, independent of Preact's deferred effect
scheduling, so a stale effect for an earlier keystroke can run after later ones have
already landed, see a mismatch, and dispatch a destructive full-document replace —
reproduced as an actual CPU-pegging freeze during ordinary typing (no fast typing or
large paste required). Gating the sync on an explicit external-reset signal instead of a
value-equality heuristic closes this structurally: the sync effect never runs at all
during typing, regardless of scheduling order. `readOnly` is applied through a
`Compartment` rather than a remount, so toggling it doesn't reset cursor/undo-history.
