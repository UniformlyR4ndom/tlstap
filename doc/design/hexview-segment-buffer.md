# Hex View Segment Buffer — design notes

**Status: steps 1–3 of the migration plan below are done — all of `TrafficView.js` (raw
and frame mode) runs on the new mechanism, both verified live; `CombinedView.js` is the
only remaining consumer of `useChunkBuffer.js`, step 4, deliberately left open.** This
document captures the design for reworking how `HexDump.js` is fed data, arrived at
collaboratively; see "Migration plan" below for how this lands without a big-bang
rewrite. Update the root `CLAUDE.md`'s TODO section once fully implemented (see "TODO
items this resolves" below).

## What problem this solves

`TrafficView.js` feeds `HexDump.js` via `useChunkBuffer.js` in two modes — raw chunks and
(once "Run" is clicked) framer-script-computed frames — using two independent,
count-oriented windowing implementations (`buildRows`/`fetchPage`/`getId` for chunks,
`frameBuildRows`/`frameFetchPage`/`frameGetId` for frames). Both page by a fixed number of
*items* (`BATCH = 50`), always loading an item's full byte span atomically.

That's fine for raw chunks (≤64KB each, bounded by `proxy.bufSize`), but not for frames: a
framer script can legitimately treat an arbitrarily large span as one frame (e.g. a whole
file transfer as one HTTP body frame), and `frameFetchPage` currently fetches such a
frame's entire byte range in one shot — unbounded memory use for a single huge frame. This
rework replaces both windowing implementations with one **byte-budgeted** buffer that
loads a segment's bytes incrementally, uniformly for chunks and frames.

## Data model

```js
Segment       = { stid, id, direction, offset, length, time, meta? }
SegmentWindow = { segment, loadedStart, loadedEnd, bytes }   // bytes covers [loadedStart, loadedEnd) ⊆ [segment.offset, segment.offset+segment.length)
```

- A `Segment` is metadata only, no bytes — a raw chunk or a frame, whichever entity type is
  in view. `time` is unconditionally present for both (see "`frames.time`" below — today
  it's frame-only-absent, handled by `ChunkHeader`'s falsy check; that special-case goes
  away once this lands).
- `id` is loaded straight off the respective table's own id column (`chunks.id` for
  chunks, `frames.id` for frames) — opaque to everything but display (`#N`) and, for
  frames, tie-break when several frames share a completing chunk's `stid`.
- **`stid` alone is not unique for frames.** A chunk's `stid` is assigned directly and is
  always unique (no ties possible). A frame *inherits* its `stid` from whichever raw chunk
  it completed on — several frames can complete on the same chunk (e.g. multiple small TLS
  records arriving in one TCP segment), so ties are routine, not an edge case. The real
  total-order key for frames is the pair `(stid, id)`; it only collapses to bare `stid` for
  chunks because chunk ties never happen. Pagination still only ever needs a bare `stid`
  cursor despite this — see "Why a bare `stid` cursor is still safe" under the wire
  protocol section below.
- A `SegmentWindow` is the buffer's actual unit of storage — a segment plus however much of
  its byte range is currently materialized. For chunks this is always the whole segment
  (chunks are small, loaded atomically). For frames it may be a sub-range, extended
  incrementally as the buffer scrolls deeper into a large one.

### `frames.time`

Required backend addition, the one non-frontend-only piece of this design. `frames`
currently has no `time` column. Add one via the same idempotent `ensureColumn`
(`ALTER TABLE`) pattern `frames.stid` itself used, and populate it the same way `stid` is
populated today: `framerRun.js`'s `catchUpFramer` already computes `stidAtOffset(byteOffset)`
by walking `rawChunks` to find the chunk a frame completes on — add a parallel
`timeAtOffset(byteOffset)` there and tag `time` from the same chunk lookup. Thread it
through `appendFrames`'s request body and the `/frames`/`/frames/timeline` response shape
alongside `stid`.

## Buffer policy

Two independent caps, not one:

- `MAX_BUFFERED_BYTES = 256 * 1024` — sum of `(loadedEnd - loadedStart)` across all
  buffered `SegmentWindow`s.
- `MAX_BUFFERED_SEGMENTS = 4096` — count of buffered `SegmentWindow`s, regardless of how
  few bytes each holds.

Both are needed: a byte cap alone doesn't guard a degenerate stream of many tiny
segments (e.g. one-byte frames) — at a 256KB budget that's up to 256K header rows before
the byte cap would ever bind. The segment cap catches that independently.

**Eviction can now cut mid-segment.** Unlike today's `findChunkBoundaryNearHalf` (which
must land on a header row boundary, since a chunk's window was always all-or-nothing),
trimming a `SegmentWindow`'s `loadedStart`/`loadedEnd` is a normal operation — a segment no
longer has to be atomic in the buffer. This is also what fixes the "buffer-trimming isn't
tied-`stid`-group-aware" TODO gap (frame mode only) as a side effect: any row is now a safe
cut point, so there's no boundary-alignment problem to have in the first place.

**Header retention rule**: a segment's header row stays visible for as long as any part of
its window is still retained — dropped only once the whole `SegmentWindow` entry is fully
evicted. A segment whose window no longer starts at its own `offset` (front-trimmed while
still partially resident) keeps showing its header, agreed as desired — exact visual
treatment (e.g. a "continued" marker) is a UI detail deferred to the migration step, not
part of this data-loading design.

### Scroll triggers and re-centering — unchanged in shape from today

`HexDump.js`'s existing trigger stays exactly as-is: `onScrollEnd(1)`/`onScrollEnd(-1)`
fire at <10% of currently loaded rows remaining below/above the viewport
(`PREFETCH_FRACTION`), watching `rows.length` — a plain count, agnostic to how those rows
were produced.

What the hook does in response mirrors today's `handleScrollEnd`, just in bytes instead of
item counts:

- **Fill target per trigger** = half of each cap (mirrors today's `BATCH` vs.
  `MAX_BUFFERED_CHUNKS = BATCH*2` ratio exactly): `FILL_TARGET_BYTES = 128 * 1024`,
  `FILL_TARGET_SEGMENTS = 2048`. Extend the buffer's edge in the triggered direction until
  either target is met or the adapter reports no more data.
- **Evict from the opposite end** back under both caps — same effect as today's
  `findChunkBoundaryNearHalf` cut, just byte-precise (can trim into a `SegmentWindow`
  instead of only dropping whole ones).
- Net effect after one trigger: buffer back near full budget, roughly half old content /
  half new — recentered on the viewport, same shape as today.

### `WINDOW_STEP` / `SEGMENT_STEP` — the per-request quantum

Filling toward a fill target happens as a **loop** of bounded adapter calls, not one
unbounded request:

- `WINDOW_STEP = 32 * 1024` (`FILL_TARGET_BYTES / 4` — four round trips per fill).
- `SEGMENT_STEP = 512` (`FILL_TARGET_SEGMENTS / 4`, same ratio, proposed by analogy —
  open to adjustment).

Each loop iteration is one `fillForward`/`fillBackward` adapter call bounded by
`{maxBytes: WINDOW_STEP, maxSegments: SEGMENT_STEP}`; the hook checks `generationRef`
(the same staleness guard `useChunkBuffer` already uses after every `await`) between
iterations, so a fast flick-through-and-reverse gets interrupted promptly instead of
finishing an already-obsolete fill. Reasons the quantum stays well under the fill target
rather than equal to it:

- **Bounded request latency** — no single request ever asks for more than `WINDOW_STEP`,
  whether opening a fresh segment or extending an already-open huge one. This is the
  actual fix for the unbounded-frame-fetch problem: a giant frame's *first* touch already
  only pulls `WINDOW_STEP` worth of it.
- **Finer-grained cancellation** — a bigger step means coarser, later interruption.
- **Uniform handling regardless of segment size** — a tiny chunk opens in one quantum; a
  huge frame opens the same way, just needing more loop iterations. No size-based
  special-casing in the loop itself.

## Adapter contract

Two entity-specific adapters (chunk mode, frame mode) implement one shape; the hook is
otherwise entity-agnostic:

```js
openConnection(entity) → handle

fillForward(handle, entity, { afterStid, resumeWindow?, maxBytes, maxSegments })
  → { windows: SegmentWindow[], reachedEnd }

fillBackward(handle, entity, { beforeStid, resumeWindow?, maxBytes, maxSegments })
  → { windows: SegmentWindow[], reachedEnd }
```

- `afterStid` / `beforeStid`: stid boundary to open *new* segments beyond. Exclusive when
  `resumeWindow` is absent (a genuinely fresh boundary with nothing loaded there yet); an
  adapter that supports tied-stid groups (frame mode) treats it as *inclusive* whenever
  `resumeWindow` is present, so it can requery a stid it has already partly consumed — see
  `resumeWindow` below for why. Deliberately two distinctly-named functions/fields rather
  than one taking a `direction: 'forward'|'backward'` parameter — a generic `direction`
  field would collide with `Segment.direction` (client→server vs. server→client), an
  unrelated axis already using that name throughout this same protocol. Keeping
  `fillForward`/`fillBackward` (and, on the wire, `afterStid`/`beforeStid`) separate avoids
  the name meaning two different things depending on which object it's read off.
- `resumeWindow` (optional): the buffer's current edge `SegmentWindow` — passed **whether
  or not it's fully loaded**, not just while still growing. Its `.segment` already carries
  `offset`/`length`/`direction` — no re-lookup needed; always `resumeWindow.segment.stid
  === afterStid`/`beforeStid` (same edge, not a conflict). While not yet fully loaded (a
  still-growing huge frame), the adapter extends it (fetching more from
  `resumeWindow.loadedEnd` forward, or before `loadedStart` backward) and returns the same
  window with `bytes`/`loadedEnd` (or `loadedStart`) extended, as the first entry of
  `windows` — the adapter already has both old and new bytes in hand, so it does the
  concatenation; the hook just replaces the old buffer entry with the returned one (matched
  by `stid`+`id`, not merely "a resumeWindow was passed" — see below). Once fully loaded,
  `resumeWindow` is still handed to the adapter on the next call (not nulled) precisely so
  a tied-stid-aware adapter can requery its own stid inclusively instead of skipping past a
  sibling segment left over there (see "Known gaps fixed after the fact" below) — a plain
  adapter (chunk mode) is free to ignore it once `isWindowFull` is true, same as before.
- `excludeIds` (present whenever `resumeWindow` is): every segment id already consumed at
  exactly the boundary stid so far — not just `resumeWindow`'s own id, since a tied group
  can have more than two members and each round resolves only one more of them. Computed
  by the hook straight from the buffer's own contents (`idsAtStid`, `byteBufferCore.js`), so
  an adapter requerying inclusively never needs to remember anything across calls itself. A
  plain adapter (chunk mode) ignores this too.
- `maxBytes`/`maxSegments`: this call's own budget (the quantum, not the whole fill
  target). Every newly-opened segment is loaded in full except possibly the last one
  returned, truncated if it alone would exceed `maxBytes` — that truncated entry becomes
  next round's `resumeWindow`.
- `reachedEnd` — **meaning differs by direction**: for `fillForward`, no segments exist
  after this point (reached the live end of the stream); for `fillBackward`, no segments
  exist before this point (reached stream start / offset 0).

**Why this shape and not a flat `[{segment, wantStart, wantEnd}, ...]` request:** the
client can't precompute per-segment ranges without first knowing each candidate segment's
`length`, which means listing metadata and deciding the byte cutoff can't be separated
into "hook decides, then adapter fetches" without a wasted round trip — the adapter
already has to walk the metadata to enforce the budget, so it should own the cutoff
decision, not receive it pre-computed.

### Chunk-mode adapter

**Updated 2026-08-25 — see "Wire protocol" below.** `fillForward`/`fillBackward` (see
`web/chunkSegments.js`) list metadata via `/chunks/timeline`, apply `selectByBudget`
(`frameSegmentsCore.js` — the same function frame mode uses, no second copy of the budget
discipline) client-side, then fetch each selected chunk's own `(offset, length)` via
`/byte-ranges`. Every returned `SegmentWindow` is still always fully loaded — a chunk
row's `data` is written as one complete, immutable blob, so requesting its own declared
range can never come back short — but `resumeWindow`/`excludeIds` are now genuinely
unused (dropped from the adapter's destructured params entirely), not just realistically
unreachable: chunks never tie on `stid`, so there's nothing for either to do.

### Frame-mode adapter

**Updated 2026-08-25 — see "Wire protocol" below.** Metadata is unchanged: a separate,
cheap `/frames/timeline` call, bytes-free, walked via `selectByBudget` client-side exactly
as before. Bytes now come from `/byte-ranges` directly — each frame's own `(offset,
length)` (or the truncated `openRange` for an oversized first candidate) is requested as
its own entry, with **no offset→stid resolution and no covering-whole-chunk over-fetch**:
`sliceFrameBytes`/`fetchDirectionRange`/`getByteStid` are gone from `frameSegments.js`
entirely, since a byte-range fetch can now name an arbitrary span itself. `resumeWindow`
extension (`extendResumeWindow`) works the same way, just requesting its extension range
directly instead of over-fetching covering chunks first.
- Once `resumeWindow`'s own segment finishes loading, `fillForward`/`fillBackward` requery
  `/frames/timeline` **inclusive** of its stid (not the usual "+1"/exclusive cursor) and
  filter out exactly that one already-loaded `(stid, id)` from the result — this is what
  lets a tied-stid sibling (a second, smaller frame completing on the same raw chunk as a
  first, oversized one) still be found instead of silently skipped; see "Known gaps fixed
  after the fact" below.

**Updated again 2026-08 — `frames.ranges` reshape.** The `/frames*` wire shape now
carries a frame's span as `ranges: [{offset, length}]` (an ordered list) instead of a
single `offset`/`length` pair — see `intercept/dbdump/CLAUDE.md`'s schema notes for the
full rationale/migration. This adapter (and `frameSegmentsCore.js`'s `initialWindowRange`/
`wantRangeFor`/`buildFrameWindow`/`extendRange`/`selectByBudget`) still consume a
single-range-shaped frame object this phase, via a temporary decode-layer shim
(`dbdumpFramerApi.js`'s `decodeFrame`) that derives `offset`/`length` from `ranges` —
behaviorally identical to before, since every framer script still emits exactly one range
per frame. Making this adapter's own logic genuinely walk/split across a multi-range
`ranges` array (the actual point of the reshape — letting a `SegmentWindow`'s loaded
range be a virtual sub-range into the concatenation of a frame's own ranges) is deferred
to a later, separate phase.

## Hook contract

New file (`web/useByteBuffer.js`, alongside — not replacing yet — `useChunkBuffer.js`; see
"Migration plan"). Same external shape as today's `useChunkBuffer`, so `TrafficView.js`'s
glue code and `HexDump.js` itself barely need to change:

```
{ display, loading, error, setError, handleScrollEnd, reloadFrom, displayRef, jumpToTop, jumpToBottom }
```

`display.rows` is *derived* from the internal `SegmentWindow[]` buffer by one shared
row-builder (replacing today's two separate `buildRows`/`frameBuildRows`), called only
when that buffer actually changes (a fill or an eviction) — never on a plain scroll tick.
`HexDump.js`'s own `scrollTop` tracking and its `rows.slice(startIdx, endIdx)`
virtualization stay entirely local, untouched by this rework, so per-scroll-frame cost is
unaffected. Worst-case buffer size under the new caps (~256KB / 16B-per-row ≈ 16K hex rows
+ up to 4096 header rows ≈ 20K rows) is cheaper to rebuild than today's effective worst
case (100 chunks × 64KB ≈ 400K rows), so no regression expected — if anything, an
improvement.

## Wire protocol: `/byte-ranges` + `/chunks/timeline` (superseded `/segments`)

**Updated 2026-08-25.** The original design below (`/segments`, kept for historical
context) bundled metadata listing and byte fetching into one WebSocket endpoint, with the
server itself performing budget selection ("checked only between whole chunks") for chunk
mode specifically — a second, Go-side copy of the exact selection discipline
`selectByBudget` already implemented in JS for frame mode. It also gave frame mode no way
to fetch an arbitrary byte span directly: `frameSegments.js` had to resolve a frame's
`offset` to a covering `stid` range, over-fetch every whole raw chunk spanning it via
`/segments`, then slice the exact bytes out client-side (`sliceFrameBytes`).

`/segments` is retired in favor of two REST endpoints that separate these concerns
cleanly and serve both adapters uniformly:

- **`POST /byte-ranges`** — a dumb, frame-unaware byte-range fetcher: given a batch of
  `(offset, length, direction)` triples for one `(session, stream)`, returns exactly those
  bytes, each independently (no dedup, no merge — two entries may legitimately reference
  overlapping or identical physical bytes, resolved separately). A short/zero-length
  result signals "not currently available" (a still-live stream not yet flushed that far,
  or the genuine end of a closed one) — never an error. This is what lets `frameSegments.js`
  drop `sliceFrameBytes`/`fetchDirectionRange`/`getByteStid` entirely: a frame's own
  `(offset, length)` is requested directly, no stid resolution or over-fetch needed.
- **`POST /chunks/timeline`** — a plain, budget-free metadata listing for raw chunks,
  mirroring `/frames/timeline`'s shape exactly (forward via `start`, backward via
  `beforeStid`, always returned ascending). No `n+1`-lookahead/tied-group logic, unlike
  `/frames/timeline` — `chunks.stid` is never tied. `chunkSegments.js` now applies
  `selectByBudget` client-side, the same function frame mode already used, eliminating the
  server-side "checked only between whole chunks" logic that used to live only in the old
  `/segments` Go handler.

Full wire format (bounds, the sign-encodes-direction trick used to pack `/byte-ranges`'
binary request without a separate JSON header, error semantics) is documented in
`intercept/dbdump/CLAUDE.md`'s "POST `/byte-ranges`" and "POST `/chunks/timeline`"
sections — this doc doesn't duplicate it. The core design constraints this section used to
argue for (real server-side backward support via `ORDER BY stid DESC`, never truncating a
single chunk mid-record, a bare `stid` cursor being safe because chunks never tie) all
still hold under the new endpoints — `/chunks/timeline`'s backward walk and per-item
integrity work the same way `/segments`' did, just without the byte-budget enforcement
(now client-side) or the bundled bytes (now a separate `/byte-ranges` call).

## Migration plan

Agreed order, lower risk than a big-bang replacement — build and prove the new mechanism
without touching the working raw-chunk path first:

1. **Done.** Implement `/segments` (backend), `frames.time` (backend), and
   `useByteBuffer.js` + its two adapters (frontend) — nothing wired into a view yet.
2. **Done.** Migrate **frame mode** in `TrafficView.js` onto the new hook first — it's
   the one with the actual defect (unbounded single-frame fetch), so it's the most direct
   validation. Verified live: `go build`/`vet`/`web` tests clean, plus a basic manual
   browser pass showing parity with the old path (no observable regression). Not yet
   stress-tested against a genuinely huge single frame — the throwaway test script used
   for the basic pass (`examples/dbdump/framer/` has no purpose-built large-frame script
   yet) only approximated one; a small dedicated client/server CLI with real large-message
   framing is planned as the next step for that deeper check.
3. **Done.** Migrate **raw-chunk mode** in `TrafficView.js` onto the same hook
   (`chunkSegments.js`) — chunks are already small, so this was largely a mechanical port
   as expected, done for uniformity. Verified live: `go build`/`vet`/`web` tests clean,
   user-confirmed no observable regression vs. the old raw-chunk view. Unexpected bonus
   observed: the browser scrollbar thumb size is now roughly consistent regardless of a
   stream's actual chunking, since the buffer is sized in bytes rather than item count —
   except in degenerate cases where the segment-count cap, not the byte cap, ends up
   binding.
4. Decide on `CombinedView.js` (`useChunkBuffer`'s other consumer) once 2–3 are proven —
   it only ever shows raw chunks (never huge), so migrating it is about consistency, not
   fixing a bug. **Deliberately left open** — decide after seeing the new hook's real size/
   complexity in practice.
5. Delete the old path (`useChunkBuffer.js`'s internals or the whole file depending on
   step 4's outcome, `frameFetchPage`/`frameBuildRows`/`frameGetId`, `sliceFrameBytes`)
   once nothing references it.
6. **Done (2026-08-25).** Replaced `/segments` with `/byte-ranges` + `/chunks/timeline` —
   see "Wire protocol" above. Groundwork for a later, separate phase letting a single
   frame span multiple non-contiguous byte ranges (a frame currently must be one
   contiguous `[offset, length)` — the new endpoints are shaped to need no further backend
   change once that lands). `/segments`/`segments.go`/`segments_test.go` and
   `openSegmentsStream`/`splitSegments` (`api.js`) are removed once manual verification
   confirms parity with the old path — not yet deleted as of this note.

## Known gaps fixed after the fact

- **Frame mode could permanently drop a tied-stid sibling frame (2026-08-08).** Two frames
  completing on the same raw chunk share a `stid` (routine, not an edge case — e.g. two
  length-prefixed messages both arriving in one read). When the first of them was large
  enough to need `resumeWindow`-based incremental loading, `selectByBudget` (correctly)
  deferred its sibling rather than truncating it — but once the oversized frame finished
  loading, `fillToTarget` nulled out `resumeWindow` and advanced the boundary to
  `edge.segment.stid`, and the next metadata query was *exclusive* of that stid. The
  sibling — real, already-listed metadata that was simply never consumed — was then
  permanently unreachable: that stid is never revisited once passed. Symptom: a stream
  whose framer produced N frames only ever showed N-1 in the UI, always missing the last
  one in each affected direction.
  Fix: `fillToTarget` now always passes the current edge as `resumeWindow`, fully loaded or
  not (`byteBufferCore.js`); a tied-stid-aware adapter (`frameSegments.js`) requeries
  inclusively of an already-loaded `resumeWindow`'s stid to let an unconsumed sibling
  surface on the very next round instead of being skipped. `computeReachedEnd`
  (`frameSegmentsCore.js`) gained an explicit `rawCount` parameter so that filtering
  doesn't get misread as the server having no more data. `selectByBudget` itself is
  unchanged.

  **First attempt regressed into an infinite duplicate/oscillation loop** (caught live,
  same day, restarting after the fix above): filtering only `resumeWindow`'s own single
  `(stid, id)` forgets every *other* sibling already consumed earlier at that same stid
  once the boundary moves on to consume the next one — the requery then finds the
  earlier-consumed sibling again, "new", and re-adds it, while the *previous* round's
  sibling becomes the thing forgotten this time, oscillating between them forever (or
  until the fill target/segment cap cuts it off, by which point the buffer is full of
  duplicates of the same one or two frames). Symptom: one raw-chunk's worth of content
  appearing to repeat endlessly in one direction's frame view.
  Fix: track *every* id already consumed at the current boundary stid, not just the most
  recent one — `byteBufferCore.js`'s `idsAtStid(windows, dir, boundary)` derives the full
  set directly from the buffer's own contents (a tied group is always contiguous at
  whichever end is being extended, so this is a short scan, not a full pass) and threads
  it through `fillToTarget`'s `req.excludeIds`; `frameSegmentsCore.js`'s
  `excludeAlreadyLoaded(frames, stid, excludeIds)` (the pure filter, now testable and
  tested directly) replaces the single-id version in `frameSegments.js`.

  Regression coverage: `byteBufferCore.test.js`'s "keeps passing the completed edge as
  resumeWindow..." test, `frameSegmentsCore.test.js`'s `computeReachedEnd` `rawCount`
  tests, `excludeAlreadyLoaded`/`idsAtStid` unit tests, and (most directly)
  `frameSegmentsCore.test.js`'s "two tied-stid groups (each oversized-then-small)..."
  integration test, which wires the real `selectByBudget`/`computeReachedEnd`/
  `excludeAlreadyLoaded`/`wantRangeFor` into a fake adapter driven by `fillToTarget` and
  asserts every frame across two multi-member groups loads exactly once.

## TODO items this resolves

From the root `CLAUDE.md`'s TODO section, remove once implemented:

- **"`useChunkBuffer`'s buffer-trimming isn't tied-`stid`-group-aware"** — moot once
  eviction no longer requires header-boundary-aligned cuts.
- **"A single frame's byte payload isn't paginated"** — the core problem this whole
  design solves.

Not addressed by this design (still separately tracked): the "no explicit empty state for
frame view" and "no in-app framer-script editor" TODO items.

## Open questions / deferred decisions

- Exact visual treatment of a "continued" segment header (front-trimmed while still
  partially resident) — deferred to the frame-mode migration step (UI detail, not a
  data-loading concern).
- `CombinedView.js` migration — deferred per the migration plan above.
- `SEGMENT_STEP = 512` is proposed by analogy to `WINDOW_STEP`'s ratio, not independently
  validated — revisit if frame-mode testing shows it's off.
- Whether `/frames/timeline` should also accept a `maxBytes` hint (purely to shrink an
  unnecessarily long metadata response for a page of many tiny frames) versus always
  fetching up to `maxSegments` records and letting the client walk/cut client-side (current
  assumption) — not expected to matter given metadata's small size, but not stress-tested.
