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

`fillForward`/`fillBackward` map directly onto the `/segments` wire endpoint (see below) —
metadata and bytes arrive together in one exchange, so every returned `SegmentWindow` is
already fully loaded; `resumeWindow` is realistically never non-null here (a chunk can't
exceed `WINDOW_STEP` by enough to matter... actually it can, up to 64KB > 32KB — see wire
protocol note below on truncation applying to chunks too, not just frames).

### Frame-mode adapter

- Metadata: still a separate, cheap call — `/frames/timeline`, unchanged shape, already
  bytes-free. Walk the returned array accumulating `length` to find the same
  `maxBytes`/`maxSegments` cutoff, entirely client-side (no server change needed here;
  metadata is small regardless of segment count).
- Bytes: fetched via the *same* `/segments` endpoint chunk-mode uses (this endpoint has
  no frame-awareness at all — it only ever serves raw chunks). The frame adapter computes
  the combined offset range needed per direction for the frames it decided to open this
  round, fetches it via one `/segments` request (batched exactly like today's
  `frameFetchPage` batches its per-direction `fetchDirectionChunks` calls), then slices
  each frame's own bytes out of the one returned blob — the same arithmetic
  `sliceFrameBytes` does today, just against one buffer instead of an array of chunk
  objects.
- `resumeWindow` for frame mode is the real case this whole rework exists for: extending
  a still-partially-loaded giant frame by one more `/segments`-backed byte range each
  round.
- Once `resumeWindow`'s own segment finishes loading, `fillForward`/`fillBackward` requery
  `/frames/timeline` **inclusive** of its stid (not the usual "+1"/exclusive cursor) and
  filter out exactly that one already-loaded `(stid, id)` from the result — this is what
  lets a tied-stid sibling (a second, smaller frame completing on the same raw chunk as a
  first, oversized one) still be found instead of silently skipped; see "Known gaps fixed
  after the fact" below.

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

## Wire protocol: `/segments`

Replaces `/stid-stream`'s per-chunk streaming (one text+binary frame pair per chunk, plus
a `done` signal) with one request → one response pair (one text+binary frame pair for the
*whole* batch). Renamed from `/stid-stream` since it's no longer streaming and now speaks
in the unified "segment" vocabulary — plain `/segments`, matching the existing bare-noun
endpoint naming convention (`/frames`, `/chunklist`, `/streams`), not `/segments-fill`.

**Request:** exactly one of `afterStid` / `beforeStid` must be present — that's how the
client indicates scan direction; the server responds `400` if both or neither are given.
No separate `direction` field (see the adapter contract note above on why that name is
avoided here).
```json
{"session":N, "stream":N, "afterStid":N,  "maxSegments":N, "maxBytes":N}
{"session":N, "stream":N, "beforeStid":N, "maxSegments":N, "maxBytes":N}
```

**Response — one exchange, two frames (not two round trips):**
1. Text: `{"segments":[{"stid":N,"segmentId":N,"direction":N,"time":N,"offset":N,"length":N}, ...], "reachedEnd":bool}`
2. Binary: each listed segment's own bytes, concatenated in array order.

`length` on each entry is that segment's own byte count, **not cumulative** — the client
reconstructs each segment's slice from the blob with one linear pass accumulating `length`
in array order. Backward requests (`beforeStid`) still return the array in ascending
`stid` order, even though the server selects the set by walking `stid DESC` internally, so
client-side consumption never special-cases direction.

**Why a bare `stid` cursor is still safe, despite frames' ties.** `/segments` itself never
returns frames — only raw chunks, whose `stid` is unique by construction, so no tie-break
concern arises at this endpoint at all. The tie concern only exists for frame *metadata*
(`/frames/timeline`, untouched by this rework), which already handles it: it guarantees a
returned page never splits a tied-`stid` group (fetches `n+1` and re-queries the boundary
`stid` fresh if the natural cutoff would land mid-group — see
`intercept/dbdump/CLAUDE.md`'s "Cross-direction interleaving"). So "everything after `stid`
X" is unambiguous there too, even though X's group may have more than one member — a prior
page either returned all of it or none of it.

**Backend note — real server-side backward support, not client approximation.** Today's
backward scroll (`handleScrollEnd`'s `-1` branch) approximates "N chunks before X" via
`start = max(0, prevId - BATCH)` then fetching *forward* from there — a count-based guess
that only worked because `BATCH` made chunk count and byte count roughly interchangeable.
That breaks under a real byte budget (a run of maximal 64KB chunks vs. a run of tiny ones
needs wildly different stid spans for the same `maxBytes`), so `beforeStid` needs the
server to walk `ORDER BY stid DESC`, accumulate until either cap is hit, then return the
result re-sorted ascending — a real, symmetric addition to the `/segments` handler, agreed
as in-scope (this is a new API; new functionality that serves a real purpose is fine).

**`/segments` never truncates a chunk — it only stops *between* whole chunks.** Both
`maxSegments` and `maxBytes` are checked after adding each whole chunk, so a single
maximal chunk (up to 64KB) can push a response slightly past a 32KB `maxBytes` budget —
the same bounded overshoot `fetchDirectionChunks` already accepts today for `toOffset`
("chunks up to, and possibly slightly past if `toOffset` lands mid-chunk"). This is a
non-issue precisely because a chunk's size is capped at 64KB; a *frame* has no such bound,
which is why capping how much of a still-open huge frame to ask for on any given round is
the frame adapter's job (computing a smaller target byte range itself), not something
`/segments` needs to support server-side.

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
