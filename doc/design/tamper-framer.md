# Tamper Framer — design notes

**Status: implemented (2026-08-16).** Extends the framer concept already shipped for
`dbdump` (see [`doc/design/packet-dissector.md`](packet-dissector.md) and
[`doc/design/framer-cross-direction-correlation.md`](framer-cross-direction-correlation.md))
to the `tamper` interceptor's scripted interception pipeline, so a script's hooks can
react to reassembled frames instead of raw TCP-layer chunks. All decisions below were
settled during planning; the one "Open for comment" item from that pass (connection-close
handling) was resolved before implementation started — see "Implementation notes" at the
end for what actually landed, including a real mechanism correction and a verified
finding that changed the close-handling design. **Not yet browser-verified** — see the
root `CLAUDE.md` TODO entry for what's still outstanding.

## What problem this solves

A `tamper` interception script today reacts to `onReceive(ctx, data)` once per raw chunk
— whatever the kernel happened to hand the proxy in one read, which may be a partial
message, several messages, or anything in between. A script that wants to act on whole
logical units (an HTTP/1 message, a length-prefixed record, a TLS record) has to
reimplement its own reassembly by hand every time. The goal is to let a script instead
receive one call per complete frame, with reassembly handled by a separate, reusable
framer script — the same division of labor `dbdump`'s framer already established for
passive analysis, applied to the live/editable path.

## Relationship to dbdump's framer

The **script contract stays close to dbdump's** — `function frame(state, chunk)`,
combined mode (one instance per stream, both directions merged into one chronological
sequence, one shared `state`) — so the mental model transfers directly and a script is
easy to port between the two. What differs is entirely on the platform side, because
dbdump's framer points `{ranges: [{offset, length}]}` into bytes that are already
permanently stored, while tamper's operates on a live, mutable, in-flight buffer that
gets edited and released out from under it:

- **Frames carry `{length, meta?}`, not `{ranges: [{offset, length}], meta?}`.** There's nothing
  durable to address by absolute offset; a frame is just "the next N bytes of whatever's
  still buffered," consumed sequentially. Carryover of an incomplete tail across calls
  remains the script's own job via `state`, exactly as today.
- **No persistence.** dbdump's `frames`/`frame_progress` tables exist so a replay/re-view
  doesn't re-run the script from scratch. Tamper has no such need — framer state lives
  only in the running script's Worker for the connection's lifetime and is discarded on
  stream end or script stop.
- **Frames are editable.** A dbdump frame is a read-only view for display. A tamper frame
  is a real held-and-releasable unit: the script's decision (forward/edit/drop) has to
  turn into an actual wire release.

## Where it runs — no backend/protocol changes needed

Entirely frontend, layered on the *existing* control/watch wire protocol — no Go-side
execution, no `heldBuffer`/`ConnHandler` changes. This matters because tamper's scripting
model is deliberately 100% frontend today ("nothing on the Go side executes a script");
this stays true. Backend work is limited to script *storage* (a second, independent
`scriptstore.Store` instance) — a separate, already-generic mechanism from the live wire
protocol, unrelated to this section's "no protocol changes" claim.

The enabling fact: `heldBuffer`'s `bounds` are already a purely client-owned,
arbitrary re-segmentation of the buffer — exactly what a human's split/merge
context-menu action does by hand today. A framer-aware script runtime does the same
thing programmatically, once per dispatch (see "Implementation notes" for why this is a
single call, not a loop):

1. `peek` the direction's currently-held buffer.
2. Call `frame(state, chunk)` **once**, with `chunk.data` = only the bytes not yet fed to
   `frame()` for this direction (dbdump's own contract: one new raw chunk, never the
   whole accumulated buffer — the script's own `state` is where an undecided carry lives).
   The call returns every currently-resolvable frame in one shot, `{frames, state}`.
3. For each returned frame, in order, consuming bytes sequentially from the front of the
   whole peeked buffer: fire `onFrame(ctx, frame)` — `frame = {direction, data, meta,
   final}` — in place of `onReceive`.
4. On that hook's forward/edit/drop decision, issue the *existing* `release` message:
   `edited:true`, `prefix_length = frame.length`, `bounds:[0]`, `release_chunks:1`, with
   the (possibly edited) frame bytes. This releases exactly that frame's bytes and leaves
   anything after it untouched in the buffer — no backend awareness of "frames" required
   at all.

## Confirmed decisions

- **Scope: scripted interception only.** `TamperQueueList`/`TamperDetailPanel`'s manual
  human review is unchanged — still raw chunks. Framing is an opt-in layer under the
  Scripts sub-tab, mirroring dbdump's framer being an optional overlay rather than a
  replacement of raw-chunk viewing.
- **Script storage: separate store from dbdump's framer scripts and from tamper's own
  interception scripts.** `framer-scripts-dir` config key, nested REST routes under
  `/api/i/tamper/framer`, own `framer-script-updated` push event — mirrors dbdump's
  existing `ScriptsDir`/`DissectScriptsDir` two-instance precedent exactly. A script can
  still be copied between stores by hand since the contract is close enough.
- **Composition: two independently-selected scripts.** A framer script and an
  interception script are picked separately and composed at runtime — the framer is
  reusable across different interception scripts, rather than baked into one file.
- **Selection UI: a picker alongside Run/Stop**, mirroring dbdump's `TrafficView.js`
  Framer control — a dropdown in the Scripts sub-tab picks which framer script (if any)
  wraps the currently-run interception script, disabled while a script is running
  (composition is fixed at Run time; Stop to change).
- **Framer sees only original incoming bytes, never edits.** An interception script's
  edit to frame N doesn't feed back into the framer's own state/decisions for frame N+1.
  If an edit changes something framing depends on (e.g. rewrites a length-prefix field),
  keeping downstream framing consistent stays the script's own responsibility, same as
  editing raw chunks today.
- **Hold-timeout mid-incomplete-frame falls back to raw release.** If the existing
  per-buffer hold-timeout fires while a frame is still incomplete, whatever's buffered so
  far is released as-is (unseen by `onFrame`), preserving tamper's existing "always
  eventually forwards something" guarantee rather than blocking forever. Needed no special
  handling to implement — see "Implementation notes."
- **Connection close with an incomplete tail still buffered** (resolved from the earlier
  "Open for comment" round): the framer gets a final `chunk.closed = true` call (empty
  `data`, mirroring dbdump's own convention) so it can flush anything whose length was
  implicit in the close. Whatever that call still doesn't resolve into a frame is exposed
  to the interception script as one final synthetic frame (`meta: null`) rather than
  bypassing `onFrame` silently. Every frame produced during close handling — both what the
  `closed:true` call itself resolves and the synthetic leftover — carries `final: true`;
  `ctx.release()`/`drop()`/`pause()` on such a frame are safe no-ops (no live buffer left
  to act on); `get()`/`set()`/`append()`/`log()` behave normally. One interception script
  may register both `onReceive` and `onFrame` — whichever applies to a given run is the
  one that fires, so the same script works with or without a framer selected.
- **`framer.*` gets `fs`/`kv` access**, matching dbdump's own `framer.fs`/`kv`, for script
  portability between the two runtimes — plus `transform`/`encode`/`decode`/`number`/
  `log` (no `hpack`; that's tied to HPACK's per-direction dynamic table, not a general
  framer need).

## Non-goals for v1

- No dissector-equivalent stage for tamper frames (meta is opaque, script-defined —
  scripts can already reach `tamper.transform.*`/`number.*` to pick apart frame bytes
  themselves).
- No re-framing/resync assistance when a script's own edits desync the byte stream from
  what the framer expects.

## Implementation notes

What actually landed, and where this diverged from (or went beyond) the design above:

- **A real mechanism bug was found and fixed while building a throwaway Node smoke test**
  (not committed — same convention as this repo's example-script verification) that runs
  the real assembled Worker source (captured via the real `start()` call path, not
  hand-copied) against a mock peek/release server. The design above's step 2 originally
  called `frame()` in a loop, re-feeding the *entire* peeked buffer as `chunk.data` on
  every iteration. Since the framer's own `state` independently carries forward its
  undecided tail (as intended — see "no persistence" above), this double-counted:
  already-buffered-but-unresolved bytes got fed to the framer a second time on the next
  call, alongside genuinely new bytes. Fixed to match dbdump's own established contract
  exactly: `chunk.data` is only the bytes not yet fed to `frame()` for that direction
  (tracked via each direction's cached tail — see next bullet — whose *length*, not a
  separate counter, is what makes "only the new bytes" computable), and a single
  `frame()` call is expected to resolve every currently-extractable frame itself (the
  script's own internal loop over its buffered state does that, exactly like dbdump's
  example framers already do) — the platform never needs to call `frame()` twice for the
  same arrival.
- **A fresh `peek`/`release` is genuinely impossible after a stream closes** — verified by
  reading the Go source directly, not assumed: `ConnectionTerminated`
  (`intercept/tamper/tamper.go`) deletes the stream from `i.streams` and closes both
  `heldBuffer`s *before* sending `stream-terminated`, and `lookupHeld` (`api.go`, used by
  both `handleRelease` and the peek path) resolves via that same now-empty map. This
  wasn't anticipated when "Confirmed decisions" above was written. Close handling
  (`resolveFramerClose` in `scriptRuntime.js`) therefore works entirely from a client-side
  cache of each direction's last-known unresolved tail (`lastRemaining`), never a fresh
  peek — no backend change was needed to make this work, preserving the "no
  backend/protocol changes" property.
- **State/tail bookkeeping is persisted incrementally**, not once per `frame()` call —
  after each individual frame is dispatched and released, not only at the end of
  processing a whole `frames` array — so a later frame's `onFrame` handler throwing
  mid-batch can't roll back bookkeeping for frames already released to the wire earlier in
  the same batch.
- **`makeCtx` gained one `opts.live` flag** rather than a parallel close-triggered ctx
  implementation: `live:false` makes `commit()` skip the wire `release` call while still
  running every other bit of buffer bookkeeping (`get`/`set`/`append`) identically, which
  is what makes `release`/`drop`/`pause` safe no-ops on a close-triggered frame without
  duplicating logic that must otherwise change together.
- Full mechanics documented in `web/CLAUDE.md`'s "Tamper framer scripts" section;
  script-author-facing reference in `doc/interceptor/tamper.md`'s "Framer scripts"
  section (§4); backend storage details in `intercept/tamper/CLAUDE.md`'s "Script
  storage" section.
- Verified via Go unit tests (`intercept/tamper/framer_scripts_test.go`), the throwaway
  Node smoke test described above (multi-chunk carry, multiple frames resolved from one
  call, forward/drop actions with correct wire `prefixLength`/`bounds`, both
  close-handling cases), and the existing `web/` JS test suite (unaffected). **Not yet
  run against a real framer+interception script pair in an actual browser** — that
  remains the one open verification step (see root `CLAUDE.md`'s TODO entry).
