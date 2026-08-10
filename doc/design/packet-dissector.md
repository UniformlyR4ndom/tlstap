# Packet Dissector — design notes

**Status: implemented, v1 complete (2026-08-09).** The framer stage
([below](#relationship-to-the-framer-stage)) shipped first, as planned; the dissector
stage documented here — schema, script store, Worker execution, and the
`TrafficView.js` panel (click a frame, click a field, see it highlighted) — is now built
end-to-end. See `intercept/dbdump/CLAUDE.md`'s and `web/CLAUDE.md`'s own "Dissector
scripts" sections for what actually shipped, not just what was planned.

## What problem this solves

Turn a byte range (a frame, in framer-stage terms — see below) into a labeled,
human-readable breakdown of its fields, à la Wireshark's packet-details pane: a
collapsible tree of field nodes, clicking a node highlights its bytes in the hex view.

## Relationship to the framer stage

The framer stage (built first) reassembles a stream's raw chunks into logical frames —
`{offset, length, direction, kind}` — and persists that index server-side so `HexDump`
can render a stream partitioned by frame instead of by raw TCP chunk. The dissector is a
second, independent layer on top: given one frame's bytes (plus its `kind`/metadata),
produce a field tree. It has no involvement in framing itself and no persistence of its
own — see below.

## Field node schema

```js
{
  label: "Content Type",       // required
  content: "FhYD",             // OR offset+length below — mutually exclusive, never both
  "display-hint": "hex",       // optional; only meaningful when the value is bytes
  sub: [ /* nested FieldNode[], for TLV / sub-structures — optional */ ]
}
```

A node carries **at most one** of:
- `content` — a literal value the script computes directly: base64-encoded bytes, a
  number, or a bool. Used for anything that isn't a direct slice of the frame's own bytes
  (a decompressed/decrypted sub-payload, a checksum computed over other fields, a decoded
  enum label, ...). A `content`-only node has no byte range, so it **cannot** be
  highlighted in the hex view — that's an accepted, deliberate limitation: it's not
  possible in general (the decompressed example above has no single contiguous range in
  the frame to point back to).
- `offset`/`length` — plain integers, relative to the frame's own bytes (not the stream).
  Means "this field's value *is* the frame's own bytes at `[offset, offset+length)`" —
  the panel adds the frame's own base stream-offset to translate this into an absolute
  byte range for highlighting in `HexDump`/`HexEditor`, the same translation the framer
  stage already needs for its own frame-boundary → absolute-offset mapping. `display-hint`
  says how to render those raw bytes; there is no numeric-decoding hint (e.g. "treat these
  2 bytes as a big-endian uint16") — a script that wants a *decoded* number displayed
  computes it itself and reports it via `content` instead, accepting the tradeoff above.

Neither is required — a node with just `label` and `sub` is a pure grouping row (e.g.
"Extensions") with no value of its own.

`display-hint` is one of `format.js`'s existing formatter names — `ascii`, `hex`,
`hexdump`, `base64`, `raw` — reused as-is rather than inventing a second formatting
vocabulary; the UI decodes (`content`'s base64, or the frame slice at `offset`/`length`)
then calls the same `fmtAsAscii`/`fmtAsHexdump`/etc. `HexDump.js`/`ExtractPanel.js`/
`TransformPanel.js` already use. Irrelevant/omitted for a `content` that's already a
number or bool — rendered as-is.

## Dissector contract

Pure function, no side effects, no async:

```js
function dissect(bytes, frame) {
  // frame: { offset, length, direction, kind, ... } — kind/metadata as tagged by the
  // framer that produced this frame (e.g. "http-response" vs "websocket-frame" for a
  // stream that upgraded partway through)
  return FieldNode[] // top-level siblings, not a single wrapping root
}
```

A script typically switches on `frame.kind` internally to pick a field layout when one
stream mixes sub-protocols (e.g. HTTP → WebSocket upgrade) — the framer is what tags each
frame with the right `kind`; the dissector just branches on it.

## Execution model

Runs in a Web Worker, but **needs none of `scriptRuntime.js`'s RPC bridge** — that
machinery exists because tamper scripts must call back into the main thread mid-execution
for async, network-backed operations (`peek`/`release`/`pause`). A dissector is a pure
function over bytes the main thread already has; the Worker interface is just
`postMessage` bytes+frame in, get a tree back. Only the "two separate Blobs so a script
syntax error can't kill the bootstrap" trick is worth carrying over from
`scriptRuntime.js` — and it's small enough (~10 lines) not to be worth abstracting into
shared code, per this repo's duplication policy.

## Laziness — no persistence, ever

Unlike the framer's frame index, dissection output is **never persisted**. It's cheap
(one frame's bytes → one tree, no cross-frame state) and only ever needed for
whatever frame is currently visible/expanded in the UI — compute-on-demand, same
principle as `HexDump.js`'s virtual scroll only rendering visible rows. Persisting trees
would additionally require tracking a *second* script's version hash for cache
invalidation (the dissector's, separate from the framer's) for something that's already
fast enough not to need caching at all.

## UI

- A collapsible field-tree panel in `TrafficView.js`'s right side — the space
  `MarkersPanel.js` was deliberately moved out of the traffic view for (see
  `web/CLAUDE.md`'s "Markers panel" section). Sized via `layout.js`/`useResizableLayout`,
  same as every other resizable panel here, not hardcoded.
- **Frame view only** — dissection needs `frame.kind`, which only exists once a framer
  script has tagged frames; there is no dissection entry point in raw-chunk view.
- **Frame selection is click-driven, not auto-follow-scroll**: clicking a frame's row/
  header while in frame view selects it as "current"; the panel recomputes automatically
  (no separate "Dissect" button) for whichever frame is currently selected. Unambiguous
  even when several frames are visible in the viewport at once.
- Clicking a node highlights its translated absolute byte range in the hex view (reuses
  `HexDump.js`'s existing per-byte `data-off`/`data-dir` selection machinery — see
  `web/CLAUDE.md`'s "Byte selection" note) — only possible for a node with `offset`/
  `length`, per the field node schema above.
- Nested/variable-length fields (TLV, length-prefixed sub-structures) are in scope from
  the start via `FieldNode.sub` — not deferred to a later cut.

## Script storage

Reuses the extraction the framer stage already did:
- Backend: the shared `scriptstore` package (name-validated flat store, atomic writes),
  the same one tamper's own scripts and the framer's scripts use — a second, independent
  `*scriptstore.Store` for dissector scripts, its own `dissect-scripts-dir` config field,
  registered under its own REST namespace (`.../dissect/scripts`, nested under `dbdump`'s
  basePath, so it can reuse `scriptstore.RegisterRoutes` unmodified rather than colliding
  with the framer's own `.../scripts`). **Settled 2026-08-09**: a fully separate
  directory/namespace, not shared with framer scripts — simpler than adding a "kind"
  concept to the shared `scriptstore` package for a cosmetic benefit.
- Frontend: `ScriptEditor.js`/`ScriptsCrudPanel.js` (already generalized during the
  framer stage — see `web/CLAUDE.md`'s "Scripted interception" section) reused directly,
  the same way `FramerScriptsPanel.js` wraps `ScriptsCrudPanel.js` today. No Run/Stop
  controls needed — execution is on-demand per selected frame, not a running process.

## Dropped for now: manual framing anchors

Not a dissector concern, but noted here since it was discussed and shelved alongside
this: manual "mark a frame start here" resync points for the *framer* stage were
considered and dropped (auto-only for v1) — see git history of this design conversation
if that need resurfaces.
