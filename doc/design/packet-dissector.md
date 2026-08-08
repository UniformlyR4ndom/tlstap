# Packet Dissector — design notes (dissector stage, deferred)

**Status: not implemented, not scheduled.** This document captures the design arrived
at for the dissector half of the "Packet Dissector" feature, split out so the
[framer stage](#relationship-to-the-framer-stage) can be built and shipped first. Treat
everything here as a starting point for whoever picks this up later, not a committed
design — revisit it against whatever the framer stage actually looks like once built.

## What problem this solves

Turn a byte range (a frame, in framer-stage terms — see below) into a labeled,
human-readable breakdown of its fields, à la Wireshark's packet-details pane: a
collapsible tree of `{label, value, byte range}` nodes, clicking a node highlights its
bytes in the hex view.

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
  label: "Content Type",
  value: "Handshake (22)",   // human-readable, formatted by the dissector script
  start: 0,                   // byte offset relative to the frame's own bytes
  length: 1,
  children: [ /* nested FieldNode[], for TLV / sub-structures */ ]
}
```

`start`/`length` are relative to the frame, not the stream — the panel adds the frame's
own base stream-offset to translate a node into an absolute byte range for highlighting
in `HexDump`/`HexEditor`, the same translation the framer stage already needs for its own
frame-boundary → absolute-offset mapping.

## Dissector contract

Pure function, no side effects, no async:

```js
function dissect(bytes, frame) {
  // frame: { offset, length, direction, kind, ... } — kind/metadata as tagged by the
  // framer that produced this frame (e.g. "http-response" vs "websocket-frame" for a
  // stream that upgraded partway through)
  return FieldNode // the tree's root
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

- A collapsible field-tree panel — side or bottom, panel placement kept easy to change
  (matches how every other resizable panel in this codebase already reads its size from
  `layout.js`/`useResizableLayout`, not hardcoded).
- Clicking a node highlights its translated absolute byte range in the hex view (reuses
  `HexDump.js`'s existing per-byte `data-off`/`data-dir` selection machinery — see
  `web/CLAUDE.md`'s "Byte selection" note).
- Nested/variable-length fields (TLV, length-prefixed sub-structures) are in scope from
  the start via `FieldNode.children` — not deferred to a later cut.

## Script storage

Reuses the same extraction planned for the framer stage:
- Backend: the shared `scriptstore` package (name-validated flat store, atomic writes),
  the same one tamper's own scripts and the framer's scripts use.
- Frontend: `ScriptEditor.js` generalized to take its autocompletion source as a prop
  (dissector scripts get no tamper-specific `tamper.*`/`ctx.*` completions); the generic
  CRUD list+editor chrome extracted from `TamperScriptsPanel.js`, parametrized by REST
  functions and an extension-point slot for controls (dissector panel likely needs none —
  no Run/Stop, since execution is on-demand per viewed frame, not a running process).

**Open question, not resolved:** whether dissector scripts share the same `scripts-dir`/
namespace as framer scripts (distinguished by some "kind" metadata) or get an entirely
separate directory/config field. Revisit once the framer stage's actual `scripts-dir`
wiring exists to model this against.

## Dropped for now: manual framing anchors

Not a dissector concern, but noted here since it was discussed and shelved alongside
this: manual "mark a frame start here" resync points for the *framer* stage were
considered and dropped (auto-only for v1) — see git history of this design conversation
if that need resurfaces.
