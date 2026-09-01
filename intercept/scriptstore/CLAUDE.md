# scriptstore package (`intercept/scriptstore/`)

Implementation notes for this package, loaded automatically when working under this
directory. See the root `CLAUDE.md` for where it fits — extracted from `tamper`'s
original `scripts.go` (see `intercept/tamper/CLAUDE.md`'s "Script storage" section for
how tamper wires it) so any other interceptor wanting script storage doesn't reimplement
it. Not an `ApiProvider` itself — `RegisterRoutes` is called directly by whichever
interceptor owns the `basePath`.

**`Store`** is a flat name → content store, one `<name>.js` file per script in a
directory, with no opinion about which script is "main" or a "library" (a runtime-level
concern for whatever loads scripts by name, not a storage-level one).

- **Name validation** (`validateName`): charset `[A-Za-z0-9_.\- ]` (letters, digits, `_`,
  `-`, `.`, and spaces — space discouraged but not forbidden). Path separators are
  excluded outright, so a name is always joined as a single path segment; the only
  dot-sequences that could still resolve outside the store's directory when joined
  (`"."`/`".."`) are rejected explicitly, along with a leading/trailing `.`/` ` (avoids
  confusable near-duplicates like `"foo"` vs `"foo "`, and — with those covered — dots
  are otherwise harmless). `net/http`'s own `ServeMux` already cleans/redirects a path
  containing `..` before it would ever reach a handler, so the explicit check is defense
  in depth — the one actually reachable path for verifying it is a direct
  `Store`/`validateName` unit test, not an HTTP round trip.
- **`Put` is atomic**: written to a `.tmp-*` temp file in the same directory, then
  `os.Rename`d into place, so a concurrent `Get` can never observe a partial write. Temp
  files never appear in `List()` regardless of timing, since listing filters strictly by
  the `.js` suffix.
- `New(dir)` creates `dir` (including any missing parents) if it doesn't already exist.

**`RegisterRoutes(mux, basePath, store, onPut, onDelete)`** wires `GET {basePath}/scripts`,
`GET/PUT/DELETE {basePath}/scripts/{name}`. `GET .../{name}?hash=1` returns
`{"sha256":"<hex>"}` (`Content-Type: application/json`) instead of the raw content —
`crypto/sha256` over the exact same bytes `Get` would return, matching the "version" a
framer/dissector run computes over identical content client-side (`framerRun.js`'s
`sha256Hex`) and dbdump persists as `frames.script_version`/
`frame_progress.script_version` (see `intercept/dbdump/CLAUDE.md`'s "Framer scripts"
section). Lets a caller that already knows a script's name learn its current version
directly — e.g. `tapctl`'s `script-get --hash`/`framer-script-get --hash` (tamper) and
`script-get --hash`/`dissect-script-get --hash` (dbdump) — without fetching the content
just to hash it itself, the only alternative before this existed (raw SQLite access to
`frames.script_version`, or reimplementing the same sha256-over-fetched-content dance a
browser client does). `store == nil` (feature disabled for that
caller) makes every route respond `501` rather than silently defaulting to some implicit
directory — the same convention other optional-feature REST surfaces in this codebase
use (`core/fs` is the one exception: it doesn't register its routes at all when
unconfigured, so an unconfigured request there gets a plain `404` instead — see
`core/CLAUDE.md`). `onPut`/`onDelete` (either may be `nil`) fire with the
script's name after a successful `PUT`/`DELETE` — this is the one extension point, since
what a caller wants to happen on a change is never this package's concern: tamper pushes
a `script-updated` control-channel event from both; a future caller with no live-push
channel at all can just pass `nil`, or use it to invalidate data derived from the old
script content — dbdump's framer scripts do exactly this (purging stale computed frame
data once a script's content changes; see `intercept/dbdump/CLAUDE.md`'s "Framer
scripts" section).

Content is transferred as a raw body on every endpoint (never JSON/base64-wrapped),
since script content is always UTF-8 JS text — wrapping it would be pure overhead and
friction for `curl`/CLI push-pull.

Unit-tested (`scriptstore_test.go`): name validation (valid/invalid, including traversal
attempts), `Store` list/get/put/delete round-trips, directory auto-creation, and an
HTTP-level end-to-end pass over the real REST handlers including the `onPut`/`onDelete`
callbacks firing.
