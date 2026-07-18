package tamper

import (
	"sync"
	"time"

	"tlstap/proxy"
)

// heldBuffer holds everything currently buffered for one (stream, direction): a single growing
// byte slice plus the offsets where each appended chunk started. Chunks are purely a review/
// release-granularity aid — merging or splitting them is just editing this offset list, since TCP
// itself has no message framing to preserve.
//
// Invariants:
//   - bounds is strictly increasing; bounds[0] == 0 whenever data is non-empty; every entry is a
//     valid index into data (0 <= bounds[i] <= len(data)).
//   - Release only ever removes a prefix (see performAction/releaseAll) — there is no other way to
//     shrink data, so the BufferingInterceptor contract's "never release out of arrival order" is
//     enforced structurally, not just by convention.
//
// One instance per (stream, direction); TamperInterceptor holds two per streamState (see
// tamper.go), implementing proxy.BufferingInterceptor by delegating HasPending/ReleaseChannel to
// the relevant direction's instance.
type heldBuffer struct {
	mu     sync.Mutex
	data   []byte
	bounds []int

	relCh        chan proxy.ReleasedData // returned by ReleaseChannel; closed exactly once, by close()
	holdTimeout  time.Duration           // <= 0 means no timer at all
	timer        *time.Timer             // nil until the first chunk is appended with holdTimeout > 0
	closed       bool
	lastActivity int64 // UnixMilli of the most recent appendChunk; reported by snapshot() for "peek"
}

func newHeldBuffer(holdTimeout time.Duration) *heldBuffer {
	return &heldBuffer{
		relCh:       make(chan proxy.ReleasedData, 1),
		holdTimeout: holdTimeout,
	}
}

// appendChunk adds data as a new chunk at the back of the buffer, and (re)starts the hold-timeout
// timer, if configured, so it always measures from the most recent arrival — not from any single
// chunk's own age. This is a deliberate simplification over per-chunk timers: once chunks can be
// merged/split by an edit, a timer tied to one original chunk's identity has nothing well-defined
// to refer to after that chunk's boundary is edited away. A single per-buffer timer that just
// flushes everything on expiry has no such problem, and preserves the original guarantee (nothing
// sits unresolved forever) without needing timer identity to survive edits.
//
// Returns the offset the new chunk was appended at (i.e. the buffer's length just before this
// call), which TamperInterceptor.Intercept needs for the "held" notification it sends afterward.
// Computed here, under the same lock acquisition as the append itself, rather than via a separate
// length() call beforehand — TamperInterceptor only ever has one goroutine appending to a given
// buffer at a time (one direction's forward loop), so this isn't strictly required for correctness
// today, but avoids relying on that as an invariant callers have to remember.
func (b *heldBuffer) appendChunk(data []byte) (offset int) {
	b.mu.Lock()
	offset = len(b.data)
	b.bounds = append(b.bounds, offset)
	b.data = append(b.data, data...)
	b.lastActivity = time.Now().UnixMilli()
	if b.holdTimeout > 0 {
		if b.timer != nil {
			b.timer.Stop()
		}
		b.timer = time.AfterFunc(b.holdTimeout, b.onTimeout)
	}
	b.mu.Unlock()
	return offset
}

func (b *heldBuffer) onTimeout() {
	b.releaseAll()
}

func (b *heldBuffer) hasPending() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data) > 0
}

func (b *heldBuffer) numChunks() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.bounds)
}

// length returns the buffer's current byte length. Separate from snapshot() so callers that just
// want counts (e.g. sendStreamList, summarizing every stream's buffers at once) don't pay for a
// full data copy.
func (b *heldBuffer) length() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

// snapshot returns a copy of the buffer's current data and bounds, plus the UnixMilli of the most
// recent appendChunk, for a "peek" reply — read-only, never mutates or releases anything. Callers
// that only need a byte-range slice (peek supports offset/length) slice the returned data
// themselves; bounds/total length/lastActivity are always reported in full regardless of the
// requested slice, since a resync always wants the complete picture and all three are cheap.
func (b *heldBuffer) snapshot() (data []byte, bounds []int, lastActivity int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), append([]int(nil), b.bounds...), b.lastActivity
}

// releaseAct selects what performAction does with the bytes it releases. Deliberately a
// separate type from tamper.go's action (the wire-level "forward"/"drop" string): this
// package is protocol-agnostic and independently unit-tested, so it never sees wire
// values directly — handleRelease is what translates one into the other.
type releaseAct int

const (
	actForward releaseAct = iota // hand the real released bytes to relCh, to be forwarded downstream
	actDrop                      // hand empty bytes to relCh — the chunks are removed from the buffer, but nothing is forwarded
)

// performAction is the control-driven entry point combining an edit with an optional release, in
// one atomic step: it replaces the buffer's first prefixLen bytes with newData/newBounds — an
// edit — then releases the resulting buffer's first releaseChunks chunks per act. Doing both under
// one lock acquisition matters: splitting them into two calls would leave a window where a
// concurrent appendChunk or hold-timeout releaseAll could land in between and either get silently
// overwritten by the edit or released before the edit meant to apply to it does.
//
// prefixLen=0 is a pure insertion at the front (newData is inserted, nothing removed); newData
// empty (with prefixLen>0) is a pure deletion of that prefix; prefixLen=0 with newData also empty
// is a no-op edit, leaving performAction as a plain (possibly partial) release. releaseChunks=0
// leaves the (possibly edited) buffer fully held — no release at all. Returns false if prefixLen,
// newBounds, or releaseChunks is invalid, or the buffer is closed; on false the buffer is left
// untouched.
//
// The release send to relCh happens while still holding b.mu — see the comment on close() for why
// send-vs-close must be serialized under one lock, the same reasoning that applied to this
// method's predecessor, releaseUpTo.
func (b *heldBuffer) performAction(prefixLen int, newData []byte, newBounds []int, releaseChunks int, act releaseAct) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || prefixLen < 0 || prefixLen > len(b.data) || !validBounds(newBounds, len(newData)) {
		return false
	}

	tail := b.data[prefixLen:]
	editedData := make([]byte, 0, len(newData)+len(tail))
	editedData = append(editedData, newData...)
	editedData = append(editedData, tail...)

	tailStart := len(b.bounds)
	for i, off := range b.bounds {
		if off >= prefixLen {
			tailStart = i
			break
		}
	}
	shift := len(newData) - prefixLen
	editedBounds := make([]int, 0, len(newBounds)+len(b.bounds)-tailStart)
	editedBounds = append(editedBounds, newBounds...)
	for _, off := range b.bounds[tailStart:] {
		editedBounds = append(editedBounds, off+shift)
	}

	if releaseChunks < 0 || releaseChunks > len(editedBounds) {
		return false
	}

	if releaseChunks == 0 {
		b.data = editedData
		b.bounds = editedBounds
		return true
	}

	var cut int
	if releaseChunks == len(editedBounds) {
		cut = len(editedData)
	} else {
		cut = editedBounds[releaseChunks]
	}

	var released []byte
	if act == actForward {
		released = append([]byte(nil), editedData[:cut]...)
	}
	remaining := append([]byte(nil), editedData[cut:]...)
	newRemBounds := make([]int, 0, len(editedBounds)-releaseChunks)
	for _, off := range editedBounds[releaseChunks:] {
		newRemBounds = append(newRemBounds, off-cut)
	}

	b.data = remaining
	b.bounds = newRemBounds
	if b.timer != nil && len(b.data) == 0 {
		b.timer.Stop()
		b.timer = nil
	}

	b.relCh <- proxy.ReleasedData{Data: released}
	return true
}

// abort terminates the connection outright via relCh's Err, independent of anything currently
// buffered — mirrors the old per-chunk protocol's "drop-connection" action. Unlike performAction,
// it isn't parameterized by buffer content, since the connection is being torn down regardless of
// what was pending; whatever was held is simply discarded. Does not set b.closed — that stays
// exclusively close()'s job, called later from the normal ConnectionTerminated lifecycle. Returns
// false if the buffer is already closed.
func (b *heldBuffer) abort() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.data = nil
	b.bounds = nil
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}

	b.relCh <- proxy.ReleasedData{Err: proxy.ErrAbort}
	return true
}

// releaseAll releases everything currently held, computed and removed atomically under one lock
// acquisition — unlike calling performAction(0, nil, nil, numChunks(), actForward) as two separate
// steps (read count, then release), which could race a concurrent appendChunk landing in between
// and release based on a stale count. Used by the hold-timeout callback above, and by
// TamperInterceptor's "control disconnected" and "switched off intercept mode" sweeps that need to
// flush a stream's buffers unconditionally (see tamper.go). Returns false if the buffer is already
// empty or closed.
func (b *heldBuffer) releaseAll() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || len(b.bounds) == 0 {
		return false
	}
	released := b.data
	b.data = nil
	b.bounds = nil
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}

	b.relCh <- proxy.ReleasedData{Data: released}
	return true
}

func validBounds(bounds []int, dataLen int) bool {
	// bounds is empty if and only if data is: an empty buffer has no chunks, and a non-empty
	// buffer always has at least one (bounds[0] == 0 marking where it starts) — a zero-length
	// chunk (an empty bounds entry paired with empty data) isn't a meaningful state.
	if dataLen == 0 {
		return len(bounds) == 0
	}
	if len(bounds) == 0 || bounds[0] != 0 {
		return false
	}
	for i, off := range bounds {
		if off < 0 || off > dataLen {
			return false
		}
		if i > 0 && off <= bounds[i-1] {
			return false
		}
	}
	return true
}

// close implements the BufferingInterceptor contract: called once ConnectionTerminated has fired
// for this stream, closes relCh so ConnHandler's fan-in can exit, and stops any pending timer.
// Setting closed and closing relCh under the same lock performAction/releaseAll/abort hold across
// their own send is what makes them mutually exclusive with a concurrent close() — see the note on
// performAction. Safe to call at most once (TamperInterceptor's ConnectionTerminated guard,
// mirroring its existing exists-check pattern, is expected to ensure this; close() itself does not
// additionally guard against being called twice, since it isn't meant to be called from more than
// one place).
func (b *heldBuffer) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
	}
	close(b.relCh)
}
