package tamper

import (
	"testing"
	"time"

	"tlstap/proxy"
)

func recvReleased(t *testing.T, ch <-chan proxy.ReleasedData, want string) {
	t.Helper()
	select {
	case rd := <-ch:
		if string(rd.Data) != want {
			t.Fatalf("expected released data %q, got %q", want, rd.Data)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for release of %q", want)
	}
}

func expectNoRelease(t *testing.T, ch <-chan proxy.ReleasedData) {
	t.Helper()
	select {
	case rd := <-ch:
		t.Fatalf("expected no release yet, got %q", rd.Data)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHeldBuffer_AppendBookkeeping(t *testing.T) {
	b := newHeldBuffer(0)
	if b.hasPending() || b.numChunks() != 0 {
		t.Fatal("expected empty buffer initially")
	}

	b.appendChunk([]byte("abc"))
	b.appendChunk([]byte("de"))
	b.appendChunk([]byte("f"))

	if !b.hasPending() {
		t.Fatal("expected hasPending after appends")
	}
	if got := b.numChunks(); got != 3 {
		t.Fatalf("expected 3 chunks, got %d", got)
	}
	if string(b.data) != "abcdef" {
		t.Fatalf("expected concatenated data %q, got %q", "abcdef", b.data)
	}
	wantBounds := []int{0, 3, 5}
	if len(b.bounds) != len(wantBounds) {
		t.Fatalf("expected bounds %v, got %v", wantBounds, b.bounds)
	}
	for i, w := range wantBounds {
		if b.bounds[i] != w {
			t.Fatalf("expected bounds %v, got %v", wantBounds, b.bounds)
		}
	}
}

func TestHeldBuffer_PerformAction_InvalidArgs(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("abc"))

	if b.performAction(-1, nil, nil, 1, actForward) {
		t.Fatal("expected negative prefixLen to be rejected")
	}
	if b.performAction(100, nil, nil, 1, actForward) {
		t.Fatal("expected out-of-range prefixLen to be rejected")
	}
	if b.performAction(0, []byte("xy"), []int{1}, 1, actForward) {
		t.Fatal("expected malformed newBounds to be rejected")
	}
	if b.performAction(0, nil, nil, -1, actForward) {
		t.Fatal("expected negative releaseChunks to be rejected")
	}
	if b.performAction(0, nil, nil, 2, actForward) {
		t.Fatal("expected releaseChunks beyond the resulting chunk count to be rejected")
	}
	expectNoRelease(t, b.relCh)
}

func TestHeldBuffer_PerformAction_ReleaseForward_Middle(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("abc"))
	b.appendChunk([]byte("de"))
	b.appendChunk([]byte("f"))

	// No edit (prefixLen=0, no newData), just release the first 2 chunks.
	if !b.performAction(0, nil, nil, 2, actForward) {
		t.Fatal("expected release to succeed")
	}
	recvReleased(t, b.relCh, "abcde")

	if got := b.numChunks(); got != 1 {
		t.Fatalf("expected 1 remaining chunk, got %d", got)
	}
	if string(b.data) != "f" {
		t.Fatalf("expected remaining data %q, got %q", "f", b.data)
	}
	if len(b.bounds) != 1 || b.bounds[0] != 0 {
		t.Fatalf("expected shifted bounds [0], got %v", b.bounds)
	}

	// The remaining chunk should still release correctly.
	if !b.performAction(0, nil, nil, 1, actForward) {
		t.Fatal("expected release to succeed for the last chunk")
	}
	recvReleased(t, b.relCh, "f")
	if b.hasPending() {
		t.Fatal("expected buffer empty after releasing everything")
	}
}

func TestHeldBuffer_PerformAction_ReleaseForward_All(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("abc"))
	b.appendChunk([]byte("def"))

	if !b.performAction(0, nil, nil, b.numChunks(), actForward) {
		t.Fatal("expected release of all chunks to succeed")
	}
	recvReleased(t, b.relCh, "abcdef")
	if b.hasPending() || b.numChunks() != 0 {
		t.Fatal("expected empty buffer after releasing all chunks")
	}
}

func TestHeldBuffer_PerformAction_ReleaseDrop(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("abc"))
	b.appendChunk([]byte("def"))

	if !b.performAction(0, nil, nil, 1, actDrop) {
		t.Fatal("expected drop-release to succeed")
	}
	recvReleased(t, b.relCh, "") // dropped: chunk removed from the buffer, but no bytes forwarded

	if got := b.numChunks(); got != 1 {
		t.Fatalf("expected 1 remaining chunk, got %d", got)
	}
	if string(b.data) != "def" {
		t.Fatalf("expected remaining data %q, got %q", "def", b.data)
	}
}

func TestHeldBuffer_PerformAction_EditOnly_NoRelease(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("original"))

	if !b.performAction(len(b.data), []byte("edited-content"), []int{0, 7}, 0, actForward) {
		t.Fatal("expected edit-only (releaseChunks=0) to succeed")
	}
	expectNoRelease(t, b.relCh)
	if string(b.data) != "edited-content" {
		t.Fatalf("expected replaced data, got %q", b.data)
	}
	if b.numChunks() != 2 {
		t.Fatalf("expected 2 chunks after edit, got %d", b.numChunks())
	}
}

func TestHeldBuffer_PerformAction_InsertAtFront(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("world"))

	if !b.performAction(0, []byte("hello "), []int{0}, 0, actForward) {
		t.Fatal("expected insertion to succeed")
	}
	if string(b.data) != "hello world" {
		t.Fatalf("expected inserted data, got %q", b.data)
	}
	if len(b.bounds) != 2 || b.bounds[0] != 0 || b.bounds[1] != 6 {
		t.Fatalf("expected bounds [0 6], got %v", b.bounds)
	}
}

func TestHeldBuffer_PerformAction_DeletePrefix(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("junkkeep"))

	if !b.performAction(4, nil, nil, 0, actForward) {
		t.Fatal("expected deletion to succeed")
	}
	if string(b.data) != "keep" {
		t.Fatalf("expected remaining data %q, got %q", "keep", b.data)
	}
}

func TestHeldBuffer_PerformAction_EditThenRelease(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("original"))
	b.appendChunk([]byte("-tail"))

	// Replace the whole first chunk with edited content, then release just that (now edited)
	// portion, leaving the untouched tail chunk still held.
	if !b.performAction(len("original"), []byte("edited"), []int{0}, 1, actForward) {
		t.Fatal("expected edit+release to succeed")
	}
	recvReleased(t, b.relCh, "edited")
	if string(b.data) != "-tail" {
		t.Fatalf("expected remaining tail %q, got %q", "-tail", b.data)
	}
	if len(b.bounds) != 1 || b.bounds[0] != 0 {
		t.Fatalf("expected shifted bounds [0], got %v", b.bounds)
	}
}

func TestHeldBuffer_Abort(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("abc"))

	if !b.abort() {
		t.Fatal("expected abort to succeed")
	}
	select {
	case rd := <-b.relCh:
		if rd.Err == nil {
			t.Fatalf("expected an Err on abort, got %+v", rd)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for abort")
	}
	if b.hasPending() {
		t.Fatal("expected buffer empty after abort")
	}
}

func TestHeldBuffer_Abort_Empty(t *testing.T) {
	b := newHeldBuffer(0)
	if !b.abort() {
		t.Fatal("expected abort on an empty buffer to succeed")
	}
	select {
	case rd := <-b.relCh:
		if rd.Err == nil {
			t.Fatalf("expected an Err on abort, got %+v", rd)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for abort")
	}
}

func TestHeldBuffer_ReleaseAll(t *testing.T) {
	b := newHeldBuffer(0)

	if b.releaseAll() {
		t.Fatal("expected releaseAll on empty buffer to be rejected")
	}

	b.appendChunk([]byte("abc"))
	b.appendChunk([]byte("def"))

	if !b.releaseAll() {
		t.Fatal("expected releaseAll to succeed")
	}
	recvReleased(t, b.relCh, "abcdef")
	if b.hasPending() || b.numChunks() != 0 {
		t.Fatal("expected empty buffer after releaseAll")
	}
}

// TestHeldBuffer_ConcurrentAppendAndReleaseAll checks that one goroutine appending while
// another keeps calling releaseAll() never corrupts the buffer: every value that comes
// out on relCh must be a well-formed, non-empty prefix — run with -race to catch any
// data race, not just logical corruption.
func TestHeldBuffer_ConcurrentAppendAndReleaseAll(t *testing.T) {
	b := newHeldBuffer(0)
	const n = 500

	appenderDone := make(chan struct{})
	go func() {
		defer close(appenderDone)
		for i := 0; i < n; i++ {
			b.appendChunk([]byte{byte(i % 256)})
		}
	}()

	drainerStop := make(chan struct{})
	drainerDone := make(chan struct{})
	go func() {
		defer close(drainerDone)
		for {
			select {
			case rd := <-b.relCh:
				if len(rd.Data) == 0 {
					t.Error("received an empty release")
				}
			case <-drainerStop:
				return
			}
		}
	}()

	for i := 0; i < n; i++ {
		b.releaseAll()
	}

	<-appenderDone

	// Drain whatever's left after appends have stopped.
	for b.hasPending() {
		b.releaseAll()
	}

	close(drainerStop)
	<-drainerDone
}

func TestHeldBuffer_PerformAction_MalformedBounds(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		bounds []int
	}{
		{"non-zero first entry", []byte("abc"), []int{1}},
		{"non-increasing entries", []byte("abcdef"), []int{0, 2, 2}},
		{"out-of-range offset", []byte("abc"), []int{0, 10}},
		{"empty data with non-empty bounds", []byte{}, []int{0}},
		{"non-empty data with no bounds", []byte("abc"), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newHeldBuffer(0)
			b.appendChunk([]byte("original"))
			if b.performAction(len(b.data), c.data, c.bounds, 0, actForward) {
				t.Fatalf("expected performAction to reject malformed bounds: %s", c.name)
			}
		})
	}
}

func TestHeldBuffer_Timeout_AutoReleasesAll(t *testing.T) {
	b := newHeldBuffer(50 * time.Millisecond)
	b.appendChunk([]byte("abc"))

	recvReleased(t, b.relCh, "abc")
	if b.hasPending() {
		t.Fatal("expected buffer empty after timeout auto-release")
	}
}

func TestHeldBuffer_Timeout_ResetOnAppend(t *testing.T) {
	// Generous margins: each check-then-wait cycle below costs up to ~150ms (100ms sleep +
	// expectNoRelease's own 50ms wait), well under the 300ms timeout, so there's no risk of
	// the timer firing mid-check.
	b := newHeldBuffer(300 * time.Millisecond)
	b.appendChunk([]byte("a"))

	time.Sleep(100 * time.Millisecond)
	expectNoRelease(t, b.relCh) // shouldn't have fired yet

	b.appendChunk([]byte("b")) // resets the clock
	time.Sleep(100 * time.Millisecond)
	expectNoRelease(t, b.relCh) // still shouldn't have fired — timer was reset

	recvReleased(t, b.relCh, "ab") // now within the (reset) window
}

func TestHeldBuffer_Close(t *testing.T) {
	b := newHeldBuffer(0)
	b.appendChunk([]byte("abc"))
	b.close()

	select {
	case _, ok := <-b.relCh:
		if ok {
			t.Fatal("expected relCh to be closed, got a value instead")
		}
	case <-time.After(time.Second):
		t.Fatal("expected relCh to already be closed")
	}

	if b.releaseAll() {
		t.Fatal("expected releaseAll after close to be rejected, not send on a closed channel")
	}
	if b.performAction(0, nil, nil, 1, actForward) {
		t.Fatal("expected performAction after close to be rejected, not send on a closed channel")
	}
	if b.abort() {
		t.Fatal("expected abort after close to be rejected, not send on a closed channel")
	}
}

func TestHeldBuffer_Close_Empty(t *testing.T) {
	b := newHeldBuffer(0)
	b.close() // must not panic on an empty buffer
}
