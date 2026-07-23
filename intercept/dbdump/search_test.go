package dbdump

import (
	"database/sql"
	"math"
	"os"
	"regexp"
	"testing"

	_ "modernc.org/sqlite"
)

// setupDB creates an in-memory SQLite DB with the dbdump schema and returns a
// DbDumpInterceptor backed by it.
func setupDB(t *testing.T) *DbDumpInterceptor {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	schema := `
		CREATE TABLE sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, start INTEGER, config TEXT);
		CREATE TABLE stream  (id INTEGER, session INTEGER, src TEXT, dst TEXT, start INTEGER, end INTEGER, PRIMARY KEY (session, id));
		CREATE TABLE chunks  (
			id INTEGER, stream INTEGER, session INTEGER, direction INTEGER,
			offset INTEGER, time INTEGER, data BLOB, sgid INTEGER, stid INTEGER,
			PRIMARY KEY (session, stream, direction, id)
		);
		CREATE INDEX idx_chunks_sgid ON chunks (session, sgid);
		CREATE INDEX idx_chunks_stid ON chunks (session, stream, stid);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}

	return &DbDumpInterceptor{db: db}
}

// insertChunk adds one chunk row; session and stream default to 1.
func insertChunk(t *testing.T, db *sql.DB, session, stream, direction, id int64, offset int64, stid int64, data []byte) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO chunks (session, stream, direction, id, offset, time, data, sgid, stid)
		 VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?)`,
		session, stream, direction, id, offset, data, stid,
	)
	if err != nil {
		t.Fatal(err)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func matchOffsets(ms []searchMatch) []int64 {
	out := make([]int64, len(ms))
	for i, m := range ms {
		out[i] = m.Offset
	}
	return out
}

func matchStids(ms []searchMatch) []int64 {
	out := make([]int64, len(ms))
	for i, m := range ms {
		out[i] = m.Stid
	}
	return out
}

// ── non-contiguous tests ──────────────────────────────────────────────────────

func TestSearchNonContiguous_BasicMatch(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("GET /index HTTP"))
	ms, err := d.searchNonContiguous(1, 1, 0, literalFinder([]byte("index")), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	// "GET /index HTTP": G=0 E=1 T=2 ' '=3 /=4 i=5 ...
	if len(ms) != 1 || ms[0].Offset != 5 {
		t.Fatalf("expected match at 5, got %v", matchOffsets(ms))
	}
}

func TestSearchNonContiguous_MultipleMatchesSameChunk(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("abcabcabc"))
	ms, err := d.searchNonContiguous(1, 1, 0, literalFinder([]byte("abc")), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	got := matchOffsets(ms)
	want := []int64{0, 3, 6}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestSearchNonContiguous_OverlappingPattern(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("aaaa"))
	ms, err := d.searchNonContiguous(1, 1, 0, literalFinder([]byte("aa")), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	got := matchOffsets(ms)
	want := []int64{0, 1, 2}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestSearchNonContiguous_CrossChunkNotFound(t *testing.T) {
	d := setupDB(t)
	// "HE" in chunk 0, "LLO" in chunk 1 — non-contiguous should NOT find "HELLO"
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("HE"))
	insertChunk(t, d.db, 1, 1, 0, 1, 2, 11, []byte("LLO"))
	ms, err := d.searchNonContiguous(1, 1, 0, literalFinder([]byte("HELLO")), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 0 {
		t.Fatalf("expected no matches, got %v", ms)
	}
}

func TestSearchNonContiguous_StartEndBound(t *testing.T) {
	d := setupDB(t)
	// pattern "ab" at offsets 0, 4, 8
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("ab__ab__ab"))
	ms, err := d.searchNonContiguous(1, 1, 0, literalFinder([]byte("ab")), 4, 9)
	if err != nil {
		t.Fatal(err)
	}
	got := matchOffsets(ms)
	// offset 0 is before start=4; offset 8 ends at 10 which is past end=9
	want := []int64{4}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSearchNonContiguous_StidAttribution(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 42, []byte("hello"))
	insertChunk(t, d.db, 1, 1, 0, 1, 5, 43, []byte("world"))
	ms, err := d.searchNonContiguous(1, 1, 0, literalFinder([]byte("world")), 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Stid != 43 || ms[0].Offset != 5 {
		t.Fatalf("unexpected match: %+v", ms)
	}
}

// ── contiguous tests ──────────────────────────────────────────────────────────

func TestSearchContiguous_BasicMatch(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("GET /index HTTP"))
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("index")), len("index")-1, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	// "GET /index HTTP": G=0 E=1 T=2 ' '=3 /=4 i=5 ...
	if len(ms) != 1 || ms[0].Offset != 5 {
		t.Fatalf("expected match at 5, got %v", matchOffsets(ms))
	}
}

func TestSearchContiguous_CrossChunkMatch(t *testing.T) {
	d := setupDB(t)
	// "HELLO" split: "HEL" in chunk 0 (stid=10), "LO" in chunk 1 (stid=11)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("...HEL"))
	insertChunk(t, d.db, 1, 1, 0, 1, 6, 11, []byte("LO..."))
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("HELLO")), len("HELLO")-1, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %v", ms)
	}
	if ms[0].Offset != 3 {
		t.Fatalf("expected offset 3, got %d", ms[0].Offset)
	}
	// The 'H' is in chunk 0 (stid=10)
	if ms[0].Stid != 10 {
		t.Fatalf("expected stid 10, got %d", ms[0].Stid)
	}
}

func TestSearchContiguous_CrossBatchMatch(t *testing.T) {
	d := setupDB(t)
	// Fill a large chunk to force a batch boundary, then split pattern across it.
	bigData := make([]byte, searchBatchSize)
	copy(bigData[searchBatchSize-3:], []byte("HEL"))
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 20, bigData)
	insertChunk(t, d.db, 1, 1, 0, 1, int64(searchBatchSize), 21, []byte("LO_world"))
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("HELLO")), len("HELLO")-1, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 cross-batch match, got %d: %v", len(ms), ms)
	}
	wantOff := int64(searchBatchSize - 3)
	if ms[0].Offset != wantOff {
		t.Fatalf("expected offset %d, got %d", wantOff, ms[0].Offset)
	}
	// 'H' is in the big chunk (stid=20)
	if ms[0].Stid != 20 {
		t.Fatalf("expected stid 20, got %d", ms[0].Stid)
	}
}

func TestSearchContiguous_RegexCrossBatchWithinOverlap(t *testing.T) {
	d := setupDB(t)
	// Split "HELLO" 3 bytes before the batch boundary — well within regexOverlapSize
	// (4 KB) of it, so the fixed regex overlap should still catch it.
	bigData := make([]byte, searchBatchSize)
	copy(bigData[searchBatchSize-3:], []byte("HEL"))
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 20, bigData)
	insertChunk(t, d.db, 1, 1, 0, 1, int64(searchBatchSize), 21, []byte("LO_world"))

	re := regexp.MustCompile("HELLO")
	ms, err := d.searchContiguous(1, 1, 0, regexFinder(re), regexOverlapSize, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 cross-batch match, got %d: %v", len(ms), ms)
	}
	wantOff := int64(searchBatchSize - 3)
	if ms[0].Offset != wantOff {
		t.Fatalf("expected offset %d, got %d", wantOff, ms[0].Offset)
	}
	if ms[0].Stid != 20 {
		t.Fatalf("expected stid 20, got %d", ms[0].Stid)
	}
}

func TestSearchContiguous_CrossBatchMatchSecondChunk(t *testing.T) {
	d := setupDB(t)
	// Pattern starts in the second batch's data (not in the overlap).
	bigData := make([]byte, searchBatchSize)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 20, bigData)
	insertChunk(t, d.db, 1, 1, 0, 1, int64(searchBatchSize), 21, []byte("__HELLO__"))
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("HELLO")), len("HELLO")-1, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("expected 1 match, got %v", ms)
	}
	wantOff := int64(searchBatchSize) + 2
	if ms[0].Offset != wantOff {
		t.Fatalf("expected offset %d, got %d", wantOff, ms[0].Offset)
	}
	if ms[0].Stid != 21 {
		t.Fatalf("expected stid 21, got %d", ms[0].Stid)
	}
}

func TestSearchContiguous_StartBoundExcludesEarlyMatch(t *testing.T) {
	d := setupDB(t)
	// Two matches: one before start, one after.
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("ab__ab"))
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("ab")), len("ab")-1, 3, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].Offset != 4 {
		t.Fatalf("expected only match at 4, got %v", matchOffsets(ms))
	}
}

func TestSearchContiguous_EndBound(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("ab__ab__ab"))
	// end=4: search window is [0,4); "ab" at 0 fits, "ab" at 4 is excluded
	// (the match starting at 4 starts at offset 4 which is == end, not < end).
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("ab")), len("ab")-1, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	got := matchOffsets(ms)
	want := []int64{0}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("want %v, got %v", want, got)
	}
}

func TestSearchContiguous_SingleBytePattern(t *testing.T) {
	d := setupDB(t)
	insertChunk(t, d.db, 1, 1, 0, 0, 0, 10, []byte("aXaXa"))
	ms, err := d.searchContiguous(1, 1, 0, literalFinder([]byte("a")), len("a")-1, 0, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 {
		t.Fatalf("expected 3 matches, got %v", matchOffsets(ms))
	}
}

// TestMain satisfies the test binary's need for a working directory.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
