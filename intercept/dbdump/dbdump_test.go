package dbdump

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"tlstap/proxy"
)

func TestEnsureColumn_AddsAndIsIdempotent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}

	if err := ensureColumn(db, "t", "extra", "INTEGER"); err != nil {
		t.Fatal(err)
	}
	// Calling again on a table that already has the column must be a no-op, not an
	// error — this is what makes it safe to call unconditionally on every startup.
	if err := ensureColumn(db, "t", "extra", "INTEGER"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.Exec(`INSERT INTO t (id, extra) VALUES (1, 42)`); err != nil {
		t.Fatalf("column should be usable after ensureColumn: %v", err)
	}
}

func TestEnsureColumn_FreshlyCreatedTable(t *testing.T) {
	// A table that never had the column at all (as opposed to one migrating from an
	// older schema) must work identically — this is the path a brand-new database file
	// takes, immediately after its own CREATE TABLE IF NOT EXISTS.
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := ensureColumn(db, "t", "extra", "INTEGER"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO t (id, extra) VALUES (1, 42)`); err != nil {
		t.Fatalf("column should be usable after ensureColumn: %v", err)
	}
}

// TestNewDbDumpInterceptor_MigratesOldFramesRangesShape confirms the pre-ranges frames
// shape (marked by its own now-gone offset column) is migrated the same way the
// pre-combined-mode frame_progress reshape already is: both frames and frame_progress
// dropped together, so a script can't end up believing it already processed bytes it now
// has no persisted frames for. Uses a real temp-file DB (not :memory:) since the test
// needs to close one connection and reopen the same file through NewDbDumpInterceptor.
func TestNewDbDumpInterceptor_MigratesOldFramesRangesShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	setup, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`
		CREATE TABLE frames (
			session INTEGER NOT NULL, stream INTEGER NOT NULL, direction INTEGER NOT NULL,
			script TEXT NOT NULL, script_version TEXT NOT NULL, id INTEGER NOT NULL,
			offset INTEGER NOT NULL, length INTEGER NOT NULL, meta TEXT,
			stid INTEGER, time INTEGER, seq INTEGER,
			PRIMARY KEY (session, stream, direction, script, script_version, id)
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`INSERT INTO frames (session, stream, direction, script, script_version, id, offset, length, meta, stid, time, seq)
		VALUES (1, 1, 0, 'foo', 'v1', 0, 0, 10, NULL, 0, 1000, 0)`); err != nil {
		t.Fatal(err)
	}
	// frame_progress already on the *current* (post-combined-mode) shape — the realistic
	// scenario for this migration specifically: a DB created after the combined-mode
	// reshape landed but before this one.
	if _, err := setup.Exec(`
		CREATE TABLE frame_progress (
			session INTEGER NOT NULL, stream INTEGER NOT NULL, script TEXT NOT NULL,
			script_version TEXT NOT NULL, processed_offset_c2s INTEGER NOT NULL DEFAULT 0,
			processed_offset_s2c INTEGER NOT NULL DEFAULT 0, state BLOB,
			closed_c2s INTEGER NOT NULL DEFAULT 0, closed_s2c INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (session, stream, script, script_version)
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`INSERT INTO frame_progress (session, stream, script, script_version, processed_offset_c2s)
		VALUES (1, 1, 'foo', 'v1', 10)`); err != nil {
		t.Fatal(err)
	}
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := NewDbDumpInterceptor(path, false, "", "", proxy.ResolvedProxyConfig{Name: "test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.db.Close() })

	hasRanges, err := columnExists(d.db, "frames", "ranges")
	if err != nil || !hasRanges {
		t.Fatalf("expected frames to have a ranges column, err=%v", err)
	}
	hasOffset, err := columnExists(d.db, "frames", "offset")
	if err != nil || hasOffset {
		t.Fatalf("expected the old offset column to be gone, err=%v", err)
	}

	var frameCount, progressCount int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM frames`).Scan(&frameCount); err != nil {
		t.Fatal(err)
	}
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM frame_progress`).Scan(&progressCount); err != nil {
		t.Fatal(err)
	}
	if frameCount != 0 || progressCount != 0 {
		t.Fatalf("expected both tables emptied by the migration, got frames=%d frame_progress=%d", frameCount, progressCount)
	}
}

// TestNewDbDumpInterceptor_MigratesOldFramesVirtualOffsetShape confirms frames lacking
// the virtual_offset bookkeeping column are migrated the same way the ranges reshape
// above is: both frames and frame_progress dropped together, since virtual_offset is a
// required, order-dependent running total that can't be sensibly backfilled for
// already-persisted frames. Starts from the *current* (post-ranges) shape specifically —
// the realistic scenario for this migration: a DB created after the ranges reshape landed
// but before this one.
func TestNewDbDumpInterceptor_MigratesOldFramesVirtualOffsetShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	setup, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`
		CREATE TABLE frames (
			session INTEGER NOT NULL, stream INTEGER NOT NULL, direction INTEGER NOT NULL,
			script TEXT NOT NULL, script_version TEXT NOT NULL, id INTEGER NOT NULL,
			ranges TEXT NOT NULL, meta TEXT,
			stid INTEGER, time INTEGER, seq INTEGER,
			PRIMARY KEY (session, stream, direction, script, script_version, id)
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`INSERT INTO frames (session, stream, direction, script, script_version, id, ranges, meta, stid, time, seq)
		VALUES (1, 1, 0, 'foo', 'v1', 0, '[{"offset":0,"length":10}]', NULL, 0, 1000, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`
		CREATE TABLE frame_progress (
			session INTEGER NOT NULL, stream INTEGER NOT NULL, script TEXT NOT NULL,
			script_version TEXT NOT NULL, processed_offset_c2s INTEGER NOT NULL DEFAULT 0,
			processed_offset_s2c INTEGER NOT NULL DEFAULT 0, state BLOB,
			closed_c2s INTEGER NOT NULL DEFAULT 0, closed_s2c INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (session, stream, script, script_version)
		)`); err != nil {
		t.Fatal(err)
	}
	if _, err := setup.Exec(`INSERT INTO frame_progress (session, stream, script, script_version, processed_offset_c2s)
		VALUES (1, 1, 'foo', 'v1', 10)`); err != nil {
		t.Fatal(err)
	}
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	d, err := NewDbDumpInterceptor(path, false, "", "", proxy.ResolvedProxyConfig{Name: "test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.db.Close() })

	hasVirtualOffset, err := columnExists(d.db, "frames", "virtual_offset")
	if err != nil || !hasVirtualOffset {
		t.Fatalf("expected frames to have a virtual_offset column, err=%v", err)
	}
	hasVirtualLength, err := columnExists(d.db, "frame_progress", "virtual_length_c2s")
	if err != nil || !hasVirtualLength {
		t.Fatalf("expected frame_progress to have a virtual_length_c2s column, err=%v", err)
	}

	var frameCount, progressCount int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM frames`).Scan(&frameCount); err != nil {
		t.Fatal(err)
	}
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM frame_progress`).Scan(&progressCount); err != nil {
		t.Fatal(err)
	}
	if frameCount != 0 || progressCount != 0 {
		t.Fatalf("expected both tables emptied by the migration, got frames=%d frame_progress=%d", frameCount, progressCount)
	}
}
