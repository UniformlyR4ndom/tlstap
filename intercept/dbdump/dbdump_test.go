package dbdump

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
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
