// Package kv implements core/kv's storage layer: a general-purpose, opaque key-value
// store backed by its own SQLite database, independent of any interceptor. See
// doc/design/core-kv-store.md for the full design and rationale.
package kv

import (
	"database/sql"
	"errors"
	"fmt"

	_ "modernc.org/sqlite"
)

const (
	maxKeyBytes   = 256     // enforced in Write; Read/Delete/List have no such limit to check
	maxValueBytes = 1 << 20 // 1 MiB
	busyTimeoutMs = 5000    // see New's PRAGMA busy_timeout call
)

// ErrKeyTooLong and ErrValueTooLarge are returned by Write when key/value exceed
// maxKeyBytes/maxValueBytes; wrap with errors.Is to distinguish them from other errors
// (e.g. to map onto a 400 response once this is wired into a REST handler).
var (
	ErrKeyTooLong    = errors.New("key exceeds maximum length")
	ErrValueTooLarge = errors.New("value exceeds maximum size")
)

type Store struct {
	db *sql.DB
}

// New opens (creating if needed) the SQLite file at path and ensures core_kv's schema
// exists.
func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Serialize all access through a single connection, same reasoning as dbdump's own
	// (intercept/dbdump/dbdump.go) — avoids SQLite locking errors among this store's own
	// concurrent callers (one goroutine per in-flight REST request, once wired up).
	db.SetMaxOpenConns(1)

	if _, err = db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, err
	}

	// Lets a write wait for a concurrent writer to finish instead of failing immediately —
	// needed if this file happens to be shared with e.g. a dbdump instance's own database;
	// see doc/design/core-kv-store.md's "Coexistence with dbdump's own database" section.
	if _, err = db.Exec(fmt.Sprintf(`PRAGMA busy_timeout=%d`, busyTimeoutMs)); err != nil {
		return nil, err
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS core_kv (
			key   TEXT PRIMARY KEY,
			value BLOB NOT NULL
		)
	`); err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// Read returns key's stored value, or found=false if key doesn't exist.
func (s *Store) Read(key string) (value []byte, found bool, err error) {
	err = s.db.QueryRow(`SELECT value FROM core_kv WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// Write stores value under key, creating or overwriting it. Both key and value are
// opaque — never parsed, validated, or interpreted beyond the size limits below. A nil
// value is stored the same as an empty one (the column is NOT NULL).
func (s *Store) Write(key string, value []byte) error {
	if len(key) > maxKeyBytes {
		return ErrKeyTooLong
	}
	if len(value) > maxValueBytes {
		return ErrValueTooLarge
	}
	if value == nil {
		value = []byte{}
	}
	_, err := s.db.Exec(
		`INSERT INTO core_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	return err
}

// Delete removes key. Idempotent — not an error if key doesn't exist.
func (s *Store) Delete(key string) error {
	_, err := s.db.Exec(`DELETE FROM core_kv WHERE key = ?`, key)
	return err
}

// List returns every key with the given byte prefix, sorted ascending. An empty prefix
// returns every key.
func (s *Store) List(prefix string) ([]string, error) {
	var rows *sql.Rows
	var err error
	switch {
	case prefix == "":
		rows, err = s.db.Query(`SELECT key FROM core_kv ORDER BY key`)
	default:
		if upper, ok := prefixUpperBound(prefix); ok {
			rows, err = s.db.Query(`SELECT key FROM core_kv WHERE key >= ? AND key < ? ORDER BY key`, prefix, upper)
		} else {
			rows, err = s.db.Query(`SELECT key FROM core_kv WHERE key >= ? ORDER BY key`, prefix)
		}
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// prefixUpperBound computes the smallest exclusive upper bound U such that
// {K : K has byte-prefix prefix} == {K : prefix <= K < U}, given SQLite's default
// BINARY (byte-lexicographic) collation on TEXT — or ok=false if prefix consists
// entirely of 0xFF bytes, which has no finite byte-string upper bound (List falls back
// to an unbounded "key >= prefix" scan in that case).
func prefixUpperBound(prefix string) (string, bool) {
	b := []byte(prefix)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0xFF {
			b[i]++
			return string(b[:i+1]), true
		}
	}
	return "", false
}
