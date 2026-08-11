package dbdump

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"tlstap/intercept/scriptstore"
	"tlstap/logging"
	"tlstap/proxy"

	_ "modernc.org/sqlite"
)

const (
	bufFlushSize = 2 * 1024 * 1024  // 2 MB: signal the flush goroutine for an early flush
	bufMaxSize   = 16 * 1024 * 1024 // 16 MB: hard cap; Intercept blocks until buffer is drained
)

const (
	directionC2S = 0 // client -> server direction
	directionS2C = 1 // server -> client direction
)

// chunkRecord holds all fields needed for one deferred INSERT INTO chunks.
type chunkRecord struct {
	id        int64
	streamID  uint32
	sessionID int64
	direction int
	offset    int64
	timestamp int64
	data      []byte
	sgid      int64
	stid      int64
}

type DbDumpConfig struct {
	FilePath string `json:"file"`
	Truncate bool   `json:"truncate"`

	// Directory framer scripts are stored in and served from, via the shared
	// intercept/scriptstore package (same feature tamper's control scripts use). Empty
	// disables the feature entirely — the REST endpoints still exist but reject every
	// request with 501, rather than silently defaulting to an implicit directory.
	ScriptsDir string `json:"scripts-dir"`

	// Directory dissector scripts (doc/design/packet-dissector.md) are stored in and
	// served from — a separate scriptstore.Store/directory from ScriptsDir above, not a
	// shared namespace with framer scripts. Same empty-disables-with-501 convention.
	DissectScriptsDir string `json:"dissect-scripts-dir"`
}

// sessionConfig is the JSON snapshot written to sessions.config on first traffic.
type sessionConfig struct {
	Name         string                 `json:"name"`
	Listen       string                 `json:"listen"`
	Connect      *string                `json:"connect,omitempty"`
	Mode         string                 `json:"mode"`
	Server       *proxy.TlsServerConfig `json:"server,omitempty"`
	Client       *proxy.TlsClientConfig `json:"client,omitempty"`
	Interceptors []interceptorInfo      `json:"interceptors,omitempty"`
}

type interceptorInfo struct {
	Name      string         `json:"name"`
	Direction string         `json:"direction,omitempty"`
	Args      map[string]any `json:"args,omitempty"`
}

// chunkKey identifies the per-(stream, direction) counters.
type chunkKey struct {
	streamID  uint32
	direction int
}

// chunkState tracks the next chunk ID and the running byte offset for one (stream, direction).
type chunkState struct {
	id     int64
	offset int64
}

// pendingStream holds the arguments for a stream row that is buffered until the
// first chunk of traffic arrives and the session row can be created.
type pendingStream struct {
	id  uint32
	src string
	dst string
	at  int64

	// sni/alpn/tlsVersion/cipherSuite are filled in by ConnectionUpgraded if it fires
	// before the session is created — nil/unset (and so NULL once flushed) for a
	// connection that either isn't TLS or hasn't upgraded yet.
	sni         *string
	alpn        *string
	tlsVersion  *int64
	cipherSuite *int64
}

// DbDumpInterceptor logs all traffic into an SQLite database.
//
// Schema:
//
//	sessions(id, start, config)
//	stream(id, session, src, dst, start, end)
//	chunks(id, stream, direction, offset, time, data)  PK: (stream, direction, id)
//	frames(session, stream, direction, script, script_version, id, offset, length, meta, seq)
//	  PK: (session, stream, direction, script, script_version, id)
//	frame_progress(session, stream, script, script_version, processed_offset_c2s,
//	  processed_offset_s2c, state, closed_c2s, closed_s2c)
//	  PK: (session, stream, script, script_version)
//
// Timestamps are milliseconds since the Unix epoch.
// stream.id equals the proxy's connection counter (ConnID).
// chunks.stream is a foreign key into stream.
// chunks.direction: 0 = client→server, 1 = server→client.
// chunks.id starts at 0 and increments independently per (stream, direction).
// chunks.offset is the byte offset of the chunk's first byte, independently per (stream, direction).
// frames/frame_progress are the persisted output of a client-run framer script (see
// frames.go); script_version is a sha256 hex digest of the script's content, computed
// client-side, so a content change is simply a different (and initially absent) key
// rather than something that needs explicit staleness detection.
type DbDumpInterceptor struct {
	filePath       string
	truncate       bool
	proxyConfig    proxy.ResolvedProxyConfig
	db             *sql.DB
	scripts        *scriptstore.Store // nil if ScriptsDir wasn't configured
	dissectScripts *scriptstore.Store // nil if DissectScriptsDir wasn't configured
	sessionID      int64              // valid only after ensureSession succeeds

	// Lazy session creation: the session row (and buffered stream rows) are only
	// written to the DB on the first Intercept call, so idle runs leave no trace.
	sessionOnce    sync.Once
	sessionErr     error           // cached error from the first ensureSession attempt
	sessionCreated bool            // true once the session row exists; guarded by mu
	sessionStart   int64           // set in Init, consumed by ensureSession
	pendingConfig  string          // set in Init, consumed by ensureSession
	pendingStreams []pendingStream // guarded by mu; flushed by ensureSession

	// clientEndpoints maps ConnID → client endpoint to derive direction in Intercept.
	// chunkStates tracks the next chunk ID and byte offset per (stream, direction).
	// streamNextSTID tracks the next stream-local chunk ID (direction-agnostic) per ConnID.
	// pendingChunks / pendingSize are the async write buffer.
	// All are protected by mu.
	clientEndpoints map[uint32]string
	chunkStates     map[chunkKey]chunkState
	streamNextSTID  map[uint32]int64
	nextSGID        int64
	streamsVersion  int64 // bumped whenever a stream row is inserted or its end is set; cheap "did the stream list change" check
	pendingChunks   []chunkRecord
	pendingSize     int
	mu              sync.RWMutex
	cond            *sync.Cond // tied to mu's write lock; used to block Intercept when buffer is full

	// flushCh receives a signal when pendingSize crosses bufFlushSize (early flush).
	// stopCh is closed by Finalize to trigger a final flush and goroutine exit.
	// flushDone is closed by the goroutine once it has exited.
	flushCh   chan struct{}
	stopCh    chan struct{}
	flushDone chan struct{}

	logger *logging.Logger
}

// NewDbDumpInterceptor opens (creating if needed) the SQLite file at path and
// ensures its schema exists. Done here rather than in Init so that RegisterRoutes'
// API handlers, wired up synchronously right after this returns, never see a nil
// or partially-schema'd i.db — Init itself runs later, asynchronously, from the
// proxy's own start goroutine. No session/stream/chunk row is written here; that
// stays deferred to the first Intercept call (see ensureSession). If scriptsDir/
// dissectScriptsDir is set, that scripts directory (including any missing parents) is
// also created here, for the same "must be usable the moment RegisterRoutes runs" reason.
func NewDbDumpInterceptor(path string, truncate bool, scriptsDir, dissectScriptsDir string, proxyConfig proxy.ResolvedProxyConfig, logger *logging.Logger) (*DbDumpInterceptor, error) {
	if truncate {
		_ = os.Remove(path)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Serialize all writes through a single connection to avoid SQLite locking errors.
	db.SetMaxOpenConns(1)

	if _, err = db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, err
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id     INTEGER PRIMARY KEY AUTOINCREMENT,
			start  INTEGER NOT NULL,
			config TEXT    NOT NULL
		)
	`); err != nil {
		return nil, err
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS stream (
			id      INTEGER NOT NULL,
			session INTEGER NOT NULL REFERENCES sessions(id),
			src     TEXT    NOT NULL,
			dst     TEXT    NOT NULL,
			start   INTEGER NOT NULL,
			end     INTEGER,
			PRIMARY KEY (session, id)
		)
	`); err != nil {
		return nil, err
	}

	// sni/alpn/tls_version/cipher_suite added after stream first shipped, via
	// ensureColumn like frame_progress.closed above — all nullable, since a plain
	// connection (or a detecttls one that never upgrades) has none of them. Captured
	// once per connection from the downstream (client-facing) TLS handshake — see
	// ConnectionUpgraded — never the proxy's separate upstream one, which can legitimately
	// negotiate differently without ALPN/SNI passthrough.
	for _, col := range []string{"sni", "alpn"} {
		if err = ensureColumn(db, "stream", col, "TEXT"); err != nil {
			return nil, err
		}
	}
	for _, col := range []string{"tls_version", "cipher_suite"} {
		if err = ensureColumn(db, "stream", col, "INTEGER"); err != nil {
			return nil, err
		}
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS chunks (
			id        INTEGER NOT NULL,
			stream    INTEGER NOT NULL,
			session   INTEGER NOT NULL REFERENCES sessions(id),
			direction INTEGER NOT NULL,
			offset    INTEGER NOT NULL,
			time      INTEGER NOT NULL,
			data      BLOB    NOT NULL,
			sgid      INTEGER NOT NULL,
			stid      INTEGER NOT NULL,
			PRIMARY KEY (session, stream, direction, id)
		)
	`); err != nil {
		return nil, err
	}

	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_chunks_sgid ON chunks (session, sgid)
	`); err != nil {
		return nil, err
	}

	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_chunks_stid ON chunks (session, stream, stid)
	`); err != nil {
		return nil, err
	}

	// Migrates the pre-combined-mode frame_progress shape (marked by its own now-gone
	// direction column) by dropping both frames and frame_progress together, rather than
	// altering either in place — frame data is a purgeable/regenerable cache (the same
	// reasoning clearStreamFrames already relies on), and leaving stale pre-migration
	// frames rows in place while frame_progress resets to processed_offset 0 would desync
	// the two (duplicate frames on the next run) and leave frames.seq — introduced in the
	// same reshape — unpopulated for them. A no-op (both queries return false) for a
	// fresh database or one already on the new shape.
	oldShape, err := columnExists(db, "frame_progress", "direction")
	if err != nil {
		return nil, err
	}
	if oldShape {
		if _, err = db.Exec(`DROP TABLE frames`); err != nil {
			return nil, err
		}
		if _, err = db.Exec(`DROP TABLE frame_progress`); err != nil {
			return nil, err
		}
	}

	// The PK's own btree is already ordered (session, stream, direction, script,
	// script_version, id), which is exactly the per-direction access pattern
	// listFrames/appendFrames need (equality filter on the first five columns, ordered
	// range on id) — no extra index needed for that. idx_frames_stid below is for the
	// separate cross-direction access pattern (listFramesTimeline).
	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS frames (
			session        INTEGER NOT NULL REFERENCES sessions(id),
			stream         INTEGER NOT NULL,
			direction      INTEGER NOT NULL,
			script         TEXT    NOT NULL,
			script_version TEXT    NOT NULL,
			id             INTEGER NOT NULL,
			offset         INTEGER NOT NULL,
			length         INTEGER NOT NULL,
			meta           TEXT,
			PRIMARY KEY (session, stream, direction, script, script_version, id)
		)
	`); err != nil {
		return nil, err
	}

	// stid added after frames first shipped, via ALTER rather than the CREATE TABLE
	// above (a no-op on an already-existing table) — see ensureColumn. Inherited from
	// whichever raw chunk a frame completes on; ties (multiple frames from one chunk)
	// are routine, not an edge case, so every access ordered by stid must break ties by
	// id (see listFramesTimeline) — never bare `ORDER BY stid`.
	if err = ensureColumn(db, "frames", "stid", "INTEGER"); err != nil {
		return nil, err
	}

	// time added the same way and for the same reason as stid above — a frame has no
	// timestamp of its own (frames aren't captured, they're computed), so it's inherited
	// from the same completing chunk stid is inherited from.
	if err = ensureColumn(db, "frames", "time", "INTEGER"); err != nil {
		return nil, err
	}

	// seq added the same way, for combined-mode's per-frame emission order: a single
	// counter per (session, stream, script, script_version) — deliberately no direction
	// column in its own scope, unlike id — assigned in appendFrames as
	// MAX(seq)+1-continuing, in newFrames' own array order. That order is exactly
	// whatever order a combined-mode script chose to return each frame in, spanning both
	// directions — e.g. a script that holds a fully-parsed request frame in state until
	// its response completes, then returns both together, produces a request-then-
	// response seq order even though the request's own stid may be earlier than an
	// intervening, unrelated frame's. Unlike stid, seq is unique per key by construction
	// (a bare counter, not derived from any shared chunk), so no tie-break/group-boundary
	// pagination logic is needed for it the way stid needs via id. Not yet surfaced in
	// any UI — see listFramesBySeq/listFramesBySeqBackward and web/CLAUDE.md's "Framer
	// scripts" section.
	if err = ensureColumn(db, "frames", "seq", "INTEGER"); err != nil {
		return nil, err
	}

	// Backs listFramesTimeline's cross-direction query (session/stream/script/version
	// filter, ordered by stid then id) — the frames table has no direction-less index
	// otherwise, since every other access pattern here filters by direction too.
	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_frames_stid ON frames (session, stream, script, script_version, stid, id)
	`); err != nil {
		return nil, err
	}

	// Backs listFramesBySeq/listFramesBySeqBackward, the seq-ordered counterpart to
	// idx_frames_stid above.
	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_frames_seq ON frames (session, stream, script, script_version, seq)
	`); err != nil {
		return nil, err
	}

	// No direction column (unlike the pre-combined-mode shape this replaces, migrated
	// above): a combined-mode script run tracks both directions' progress/closed state
	// at once, in one shared state value, so one row per (session, stream, script,
	// script_version) is the natural key — see doc/design/framer-cross-direction-
	// correlation.md.
	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS frame_progress (
			session               INTEGER NOT NULL REFERENCES sessions(id),
			stream                INTEGER NOT NULL,
			script                TEXT    NOT NULL,
			script_version        TEXT    NOT NULL,
			processed_offset_c2s  INTEGER NOT NULL DEFAULT 0,
			processed_offset_s2c  INTEGER NOT NULL DEFAULT 0,
			state                 BLOB,
			closed_c2s            INTEGER NOT NULL DEFAULT 0,
			closed_s2c            INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (session, stream, script, script_version)
		)
	`); err != nil {
		return nil, err
	}

	var scripts *scriptstore.Store
	if scriptsDir != "" {
		scripts, err = scriptstore.New(scriptsDir)
		if err != nil {
			return nil, err
		}
	}

	var dissectScripts *scriptstore.Store
	if dissectScriptsDir != "" {
		dissectScripts, err = scriptstore.New(dissectScriptsDir)
		if err != nil {
			return nil, err
		}
	}

	return &DbDumpInterceptor{
		filePath:        path,
		truncate:        truncate,
		proxyConfig:     proxyConfig,
		db:              db,
		scripts:         scripts,
		dissectScripts:  dissectScripts,
		clientEndpoints: make(map[uint32]string),
		chunkStates:     make(map[chunkKey]chunkState),
		streamNextSTID:  make(map[uint32]int64),
		logger:          logger,
	}, nil
}

// ensureColumn adds column to table via ALTER TABLE if it isn't already present,
// idempotently — this codebase has no migration system beyond "CREATE TABLE/INDEX IF
// NOT EXISTS" (which is a no-op on a table that already exists, columns and all, so it
// can't retroactively add a column to a database file created before that column
// existed). Safe to call on a table that was just freshly CREATE TABLE IF NOT EXISTS'd
// too — PRAGMA table_info simply won't find the column yet in that case either, and the
// ALTER adds it, so callers don't need to know or care which case they're in.
func ensureColumn(db *sql.DB, table, column, ddlType string) error {
	exists, err := columnExists(db, table, column)
	if err != nil || exists {
		return err
	}
	_, err = db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, ddlType))
	return err
}

// columnExists reports whether table has column, via PRAGMA table_info — false, nil for
// a table that doesn't exist yet (an empty result set, not an error), which is exactly
// what a caller migrating a not-yet-created table wants.
func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (i *DbDumpInterceptor) Init(addr net.TCPAddr) error {
	cfgJSON, err := i.marshalConfig()
	if err != nil {
		return err
	}

	// Store session metadata for lazy insertion on first traffic.
	i.sessionStart = time.Now().UnixMilli()
	i.pendingConfig = cfgJSON

	i.cond = sync.NewCond(&i.mu)
	i.flushCh = make(chan struct{}, 1)
	i.stopCh = make(chan struct{})
	i.flushDone = make(chan struct{})
	go i.flushLoop()
	return nil
}

func (i *DbDumpInterceptor) marshalConfig() (string, error) {
	iInfos := make([]interceptorInfo, len(i.proxyConfig.Interceptors))
	for j, ic := range i.proxyConfig.Interceptors {
		iInfos[j] = interceptorInfo{
			Name:      ic.Name,
			Direction: ic.Direction,
			Args:      ic.Args,
		}
	}

	cfg := sessionConfig{
		Name:         i.proxyConfig.Name,
		Listen:       i.proxyConfig.ListenEndpoint,
		Connect:      i.proxyConfig.ConnectEndpoint,
		Mode:         i.proxyConfig.Mode,
		Server:       i.proxyConfig.Server,
		Client:       i.proxyConfig.Client,
		Interceptors: iInfos,
	}

	b, err := json.Marshal(cfg)
	return string(b), err
}

// ensureSession inserts the session row and flushes all buffered stream rows on
// the first call. Subsequent calls are no-ops and return the cached result.
// mu must NOT be held by the caller.
func (i *DbDumpInterceptor) ensureSession() error {
	i.sessionOnce.Do(func() {
		result, err := i.db.Exec(
			`INSERT INTO sessions (start, config) VALUES (?, ?)`,
			i.sessionStart, i.pendingConfig,
		)
		if err != nil {
			i.sessionErr = err
			return
		}
		id, err := result.LastInsertId()
		if err != nil {
			i.sessionErr = err
			return
		}

		// Flush pending stream rows while holding mu so that concurrent callers see
		// a consistent sessionCreated state only after all rows are in the DB.
		i.mu.Lock()
		defer i.mu.Unlock()
		for _, ps := range i.pendingStreams {
			result, err := i.db.Exec(
				`INSERT OR IGNORE INTO stream (id, session, src, dst, start, sni, alpn, tls_version, cipher_suite)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				ps.id, id, ps.src, ps.dst, ps.at, ps.sni, ps.alpn, ps.tlsVersion, ps.cipherSuite,
			)
			if err != nil {
				i.logger.Error("dbdump: flush pending stream %d: %v", ps.id, err)
				continue
			}
			// ConnectionEstablished is called once per direction, so a same-ConnID entry can
			// appear here twice; OR IGNORE makes the second INSERT a no-op (RowsAffected == 0).
			if n, _ := result.RowsAffected(); n > 0 {
				i.streamsVersion++
			}
		}
		i.pendingStreams = nil
		i.sessionID = id
		i.sessionCreated = true
	})
	return i.sessionErr
}

func (i *DbDumpInterceptor) Finalize(addr net.TCPAddr) {
	if i.stopCh != nil {
		close(i.stopCh)
		<-i.flushDone
	}
	if i.db != nil {
		i.db.Close()
	}
}

// ConnectionEstablished is called once per direction for "any" interceptors. The first call
// arrives with src=client, dst=server (upstream direction), which is what we record.
// INSERT OR IGNORE silently drops the second call (src=server, dst=client).
func (i *DbDumpInterceptor) ConnectionEstablished(info *proxy.ConnInfo) error {
	i.mu.Lock()
	if _, exists := i.clientEndpoints[info.ConnID]; !exists {
		i.clientEndpoints[info.ConnID] = info.SrcEndpoint
	}
	if !i.sessionCreated {
		i.pendingStreams = append(i.pendingStreams, pendingStream{
			id:  info.ConnID,
			src: info.SrcEndpoint,
			dst: info.DstEndpoint,
			at:  time.Now().UnixMilli(),
		})
		i.mu.Unlock()
		return nil
	}
	i.mu.Unlock()

	result, err := i.db.Exec(
		`INSERT OR IGNORE INTO stream (id, session, src, dst, start) VALUES (?, ?, ?, ?, ?)`,
		info.ConnID, i.sessionID, info.SrcEndpoint, info.DstEndpoint, time.Now().UnixMilli(),
	)
	if err != nil {
		return err
	}
	// Called once per direction; only the call that actually inserted the row
	// (RowsAffected == 1) should count as a stream-list change — OR IGNORE makes the
	// other call's INSERT a no-op.
	if n, _ := result.RowsAffected(); n > 0 {
		i.mu.Lock()
		i.streamsVersion++
		i.mu.Unlock()
	}
	return nil
}

// ConnectionUpgraded captures the downstream TLS handshake's SNI/ALPN/version/cipher
// suite into stream once (info.TLS is nil for a plain connection). Called once per
// direction with identical info.TLS; the second call is a harmless no-op — the
// pendingStreams path (below) always ends up with the same values from either call, and
// the direct-UPDATE path's own WHERE guard makes its second call's write affect 0 rows.
func (i *DbDumpInterceptor) ConnectionUpgraded(info *proxy.ConnInfo) error {
	if info.TLS == nil {
		return nil
	}

	sni, alpn := info.TLS.SNI, info.TLS.ALPN
	var sniPtr, alpnPtr *string
	if sni != "" {
		sniPtr = &sni
	}
	if alpn != "" {
		alpnPtr = &alpn
	}
	version, cipherSuite := int64(info.TLS.Version), int64(info.TLS.CipherSuite)

	i.mu.Lock()
	if !i.sessionCreated {
		// ConnectionEstablished (both directions) always completes before
		// ConnectionUpgraded (either direction) begins, in every proxy mode — so both of
		// this ConnID's pendingStreams entries (one per direction — see
		// ConnectionEstablished's own doc comment on why there can be two) already exist
		// here. Set on both: ensureSession's flush INSERT OR IGNORE only keeps whichever
		// is enumerated first, so leaving the other's TLS fields unset would risk losing
		// them if that happened to be the "wrong" one.
		for j := range i.pendingStreams {
			if i.pendingStreams[j].id == info.ConnID {
				i.pendingStreams[j].sni, i.pendingStreams[j].alpn = sniPtr, alpnPtr
				i.pendingStreams[j].tlsVersion, i.pendingStreams[j].cipherSuite = &version, &cipherSuite
			}
		}
		i.mu.Unlock()
		return nil
	}
	i.mu.Unlock()

	// tls_version IS NULL guards against this connection's second ConnectionUpgraded
	// call (same info.TLS) re-triggering the streamsVersion bump below.
	result, err := i.db.Exec(
		`UPDATE stream SET sni = ?, alpn = ?, tls_version = ?, cipher_suite = ?
		 WHERE session = ? AND id = ? AND tls_version IS NULL`,
		sniPtr, alpnPtr, version, cipherSuite, i.sessionID, info.ConnID,
	)
	if err != nil {
		return err
	}
	// Matters most for detecttls, where this fires well after ConnectionEstablished
	// (mid-connection, once the Client Hello is seen) — without the bump, a frontend
	// already polling wouldn't know to refetch /streams until some other event (e.g. the
	// stream closing) happened to bump it anyway.
	if n, _ := result.RowsAffected(); n > 0 {
		i.mu.Lock()
		i.streamsVersion++
		i.mu.Unlock()
	}
	return nil
}

// ConnectionTerminated is called once per direction; the WHERE guard ensures only the first call writes.
func (i *DbDumpInterceptor) ConnectionTerminated(info *proxy.ConnInfo) error {
	i.mu.Lock()
	delete(i.clientEndpoints, info.ConnID)
	delete(i.chunkStates, chunkKey{info.ConnID, directionC2S})
	delete(i.chunkStates, chunkKey{info.ConnID, directionS2C})
	delete(i.streamNextSTID, info.ConnID)
	sessionCreated := i.sessionCreated
	if !sessionCreated {
		// Connection closed with no data — discard the buffered stream entry.
		for j, ps := range i.pendingStreams {
			if ps.id == info.ConnID {
				i.pendingStreams = slices.Delete(i.pendingStreams, j, j+1)
				break
			}
		}
	}
	i.mu.Unlock()

	if !sessionCreated {
		return nil
	}

	result, err := i.db.Exec(
		`UPDATE stream SET end = ? WHERE session = ? AND id = ? AND end IS NULL`,
		time.Now().UnixMilli(), i.sessionID, info.ConnID,
	)
	if err != nil {
		return err
	}
	// Called once per direction; only the call that actually set end (RowsAffected == 1)
	// should count as a stream-list change — the other call's WHERE guard makes it a no-op.
	if n, _ := result.RowsAffected(); n > 0 {
		i.mu.Lock()
		i.streamsVersion++
		i.mu.Unlock()
	}
	return nil
}

func (i *DbDumpInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	if err := i.ensureSession(); err != nil {
		return nil, err
	}

	i.mu.RLock()
	clientEndpoint := i.clientEndpoints[info.ConnID]
	i.mu.RUnlock()

	direction := directionS2C
	if info.SrcEndpoint == clientEndpoint {
		direction = directionC2S
	}

	// data is a view into the proxy's shared read buffer; copy it before the
	// caller's next Read() can overwrite it.
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	key := chunkKey{info.ConnID, direction}
	i.mu.Lock()
	// Block if the buffer has hit the hard cap; flush() will broadcast when it drains.
	for i.pendingSize >= bufMaxSize {
		i.cond.Wait()
	}
	state := i.chunkStates[key]
	sgid := i.nextSGID
	stid := i.streamNextSTID[info.ConnID]
	i.nextSGID++
	i.streamNextSTID[info.ConnID]++
	i.chunkStates[key] = chunkState{id: state.id + 1, offset: state.offset + int64(len(data))}
	i.pendingChunks = append(i.pendingChunks, chunkRecord{
		id:        state.id,
		streamID:  info.ConnID,
		sessionID: i.sessionID,
		direction: direction,
		offset:    state.offset,
		timestamp: time.Now().UnixMilli(),
		data:      dataCopy,
		sgid:      sgid,
		stid:      stid,
	})
	i.pendingSize += len(dataCopy)
	needsFlush := i.pendingSize >= bufFlushSize
	i.mu.Unlock()

	if needsFlush {
		select {
		case i.flushCh <- struct{}{}:
		default:
		}
	}

	return data, nil
}

func (i *DbDumpInterceptor) flushLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			i.flush()
		case <-i.flushCh:
			i.flush()
		case <-i.stopCh:
			i.flush()
			close(i.flushDone)
			return
		}
	}
}

// flush swaps out the pending buffer under the lock (fast), broadcasts to wake
// any blocked Intercept callers, then writes all records in a single transaction.
func (i *DbDumpInterceptor) flush() {
	i.mu.Lock()
	chunks := i.pendingChunks
	i.pendingChunks = nil
	i.pendingSize = 0
	i.mu.Unlock()
	i.cond.Broadcast()

	if len(chunks) == 0 {
		return
	}

	tx, err := i.db.Begin()
	if err != nil {
		i.logger.Error("dbdump: begin flush transaction: %v", err)
		return
	}
	stmt, err := tx.Prepare(
		`INSERT INTO chunks (id, stream, session, direction, offset, time, data, sgid, stid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		tx.Rollback()
		i.logger.Error("dbdump: prepare flush statement: %v", err)
		return
	}
	defer stmt.Close()

	for _, c := range chunks {
		if _, err := stmt.Exec(c.id, c.streamID, c.sessionID, c.direction, c.offset, c.timestamp, c.data, c.sgid, c.stid); err != nil {
			tx.Rollback()
			i.logger.Error("dbdump: flush INSERT: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		i.logger.Error("dbdump: flush commit: %v", err)
	}
}
