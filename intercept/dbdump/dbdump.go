package dbdump

import (
	"database/sql"
	"encoding/json"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"tlstap/proxy"
)

type DbDumpConfig struct {
	FilePath string `json:"file"`
	Truncate bool   `json:"truncate"`
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
}

// DbDumpInterceptor logs all traffic into an SQLite database.
//
// Schema:
//
//	sessions(id, start, config)
//	stream(id, session, src, dst, start, end)
//	chunks(id, stream, direction, offset, time, data)  PK: (stream, direction, id)
//
// Timestamps are milliseconds since the Unix epoch.
// stream.id equals the proxy's connection counter (ConnID).
// chunks.stream is a foreign key into stream.
// chunks.direction: 0 = client→server, 1 = server→client.
// chunks.id starts at 0 and increments independently per (stream, direction).
// chunks.offset is the byte offset of the chunk's first byte, independently per (stream, direction).
type DbDumpInterceptor struct {
	filePath    string
	truncate    bool
	proxyConfig proxy.ResolvedProxyConfig
	db          *sql.DB
	sessionID   int64 // valid only after ensureSession succeeds

	// Lazy session creation: the session row (and buffered stream rows) are only
	// written to the DB on the first Intercept call, so idle runs leave no trace.
	sessionOnce   sync.Once
	sessionErr    error  // cached error from the first ensureSession attempt
	sessionCreated bool   // true once the session row exists; guarded by mu
	sessionStart   int64  // set in Init, consumed by ensureSession
	pendingConfig  string // set in Init, consumed by ensureSession
	pendingStreams  []pendingStream // guarded by mu; flushed by ensureSession

	// clientEndpoints maps ConnID → client endpoint to derive direction in Intercept.
	// chunkStates tracks the next chunk ID and byte offset per (stream, direction).
	// streamNextSTID tracks the next stream-local chunk ID (direction-agnostic) per ConnID.
	// All three are protected by mu.
	clientEndpoints map[uint32]string
	chunkStates     map[chunkKey]chunkState
	streamNextSTID  map[uint32]int64
	nextSGID        int64
	mu              sync.RWMutex
}

func NewDbDumpInterceptor(path string, truncate bool, proxyConfig proxy.ResolvedProxyConfig) DbDumpInterceptor {
	return DbDumpInterceptor{
		filePath:        path,
		truncate:        truncate,
		proxyConfig:     proxyConfig,
		clientEndpoints: make(map[uint32]string),
		chunkStates:     make(map[chunkKey]chunkState),
		streamNextSTID:  make(map[uint32]int64),
	}
}

func (i *DbDumpInterceptor) Init(addr net.TCPAddr) error {
	if i.truncate {
		_ = os.Remove(i.filePath)
	}

	db, err := sql.Open("sqlite", i.filePath)
	if err != nil {
		return err
	}

	// Serialize all writes through a single connection to avoid SQLite locking errors.
	db.SetMaxOpenConns(1)
	i.db = db

	if _, err = db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return err
	}

	if _, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id     INTEGER PRIMARY KEY AUTOINCREMENT,
			start  INTEGER NOT NULL,
			config TEXT    NOT NULL
		)
	`); err != nil {
		return err
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
		return err
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
		return err
	}

	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_chunks_sgid ON chunks (session, sgid)
	`); err != nil {
		return err
	}

	if _, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_chunks_stid ON chunks (session, stream, stid)
	`); err != nil {
		return err
	}

	cfgJSON, err := i.marshalConfig()
	if err != nil {
		return err
	}

	// Store session metadata for lazy insertion on first traffic.
	i.sessionStart = time.Now().UnixMilli()
	i.pendingConfig = cfgJSON
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

		// Flush pending stream rows while holding mu so that concurrent
		// ConnectionEstablished / ConnectionTerminated calls see a consistent
		// sessionCreated state only after all rows are in the DB.
		i.mu.Lock()
		defer i.mu.Unlock()
		for _, ps := range i.pendingStreams {
			i.db.Exec(
				`INSERT OR IGNORE INTO stream (id, session, src, dst, start) VALUES (?, ?, ?, ?, ?)`,
				ps.id, id, ps.src, ps.dst, ps.at,
			)
		}
		i.pendingStreams = nil
		i.sessionID = id
		i.sessionCreated = true
	})
	return i.sessionErr
}

func (i *DbDumpInterceptor) Finalize(addr net.TCPAddr) {
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

	_, err := i.db.Exec(
		`INSERT OR IGNORE INTO stream (id, session, src, dst, start) VALUES (?, ?, ?, ?, ?)`,
		info.ConnID, i.sessionID, info.SrcEndpoint, info.DstEndpoint, time.Now().UnixMilli(),
	)
	return err
}

func (i *DbDumpInterceptor) ConnectionUpgraded(info *proxy.ConnInfo) error {
	return nil
}

// ConnectionTerminated is called once per direction; the WHERE guard ensures only the first call writes.
func (i *DbDumpInterceptor) ConnectionTerminated(info *proxy.ConnInfo) error {
	i.mu.Lock()
	delete(i.clientEndpoints, info.ConnID)
	delete(i.chunkStates, chunkKey{info.ConnID, 0})
	delete(i.chunkStates, chunkKey{info.ConnID, 1})
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

	_, err := i.db.Exec(
		`UPDATE stream SET end = ? WHERE session = ? AND id = ? AND end IS NULL`,
		time.Now().UnixMilli(), i.sessionID, info.ConnID,
	)
	return err
}

func (i *DbDumpInterceptor) Intercept(info *proxy.ConnInfo, data []byte) ([]byte, error) {
	if err := i.ensureSession(); err != nil {
		return nil, err
	}

	i.mu.RLock()
	clientEndpoint := i.clientEndpoints[info.ConnID]
	i.mu.RUnlock()

	direction := 1 // server→client
	if info.SrcEndpoint == clientEndpoint {
		direction = 0 // client→server
	}

	key := chunkKey{info.ConnID, direction}
	i.mu.Lock()
	state := i.chunkStates[key]
	sgid := i.nextSGID
	stid := i.streamNextSTID[info.ConnID]
	i.nextSGID++
	i.streamNextSTID[info.ConnID]++
	i.chunkStates[key] = chunkState{id: state.id + 1, offset: state.offset + int64(len(data))}
	i.mu.Unlock()

	_, err := i.db.Exec(
		`INSERT INTO chunks (id, stream, session, direction, offset, time, data, sgid, stid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		state.id, info.ConnID, i.sessionID, direction, state.offset, time.Now().UnixMilli(), data, sgid, stid,
	)
	return data, err
}
