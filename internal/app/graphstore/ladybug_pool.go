package graphstore

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// defaultPoolSize is the number of concurrent Ladybug read connections when
// LADYBUG_POOL_SIZE is not set: enough headroom above the enrich worker count
// that simultaneous cache misses across workers don't block on the pool.
const defaultPoolSize = 8

// cypherPoolSize is the number of connections reserved for caller-supplied
// Cypher (API, NL→Cypher, MCP, saved queries, chat). It is separate from the
// internal read pool so a burst of slow user queries can only exhaust its own
// slots — never starve enrich/respond reads — and small so at most this many
// user queries can hold the swap lock's read side at once.
const cypherPoolSize = 2

// cypherMaxPathDepth caps variable-length paths in caller-supplied Cypher. The
// engine enforces it per connection: a deeper upper bound is a binder error and
// an unbounded [*] stops at it. Without the cap one dense [*1..20] fills the
// buffer pool and fails every concurrent query with it.
const cypherMaxPathDepth = 6

// defaultQueryThreads is the per-connection Ladybug query parallelism when
// LADYBUG_QUERY_THREADS is not set. Kept low deliberately: the workload is many
// short BFS hops, not long analytical scans, so more connections at fewer
// threads each gives better concurrent throughput than fewer connections at
// more threads.
const defaultQueryThreads = 2

// ladybugDB holds the open Ladybug database and two pools of independent read
// connections: readPool for internal reads and cypherPool for untrusted Cypher.
// Each connection is used by at most one goroutine at a time. Write connections
// are opened per-operation and closed immediately.
type ladybugDB struct {
	db           *ladybug.Database
	readPool     chan *ladybug.Connection // buffered channel, capacity = poolSize
	cypherPool   chan *ladybug.Connection // buffered channel, capacity = cypherPoolSize
	poolBusyHits atomic.Int64             // ErrPoolBusy count since last reset
	queryCount   atomic.Int64             // total queries served since open
}

func openLadybug(path string, bufferPoolMB, poolSize, queryThreads int) (*ladybugDB, error) {
	if poolSize <= 0 {
		poolSize = defaultPoolSize
	}
	if queryThreads <= 0 {
		queryThreads = defaultQueryThreads
	}

	cfg := ladybug.DefaultSystemConfig()
	cfg.BufferPoolSize = uint64(bufferPoolMB) * 1024 * 1024
	cfg.MaxNumThreads = uint64(queryThreads)

	db, err := ladybug.OpenDatabase(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("openLadybug: %w", err)
	}
	k := &ladybugDB{
		db:         db,
		readPool:   make(chan *ladybug.Connection, poolSize),
		cypherPool: make(chan *ladybug.Connection, cypherPoolSize),
	}
	for _, pool := range []chan *ladybug.Connection{k.readPool, k.cypherPool} {
		for i := 0; i < cap(pool); i++ {
			conn, connErr := ladybug.OpenConnection(db)
			if connErr != nil {
				k.close()
				return nil, fmt.Errorf("openLadybug: connection %d: %w", i, connErr)
			}
			if pool == k.cypherPool {
				if err := capPathDepth(conn); err != nil {
					conn.Close()
					k.close()
					return nil, fmt.Errorf("openLadybug: %w", err)
				}
			}
			pool <- conn
		}
	}
	return k, nil
}

func capPathDepth(conn *ladybug.Connection) error {
	res, err := conn.Query(fmt.Sprintf("CALL var_length_extend_max_depth=%d", cypherMaxPathDepth))
	if err != nil {
		return fmt.Errorf("capPathDepth: %w", err)
	}
	res.Close()
	return nil
}

func (k *ladybugDB) newWriteConn() (*ladybug.Connection, error) {
	return ladybug.OpenConnection(k.db)
}

// withRead runs fn on a connection from the internal read pool. Acquisition
// waits for a free slot but gives up when ctx is done, and the query itself is
// bounded by timeout (or ctx's earlier deadline) — see runBounded.
func (k *ladybugDB) withRead(ctx context.Context, timeout time.Duration, fn func(*ladybug.Connection) error) error {
	return k.runBounded(ctx, k.readPool, timeout, fn)
}

// withCypher is withRead on the dedicated untrusted-Cypher pool.
func (k *ladybugDB) withCypher(ctx context.Context, timeout time.Duration, fn func(*ladybug.Connection) error) error {
	return k.runBounded(ctx, k.cypherPool, timeout, fn)
}

// runBounded acquires a connection from pool (or returns ctx's error), arms the
// engine-side query timeout, and interrupts the running query if ctx is
// cancelled first. Without both, a slow query held its pool slot — and the
// swap lock's read side, blocking the rebuild — for as long as the engine took.
func (k *ladybugDB) runBounded(ctx context.Context, pool chan *ladybug.Connection, timeout time.Duration, fn func(*ladybug.Connection) error) error {
	waitStart := time.Now()
	var conn *ladybug.Connection
	select {
	case conn = <-pool:
	case <-ctx.Done():
		k.poolBusyHits.Add(1)
		return fmt.Errorf("ladybug: waiting for a read connection: %w", ctx.Err())
	}
	defer func() {
		k.queryCount.Add(1)
		pool <- conn
	}()
	if waitElapsed := time.Since(waitStart); waitElapsed > 20*time.Millisecond {
		log.FromContext(ctx).Warn().
			Dur("pool_wait", waitElapsed).
			Int64("pool_busy_total", k.poolBusyHits.Load()).
			Msg("ladybug: read pool contention")
	}
	if d, ok := ctx.Deadline(); ok && time.Until(d) < timeout {
		timeout = time.Until(d)
	}
	if timeout <= 0 {
		return fmt.Errorf("ladybug: no time left for the query: %w", context.DeadlineExceeded)
	}
	conn.SetTimeout(uint64(max(timeout.Milliseconds(), 1)))
	defer conn.SetTimeout(0)
	interrupted := make(chan struct{})
	queryDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(interrupted)
		// The engine clears a pending interrupt when a query starts, so one
		// sent before execution begins is lost: repeat until fn returns.
		for {
			conn.Interrupt()
			select {
			case <-queryDone:
				return
			case <-time.After(interruptRetry):
			}
		}
	})
	err := fn(conn)
	close(queryDone)
	if !stop() {
		// The interrupt fired. Wait for it to finish so it cannot land on the
		// next query to use this connection, and do not trust the result.
		<-interrupted
		if err == nil {
			err = errors.New("ladybug: query interrupted")
		}
		return fmt.Errorf("%w: %w", err, ctx.Err())
	}
	return err
}

// interruptRetry is how often runBounded re-sends Interrupt to a query that
// has not stopped yet.
const interruptRetry = 50 * time.Millisecond

// ErrPoolBusy is returned by withTryRead when no connection is immediately
// available. Callers that can fall back to ClickHouse should check for this.
var ErrPoolBusy = fmt.Errorf("ladybug: connection pool busy")

// withTryRead is a non-blocking variant of withRead. It returns ErrPoolBusy
// immediately if all connections are in use, rather than blocking indefinitely.
// Used by blast-radius walks in the respond agent so that a saturated pool
// (e.g. 16 enrich workers all holding connections) causes immediate fallback
// to ClickHouse BFS instead of a multi-minute wait that jams the respond queue.
func (k *ladybugDB) withTryRead(timeout time.Duration, fn func(*ladybug.Connection) error) error {
	select {
	case conn := <-k.readPool:
		defer func() {
			k.queryCount.Add(1)
			k.readPool <- conn
		}()
		conn.SetTimeout(uint64(max(timeout.Milliseconds(), 1)))
		defer conn.SetTimeout(0)
		return fn(conn)
	default:
		k.poolBusyHits.Add(1)
		return ErrPoolBusy
	}
}

func (k *ladybugDB) close() {
	for _, pool := range []chan *ladybug.Connection{k.readPool, k.cypherPool} {
		for len(pool) > 0 {
			(<-pool).Close()
		}
	}
	if k.db != nil {
		// ladybug.Database.Close() itself trims the freed glibc arena memory — it
		// has to live there, not here, since other callers (the GC finalizer,
		// the database/sql driver's connector.Close()) close a *ladybug.Database
		// directly, bypassing this wrapper.
		k.db.Close()
	}
}
