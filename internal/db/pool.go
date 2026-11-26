// Package db provides the Postgres connection pool used by all repositories.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxConnsWorker/MaxConnsServe/MaxConnsScanner are the defaults cmd/graph
// passes to NewPool; PG_MAX_CONNS_WORKER/_SERVE/_SCANNER override them per
// role for a self-host that scales replicas or Postgres's max_connections
// differently from the topology these were sized against.
//
// MaxConnsWorker is the worker pod's pool size: it runs many concurrent job
// workers (sync + enrich + respond + correlate) plus River's own pool use,
// and each sync also needs a connection for SetSyncResult and the in-tx
// enrich enqueue.
//
// MaxConnsServe and MaxConnsScanner are deliberately smaller than the
// worker's: neither runs anywhere near as many concurrent job workers (serve
// answers HTTP/MCP requests plus its own periodic Ladybug-replica sync; scanner
// executes bounded disk-volume reads). Serve also holds one
// connection outside its pool for its readiness check (Readiness). Each pod type is sized
// independently rather than sharing one constant, because the sum across all
// replicas of all pod types must stay under Postgres's max_connections.
const (
	MaxConnsWorker  = 30
	MaxConnsServe   = 10
	MaxConnsScanner = 10
)

// NewPool opens a pgx pool with sane timeouts and verifies connectivity.
// maxConns should be one of the MaxConns* constants above, sized to the
// caller's actual concurrency — never assume a shared default is safe just
// because it worked for one pod; check how many OTHER pods share the same
// Postgres max_connections budget first.
func NewPool(ctx context.Context, dsn string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("NewPool: parse config: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("NewPool: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("NewPool: ping: %w", err)
	}
	return pool, nil
}
