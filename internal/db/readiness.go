package db

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// readinessTimeout stays under the chart's 3s readinessProbe timeoutSeconds, so
// an unreachable database answers 503 instead of a probe timeout.
const readinessTimeout = 2 * time.Second

// Readiness checks that Postgres answers, on one connection of its own rather
// than one acquired from the pool: a pool saturated by request load would make
// the check wait for a free connection and take a busy but healthy pod out of
// its Service. It costs one Postgres connection per process beyond the pool.
type Readiness struct {
	cfg  *pgx.ConnConfig
	mu   sync.Mutex
	conn *pgx.Conn
}

// NewReadiness returns a check that dials cfg on first use. Pass the pool's
// ConnConfig so the check reaches the same database as the pool.
func NewReadiness(cfg *pgx.ConnConfig) *Readiness {
	return &Readiness{cfg: cfg.Copy()}
}

// Check pings Postgres and returns an error when it does not answer within
// readinessTimeout. A failed ping drops the connection so the next check
// redials instead of reusing a broken one.
func (r *Readiness) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, readinessTimeout)
	defer cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil || r.conn.IsClosed() {
		conn, err := pgx.ConnectConfig(ctx, r.cfg)
		if err != nil {
			return fmt.Errorf("Readiness: connect: %w", err)
		}
		r.conn = conn
	}
	if err := r.conn.Ping(ctx); err != nil {
		r.closeLocked(ctx)
		return fmt.Errorf("Readiness: ping: %w", err)
	}
	return nil
}

// Close releases the check's connection.
func (r *Readiness) Close(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeLocked(ctx)
}

func (r *Readiness) closeLocked(ctx context.Context) {
	if r.conn == nil {
		return
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), readinessTimeout)
	defer cancel()
	_ = r.conn.Close(closeCtx)
	r.conn = nil
}
