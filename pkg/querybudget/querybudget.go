// Package querybudget carries a per-request ceiling for the ClickHouse reads a
// request triggers, so a caller that cannot import the storage layer (a domain
// service dispatching an LLM tool call) can still bound the reads its callee
// runs. Only internal/db's CH.Select applies it; CH.Exec, CH.Batch and
// Postgres queries ignore it.
package querybudget

import (
	"context"
	"time"
)

// Budget bounds every ClickHouse read (db.CH.Select) run under a context that
// carries it.
type Budget struct {
	// Timeout is the client-side wall clock for one query; the driver cancels
	// the query server-side when it expires, which frees the query slot.
	Timeout time.Duration
	// MaxExecutionTime is sent as ClickHouse's max_execution_time (seconds),
	// so the server aborts a query that outgrows it even if the client stays.
	MaxExecutionTime int
}

type key struct{}

// With returns ctx carrying b. An existing budget is kept where it is tighter,
// so nesting never loosens a bound.
func With(ctx context.Context, b Budget) context.Context {
	if cur, ok := From(ctx); ok {
		b.Timeout = tighter(cur.Timeout, b.Timeout)
		b.MaxExecutionTime = int(tighter(time.Duration(cur.MaxExecutionTime), time.Duration(b.MaxExecutionTime)))
	}
	return context.WithValue(ctx, key{}, b)
}

// From returns the budget ctx carries, if any.
func From(ctx context.Context) (Budget, bool) {
	b, ok := ctx.Value(key{}).(Budget)
	return b, ok
}

// tighter returns the smaller positive bound; zero means unbounded.
func tighter(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	}
	return b
}
