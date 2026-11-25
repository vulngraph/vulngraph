package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Unit tests — no live database needed: construction/validation paths.

func TestNewPool_BadDSN(t *testing.T) {
	_, err := NewPool(context.Background(), "://not a dsn", MaxConnsWorker)
	require.Error(t, err)
}

// postgresMaxConnections is Postgres's default max_connections — the ONE thing
// every pool-size constant in pool.go has to fit inside together, not
// separately.
const postgresMaxConnections = 100

// TestPoolSizesFitPostgresConnectionLimit guards against the combined pool
// ceiling across all pod types (worker + N serve replicas + scanner) creeping
// over Postgres's connection limit. A bump to any one constant, or another
// serve replica, has to clear this arithmetic, not just compile.
func TestPoolSizesFitPostgresConnectionLimit(t *testing.T) {
	const serveReplicas = 2
	// +1 per serve replica: its Readiness connection sits outside the pool.
	worstCase := MaxConnsWorker + serveReplicas*(MaxConnsServe+1) + MaxConnsScanner
	require.LessOrEqual(t, worstCase, postgresMaxConnections*7/10,
		"worker+serve+scanner's combined pool ceiling must leave real headroom under "+
			"Postgres's max_connections, not just fit under it")
}

func TestNewCH_BadDSN(t *testing.T) {
	_, err := NewCH(context.Background(), "://not a clickhouse dsn", 0)
	require.Error(t, err)
}

func TestNewCH_UnreachableHost(t *testing.T) {
	// Valid DSN, dead host → ping fails fast and the error is wrapped.
	_, err := NewCH(context.Background(), "clickhouse://graph:graph@127.0.0.1:1/graph", 0)
	require.ErrorContains(t, err, "NewCH")
}

// WithWriteBudget is what stops an idempotent inventory upsert from being thrown
// away because the sync job's shared deadline was consumed by collection — the
// usual cause of a discarded sync_connector job.
func TestWithWriteBudget(t *testing.T) {
	budget := 30 * time.Second

	t.Run("an already-expired parent still gets the full budget", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), -time.Second)
		defer cancel()
		require.Error(t, parent.Err(), "parent must be expired for this to be meaningful")

		ctx, cancel2 := WithWriteBudget(parent, budget)
		defer cancel2()

		require.NoError(t, ctx.Err(), "the write must not inherit the dead deadline")
		dl, ok := ctx.Deadline()
		require.True(t, ok)
		require.Greater(t, time.Until(dl), budget-time.Second)
	})

	t.Run("a nearly-exhausted parent is re-based", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		ctx, cancel2 := WithWriteBudget(parent, budget)
		defer cancel2()

		dl, ok := ctx.Deadline()
		require.True(t, ok)
		require.Greater(t, time.Until(dl), budget-time.Second,
			"1s left is less than the budget, so the budget must win")
	})

	t.Run("a generous parent deadline is preserved, not extended", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()

		ctx, cancel2 := WithWriteBudget(parent, budget)
		defer cancel2()

		dl, ok := ctx.Deadline()
		require.True(t, ok)
		require.Greater(t, time.Until(dl), budget,
			"the caller already grants more than the budget; keep its deadline")
	})

	t.Run("context values survive re-basing", func(t *testing.T) {
		type ctxKey struct{}
		parent, cancel := context.WithTimeout(
			context.WithValue(context.Background(), ctxKey{}, "logger"), -time.Second)
		defer cancel()

		ctx, cancel2 := WithWriteBudget(parent, budget)
		defer cancel2()

		require.Equal(t, "logger", ctx.Value(ctxKey{}),
			"re-basing must keep values (pkg/log reads the logger off the context)")
	})

	t.Run("the budget is a real bound, not unlimited", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), -time.Second)
		defer cancel()

		ctx, cancel2 := WithWriteBudget(parent, 10*time.Millisecond)
		defer cancel2()

		<-ctx.Done()
		require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded,
			"a detached write must still terminate so a draining pod is not held open")
	})
}

// batchContext is the workaround for the clickhouse-go batch.Send watchdog
// race (see its doc). The property that matters is a nil Done channel: with
// it, the driver's watchdog can never select the cancel case and close a conn
// that is already back in the pool.
func TestBatchContext(t *testing.T) {
	type ctxKey struct{}
	parent, cancel := context.WithTimeout(
		context.WithValue(context.Background(), ctxKey{}, "v"), time.Minute)
	want, _ := parent.Deadline()

	ctx := batchContext(parent)
	cancel()

	require.Nil(t, ctx.Done(), "a non-nil Done reopens the pooled-conn close race")
	require.NoError(t, ctx.Err(), "cancelling the parent must not reach the driver")
	dl, ok := ctx.Deadline()
	require.True(t, ok, "the deadline must still reach the driver's conn.SetDeadline")
	require.Equal(t, want, dl)
	require.Equal(t, "v", ctx.Value(ctxKey{}), "values (query settings, logger) must survive")

	_, ok = batchContext(context.Background()).Deadline()
	require.False(t, ok, "no parent deadline means none is invented")
}

func TestBatchErr(t *testing.T) {
	ioTimeout := errors.New("read tcp: i/o timeout")

	require.Equal(t, ioTimeout, batchErr(context.Background(), ioTimeout),
		"a live ctx leaves the driver error untouched")

	expired, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()
	err := batchErr(expired, ioTimeout)
	require.ErrorIs(t, err, context.DeadlineExceeded,
		"callers matching the deadline must keep matching under batchContext")
	require.ErrorIs(t, err, ioTimeout)

	require.Equal(t, context.DeadlineExceeded, batchErr(expired, context.DeadlineExceeded),
		"an error that already is the ctx error is not wrapped twice")
}
