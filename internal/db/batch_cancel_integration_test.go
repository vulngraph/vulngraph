//go:build integration

package db

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
)

// Cancelling a batch's context right after Batch returns must not close the
// conn it just returned to the pool (see batchContext). The race needs the
// driver's watchdog goroutine to be starved of a P, so this spins one busy
// goroutine per P. Probabilistic: before the fix it failed with "use of closed
// network connection" at roughly 1-5 per 500 iterations on a laptop, so this
// is a smoke check; TestBatchContext is the deterministic guard.
func TestCH_BatchCancelAfterSendKeepsPooledConnUsable(t *testing.T) {
	ctx := context.Background()
	ch, err := NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	require.NoError(t, ch.Exec(ctx, "CREATE TABLE IF NOT EXISTS db_it_cancel (k String) ENGINE = MergeTree ORDER BY k"))
	t.Cleanup(func() { _ = ch.Exec(ctx, "DROP TABLE IF EXISTS db_it_cancel") })

	var stop atomic.Bool
	defer stop.Store(true)
	for range runtime.GOMAXPROCS(0) {
		go func() {
			for !stop.Load() {
			}
		}()
	}

	for i := range 150 {
		bctx, cancel := context.WithCancel(ctx)
		require.NoError(t, ch.Batch(bctx, "INSERT INTO db_it_cancel (k)", func(b driver.Batch) error {
			return b.Append("x")
		}))
		cancel()
		require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
			}
			return nil
		}, "SELECT 1"), "iteration %d: query after a cancelled batch", i)
	}
}
