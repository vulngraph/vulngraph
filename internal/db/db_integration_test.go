//go:build integration

package db

import (
	"context"
	"sync"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
)

// Requires `docker compose up`. Exercises the CH client (Select/Exec/Batch) and
// the pgx pool against live datastores.

func TestCH_BatchSelectExec(t *testing.T) {
	ctx := context.Background()
	ch, err := NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	require.NoError(t, ch.Exec(ctx, "CREATE TABLE IF NOT EXISTS db_it (k String, v UInt32) ENGINE = MergeTree ORDER BY k"))
	t.Cleanup(func() { _ = ch.Exec(ctx, "DROP TABLE IF EXISTS db_it") })
	require.NoError(t, ch.Exec(ctx, "TRUNCATE TABLE db_it"))

	require.NoError(t, ch.Batch(ctx, "INSERT INTO db_it (k, v)", func(b driver.Batch) error {
		_ = b.Append("a", uint32(1))
		return b.Append("b", uint32(2))
	}))

	var total uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var v uint64
			if err := rows.Scan(&v); err != nil {
				return err
			}
			total += v
		}
		return nil
	}, "SELECT sum(v) FROM db_it"))
	require.Equal(t, uint64(3), total)
}

func TestCH_SemaphoreSerializesUnderLoad(t *testing.T) {
	ctx := context.Background()
	ch, err := NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	// More concurrent queries than semaphore slots — all must complete, none
	// deadlock, the semaphore bounds in-flight work.
	var wg sync.WaitGroup
	errs := make([]error, 32)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = ch.Select(ctx, func(rows driver.Rows) error {
				for rows.Next() {
					var one uint8
					_ = rows.Scan(&one)
				}
				return nil
			}, "SELECT 1")
		}(i)
	}
	wg.Wait()
	for _, e := range errs {
		require.NoError(t, e)
	}
}

func TestCH_ContextCancelled(t *testing.T) {
	ch, err := NewCH(context.Background(), "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	err = ch.Select(cancelled, func(driver.Rows) error { return nil }, "SELECT 1")
	require.Error(t, err)
}

func TestNewPool_LivePing(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()

	var one int
	require.NoError(t, pool.QueryRow(ctx, "SELECT 1").Scan(&one))
	require.Equal(t, 1, one)
}

// Readiness must not depend on a free pool connection: a pool fully acquired by
// request load is busy, not down.
func TestReadiness_SaturatedPoolStaysReady(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", 2)
	require.NoError(t, err)
	defer pool.Close()
	for range 2 {
		conn, err := pool.Acquire(ctx)
		require.NoError(t, err)
		defer conn.Release()
	}

	r := NewReadiness(pool.Config().ConnConfig)
	defer r.Close(ctx)
	require.NoError(t, r.Check(ctx))
	require.NoError(t, r.Check(ctx), "a second check reuses the connection")
}
