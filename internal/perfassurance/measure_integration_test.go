//go:build integration

package perfassurance

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/migrate"
)

// Only the disposable query runner sets this marker and both loopback URLs.
func TestPrepareQueryDatabases(t *testing.T) {
	if os.Getenv("PERF_QUERY_ISOLATED") != "1" {
		t.Skip("run scripts/benchmark-queries.sh")
	}
	pg, ch := os.Getenv("PERF_POSTGRES_URL"), os.Getenv("PERF_CLICKHOUSE_URL")
	for _, dsn := range []string{pg, ch} {
		u, err := url.Parse(dsn)
		require.NoError(t, err)
		require.Equal(t, "127.0.0.1", u.Hostname())
		require.NotEmpty(t, u.Port())
		require.Equal(t, "/vg_query_perf", u.Path)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	require.NoError(t, waitForQueryStores(ctx, pg, ch))
	require.NoError(t, migrate.Run(ctx, pg, ch))
}

func waitForQueryStores(ctx context.Context, pgDSN, chDSN string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	var lastErr error
	for ctx.Err() == nil {
		probe, stop := context.WithTimeout(ctx, 2*time.Second)
		pool, err := db.NewPool(probe, pgDSN, db.MaxConnsWorker)
		if err == nil {
			pool.Close()
			ch, e := db.NewCH(probe, chDSN, 1)
			err = e
			if err == nil {
				_ = ch.Close()
				stop()
				return nil
			}
		}
		stop()
		lastErr = err
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("database readiness: %w (last probe: %v)", ctx.Err(), lastErr)
}
