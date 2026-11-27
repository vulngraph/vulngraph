//go:build integration

package throughput

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

// A caller deadline can precede the server's terminal log record. Stop only
// this isolated fixture's tagged failed request before measuring another one.
func finishFailedJoinSample(ctx context.Context, admin *db.CH, logs perfassurance.QueryLogAccess, sample *perfassurance.QuerySample) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := stopJoinRequests(ctx, admin, sample.Name, false); err != nil {
		return err
	}
	if err := logs.Flush(ctx); err != nil {
		return err
	}
	var costs []perfassurance.QueryCost
	if err := admin.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var q perfassurance.QueryCost
			if err := rows.Scan(&q.SQL, &q.Milliseconds, &q.ReadRows, &q.ReadBytes, &q.Memory, &q.Exception, &q.MaxThreads, &q.MaxBlockSize, &q.ProfileEvents); err != nil {
				return err
			}
			costs = append(costs, q)
		}
		return rows.Err()
	}, logs.Select, sample.Name); err != nil {
		return err
	}
	sample.Queries = costs
	return nil
}

func stopJoinRequests(ctx context.Context, admin *db.CH, tag string, prefix bool) error {
	query := `SELECT query_id FROM system.processes WHERE current_database=currentDatabase() AND Settings['log_comment']=?`
	if prefix {
		query = strings.Replace(query, "Settings['log_comment']=?", "startsWith(Settings['log_comment'],?)", 1)
	}
	var ids []string
	if err := admin.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}, query, tag); err != nil {
		return err
	}
	for _, id := range ids {
		if err := admin.Exec(ctx, `KILL QUERY WHERE query_id=? SYNC`, id); err != nil {
			return err
		}
	}
	return nil
}

func TestLargeJoinTimeoutTelemetry(t *testing.T) {
	if os.Getenv("PERF_LARGE_JOIN_ISOLATED") != "1" {
		t.Skip("isolated benchmark only")
	}
	ctx := t.Context()
	ch, err := perfassurance.OpenQueryStore(ctx, os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	defer ch.Close()
	logs := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return ch.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: largeJoinCosts}
	sample, err := perfassurance.Measure(ctx, ch, logs, "join-timeout-telemetry", func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		return ch.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
			}
			return rows.Err()
		}, "SELECT sleep(2)")
	})
	require.Error(t, err, "the deliberate timeout must not become a successful measurement")
	require.NoError(t, finishFailedJoinSample(ctx, ch, logs, &sample))
	require.Len(t, sample.Queries, 1, "retain terminal telemetry after caller timeout")
}
