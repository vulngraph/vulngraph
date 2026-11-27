//go:build integration

package clickhouse

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Opt-in because this measures a populated upgrade rather than a fresh install.
// versionTestDB always creates its own database, even on a shared test server.
func TestPreciseVersionsPopulatedScale(t *testing.T) {
	raw := os.Getenv("PERF_MIGRATION_ROWS")
	if raw == "" {
		t.Skip("set PERF_MIGRATION_ROWS and TEST_CLICKHOUSE_URL")
	}
	n, err := strconv.Atoi(raw)
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 1000)
	require.LessOrEqual(t, n, 20000000)
	ctx, db, p := versionTestDB(t)
	require.NoError(t, exec(ctx, db, `INSERT INTO graph_edges(src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at)
 SELECT concat('image-',toString(number%100000)),'container_image',concat('package-',toString(number)),
 'package','runs_package','{"version":"original","location":"/usr/lib"}',now() FROM numbers(`+strconv.Itoa(n)+`) SETTINGS max_threads=2`))
	start := time.Now()
	_, err = p.UpTo(ctx, 3)
	seconds := time.Since(start).Seconds()
	require.NoError(t, err)
	var count uint64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count() FROM graph_edges FINAL WHERE properties='{"version":"original","location":"/usr/lib"}' AND src_type='container_image' AND dst_type='package' AND edge_type='runs_package'`).Scan(&count))
	require.EqualValues(t, n, count)
	t.Logf("verified populated upgrade: rows=%d seconds=%.3f rows_per_second=%.0f", n, seconds, float64(n)/seconds)
	if path := os.Getenv("PERF_MIGRATION_REPORT"); path != "" {
		b, err := json.MarshalIndent(struct {
			Rows    int     `json:"rows"`
			Seconds float64 `json:"seconds"`
			Passed  bool    `json:"passed"`
		}{n, seconds, true}, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, b, 0600))
	}
}
