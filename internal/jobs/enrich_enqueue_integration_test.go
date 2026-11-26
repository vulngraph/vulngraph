//go:build integration

package jobs

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertest"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestEnrichBatchQueuePreservesPriorityUniquenessAndCapacity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated Postgres")
	}
	ctx := context.Background()
	pool, err := db.NewPool(ctx, dsn, db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)
	ctx = rivertest.WorkContext(ctx, client)
	prefix := fmt.Sprintf("batch-enrich-%d-", time.Now().UnixNano())
	defer func() {
		_, e := pool.Exec(ctx, "DELETE FROM river_job WHERE args->>'finding_id' LIKE $1", prefix+"%")
		require.NoError(t, e)
	}()
	var findings []finding.Finding
	for i := range 1001 {
		findings = append(findings, finding.Finding{ID: fmt.Sprintf("%s%d", prefix, i)})
	}
	enqueueEnrichPriority(ctx, findings, enrichSweepPriority)
	enqueueEnrichPriority(ctx, findings, enrichSweepPriority)
	var count, bad int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE queue<>$2 OR priority<>$3 OR state<>'available') FROM river_job WHERE args->>'finding_id' LIKE $1`, prefix+"%", queueEnrich, enrichSweepPriority).Scan(&count, &bad))
	require.Equal(t, 1001, count, "repeated insert must preserve ByArgs uniqueness")
	require.Zero(t, bad)
	enqueueEnrichIfCapacity(ctx, []finding.Finding{{ID: prefix + "overflow"}})
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job WHERE args->>'finding_id'=$1", prefix+"overflow").Scan(&count))
	require.Zero(t, count, "existing backpressure must still apply")
}
