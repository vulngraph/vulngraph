//go:build integration

package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
)

// TestMalFeedWorker_Work_WatermarkNotAdvancedOnRecordFailure pins the
// watermark ordering: the watermark must only advance after findings.Record
// has actually succeeded. Against a
// real Postgres pool (unit tests can't exercise this — *pgxpool.Pool is a
// concrete type, not an interface, by design), this scripts a
// FetchSince that returns new records and a findings store that fails to
// Record them, then asserts the watermark was NOT persisted — a retry must
// still see this run's fetch range as unprocessed, not skip past it.
func TestMalFeedWorker_Work_WatermarkNotAdvancedOnRecordFailure(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	_, err = pool.Exec(ctx, "DELETE FROM osv_malfeed_watermark WHERE id = 1")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM osv_malfeed_watermark WHERE id = 1")
	})

	pkg := osv.Package{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"}
	w := &MalFeedWorker{
		querier: &fakeMalFeedQuerier{headSHA: "sha-after-failure", records: []osv.MalRecord{{
			Affected: []osv.Package{pkg},
			Vuln:     osv.Vuln{ID: "MAL-2026-11524"},
		}}},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset("pkg:npm/keyv@6.0.0", "npm", "keyv", "6.0.0")}},
		findings: &fakeFindingStore{recordErr: errors.New("clickhouse write failed")},
		pool:     pool,
	}

	err = w.Work(ctx, &river.Job[RefreshMalFeedArgs]{})
	require.Error(t, err, "a Record failure must surface as a job error so River retries")

	q := sqlcgen.New(pool)
	_, err = q.GetOSVMalFeedWatermark(ctx)
	require.ErrorIs(t, err, pgx.ErrNoRows,
		"the watermark must NOT have been persisted — a retry needs to see this run's fetch range as still unprocessed")
}
