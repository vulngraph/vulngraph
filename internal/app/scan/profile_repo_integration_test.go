//go:build integration

package scan

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestListOpenScanFindingsByRun_ScopedToProfile is the regression test for the
// cross-profile auto-resolution bug: ReconcileFindingLifecycle used to pass
// profileID="" and resolve confirmed findings from OTHER profiles. The query is
// now scoped to the current run's own profile, so a run of profile A must never
// surface (and thus never auto-resolve) profile B's confirmed findings.
//
// Fixtures use raw SQL (uuid id columns default themselves) rather than the
// repo's Create* helpers, to keep this query-scoping test independent of
// CreateProfile — see TestCreateProfile_GeneratesRealUUID for that method's
// own regression test.
//
// Requires `docker compose up` and applied migrations (graph migrate).
func TestListOpenScanFindingsByRun_ScopedToProfile(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGProfileRepo(pool)

	var profileA, profileB string
	require.NoError(t, pool.QueryRow(ctx, "INSERT INTO scan_profiles (name) VALUES ('prof-a') RETURNING id").Scan(&profileA))
	require.NoError(t, pool.QueryRow(ctx, "INSERT INTO scan_profiles (name) VALUES ('prof-b') RETURNING id").Scan(&profileB))

	var runIDs []string
	t.Cleanup(func() {
		// Delete runs first (cascades to scan_findings), then the profiles.
		for _, id := range runIDs {
			_, _ = pool.Exec(ctx, "DELETE FROM scan_runs WHERE id = $1", id)
		}
		_, _ = pool.Exec(ctx, "DELETE FROM scan_profiles WHERE id IN ($1,$2)", profileA, profileB)
	})

	// newRun inserts a completed run, optionally bound to a profile (empty = ad-hoc).
	newRun := func(profile string) string {
		var id string
		if profile == "" {
			require.NoError(t, pool.QueryRow(ctx,
				"INSERT INTO scan_runs (status) VALUES ('completed') RETURNING id").Scan(&id))
		} else {
			require.NoError(t, pool.QueryRow(ctx,
				"INSERT INTO scan_runs (profile_id, status) VALUES ($1, 'completed') RETURNING id", profile).Scan(&id))
		}
		runIDs = append(runIDs, id)
		return id
	}
	priorA, priorB, currentA := newRun(profileA), newRun(profileB), newRun(profileA)

	confirmed := func(runID, asset, check string) {
		_, err := pool.Exec(ctx,
			`INSERT INTO scan_findings (scan_run_id, finding_id, asset_id, check_id, title, severity, status)
			 VALUES ($1, $2, $3, $4, 't', 'high', 'confirmed')`,
			runID, "fid-"+asset, asset, check)
		require.NoError(t, err)
	}
	confirmed(priorA, "asset-a", "check-a")
	confirmed(priorB, "asset-b", "check-b")

	// A new run of profile A sees ONLY profile A's confirmed finding.
	open, err := repo.ListOpenScanFindingsByRun(ctx, currentA)
	require.NoError(t, err)
	ids := make([]string, len(open))
	for i, f := range open {
		ids[i] = f.AssetID
	}
	require.Contains(t, ids, "asset-a", "profile A's own prior confirmed finding must be a resolve candidate")
	require.NotContains(t, ids, "asset-b", "profile B's finding must NEVER be visible to a profile A run")

	// An ad-hoc run with no profile resolves nothing cross-run.
	openAdhoc, err := repo.ListOpenScanFindingsByRun(ctx, newRun(""))
	require.NoError(t, err)
	require.Empty(t, openAdhoc, "a profile-less run must not surface any other run's findings")
}

// TestCreateProfile_GeneratesRealUUID is the regression test for a
// CreateProfile bug that made every real call fail: the query generated the
// id as gen_random_uuid()::text, and scan_profiles.id is uuid — Postgres has
// no implicit text-to-uuid assignment cast, so the INSERT itself errored
// every time, 100% of calls, uncaught because no test exercised this repo
// method against real Postgres (found while wiring drift scanning end-to-end;
// see profile_repo.go's createProfileQ comment).
func TestCreateProfile_GeneratesRealUUID(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGProfileRepo(pool)

	p, err := repo.CreateProfile(ctx, "it-create-profile", "desc", []string{"tag1"}, true, "", true, "", "nuclei", "all")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM scan_profiles WHERE id = $1", p.ID) })
	require.NotEmpty(t, p.ID)
	require.True(t, p.DriftEnabled)

	got, err := repo.GetProfile(ctx, p.ID)
	require.NoError(t, err, "the generated id must be a real, readable uuid")
	require.Equal(t, "it-create-profile", got.Name)
}

// TestListDriftEnabledProfiles_ExcludesScopedProfiles is the regression test
// for a scope-violation gap in the drift-trigger path: ScanAssetWorker (the
// consumer) has no Cypher resolver to check a drift-changed asset against a
// profile's TargetQuery, so a scoped drift-enabled profile firing here would
// run nuclei on every drift-changed external asset in the whole estate, not
// just the ones the profile was scoped to. Only unscoped (empty TargetQuery)
// drift-enabled profiles should be returned.
func TestListDriftEnabledProfiles_ExcludesScopedProfiles(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGProfileRepo(pool)

	unscoped, err := repo.CreateProfile(ctx, "it-drift-unscoped", "", nil, true, "", true, "", "nuclei", "all")
	require.NoError(t, err)
	scoped, err := repo.CreateProfile(ctx, "it-drift-scoped", "", nil, true,
		"MATCH (n:Asset) WHERE n.account_id = 'acct-1' RETURN n LIMIT 100", true, "", "nuclei", "all")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM scan_profiles WHERE id IN ($1,$2)", unscoped.ID, scoped.ID)
	})

	got, err := repo.ListDriftEnabledProfiles(ctx)
	require.NoError(t, err)
	var ids []string
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	require.Contains(t, ids, unscoped.ID, "an unscoped drift-enabled profile must be included")
	require.NotContains(t, ids, scoped.ID, "a scoped drift-enabled profile must be excluded — no resolver checks the asset against its scope")
}

// TestUpsertScanFinding_NewFindingGeneratesRealUUID is UpsertScanFinding's
// half of the same bug class: a NEW finding (ScanFinding.ID empty, the repo
// generates one) went through COALESCE(NULLIF($1, ”), gen_random_uuid()::text)
// — the ::text branch made the whole COALESCE expression text, so it failed
// the same "column is uuid but expression is text" error on every genuinely
// new finding, which is the common case (profileResultsToScanFindings always
// leaves ID empty).
func TestUpsertScanFinding_NewFindingGeneratesRealUUID(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGProfileRepo(pool)

	var runID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO scan_runs (status) VALUES ('completed') RETURNING id").Scan(&runID))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM scan_runs WHERE id = $1", runID) })

	err = repo.UpsertScanFinding(ctx, ScanFinding{
		ScanRunID: runID, FindingID: "fid-1", AssetID: "asset-1", CheckID: "check-1",
		Title: "t", Severity: "high", Status: ScanFindingNew,
	})
	require.NoError(t, err, "a new finding (empty ID) must insert with a real generated uuid")

	got, err := repo.GetScanFindingByAssetCheck(ctx, "asset-1", "check-1")
	require.NoError(t, err)
	require.NotEmpty(t, got.ID)

	// Re-upserting the SAME finding (ID now populated from the read-back) must
	// hit the ON CONFLICT branch, not insert a second row.
	got.Status = ScanFindingConfirmed
	require.NoError(t, repo.UpsertScanFinding(ctx, got))
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM scan_findings WHERE asset_id = 'asset-1' AND check_id = 'check-1'").Scan(&count))
	require.Equal(t, 1, count, "re-upserting an existing finding by its own uuid must update, not duplicate")
}

// TestCreateRunForProfileAndEnqueue_AtomicWithEnqueue pins the
// guarantee this method exists for: the run row and its follow-up job enqueue
// commit together, or neither does. Before this fix, TriggerProfileScan
// called CreateRunForProfile and EnqueueProfileScan as two separate
// statements — a crash or a failed enqueue between them stranded a run row in
// 'running' forever with no job ever queued to move it forward.
func TestCreateRunForProfileAndEnqueue_AtomicWithEnqueue(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGProfileRepo(pool)

	var profileID string
	require.NoError(t, pool.QueryRow(ctx,
		"INSERT INTO scan_profiles (name) VALUES ('atomic-enqueue-test') RETURNING id").Scan(&profileID))
	// scan_runs.profile_id is ON DELETE SET NULL, not CASCADE — deleting the
	// profile alone leaves the successful-enqueue half's run row behind
	// (orphaned, profile_id nulled) forever in a persistent dev/CI database.
	// Deleting the specific run id(s) first, like
	// TestListOpenScanFindingsByRun_ScopedToProfile above already does, is
	// what actually cleans up.
	var runIDs []string
	t.Cleanup(func() {
		for _, id := range runIDs {
			_, _ = pool.Exec(ctx, "DELETE FROM scan_runs WHERE id = $1", id)
		}
		_, _ = pool.Exec(ctx, "DELETE FROM scan_profiles WHERE id = $1", profileID)
	})

	// A failing enqueue must roll back the run row too — nothing left behind
	// for a caller to ever observe as a stranded 'running' row.
	enqueueErr := fmt.Errorf("boom")
	_, err = repo.CreateRunForProfileAndEnqueue(ctx, profileID, 0, func(context.Context, pgx.Tx, string) error {
		return enqueueErr
	})
	require.ErrorIs(t, err, enqueueErr)

	var count int
	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM scan_runs WHERE profile_id = $1", profileID).Scan(&count))
	require.Zero(t, count, "a failed enqueue must roll back the run row — no stranded 'running' row left behind")

	// A successful enqueue commits the run row.
	var enqueuedRunID string
	run, err := repo.CreateRunForProfileAndEnqueue(ctx, profileID, 3, func(_ context.Context, _ pgx.Tx, runID string) error {
		enqueuedRunID = runID
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, run.ID, enqueuedRunID, "enqueue must see the same run ID the caller gets back")
	runIDs = append(runIDs, run.ID)

	require.NoError(t, pool.QueryRow(ctx,
		"SELECT count(*) FROM scan_runs WHERE id = $1", run.ID).Scan(&count))
	require.Equal(t, 1, count, "a successful enqueue must commit the run row")
}
