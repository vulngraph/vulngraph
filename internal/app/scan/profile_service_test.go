package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// stubProfileRepo is the minimum ProfileRepo TriggerProfileScan touches:
// CreateRunForProfileAndEnqueue records whether a run row was created and
// invokes the caller's enqueue callback exactly as the real transactional
// repo does, so a fake test can exercise the same wiring without Postgres.
// Every other method panics if reached — none should be from TriggerProfileScan.
type stubProfileRepo struct {
	ProfileRepo
	runsCreated int
}

func (s *stubProfileRepo) GetProfile(_ context.Context, id string) (ScanProfile, error) {
	return ScanProfile{ID: id}, nil
}

func (s *stubProfileRepo) CreateRunForProfileAndEnqueue(
	ctx context.Context, profileID string, _ int,
	enqueue func(ctx context.Context, tx pgx.Tx, runID string) error,
) (Run, error) {
	s.runsCreated++
	run := Run{ID: "run-1", Status: StatusRunning}
	if err := enqueue(ctx, nil, run.ID); err != nil {
		s.runsCreated-- // mirrors the real repo's rollback: a failed enqueue commits no row
		return Run{}, err
	}
	return run, nil
}

type stubEnqueuer struct {
	calls int
	err   error
}

func (s *stubEnqueuer) EnqueueProfileScan(_ context.Context, _ pgx.Tx, _, _ string) error {
	s.calls++
	return s.err
}

// A ProfileService built without an enqueuer (the scanner pod's wiring) must
// refuse to trigger BEFORE it writes a scan_runs row. Previously the nil call
// panicked after the row was committed, so River recovered the panic into a job
// error and left a run stuck `running` with nothing alive to finish it.
func TestTriggerProfileScan_NilEnqueuer_NoRunCreated(t *testing.T) {
	repo := &stubProfileRepo{}
	svc := NewProfileService(repo, nil, nil, nil, nil)

	runID, err := svc.TriggerProfileScan(context.Background(), "p-1")

	require.ErrorIs(t, err, ErrNoEnqueuer)
	require.Empty(t, runID)
	require.Zero(t, repo.runsCreated, "no scan run may be created when the enqueue cannot happen")
}

func TestTriggerProfileScan_WithEnqueuer_CreatesRunAndEnqueues(t *testing.T) {
	repo := &stubProfileRepo{}
	enq := &stubEnqueuer{}
	svc := NewProfileService(repo, nil, nil, nil, enq)

	runID, err := svc.TriggerProfileScan(context.Background(), "p-1")

	require.NoError(t, err)
	require.Equal(t, "run-1", runID)
	require.Equal(t, 1, repo.runsCreated)
	require.Equal(t, 1, enq.calls)
}

// A failing enqueue must roll back the run row too (CreateRunForProfileAndEnqueue)
// — this pins that the caller sees the error
// AND that no row is left stranded, which stubProfileRepo's rollback-mirror
// makes observable without a real Postgres transaction.
func TestTriggerProfileScan_EnqueueError_Surfaces(t *testing.T) {
	repo := &stubProfileRepo{}
	boom := errors.New("river down")
	svc := NewProfileService(repo, nil, nil, nil, &stubEnqueuer{err: boom})

	_, err := svc.TriggerProfileScan(context.Background(), "p-1")

	require.ErrorIs(t, err, boom)
	require.Zero(t, repo.runsCreated, "a failed enqueue must not leave a run row behind")
}

// TestTriggerProfileScan_EnqueuerSeesTheCallersTxAndIDs pins the exact
// wiring: TriggerProfileScan must hand EnqueueProfileScan the SAME profile ID
// and run ID the transaction just produced, not stale or mismatched values.
// The transaction-atomicity property itself (rollback on failure, commit on
// success against a REAL Postgres transaction) is verified separately in
// profile_repo_integration_test.go's TestCreateRunForProfileAndEnqueue_AtomicWithEnqueue.
func TestTriggerProfileScan_EnqueuerSeesTheCallersTxAndIDs(t *testing.T) {
	var gotProfileID, gotRunID string
	repo := &stubProfileRepo{}
	enq := &fakeIDCapturingEnqueuer{capture: func(profileID, runID string) {
		gotProfileID, gotRunID = profileID, runID
	}}
	svc := NewProfileService(repo, nil, nil, nil, enq)

	runID, err := svc.TriggerProfileScan(context.Background(), "profile-42")
	require.NoError(t, err)
	require.Equal(t, "profile-42", gotProfileID)
	require.Equal(t, runID, gotRunID)
}

type fakeIDCapturingEnqueuer struct {
	capture func(profileID, runID string)
}

func (f *fakeIDCapturingEnqueuer) EnqueueProfileScan(_ context.Context, _ pgx.Tx, profileID, runID string) error {
	f.capture(profileID, runID)
	return nil
}

// ai_contextual has no LLM tag selector on any pod that runs profiles, so it
// is refused when saved and fails loudly when a stored profile still has it,
// never falling back to the default selection.
func TestAIContextualStrategy_Unavailable(t *testing.T) {
	svc := &ProfileService{profiles: &stubProfileRepo{}}
	ctx := context.Background()
	_, err := svc.CreateProfile(ctx, "n", "", nil, true, "", false, "", "nuclei", "ai_contextual")
	require.ErrorIs(t, err, ErrStrategyUnavailable)
	_, err = svc.UpdateProfile(ctx, "id", "n", "", nil, true, "", false, "", "nuclei", "ai_contextual")
	require.ErrorIs(t, err, ErrStrategyUnavailable)
	tags, err := svc.SelectTemplates(ctx, ScanProfile{TemplateStrategy: StrategyAIContextual}, Target{URL: "https://x"})
	require.ErrorIs(t, err, ErrStrategyUnavailable)
	require.Nil(t, tags)
}

// reconcileRepo is the ProfileRepo surface ReconcileFindingLifecycle touches.
type reconcileRepo struct {
	ProfileRepo
	prior    []ScanFinding
	upserted []ScanFinding
}

func (r *reconcileRepo) BatchGetScanFindingsByAssetIDs(context.Context, []string) ([]ScanFinding, error) {
	return nil, nil
}

func (r *reconcileRepo) UpsertScanFinding(_ context.Context, f ScanFinding) error {
	r.upserted = append(r.upserted, f)
	return nil
}

func (r *reconcileRepo) ListOpenScanFindingsByRun(context.Context, string) ([]ScanFinding, error) {
	return r.prior, nil
}

// Only a target this run finished scanning can resolve a confirmed finding.
// Absence from an errored target's empty result is not evidence of a fix.
// TestReconcileFindingLifecycle_DuplicateResultsWriteOneRow: a template that
// matches one host twice yields one row, so the (asset_id, check_id) unique
// key can't fail the second insert and stop reconciliation partway.
func TestReconcileFindingLifecycle_DuplicateResultsWriteOneRow(t *testing.T) {
	repo := &reconcileRepo{}
	svc := NewProfileService(repo, nil, nil, nil, nil)
	dupes := []ScanFinding{
		{ID: "n1", AssetID: "a.example", CheckID: "tpl-1"},
		{ID: "n2", AssetID: "a.example", CheckID: "tpl-1"},
		{ID: "n3", AssetID: "a.example", CheckID: "tpl-2"},
	}
	require.NoError(t, svc.ReconcileFindingLifecycle(context.Background(), "run-1", dupes, []string{"a.example"}))
	var ids []string
	for _, f := range repo.upserted {
		ids = append(ids, f.ID)
	}
	require.Equal(t, []string{"n1", "n3"}, ids)
}

func TestReconcileFindingLifecycle_ResolvesOnlyCompletedTargets(t *testing.T) {
	prior := []ScanFinding{
		{ID: "fa", AssetID: "a.example", CheckID: "tpl-1", Status: ScanFindingConfirmed},
		{ID: "fb", AssetID: "b.example", CheckID: "tpl-1", Status: ScanFindingConfirmed},
	}
	cases := []struct {
		name      string
		completed []string
		want      []string
	}{
		{"no target completed", nil, nil},
		{"one of two completed", []string{"a.example"}, []string{"fa"}},
		{"both completed", []string{"a.example", "b.example"}, []string{"fa", "fb"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &reconcileRepo{prior: prior}
			svc := NewProfileService(repo, nil, nil, nil, nil)
			require.NoError(t, svc.ReconcileFindingLifecycle(context.Background(), "run-2", nil, tc.completed))
			var resolved []string
			for _, f := range repo.upserted {
				require.Equal(t, ScanFindingResolved, f.Status)
				resolved = append(resolved, f.ID)
			}
			require.Equal(t, tc.want, resolved)
		})
	}
}
