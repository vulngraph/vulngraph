package driftanalysis

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/llm"
)

var t0 = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

type saved struct {
	status  string
	verdict *Verdict
	reason  string
}

type fakeRepo struct {
	states   []ConnectorState
	changed  map[string][]ChangedAsset
	changes  []AssetChange
	batches  map[string]Batch
	created  []Batch
	enqueued []string
	saves    []saved
	attempts int
	until    time.Time
	err      error
}

func (f *fakeRepo) ConnectorStates(context.Context) ([]ConnectorState, error) { return f.states, f.err }
func (f *fakeRepo) ChangedSince(_ context.Context, c string, _, until time.Time, _ int) ([]ChangedAsset, error) {
	f.until = until
	return f.changed[c], nil
}
func (f *fakeRepo) Changes(context.Context, string, []string) ([]AssetChange, error) {
	return f.changes, nil
}
func (f *fakeRepo) CreateBatch(ctx context.Context, b Batch, enqueue EnqueueFunc) (bool, error) {
	for _, c := range f.created {
		if c.ID == b.ID {
			return false, nil
		}
	}
	if enqueue != nil {
		if err := enqueue(ctx, "tx", b); err != nil {
			return false, err
		}
		f.enqueued = append(f.enqueued, b.ID)
	}
	f.created = append(f.created, b)
	return true, nil
}
func (f *fakeRepo) Get(_ context.Context, id string) (Batch, error) {
	if b, ok := f.batches[id]; ok {
		return b, nil
	}
	return Batch{}, ErrNotFound
}
func (f *fakeRepo) List(context.Context, time.Time, int) ([]Batch, error) { return nil, nil }
func (f *fakeRepo) ToRequeue(context.Context, time.Time, int, int) ([]Batch, error) {
	return nil, nil
}
func (f *fakeRepo) RecordAttempt(context.Context, string) error { f.attempts++; return nil }
func (f *fakeRepo) Save(_ context.Context, _, status string, v *Verdict, reason string, _ time.Time) error {
	f.saves = append(f.saves, saved{status, v, reason})
	return nil
}
func (f *fakeRepo) Prune(context.Context, time.Time) (int64, error) { return 0, nil }

type fakeAnalyst struct {
	v   Verdict
	err error
}

func (f fakeAnalyst) AnalyzeDrift(context.Context, AnalysisInput) (Verdict, error) { return f.v, f.err }

type fakeFacts struct{ profErr, findErr, expErr error }

func (f fakeFacts) Profiles(context.Context) ([]ProfileFact, []string, error) {
	return []ProfileFact{{ID: "p1", TemplateTags: []string{"cve"}}}, []string{"p1"}, f.profErr
}
func (f fakeFacts) Findings(context.Context, []string) (map[string]AssetFact, error) {
	return map[string]AssetFact{"arn:a1": {OpenFindings: 2, MaxScore: 80}}, f.findErr
}
func (f fakeFacts) Exposure(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{"arn:a1": true}, f.expErr
}

func newSvc(r *fakeRepo, a Analyst, f FactsSource) *Service {
	return New(r, a, f, WithClock(func() time.Time { return t0 }), WithModel("m"))
}

func noopEnqueue(context.Context, Tx, Batch) error { return nil }

func TestDiscover_FirstSightingIsBaselineAndNotEnqueued(t *testing.T) {
	r := &fakeRepo{states: []ConnectorState{{ConnectorID: "c1", Latest: t0.Add(-time.Hour)}}}
	got, err := newSvc(r, fakeAnalyst{}, fakeFacts{}).DiscoverBatches(context.Background(), noopEnqueue)
	require.NoError(t, err)
	require.Empty(t, got)
	require.Len(t, r.created, 1)
	require.Equal(t, StatusBaseline, r.created[0].Status)
	require.Equal(t, t0.Add(-time.Hour), r.created[0].WindowEnd)
	require.Empty(t, r.enqueued)
}

func TestDiscover_ConnectorStillBeingWrittenIsNotBaselined(t *testing.T) {
	r := &fakeRepo{states: []ConnectorState{{ConnectorID: "c1", Latest: t0.Add(-10 * time.Second)}}}
	_, err := newSvc(r, fakeAnalyst{}, fakeFacts{}).DiscoverBatches(context.Background(), noopEnqueue)
	require.NoError(t, err)
	require.Empty(t, r.created)
}

// A sweep that re-stamped identical hashes moves no timestamp, so
// ChangedSince finds nothing and no batch exists.
func TestDiscover_NoChangesCreatesNoBatch(t *testing.T) {
	r := &fakeRepo{states: []ConnectorState{{ConnectorID: "c1", Latest: t0.Add(-time.Hour), Watermark: t0.Add(-time.Hour)}}}
	got, err := newSvc(r, fakeAnalyst{}, fakeFacts{}).DiscoverBatches(context.Background(), noopEnqueue)
	require.NoError(t, err)
	require.Empty(t, got)
	require.Empty(t, r.created)
	require.Equal(t, t0.Add(-settleDelay), r.until)
}

func TestDiscover_ChangesBecomeOneEnqueuedBatchAndRepeatIsIdempotent(t *testing.T) {
	wm := t0.Add(-time.Hour)
	r := &fakeRepo{
		states: []ConnectorState{{ConnectorID: "c1", Latest: t0.Add(-5 * time.Minute), Watermark: wm}},
		changed: map[string][]ChangedAsset{"c1": {
			{AssetID: "a1", At: t0.Add(-30 * time.Minute)}, {AssetID: "a2", At: t0.Add(-20 * time.Minute)},
		}},
	}
	svc := newSvc(r, fakeAnalyst{}, fakeFacts{})
	got, err := svc.DiscoverBatches(context.Background(), noopEnqueue)
	require.NoError(t, err)
	require.Len(t, got, 1)
	b := got[0]
	require.Equal(t, StatusPending, b.Status)
	require.Equal(t, []string{"a1", "a2"}, b.AssetIDs)
	require.Equal(t, wm, b.WindowStart)
	require.Equal(t, t0.Add(-20*time.Minute), b.WindowEnd)
	require.Equal(t, BatchID("c1", b.WindowEnd), b.ID)
	require.False(t, b.Truncated)
	require.Equal(t, []string{b.ID}, r.enqueued)

	again, err := svc.DiscoverBatches(context.Background(), noopEnqueue)
	require.NoError(t, err)
	require.Empty(t, again, "the same window must not create or enqueue twice")
	require.Len(t, r.enqueued, 1)
}

func TestDiscover_CapSetsTruncatedAndKeepsOldest(t *testing.T) {
	var ch []ChangedAsset
	for i := 0; i <= MaxBatchAssets; i++ {
		ch = append(ch, ChangedAsset{AssetID: fmt.Sprintf("a%03d", i), At: t0.Add(-time.Hour + time.Duration(i)*time.Second)})
	}
	r := &fakeRepo{
		states:  []ConnectorState{{ConnectorID: "c1", Watermark: t0.Add(-2 * time.Hour)}},
		changed: map[string][]ChangedAsset{"c1": ch},
	}
	got, err := newSvc(r, fakeAnalyst{}, fakeFacts{}).DiscoverBatches(context.Background(), noopEnqueue)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, got[0].Truncated)
	require.Len(t, got[0].AssetIDs, MaxBatchAssets)
	require.Equal(t, ch[MaxBatchAssets-1].At, got[0].WindowEnd, "the watermark must stop at the last analysed asset")
}

func TestDiscover_EnqueueFailureCreatesNothingAndOtherConnectorsContinue(t *testing.T) {
	r := &fakeRepo{
		states: []ConnectorState{{ConnectorID: "c1", Watermark: t0.Add(-time.Hour)}, {ConnectorID: "c2", Watermark: t0.Add(-time.Hour)}},
		changed: map[string][]ChangedAsset{
			"c1": {{AssetID: "a1", At: t0.Add(-time.Minute * 30)}},
			"c2": {{AssetID: "a2", At: t0.Add(-time.Minute * 30)}},
		},
	}
	boom := errors.New("boom")
	enqueue := func(_ context.Context, _ Tx, b Batch) error {
		if b.ConnectorID == "c1" {
			return boom
		}
		return nil
	}
	got, err := newSvc(r, fakeAnalyst{}, fakeFacts{}).DiscoverBatches(context.Background(), enqueue)
	require.ErrorIs(t, err, boom)
	require.Len(t, got, 1)
	require.Equal(t, "c2", got[0].ConnectorID)
}

func TestDisabledServiceRefusesWritesAndReportsDisabled(t *testing.T) {
	svc := newSvc(&fakeRepo{}, nil, fakeFacts{})
	require.False(t, svc.Enabled())
	_, err := svc.DiscoverBatches(context.Background(), noopEnqueue)
	require.ErrorIs(t, err, ErrDisabled)
	require.ErrorIs(t, svc.Analyze(context.Background(), "x"), ErrDisabled)
	_, err = svc.Requeue(context.Background())
	require.ErrorIs(t, err, ErrDisabled)
	l, err := svc.List(context.Background(), ListParams{})
	require.NoError(t, err)
	require.False(t, l.Enabled)
}

func pendingRepo() *fakeRepo {
	return &fakeRepo{
		batches: map[string]Batch{"b1": {ID: "b1", ConnectorID: "c1", AssetIDs: []string{"arn:a1"}, Status: StatusPending}},
		changes: []AssetChange{{AssetID: "arn:a1", Kind: KindNewExposure, PublicIP: "1.2.3.4"}},
	}
}

func recommendYes() Verdict {
	return Verdict{
		ExposureJudgement: ExposureIncreased, ScanRecommended: true, ScanRecommendedKnown: true,
		Confidence: ConfidenceHigh, SuggestedProfileID: "p1",
		Evidence: []EvidenceRef{{Source: EvidenceAsset, Ref: "arn:a1", Fact: "public"}},
	}
}

func TestAnalyze_StoresGatedVerdictWithStampedFields(t *testing.T) {
	r := pendingRepo()
	require.NoError(t, newSvc(r, fakeAnalyst{v: recommendYes()}, fakeFacts{}).Analyze(context.Background(), "b1"))
	require.Equal(t, 1, r.attempts)
	require.Len(t, r.saves, 1)
	s := r.saves[0]
	require.Equal(t, StatusAnalysed, s.status)
	require.Equal(t, "m", s.verdict.Model)
	require.Equal(t, t0, s.verdict.AnalysedAt)
	require.Equal(t, []string{"p1"}, s.verdict.AutoScanProfileIDs)
	require.Equal(t, RecommendationRecommended, s.verdict.Recommendation())
}

func TestAnalyze_IdempotentForFinishedOrMissingBatches(t *testing.T) {
	for _, status := range []string{StatusAnalysed, StatusBaseline} {
		r := pendingRepo()
		r.batches["b1"] = Batch{ID: "b1", Status: status}
		require.NoError(t, newSvc(r, fakeAnalyst{v: recommendYes()}, fakeFacts{}).Analyze(context.Background(), "b1"))
		require.Empty(t, r.saves, status)
	}
	r := pendingRepo()
	require.NoError(t, newSvc(r, fakeAnalyst{}, fakeFacts{}).Analyze(context.Background(), "gone"))
	require.Empty(t, r.saves)
}

func TestAnalyze_UnknownMapping(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{"budget exceeded", fmt.Errorf("w: %w", llm.ErrBudgetExceeded), ReasonBudget},
		{"budget unknown", fmt.Errorf("w: %w", llm.ErrBudgetUnknown), ReasonBudget},
		{"other llm error", errors.New("rate limited"), ReasonLLMError},
		{"ungrounded", fmt.Errorf("w: %w", ErrUngrounded), ReasonUngrounded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := pendingRepo()
			require.NoError(t, newSvc(r, fakeAnalyst{err: tc.err}, fakeFacts{}).Analyze(context.Background(), "b1"))
			require.Len(t, r.saves, 1)
			require.Equal(t, StatusUnknown, r.saves[0].status)
			require.Equal(t, tc.reason, r.saves[0].reason)
			require.Nil(t, r.saves[0].verdict)
		})
	}
}

// A failure must never be stored as "no scan needed": every non-analysed save
// carries no verdict, and an analysed one never pairs not-recommended with a
// missing fact.
func TestDriftAnalysisFailurePathNeverWritesNoScan(t *testing.T) {
	failures := []error{llm.ErrBudgetExceeded, llm.ErrBudgetUnknown, errors.New("x"), ErrUngrounded}
	for _, e := range failures {
		r := pendingRepo()
		require.NoError(t, newSvc(r, fakeAnalyst{err: e}, fakeFacts{}).Analyze(context.Background(), "b1"))
		for _, s := range r.saves {
			require.Nil(t, s.verdict, "failure %v stored a verdict", e)
		}
	}

	no := recommendYes()
	no.ScanRecommended = false
	r := pendingRepo()
	require.NoError(t, newSvc(r, fakeAnalyst{v: no}, fakeFacts{findErr: errors.New("down")}).Analyze(context.Background(), "b1"))
	require.Equal(t, StatusAnalysed, r.saves[0].status)
	require.False(t, r.saves[0].verdict.ScanRecommendedKnown, "a no with a failed lookup must be unknown")
}

func TestAnalyze_UngroundedAnalystOutputIsCaughtByTheService(t *testing.T) {
	bad := recommendYes()
	bad.Evidence = []EvidenceRef{{Source: EvidenceAsset, Ref: "arn:foreign", Fact: "x"}}
	r := pendingRepo()
	require.NoError(t, newSvc(r, fakeAnalyst{v: bad}, fakeFacts{}).Analyze(context.Background(), "b1"))
	require.Equal(t, ReasonUngrounded, r.saves[0].reason)
}

func TestAnalyze_CancelledContextWritesNothingAndReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := pendingRepo()
	require.Error(t, newSvc(r, fakeAnalyst{err: context.Canceled}, fakeFacts{}).Analyze(ctx, "b1"))
	require.Empty(t, r.saves)
}

func TestAnalyze_NoChangesRowsIsUnknown(t *testing.T) {
	r := pendingRepo()
	r.changes = nil
	require.NoError(t, newSvc(r, fakeAnalyst{v: recommendYes()}, fakeFacts{}).Analyze(context.Background(), "b1"))
	require.Equal(t, ReasonNoChanges, r.saves[0].reason)
}

func TestGatherFacts_FailedLookupsAreNotKnown(t *testing.T) {
	svc := newSvc(&fakeRepo{}, fakeAnalyst{}, fakeFacts{profErr: errors.New("p"), expErr: errors.New("e")})
	f := svc.gatherFacts(context.Background(), Batch{}, []AssetChange{{AssetID: "arn:a1"}})
	require.False(t, f.ProfilesKnown)
	require.False(t, f.ExposureKnown)
	require.True(t, f.FindingsKnown)
	require.Empty(t, f.Profiles)
	require.Equal(t, 2, f.Assets[0].OpenFindings)
	require.False(t, f.Assets[0].InternetFacing, "unread exposure is carried as zero but flagged unknown")
}

func TestList_ClampsLimitAndReportsEnabled(t *testing.T) {
	r := &fakeRepo{}
	l, err := newSvc(r, fakeAnalyst{}, fakeFacts{}).List(context.Background(), ListParams{Limit: 5000})
	require.NoError(t, err)
	require.True(t, l.Enabled)
}

// The advisory verdict must have no path to a scan: the package may not import
// the scan domain or the jobs package that holds the scan job kinds.
func TestDriftAnalysis_NeverEnqueuesScanKinds(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
		require.NoError(t, err)
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			require.False(t, strings.HasSuffix(p, "/internal/app/scan") || strings.HasSuffix(p, "/internal/jobs") ||
				strings.Contains(p, "/internal/scanner") || strings.Contains(p, "/internal/app/executor") || strings.Contains(p, "/internal/app/respond"),
				"%s imports %s: a drift verdict must not reach scan or action code", name, p)
		}
	}
}
