package enrich

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeSource is a configurable Source for service wiring tests.
type fakeSource struct {
	name    string
	factor  Factor
	applied bool
	err     error
	panics  bool
}

func (s fakeSource) Name() string { return s.name }
func (s fakeSource) Evaluate(context.Context, finding.Finding) (Factor, bool, error) {
	if s.panics {
		panic("source boom")
	}
	return s.factor, s.applied, s.err
}

type fakeFindingWriter struct {
	recorded []finding.Enrichment
	err      error
	// stored is what ByIDs returns — the finding as it stands at write time.
	stored  map[string]finding.Finding
	readErr error
	reads   int
}

func (w *fakeFindingWriter) RecordEnrichment(_ context.Context, enrichments []finding.Enrichment) error {
	if w.err != nil {
		return w.err
	}
	w.recorded = append(w.recorded, enrichments...)
	return nil
}

func (w *fakeFindingWriter) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	w.reads++
	if w.readErr != nil {
		return nil, w.readErr
	}
	var out []finding.Finding
	for _, id := range ids {
		if f, ok := w.stored[id]; ok {
			out = append(out, f)
		}
	}
	return out, nil
}

type fakeSignalRepo struct {
	wrote     bool
	findingID string
	score     Score
	err       error
}

func (r *fakeSignalRepo) WriteFactors(_ context.Context, findingID, _ string, score Score) error {
	if r.err != nil {
		return r.err
	}
	r.wrote = true
	r.findingID = findingID
	r.score = score
	return nil
}

func (r *fakeSignalRepo) Factors(_ context.Context, _ string) ([]Factor, error) {
	return r.score.Factors, nil
}

func sampleFinding() finding.Finding {
	return finding.Finding{
		ID: "f-1", Source: "cspm", Type: "exposure", Severity: finding.SeverityMedium,
		Title: "public bucket", ResourceID: "r-1", ResourceType: "s3_bucket",
	}
}

func TestEnrich_WritesScoreBackAndPreservesFields(t *testing.T) {
	fw := &fakeFindingWriter{}
	sr := &fakeSignalRepo{}
	svc := NewService(fw, sr, []Source{
		fakeSource{name: "a", factor: Factor{Source: "a", Points: 34}, applied: true},
		fakeSource{name: "b", factor: Factor{Source: "b", Points: 20}, applied: true},
	})

	score, err := svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err)
	require.Equal(t, uint8(54), score.Value)
	require.Equal(t, BandPipeline, score.Band)

	// The per-source breakdown is persisted.
	require.True(t, sr.wrote)
	require.Equal(t, "f-1", sr.findingID)
	require.Len(t, sr.score.Factors, 2)

	// The outputs are written to finding_enrichment — the only write.
	require.Len(t, fw.recorded, 1)
	enr := fw.recorded[0]
	require.Equal(t, "f-1", enr.ID)
	require.Equal(t, uint8(54), enr.Score)
	require.Equal(t, string(BandPipeline), enr.ScoreBand)
	require.False(t, enr.EnrichedAt.IsZero(), "enriched_at is stamped")
	require.Zero(t, fw.reads, "a non-CVE finding can never be KEV-flagged, so it is not re-read")
}

// TestEnrich_CarriesForwardAKEVFlagSetMidEnrich pins that enrich never clears
// a KnownExploited flag the KEV refresh wrote after enrich's job-start read:
// the enrichment row is one argMax version, so writing the stale false would
// silently drop the flag. The re-run also has to apply the KEV page floor.
func TestEnrich_CarriesForwardAKEVFlagSetMidEnrich(t *testing.T) {
	f := finding.Finding{ID: "f-cve", Source: "vm_vuln", CheckID: "CVE-2021-44228", Severity: finding.SeverityHigh}
	flagged := f
	flagged.KnownExploited = true
	fw := &fakeFindingWriter{stored: map[string]finding.Finding{f.ID: flagged}}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{BaseSeverity{}, KEV{}})

	score, err := svc.Enrich(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, fw.recorded, 1)
	require.True(t, fw.recorded[0].KnownExploited, "the KEV flag must survive a concurrent enrich")
	require.Equal(t, BandPage, score.Band, "the re-run applies the KEV page floor")
}

// TestEnrich_BeliefCarriesThePageFloor pins the wiring Reconcile's page-floor
// guard depends on: a KEV finding's belief input must say it is page-floored.
func TestEnrich_BeliefCarriesThePageFloor(t *testing.T) {
	bf := &fakeBeliefFormer{}
	svc := NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, []Source{BaseSeverity{}, KEV{}}, WithBeliefFormer(bf))
	f := finding.Finding{ID: "f-kev", CheckID: "CVE-2021-44228", KnownExploited: true, ResourceID: "i-1", Severity: finding.SeverityHigh}

	_, err := svc.Enrich(context.Background(), f)
	require.NoError(t, err)
	require.True(t, bf.in.PageFloor)

	_, err = svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err)
	require.False(t, bf.in.PageFloor, "no page floor without a page-level source")
}

func TestEnrich_KEVReReadErrorFailsEnrich(t *testing.T) {
	fw := &fakeFindingWriter{readErr: errors.New("ch down")}
	svc := NewService(fw, &fakeSignalRepo{}, nil)
	_, err := svc.Enrich(context.Background(), finding.Finding{ID: "f-cve", CheckID: "CVE-2021-44228"})
	require.ErrorContains(t, err, "re-read known_exploited",
		"an unread flag must not be overwritten with false")
	require.Empty(t, fw.recorded)
}

type fakeBeliefFormer struct {
	called bool
	in     BeliefInput
	err    error
}

func (f *fakeBeliefFormer) FormBelief(_ context.Context, in BeliefInput) error {
	f.called = true
	f.in = in
	return f.err
}

func TestEnrich_FormsBeliefFromOutputs(t *testing.T) {
	fw := &fakeFindingWriter{}
	bf := &fakeBeliefFormer{}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{
		fakeSource{name: "a", factor: Factor{Source: "a", Points: 34}, applied: true},
	}, WithBeliefFormer(bf))

	_, err := svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err)
	require.True(t, bf.called, "belief former invoked with the enrich outputs")
	require.Equal(t, "f-1", bf.in.FindingID)
	require.Equal(t, "r-1", bf.in.ResourceID)
	require.Equal(t, uint8(34), bf.in.Score)
}

func TestEnrich_BeliefFormerErrorDoesNotFailEnrich(t *testing.T) {
	fw := &fakeFindingWriter{}
	bf := &fakeBeliefFormer{err: context.DeadlineExceeded}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{
		fakeSource{name: "a", factor: Factor{Source: "a", Points: 34}, applied: true},
	}, WithBeliefFormer(bf))

	_, err := svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err, "belief-former failure is fail-open")
	require.True(t, bf.called)
}

// A panic inside any of Enrich's concurrent stages must fail the one finding
// (or fail open, per that stage's contract) — never crash the worker pod. The
// write goroutines run without River's job-level recover, so an unguarded
// panic there took the whole pod down.
func TestEnrich_PanicsAreConfinedToTheFinding(t *testing.T) {
	t.Run("record panic surfaces as error", func(t *testing.T) {
		svc := NewService(&panickyFindingWriter{}, &fakeSignalRepo{}, nil)
		_, err := svc.Enrich(context.Background(), sampleFinding())
		require.ErrorContains(t, err, "panic recording finding",
			"a record panic must fail the enrichment (job retries), not report success")
	})

	t.Run("write-factors panic surfaces as error", func(t *testing.T) {
		svc := NewService(&fakeFindingWriter{}, &panickySignalRepo{}, nil)
		_, err := svc.Enrich(context.Background(), sampleFinding())
		require.ErrorContains(t, err, "panic writing factors")
	})

	t.Run("belief-former panic is fail-open", func(t *testing.T) {
		fw := &fakeFindingWriter{}
		svc := NewService(fw, &fakeSignalRepo{}, nil, WithBeliefFormer(panickyBeliefFormer{}))
		_, err := svc.Enrich(context.Background(), sampleFinding())
		require.NoError(t, err, "belief forming is advisory — a panic must not fail enrichment")
		require.Len(t, fw.recorded, 1, "the finding is still recorded")
	})
}

type panickyFindingWriter struct{}

func (panickyFindingWriter) RecordEnrichment(context.Context, []finding.Enrichment) error {
	panic("record boom")
}

func (panickyFindingWriter) ByIDs(context.Context, []string) ([]finding.Finding, error) {
	return nil, nil
}

type panickySignalRepo struct{}

func (panickySignalRepo) WriteFactors(context.Context, string, string, Score) error {
	panic("factors boom")
}
func (panickySignalRepo) Factors(context.Context, string) ([]Factor, error) { return nil, nil }

type panickyBeliefFormer struct{}

func (panickyBeliefFormer) FormBelief(context.Context, BeliefInput) error { panic("belief boom") }

func TestEnrich_GracefulDegradation(t *testing.T) {
	fw := &fakeFindingWriter{}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{
		fakeSource{name: "ok", factor: Factor{Source: "ok", Points: 40}, applied: true},
		fakeSource{name: "errs", err: errors.New("unavailable")},
		fakeSource{name: "panics", panics: true},
		fakeSource{name: "skip", applied: false},
	})

	score, err := svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err, "a failing/panicking source must not fail enrichment")
	require.Equal(t, uint8(40), score.Value, "score comes from the surviving source only")
	require.Len(t, score.Factors, 1)
}

func TestEnrich_NoSourcesScoresZero(t *testing.T) {
	svc := NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil)
	score, err := svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err)
	require.Equal(t, uint8(0), score.Value)
	require.Equal(t, BandMonitor, score.Band)
}

// The safety/must-fix assessments and the three post-score writes (RecordEnrichment,
// WriteFactors, FormBelief) now run concurrently instead of strictly
// sequentially — these tests lock in that RecordEnrichment/WriteFactors errors still
// abort Enrich (unchanged contract) even though they run alongside two other
// goroutines, and that a slow/erroring belief write never affects either.

func TestEnrich_RecordErrorFailsEnrich(t *testing.T) {
	fw := &fakeFindingWriter{err: errors.New("ch down")}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{
		fakeSource{name: "a", factor: Factor{Source: "a", Points: 34}, applied: true},
	})
	_, err := svc.Enrich(context.Background(), sampleFinding())
	require.ErrorContains(t, err, "record finding")
}

func TestEnrich_WriteFactorsErrorFailsEnrich(t *testing.T) {
	fw := &fakeFindingWriter{}
	sr := &fakeSignalRepo{err: errors.New("signals table unavailable")}
	svc := NewService(fw, sr, []Source{
		fakeSource{name: "a", factor: Factor{Source: "a", Points: 34}, applied: true},
	})
	_, err := svc.Enrich(context.Background(), sampleFinding())
	require.ErrorContains(t, err, "write factors")
	// RecordEnrichment still happens — the two writes are concurrent, not sequential;
	// one failing must not prevent the other from running.
	require.Len(t, fw.recorded, 1)
}

// A belief-write error must stay fail-open even when it runs concurrently with
// the RecordEnrichment/WriteFactors writes — matching TestEnrich_BeliefFormerErrorDoesNotFailEnrich's
// contract, now under the concurrent execution path.
func TestEnrich_ConcurrentWritesAllSucceedIndependently(t *testing.T) {
	fw := &fakeFindingWriter{}
	sr := &fakeSignalRepo{}
	bf := &fakeBeliefFormer{err: errors.New("belief store down")}
	svc := NewService(fw, sr, []Source{
		fakeSource{name: "a", factor: Factor{Source: "a", Points: 34}, applied: true},
	}, WithBeliefFormer(bf))

	_, err := svc.Enrich(context.Background(), sampleFinding())
	require.NoError(t, err, "a belief error must not fail enrichment, even running concurrently")
	require.Len(t, fw.recorded, 1, "RecordEnrichment still succeeds")
	require.True(t, sr.wrote, "WriteFactors still succeeds")
	require.True(t, bf.called, "belief formation was still attempted")
}

// INV-4 END TO END, through Enrich and onto the persisted row.
//
// Every other INV-4 test calls reconcileConsistency directly, and the gate's
// entire connection to production is one assignment in Enrich. Deleting that line
// left every enrich test green while a deployment logged the violation, incremented the
// metric, and persisted the un-demoted `safe` class forever — the
// built-but-never-wired failure class. This test
// asserts on what RecordEnrichment received, so it fails if the wiring is removed.
func TestEnrich_INV4DemotesSafetyClassOnThePersistedFinding(t *testing.T) {
	// A non-test-mode credential leak (validity unknown) in a PUBLIC repo →
	// must-fix, with no reach or blast providers needed. The same seed is
	// present, unreferenced, non-prod and not internet-facing → SafetySafe. The
	// two claims contradict.
	seed := asset.Asset{
		ID: "org/app", Type: "github_repo", LastSeen: time.Now(),
		Metadata: map[string]string{"visibility": "public"},
	}
	fw := &fakeFindingWriter{}
	var observed []string
	svc := NewService(fw, &fakeSignalRepo{}, nil,
		WithSafetyProvider(fakeSafetyProvider{seed: seed}),
		WithConsistencyGate(true, false, func(inv string, _ int) { observed = append(observed, inv) }),
	)

	f := finding.Finding{
		ID: "f-leak", Source: "ghas_secrets", Severity: finding.SeverityHigh,
		CheckID: "aws_secret_access_key", ResourceID: "org/app", ResourceType: "github_repo",
	}
	_, err := svc.Enrich(context.Background(), f)
	require.NoError(t, err)

	require.Contains(t, observed, consistencyInvSafeMustFix, "the invariant must have fired")
	require.Len(t, fw.recorded, 1)
	got := fw.recorded[0]

	require.Equal(t, MustFix, got.MustFixClass,
		"INV-4 must never demote the finding — only the safety claim")
	require.Equal(t, SafetyCaution, got.SafetyClass,
		"the demoted safety class must reach the persisted row; safety_class drives the "+
			"Start-here worklist, so a `safe` label here recommends deleting a must-fix resource")
}

// Shadow mode observes without repairing — including for the safety class, so a
// shadow rollout cannot quietly change persisted state.
func TestEnrich_INV4ShadowModeDoesNotDemoteThePersistedFinding(t *testing.T) {
	seed := asset.Asset{
		ID: "org/app", Type: "github_repo", LastSeen: time.Now(),
		Metadata: map[string]string{"visibility": "public"},
	}
	fw := &fakeFindingWriter{}
	var observed []string
	svc := NewService(fw, &fakeSignalRepo{}, nil,
		WithSafetyProvider(fakeSafetyProvider{seed: seed}),
		WithConsistencyGate(true, true, func(inv string, _ int) { observed = append(observed, inv) }),
	)

	_, err := svc.Enrich(context.Background(), finding.Finding{
		ID: "f-leak", Source: "ghas_secrets", Severity: finding.SeverityHigh,
		CheckID: "aws_secret_access_key", ResourceID: "org/app", ResourceType: "github_repo",
	})
	require.NoError(t, err)

	require.Contains(t, observed, consistencyInvSafeMustFix, "shadow mode still counts the violation")
	require.Equal(t, SafetySafe, fw.recorded[0].SafetyClass, "shadow mode must not repair")
}
