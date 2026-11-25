package jobs

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
)

// These fixtures mirror the two nuclei result shapes the SDK produces: an
// http-protocol template, whose Matched carries the full matched URL
// (scheme+host+path), and a network-protocol template, whose Matched carries
// "host:port" (no scheme/path). profileResultsToFindings must use a non-empty
// MatchedURL for ResourceID/ResourceType rather than discard it — see the
// resource-attribution paragraph on profileResultsToFindings.

func TestProfileResultsToFindings_HTTPTemplate(t *testing.T) {
	results := []scan.Result{{
		Scanner:    "nuclei",
		TemplateID: "msmtp-config",
		Name:       "Msmtp - Config Exposure",
		Severity:   "high",
		MatchedURL: "https://host.example.com/.msmtprc",
	}}
	target := scan.Target{URL: "https://host.example.com", Host: "host.example.com"}

	got := profileResultsToFindings("run-1", results, target, time.Now())
	require.Len(t, got, 1)
	f := got[0]
	require.Equal(t, "https://host.example.com/.msmtprc", f.ResourceID)
	require.Equal(t, "endpoint", f.ResourceType)
	require.Equal(t, "msmtp-config", f.CheckID)
	require.NotEmpty(t, f.ID, "finding ID must be set — a blank ID collides with every other nuclei finding under the (source, id) ReplacingMergeTree key")
}

func TestProfileResultsToFindings_NetworkTemplate(t *testing.T) {
	results := []scan.Result{{
		Scanner:    "nuclei",
		TemplateID: "unauth-psql",
		Name:       "Unauthenticated PostgreSQL Access",
		Severity:   "critical",
		MatchedURL: "10.0.0.5:5432", // network-protocol templates report host:port, no scheme
	}}
	target := scan.Target{URL: "https://10.0.0.5", Host: "10.0.0.5"}

	got := profileResultsToFindings("run-1", results, target, time.Now())
	require.Len(t, got, 1)
	require.Equal(t, "10.0.0.5:5432", got[0].ResourceID)
	require.Equal(t, "endpoint", got[0].ResourceType)
}

// TestProfileResultsToFindings_FallsBackToTargetURL covers the retry/error
// event shape (e.g. a network dial failure) where nuclei reports no per-match
// URL at all — the mapper must still anchor the finding to the scanned target
// rather than leaving it blank.
func TestProfileResultsToFindings_FallsBackToTargetURL(t *testing.T) {
	results := []scan.Result{{
		Scanner:    "nuclei",
		TemplateID: "open-proxy-internal",
		Name:       "Open Proxy",
		Severity:   "medium",
		MatchedURL: "",
	}}
	target := scan.Target{URL: "https://proxy.example.com", Host: "proxy.example.com", AssetType: "ec2_instance"}

	got := profileResultsToFindings("run-1", results, target, time.Now())
	require.Len(t, got, 1)
	require.Equal(t, "https://proxy.example.com", got[0].ResourceID)
	require.Equal(t, "ec2_instance", got[0].ResourceType, "known asset type wins over the generic endpoint fallback")
}

// TestProfileResultsToFindings_FallsBackToHost covers a target with neither a
// MatchedURL nor a URL (only a bare host) — resource attribution must still
// land on something traceable, never both fields blank.
func TestProfileResultsToFindings_FallsBackToHost(t *testing.T) {
	results := []scan.Result{{
		Scanner:    "nuclei",
		TemplateID: "generic-php-files",
		Name:       "Generic PHP Files",
		Severity:   "info",
	}}
	target := scan.Target{Host: "10.0.0.9"}

	got := profileResultsToFindings("run-1", results, target, time.Now())
	require.Len(t, got, 1)
	require.Equal(t, "10.0.0.9", got[0].ResourceID)
	require.Equal(t, "endpoint", got[0].ResourceType)
}

func TestProfileResultsToFindings_DeterministicID(t *testing.T) {
	results := []scan.Result{{TemplateID: "t1", MatchedURL: "https://x/path"}}
	target := scan.Target{URL: "https://x"}
	first := profileResultsToFindings("run-1", results, target, time.Now())
	second := profileResultsToFindings("run-2", results, target, time.Now().Add(time.Hour))
	require.Equal(t, first[0].ID, second[0].ID, "same scanner+check+resource must produce the same ID across re-scans")
}

// ─── ScanProfileWorker.Work: cypher target resolution ───────────────────────

// fakeProfileRunner satisfies profileRunner for Work() tests. ResolveTargets
// is deliberately never expected to be called for a TargetQuery profile —
// asserting that guards against silently falling back to "all externals"
// when a cypher resolver is (or isn't) configured.
type fakeProfileRunner struct {
	profile      scan.ScanProfile
	getErr       error
	finished     bool
	finishStatus scan.Status
	finishErrMsg string
	reconciled   [][]string // completedTargets of each ReconcileFindingLifecycle call
}

func (f *fakeProfileRunner) GetProfile(context.Context, string) (scan.ScanProfile, error) {
	return f.profile, f.getErr
}

func (f *fakeProfileRunner) FinishRun(_ context.Context, _ string, status scan.Status, _ int, errMsg string) error {
	f.finished = true
	f.finishStatus = status
	f.finishErrMsg = errMsg
	return nil
}

func (f *fakeProfileRunner) ResolveTargets(context.Context, scan.ScanProfile) ([]scan.Target, error) {
	panic("ResolveTargets must not be called for a profile with a non-empty TargetQuery")
}

func (f *fakeProfileRunner) SelectTemplates(context.Context, scan.ScanProfile, scan.Target) ([]string, error) {
	return nil, nil
}

func (f *fakeProfileRunner) ReconcileFindingLifecycle(_ context.Context, _ string, _ []scan.ScanFinding, completedTargets []string) error {
	f.reconciled = append(f.reconciled, completedTargets)
	return nil
}

type fakeProfileScanner struct {
	out scan.ScanOutput
	err error
}

func (f *fakeProfileScanner) ScanTargets(context.Context, []scan.Target, []string) (scan.ScanOutput, error) {
	return f.out, f.err
}

type fakeProfileFindingRecorder struct {
	recorded []finding.Finding
}

func (f *fakeProfileFindingRecorder) RecordObserved(_ context.Context, findings []finding.Finding) error {
	f.recorded = append(f.recorded, findings...)
	return nil
}

type fakeCypherResolver struct {
	targets []scan.Target
	err     error
	calls   int
	query   string
}

func (f *fakeCypherResolver) ResolveFromCypher(_ context.Context, query string) ([]scan.Target, error) {
	f.calls++
	f.query = query
	return f.targets, f.err
}

// TestScanProfileWorker_ResolvesCypherTargets is the regression test for
// unresolved Cypher target queries: a profile with a non-empty TargetQuery must resolve its
// targets via cypherResolver (not ResolveTargets/ListExternal) and complete
// successfully when one is wired.
func TestScanProfileWorker_ResolvesCypherTargets(t *testing.T) {
	profiles := &fakeProfileRunner{profile: scan.ScanProfile{
		ID:               "p1",
		TargetQuery:      "MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'}) RETURN a",
		TemplateStrategy: scan.StrategyAll,
	}}
	cypher := &fakeCypherResolver{targets: []scan.Target{{URL: "https://host1", Host: "host1"}}}
	scanner := &fakeProfileScanner{out: scan.ScanOutput{Results: []scan.Result{{
		TemplateID: "t1", MatchedURL: "https://host1/x",
	}}}}
	finder := &fakeProfileFindingRecorder{}

	w := &ScanProfileWorker{
		profiles:       profiles,
		scanSvc:        scanner,
		finder:         finder,
		cypherResolver: cypher,
	}

	err := w.Work(context.Background(), &river.Job[ScanProfileJobArgs]{Args: ScanProfileJobArgs{ProfileID: "p1", RunID: "r1"}})
	require.NoError(t, err)
	require.Equal(t, 1, cypher.calls, "cypherResolver.ResolveFromCypher must be called exactly once")
	require.Equal(t, profiles.profile.TargetQuery, cypher.query)
	require.True(t, profiles.finished)
	require.Equal(t, scan.StatusCompleted, profiles.finishStatus)
	require.Len(t, finder.recorded, 1)
}

// TestScanProfileWorker_TargetQueryWithoutResolver_ExplicitError is the "not
// configured" case: a nil cypherResolver on a TargetQuery profile must fail
// the run with a clear, named error rather than silently falling back to
// ResolveTargets's all-externals set (a completely different, unintended
// target set) or the generic error ProfileService.ResolveTargets used to
// return for this case.
func TestScanProfileWorker_TargetQueryWithoutResolver_ExplicitError(t *testing.T) {
	profiles := &fakeProfileRunner{profile: scan.ScanProfile{
		ID:          "p1",
		TargetQuery: "MATCH (a:Asset) RETURN a",
	}}
	w := &ScanProfileWorker{
		profiles: profiles,
		scanSvc:  &fakeProfileScanner{},
		finder:   &fakeProfileFindingRecorder{},
		// cypherResolver intentionally left nil.
	}

	err := w.Work(context.Background(), &river.Job[ScanProfileJobArgs]{Args: ScanProfileJobArgs{ProfileID: "p1", RunID: "r1"}})
	require.Error(t, err)
	require.ErrorContains(t, err, "cypherResolver is configured")
	require.ErrorContains(t, err, "p1")
	require.True(t, profiles.finished)
	require.Equal(t, scan.StatusFailed, profiles.finishStatus)
	require.NotEmpty(t, profiles.finishErrMsg)
}

// TestScanProfileWorker_EmptyTargetQuery_UsesResolveTargets confirms the
// unaffected path: a profile with NO TargetQuery still goes through
// ResolveTargets (all externals), cypherResolver or not.
func TestScanProfileWorker_EmptyTargetQuery_UsesResolveTargets(t *testing.T) {
	calls := 0
	profiles := &fakeProfileRunnerWithResolveTargets{
		fakeProfileRunner: fakeProfileRunner{profile: scan.ScanProfile{ID: "p2"}},
		resolveTargets: func() ([]scan.Target, error) {
			calls++
			return nil, errors.New("no external assets")
		},
	}
	w := &ScanProfileWorker{
		profiles: profiles,
		scanSvc:  &fakeProfileScanner{},
		finder:   &fakeProfileFindingRecorder{},
	}

	err := w.Work(context.Background(), &river.Job[ScanProfileJobArgs]{Args: ScanProfileJobArgs{ProfileID: "p2", RunID: "r2"}})
	require.Error(t, err)
	require.Equal(t, 1, calls, "ResolveTargets must be called when TargetQuery is empty")
}

// fakeProfileRunnerWithResolveTargets overrides fakeProfileRunner's panicking
// ResolveTargets so the empty-TargetQuery path can be exercised directly.
type fakeProfileRunnerWithResolveTargets struct {
	fakeProfileRunner
	resolveTargets func() ([]scan.Target, error)
}

func (f *fakeProfileRunnerWithResolveTargets) ResolveTargets(context.Context, scan.ScanProfile) ([]scan.Target, error) {
	return f.resolveTargets()
}

// TestScanProfileWorker_CypherZeroTargets_FailsRunInsteadOfAutoResolving:
// a cold/rebuilding Ladybug, a graph swap mid-flight, or a renamed edge label
// all resolve a TargetQuery to zero nodes, and a run over that empty set
// would report StatusCompleted as if the profile's targets were scanned
// clean. This must fail the run instead, and must never reach
// scanSvc/finder at all — the fakes panic on any call, proving the guard
// fires before *any* scan work happens.
func TestScanProfileWorker_CypherZeroTargets_FailsRunInsteadOfAutoResolving(t *testing.T) {
	profiles := &fakeProfileRunner{profile: scan.ScanProfile{
		ID:          "p3",
		TargetQuery: "MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'}) RETURN a",
	}}
	cypher := &fakeCypherResolver{targets: nil} // legitimate empty match, not a resolver error

	w := &ScanProfileWorker{
		profiles:       profiles,
		scanSvc:        panicProfileScanner{},
		finder:         panicProfileFindingRecorder{},
		cypherResolver: cypher,
	}

	err := w.Work(context.Background(), &river.Job[ScanProfileJobArgs]{Args: ScanProfileJobArgs{ProfileID: "p3", RunID: "r3"}})
	require.Error(t, err)
	require.ErrorContains(t, err, "zero targets")
	require.Equal(t, 1, cypher.calls)
	require.True(t, profiles.finished)
	require.Equal(t, scan.StatusFailed, profiles.finishStatus)
}

// panicProfileScanner/panicProfileFindingRecorder panic on any call, so a
// test using them fails loudly (not silently-green) if the zero-target guard
// above is ever removed and scan work proceeds against an empty target set.
type panicProfileScanner struct{}

func (panicProfileScanner) ScanTargets(context.Context, []scan.Target, []string) (scan.ScanOutput, error) {
	panic("ScanTargets must not be called for a profile that resolved zero targets")
}

type panicProfileFindingRecorder struct{}

func (panicProfileFindingRecorder) RecordObserved(context.Context, []finding.Finding) error {
	panic("RecordObserved must not be called for a profile that resolved zero targets")
}

type fakeDriftRunner struct {
	fakeProfileRunner
	finishErr error
}

func (f *fakeDriftRunner) CreateRunForProfile(context.Context, string, int) (scan.Run, error) {
	return scan.Run{ID: "run-1"}, nil
}

func (f *fakeDriftRunner) FinishRun(ctx context.Context, runID string, status scan.Status, n int, errMsg string) error {
	_ = f.fakeProfileRunner.FinishRun(ctx, runID, status, n, errMsg)
	return f.finishErr
}

type fakeSingleAsset struct{ a asset.Asset }

func (f fakeSingleAsset) Get(context.Context, string) (asset.Asset, error) { return f.a, nil }

// A drift scan that fails and then cannot mark its run failed surfaces both
// errors: the run would otherwise sit as running with nobody told.
func TestScanAssetWorker_FinishRunFailureIsReturned(t *testing.T) {
	scanErr := errors.New("nuclei crashed")
	finishErr := errors.New("pg down")
	runner := &fakeDriftRunner{finishErr: finishErr}
	w := &ScanAssetWorker{
		profiles: runner,
		scanSvc:  &fakeProfileScanner{err: scanErr},
		finder:   &fakeProfileFindingRecorder{},
		assets:   fakeSingleAsset{a: asset.Asset{ID: "a1", Domain: "example.test"}},
	}
	err := w.Work(context.Background(), &river.Job[ScanAssetArgs]{Args: ScanAssetArgs{ProfileID: "p", AssetID: "a1"}})
	require.ErrorIs(t, err, scanErr)
	require.ErrorIs(t, err, finishErr)
	require.True(t, runner.finished)
	require.Equal(t, scan.StatusFailed, runner.finishStatus)
	require.Equal(t, scanErr.Error(), runner.finishErrMsg)

	runner.finishErr = nil
	err = w.Work(context.Background(), &river.Job[ScanAssetArgs]{Args: ScanAssetArgs{ProfileID: "p", AssetID: "a1"}})
	require.ErrorIs(t, err, scanErr)
	require.NotErrorIs(t, err, finishErr)
}

// hostErrScanner fails the scan of every host in failHosts, returns nothing
// for a host in emptyHosts, and returns one result for any other host.
type hostErrScanner struct{ failHosts, emptyHosts map[string]bool }

func (s hostErrScanner) ScanTargets(_ context.Context, targets []scan.Target, _ []string) (scan.ScanOutput, error) {
	if s.failHosts[targets[0].Host] {
		return scan.ScanOutput{}, errors.New("scanner down")
	}
	if s.emptyHosts[targets[0].Host] {
		return scan.ScanOutput{}, nil
	}
	return scan.ScanOutput{Results: []scan.Result{{Scanner: "nuclei", TemplateID: "tpl-1", Severity: "high"}}}, nil
}

// A profile run where no target completed must not reconcile: an empty
// finding set would auto-resolve every confirmed finding of the profile.
// A mixed run reconciles, but only the completed targets may resolve, and it
// is completed (not failed) even when the completed targets found nothing,
// since their reconciliation resolved findings.
func TestScanProfileWorker_ReconcilesOnlyCompletedTargets(t *testing.T) {
	targets := []scan.Target{{Host: "a.example"}, {Host: "b.example"}}
	cases := []struct {
		name       string
		fail       map[string]bool
		empty      map[string]bool
		wantRecon  [][]string
		wantStatus scan.Status
		wantErrMsg string
	}{
		{"all targets error", map[string]bool{"a.example": true, "b.example": true}, nil,
			nil, scan.StatusFailed, "all 2 target(s) errored, nothing reconciled"},
		{"mixed", map[string]bool{"b.example": true}, nil,
			[][]string{{"a.example"}}, scan.StatusCompleted, "1 of 2 target(s) errored; only completed targets were reconciled"},
		{"mixed, completed target found nothing", map[string]bool{"b.example": true}, map[string]bool{"a.example": true},
			[][]string{{"a.example"}}, scan.StatusCompleted, "1 of 2 target(s) errored; only completed targets were reconciled"},
		{"all completed", nil, nil, [][]string{{"a.example", "b.example"}}, scan.StatusCompleted, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profiles := &fakeProfileRunnerWithResolveTargets{
				fakeProfileRunner: fakeProfileRunner{profile: scan.ScanProfile{ID: "p"}},
				resolveTargets:    func() ([]scan.Target, error) { return targets, nil },
			}
			w := &ScanProfileWorker{
				profiles: profiles,
				scanSvc:  hostErrScanner{failHosts: tc.fail, emptyHosts: tc.empty},
				finder:   &fakeProfileFindingRecorder{},
			}
			require.NoError(t, w.Work(context.Background(), &river.Job[ScanProfileJobArgs]{Args: ScanProfileJobArgs{ProfileID: "p", RunID: "r"}}))
			for _, r := range profiles.reconciled {
				slices.Sort(r)
			}
			require.Equal(t, tc.wantRecon, profiles.reconciled)
			require.Equal(t, tc.wantStatus, profiles.finishStatus)
			require.Equal(t, tc.wantErrMsg, profiles.finishErrMsg)
		})
	}
}

func TestProfileResultsToScanFindings_KeyedByTargetHost(t *testing.T) {
	got := profileResultsToScanFindings("r", []scan.Result{{TemplateID: "tpl-1"}}, scan.Target{Host: "a.example"}, time.Now())
	require.Len(t, got, 1)
	require.Equal(t, "a.example", got[0].AssetID)
}
