package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeRepo struct {
	run         Run
	finished    Run
	scannerName string
	staleCutoff time.Time // captured by FailStaleRuns
	staleIDs    []string  // returned by FailStaleRuns
}

func (f *fakeRepo) CreateRun(_ context.Context, targetCount int) (Run, error) {
	f.run = Run{ID: "run-1", Status: StatusRunning, TargetCount: targetCount}
	return f.run, nil
}
func (f *fakeRepo) FinishRun(_ context.Context, id string, status Status, findingCount int, scanErr string, _ []string, _ int, _ []string, scannerName string) error {
	f.finished = Run{ID: id, Status: status, FindingCount: findingCount, Error: scanErr}
	f.scannerName = scannerName
	return nil
}
func (f *fakeRepo) GetRun(_ context.Context, id string) (Run, error) {
	if id == f.run.ID {
		return f.run, nil
	}
	return Run{}, ErrNotFound
}
func (f *fakeRepo) CancelRun(_ context.Context, _ string) error      { return nil }
func (f *fakeRepo) ListRuns(_ context.Context, _ int) ([]Run, error) { return []Run{f.run}, nil }
func (f *fakeRepo) FailStaleRuns(_ context.Context, cutoff time.Time) ([]string, error) {
	f.staleCutoff = cutoff
	return f.staleIDs, nil
}

type fakeAssets struct{ external []asset.Asset }

func (f fakeAssets) ListExternal(context.Context, int) ([]asset.Asset, error) {
	return f.external, nil
}

type fakeResolver struct{ assets []asset.Asset }

func (f *fakeResolver) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	var out []asset.Asset
	for _, a := range f.assets {
		for _, id := range ids {
			if a.ID == id {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func (f *fakeResolver) List(_ context.Context, _ asset.Filter) ([]asset.Asset, error) {
	return f.assets, nil
}

type fakeScanner struct {
	name       string
	caps       Capability
	results    []Result
	err        error
	gotTargets []Target
	gotTags    []string
}

func (f *fakeScanner) Name() string {
	if f.name == "" {
		return "fake"
	}
	return f.name
}

func (f *fakeScanner) Capabilities() Capability {
	if f.caps == 0 {
		return CapWeb // default fakes scan web targets unless told otherwise
	}
	return f.caps
}

func (f *fakeScanner) Scan(_ context.Context, targets []Target, templateTags []string) (ScanOutput, error) {
	f.gotTargets = targets
	f.gotTags = templateTags
	if f.err != nil {
		return ScanOutput{}, f.err
	}
	return ScanOutput{Results: f.results, TemplateTags: []string{"test"}, TemplateCount: len(f.results)}, nil
}

// gotURLs is the set of target URLs the scanner was handed, for assertions.
func (f *fakeScanner) gotURLs() []string {
	urls := make([]string, 0, len(f.gotTargets))
	for _, t := range f.gotTargets {
		urls = append(urls, t.URL)
	}
	return urls
}

type fakeFindings struct {
	recorded []finding.Finding
	listed   []finding.Finding // returned by List
}

func (f *fakeFindings) RecordObserved(_ context.Context, fs []finding.Finding) error {
	f.recorded = append(f.recorded, fs...)
	return nil
}

func (f *fakeFindings) List(_ context.Context, _ finding.Filter) ([]finding.Finding, error) {
	return f.listed, nil
}

func TestRunScan_HappyPath(t *testing.T) {
	repo := &fakeRepo{}
	assets := fakeAssets{external: []asset.Asset{
		{ID: "i-1", Type: "ec2_instance", Region: "eu-west-1", PublicIP: "1.2.3.4"},
		{ID: "site", Type: "github_repo", Domain: "example.com"},
	}}
	scanner := &fakeScanner{name: "nuclei", results: []Result{
		{Scanner: "nuclei", TemplateID: "CVE-2021-1", Name: "Bad", Severity: "high", MatchedURL: "https://1.2.3.4"},
		{Scanner: "nuclei", TemplateID: "tech", Name: "Tech", Severity: "info", MatchedURL: "https://example.com"},
	}}
	findings := &fakeFindings{}
	svc := NewService(repo, assets, &fakeResolver{}, scanner, findings)

	run, recorded, err := svc.RunScan(context.Background())
	require.NoError(t, err)

	require.ElementsMatch(t, []string{"https://1.2.3.4", "https://example.com"}, scanner.gotURLs())
	require.Equal(t, StatusCompleted, repo.finished.Status)
	require.Equal(t, 2, repo.finished.FindingCount)
	require.Equal(t, StatusCompleted, run.Status)
	require.Len(t, recorded, 2, "RunScan returns the recorded findings for enrichment")

	require.Len(t, findings.recorded, 2)
	byCheck := map[string]finding.Finding{}
	for _, f := range findings.recorded {
		byCheck[f.CheckID] = f
		require.Equal(t, "nuclei", f.Source)
	}
	require.Equal(t, "i-1", byCheck["CVE-2021-1"].ResourceID, "finding attributed to the asset behind its URL")
	require.Equal(t, finding.SeverityHigh, byCheck["CVE-2021-1"].Severity)
}

func TestRunScan_EngineError_MarksFailed(t *testing.T) {
	repo := &fakeRepo{}
	assets := fakeAssets{external: []asset.Asset{{ID: "i-1", PublicIP: "1.2.3.4"}}}
	scanner := &fakeScanner{err: errors.New("scan exploded")}
	svc := NewService(repo, assets, &fakeResolver{}, scanner, &fakeFindings{})

	_, _, err := svc.RunScan(context.Background())
	require.ErrorContains(t, err, "scan exploded")
	require.Equal(t, StatusFailed, repo.finished.Status)
}

func TestReapStaleRuns(t *testing.T) {
	repo := &fakeRepo{staleIDs: []string{"orphan-1", "orphan-2"}}
	svc := NewService(repo, fakeAssets{}, &fakeResolver{}, &fakeScanner{}, &fakeFindings{})

	before := time.Now()
	ids, err := svc.ReapStaleRuns(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"orphan-1", "orphan-2"}, ids)

	// Cutoff is at least the scan timeout in the past, so a legitimately long
	// scan is never reaped — only genuinely orphaned rows.
	require.True(t, repo.staleCutoff.Before(before.Add(-4*time.Hour)),
		"reap cutoff must be older than the 4h scan job timeout, got %v", repo.staleCutoff)
}

func TestRunScan_NoExternalAssets(t *testing.T) {
	repo := &fakeRepo{}
	scanner := &fakeScanner{}
	svc := NewService(repo, fakeAssets{}, &fakeResolver{}, scanner, &fakeFindings{})

	run, _, err := svc.RunScan(context.Background())
	require.NoError(t, err)
	require.Equal(t, 0, run.TargetCount)
	require.Empty(t, scanner.gotTargets)
	require.Equal(t, StatusCompleted, repo.finished.Status)
}

func TestTargetsFor_PrefersDomainAndDedups(t *testing.T) {
	targets, byURL := targetsFor([]asset.Asset{
		{ID: "a", Domain: "x.com", PublicIP: "1.1.1.1"}, // domain wins
		{ID: "b", PublicIP: "2.2.2.2"},
		{ID: "c"},                  // no host — skipped
		{ID: "d", Domain: "x.com"}, // duplicate URL — deduped
	})
	urls := make([]string, len(targets))
	hostByURL := map[string]string{}
	for i, tg := range targets {
		urls[i] = tg.URL
		hostByURL[tg.URL] = tg.Host
	}
	require.ElementsMatch(t, []string{"https://x.com", "https://2.2.2.2"}, urls)
	require.Equal(t, "x.com", hostByURL["https://x.com"], "Host carried alongside URL for network scanners")
	require.Equal(t, "a", byURL["https://x.com"].ID)
}

func TestNormalizeSeverity(t *testing.T) {
	require.Equal(t, finding.SeverityHigh, normalizeSeverity("high"))
	require.Equal(t, finding.SeverityInfo, normalizeSeverity("bogus"))
	require.Equal(t, finding.SeverityInfo, normalizeSeverity(""))
}

func TestToFindings_DeterministicID(t *testing.T) {
	results := []Result{{TemplateID: "t1", MatchedURL: "https://x"}}
	a := map[string]asset.Asset{"https://x": {ID: "asset-1"}}
	first := toFindings(results, a, time.Now())
	second := toFindings(results, a, time.Now().Add(time.Hour))
	require.Equal(t, first[0].ID, second[0].ID)
}

func TestToFindings_CarriesContext(t *testing.T) {
	results := []Result{{
		TemplateID:  "redpanda-console",
		Name:        "Redpanda Console - Exposure",
		Severity:    "medium",
		MatchedURL:  "https://console.example.com",
		Description: "Detects an exposed Redpanda console.",
		Remediation: "Put it behind auth.",
		Reference:   "https://ref1\nhttps://ref2",
		Evidence:    "HTTP 200, title match",
	}}
	// No matching asset → resource falls back to the scanned URL.
	got := toFindings(results, map[string]asset.Asset{}, time.Now())
	require.Len(t, got, 1)
	f := got[0]

	require.Equal(t, "Detects an exposed Redpanda console.", f.Description)
	require.Equal(t, "Put it behind auth.", f.Remediation)
	require.Equal(t, "https://console.example.com", f.Metadata["matched_url"])
	require.Equal(t, "HTTP 200, title match", f.Metadata["evidence"])
	require.Equal(t, "https://ref1\nhttps://ref2", f.Metadata["references"])
	// Resource fallback so the detail view is never blank.
	require.Equal(t, "https://console.example.com", f.ResourceID)
	require.Equal(t, "endpoint", f.ResourceType)
}

func TestToFindings_PrefersMatchedAsset(t *testing.T) {
	results := []Result{{TemplateID: "t1", MatchedURL: "https://x"}}
	a := map[string]asset.Asset{"https://x": {ID: "asset-1", Type: "load_balancer", Name: "lb-1"}}
	got := toFindings(results, a, time.Now())
	require.Equal(t, "asset-1", got[0].ResourceID)
	require.Equal(t, "load_balancer", got[0].ResourceType)
}
