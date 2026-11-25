package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/intel/kev"
)

type fakeKEVFetcher struct {
	cat *kev.Catalog
	err error
}

func (f fakeKEVFetcher) Fetch(context.Context) (*kev.Catalog, error) {
	return f.cat, f.err
}

type fakeFindingStore struct {
	mu                 sync.Mutex
	list               []finding.Finding
	recorded           []finding.Finding
	recordedEnrichment []finding.Enrichment
	resolved           []finding.Finding
	// reasons records the ResolutionReason each finding was resolved WITH, so a
	// test can tell resource_gone from fixed.
	reasons   map[string]finding.ResolutionReason
	listErr   error
	recordErr error
	// offsets tracks how many items have already been returned per source, so
	// List can honor real pagination semantics without needing to decode the
	// caller's opaque cursor string — a cursor=="" call resets to page one (the
	// real listAll's first call), any non-empty cursor means "give me the next
	// page after wherever we left off".
	offsets map[string]int
	// gotFilters records every Filter List was called with, so a test can
	// assert listAll actually passed CVEIn through — this fake deliberately
	// does NOT itself filter by CVEIn (see List's own comment), so a bug that
	// dropped the field silently would otherwise still pass every other
	// assertion here (kev.Enrich's own Go-side check would still find and
	// escalate the right findings from the unfiltered list).
	gotFilters []finding.Filter
	// fresh, when set, is what ByIDs returns for an id instead of the list
	// entry — the row as it stands at write time, after a concurrent writer.
	fresh map[string]finding.Finding
}

func (f *fakeFindingStore) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []finding.Finding
	for _, fd := range f.list {
		if !want[fd.ID] {
			continue
		}
		if fr, ok := f.fresh[fd.ID]; ok {
			fd = fr
		}
		out = append(out, fd)
	}
	return out, nil
}

// List honors filter.Limit and treats filter.Cursor purely as a page-boundary
// signal (empty = start over, non-empty = continue) so tests can prove
// listAll actually walks every page instead of stopping at the first one.
// Deliberately does NOT filter by CVEIn itself — see TestKEVWorker_PassesCVEInFilter,
// which asserts on gotFilters instead, so this fake's behavior stays
// independent of whether the production SQL pushdown is correctly wired.
func (f *fakeFindingStore) List(_ context.Context, filter finding.Filter) ([]finding.Finding, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotFilters = append(f.gotFilters, filter)
	var matched []finding.Finding
	for _, fd := range f.list {
		if filter.Source == "" || fd.Source == filter.Source {
			matched = append(matched, fd)
		}
	}
	if f.offsets == nil {
		f.offsets = make(map[string]int)
	}
	offset := f.offsets[filter.Source]
	if filter.Cursor == "" {
		offset = 0
	}
	if offset >= len(matched) {
		return nil, nil
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = len(matched)
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	f.offsets[filter.Source] = end
	return matched[offset:end], nil
}
func (f *fakeFindingStore) Record(_ context.Context, fs []finding.Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, fs...)
	return f.recordErr
}

func (f *fakeFindingStore) RecordEnrichment(_ context.Context, enrichments []finding.Enrichment) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recordedEnrichment = append(f.recordedEnrichment, enrichments...)
	return nil
}

// RecordObserved mirrors Record for these tests' purposes — none of them
// exercise the real carry-forward-enrichment behavior that distinguishes it
// in production (finding.Service.RecordObserved); that's covered directly in
// internal/app/finding's own tests. Producer-worker tests here only care that
// their findings landed in .recorded.
func (f *fakeFindingStore) RecordObserved(_ context.Context, fs []finding.Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recorded = append(f.recorded, fs...)
	return f.recordErr
}

func (f *fakeFindingStore) Resolve(_ context.Context, fs []finding.Finding, reason finding.ResolutionReason) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, fs...)
	if f.reasons == nil {
		f.reasons = map[string]finding.ResolutionReason{}
	}
	for _, fd := range fs {
		f.reasons[fd.ID] = reason
	}
	return nil
}

// TestKEVWorker_FlagsEverySourceEnrichmentOnly pins three things: the scan is
// by CVE across every source (vm_vuln emits CVE findings too, and a source
// allowlist silently skipped them), the only write is to finding_enrichment
// (a findings-row write from the List read could reopen a finding resolved
// since), and EnrichedAt is stamped now (the argMax version — reusing the
// stored value ties with the row being superseded).
func TestKEVWorker_FlagsEverySourceEnrichmentOnly(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	prior := now.Add(-time.Hour)
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: "1", Source: "nuclei", CheckID: "CVE-2021-44228", Severity: finding.SeverityMedium},
		{ID: "2", Source: "nuclei", CheckID: "CVE-2099-0000", Severity: finding.SeverityHigh},
		{ID: "3", Source: "supply_chain", CheckID: "CVE-2021-44228", Severity: finding.SeverityHigh},
		{ID: "4", Source: "vm_vuln", Type: "vulnerability", CheckID: "CVE-2021-44228", Severity: finding.SeverityHigh,
			Score: 70, ScoreBand: "high", MustFixClass: "routine", EnrichedAt: prior},
	}}
	w := &KEVWorker{
		fetcher:  fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2021-44228"})},
		findings: store,
		now:      func() time.Time { return now },
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.Empty(t, store.recorded, "KEV never writes the findings row")
	for _, f := range store.gotFilters {
		require.Empty(t, f.Source, "the CVE scan must not be scoped to a source allowlist")
	}
	byID := map[string]finding.Enrichment{}
	for _, enr := range store.recordedEnrichment {
		byID[enr.ID] = enr
	}
	require.Len(t, byID, 3)
	require.Contains(t, byID, "4", "a vm_vuln CVE finding is flagged too")
	for _, enr := range byID {
		require.True(t, enr.KnownExploited)
		require.Equal(t, now, enr.EnrichedAt, "EnrichedAt is stamped now, never reused or zero")
	}
	require.Equal(t, uint8(70), byID["4"].Score, "the other enrichment outputs are carried forward")
	require.Equal(t, "routine", byID["4"].MustFixClass)
}

// TestKEVWorker_WritesFromFreshRead pins that the enrichment write is built
// from a re-read taken just before it, not from the List read: an enrich that
// landed in between must not be rolled back, and a finding another writer
// already flagged is not rewritten.
func TestKEVWorker_WritesFromFreshRead(t *testing.T) {
	store := &fakeFindingStore{
		list: []finding.Finding{
			{ID: "1", Source: "nuclei", CheckID: "CVE-2021-44228"},
			{ID: "2", Source: "nuclei", CheckID: "CVE-2021-44228"},
		},
		fresh: map[string]finding.Finding{
			"1": {ID: "1", Source: "nuclei", CheckID: "CVE-2021-44228", Score: 55, MustFixClass: "elevated"},
			"2": {ID: "2", Source: "nuclei", CheckID: "CVE-2021-44228", KnownExploited: true},
		},
	}
	w := &KEVWorker{fetcher: fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2021-44228"})}, findings: store}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.Len(t, store.recordedEnrichment, 1, "a finding already flagged at write time is not rewritten")
	require.Equal(t, "1", store.recordedEnrichment[0].ID)
	require.Equal(t, uint8(55), store.recordedEnrichment[0].Score)
	require.Equal(t, "elevated", store.recordedEnrichment[0].MustFixClass)
}

// TestKEVWorker_PaginatesPastFirstPage pins pagination: a KEV-listed CVE
// sitting beyond the first kevListPageLimit-sized page must
// still be found and escalated, not silently missed because the scan stopped
// at page one.
func TestKEVWorker_PaginatesPastFirstPage(t *testing.T) {
	var list []finding.Finding
	for i := 0; i < kevListPageLimit+50; i++ {
		list = append(list, finding.Finding{
			ID: fmt.Sprintf("filler-%d", i), Source: "supply_chain",
			CheckID: "CVE-2099-0000", Severity: finding.SeverityLow,
		})
	}
	// The KEV-listed finding sits well past the first page.
	list = append(list, finding.Finding{
		ID: "the-real-one", Source: "supply_chain",
		CheckID: "CVE-2021-44228", Severity: finding.SeverityHigh,
	})
	store := &fakeFindingStore{list: list}
	w := &KEVWorker{
		fetcher:  fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2021-44228"})},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.Len(t, store.recordedEnrichment, 1, "the KEV match beyond page 1 must still be found and flagged")
	require.Equal(t, "the-real-one", store.recordedEnrichment[0].ID)
	require.True(t, store.recordedEnrichment[0].KnownExploited)
}

func TestKEVWorker_NoEscalations_NoWrite(t *testing.T) {
	store := &fakeFindingStore{list: []finding.Finding{{ID: "1", Source: "nuclei", CheckID: "CVE-2099-0000", Severity: finding.SeverityLow}}}
	w := &KEVWorker{fetcher: fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2021-44228"})}, findings: store}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.Empty(t, store.recordedEnrichment)
}

// TestKEVWorker_PassesCVEInFilter guards the fix for
// refresh_kev's ClickHouse timeout: listAll must push the catalog's own CVE
// list into Filter.CVEIn (a pre-aggregation SQL predicate) rather than
// fetching every open finding for the source and filtering in Go. The fake
// store deliberately ignores CVEIn (see its own comment) precisely so this
// is the one test that would fail if that field were ever dropped from the
// call — every other KEVWorker test would keep passing regardless, since
// kev.Enrich's own Go-side check still finds the right findings either way.
func TestKEVWorker_PassesCVEInFilter(t *testing.T) {
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: "1", Source: "nuclei", CheckID: "CVE-2021-44228", Severity: finding.SeverityHigh},
	}}
	w := &KEVWorker{
		fetcher:  fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2021-44228", "CVE-2024-0001"})},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.NotEmpty(t, store.gotFilters, "listAll must have called List")
	for _, f := range store.gotFilters {
		require.ElementsMatch(t, []string{"CVE-2021-44228", "CVE-2024-0001"}, f.CVEIn,
			"every List call must carry the full catalog CVE list as a pre-aggregation filter")
	}
}

func TestKEVWorker_FetchError(t *testing.T) {
	w := &KEVWorker{fetcher: fakeKEVFetcher{err: errors.New("cisa down")}, findings: &fakeFindingStore{}}
	err := w.Work(context.Background(), &river.Job[RefreshKEVArgs]{})
	require.ErrorContains(t, err, "cisa down")
}

// TestRefreshKEVInsertOptsCapsRetries pins MaxAttempts against River's library
// default of 25, which an InsertOpts setting only Queue silently inherits —
// the same guard as TestCorrelateInsertOptsCapsRetries and
// TestEnrichSweepInsertOptsCapsRetries: if refresh_kev blocks on ClickHouse's
// concurrency semaphore during a routine post-restart boot storm, with no cap
// it is left to grind through ~attempt^4 backoff for up to 25 attempts
// (potentially days) re-walking its full pagination from scratch each time,
// instead of surfacing loud after one retry.
func TestRefreshKEVInsertOptsCapsRetries(t *testing.T) {
	opts := RefreshKEVArgs{}.InsertOpts()
	require.Equal(t, 2, opts.MaxAttempts,
		"a failing KEV refresh must surface after one retry, not grind for ~25 attempts")
	require.Equal(t, queueFeeds, opts.Queue)
	require.Equal(t, uniqueStates, opts.UniqueOpts.ByState, "a refresh is a singleton while queued/running")
}
