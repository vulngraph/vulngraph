package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/kevwatch"
	"github.com/vulngraph/vulngraph/internal/intel/kev"
)

type fakeKEVAdditions struct {
	entries []kevwatch.Entry
	open    map[string]int
	err     error
	calls   int
}

func (f *fakeKEVAdditions) Reconcile(_ context.Context, entries []kevwatch.Entry, open map[string]int) ([]kevwatch.Addition, error) {
	f.calls++
	f.entries, f.open = entries, open
	return nil, f.err
}

// The refresh hands the whole catalog (with dateAdded) and the open-finding
// count per KEV CVE to the additions diff.
func TestKEVWorker_RecordsAdditions(t *testing.T) {
	added := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: "1", Source: "nuclei", CheckID: "CVE-2026-0001"},
		{ID: "2", Source: "supply_chain", CheckID: "MAL-1", Metadata: map[string]string{"cve": "cve-2026-0001"}},
		{ID: "3", Source: "nuclei", CheckID: "CVE-2099-0000"},
	}}
	rec := &fakeKEVAdditions{}
	w := &KEVWorker{
		fetcher:   fakeKEVFetcher{cat: kev.NewCatalogFromEntries([]kev.Entry{{CVEID: "CVE-2026-0001", DateAdded: added, Name: "n"}})},
		findings:  store,
		additions: rec,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.Equal(t, []kevwatch.Entry{{CVEID: "CVE-2026-0001", DateAdded: added, Name: "n"}}, rec.entries)
	require.Equal(t, map[string]int{"CVE-2026-0001": 2}, rec.open)
}

// A failed diff fails the job (River retries it); the flag write already made
// stands.
func TestKEVWorker_AdditionFailureFailsTheJob(t *testing.T) {
	store := &fakeFindingStore{list: []finding.Finding{{ID: "1", Source: "nuclei", CheckID: "CVE-2026-0001"}}}
	boom := errors.New("pg down")
	w := &KEVWorker{
		fetcher:   fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2026-0001"})},
		findings:  store,
		additions: &fakeKEVAdditions{err: boom},
	}
	require.ErrorIs(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}), boom)
	require.Len(t, store.recordedEnrichment, 1)
}

// A failed finding scan returns before the diff, so the catalog is not marked
// seen and the next refresh reports the same additions.
func TestKEVWorker_ScanFailureSkipsTheDiff(t *testing.T) {
	store := &fakeFindingStore{list: []finding.Finding{{ID: "1", Source: "nuclei", CheckID: "CVE-2026-0001"}}, listErr: errors.New("ch down")}
	rec := &fakeKEVAdditions{}
	w := &KEVWorker{fetcher: fakeKEVFetcher{cat: kev.NewCatalog([]string{"CVE-2026-0001"})}, findings: store, additions: rec}
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshKEVArgs]{}))
	require.Zero(t, rec.calls)
}
