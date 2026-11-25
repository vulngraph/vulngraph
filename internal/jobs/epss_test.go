package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/intel/epss"
)

type fakeEPSSFetcher struct {
	cat *epss.Catalog
	err error
}

func (f fakeEPSSFetcher) Fetch(context.Context) (*epss.Catalog, error) { return f.cat, f.err }

func TestEPSSWorker_RefreshesCache(t *testing.T) {
	cache := epss.NewCache()
	w := &EPSSWorker{
		fetcher: fakeEPSSFetcher{cat: epss.NewCatalog(map[string]float64{"CVE-2021-44228": 0.97})},
		cache:   cache,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshEPSSArgs]{}))

	s, ok := cache.Score("CVE-2021-44228")
	require.True(t, ok)
	require.InDelta(t, 0.97, s, 1e-9)
}

func TestEPSSWorker_FetchErrorLeavesCacheIntact(t *testing.T) {
	cache := epss.NewCache()
	w := &EPSSWorker{fetcher: fakeEPSSFetcher{err: errors.New("boom")}, cache: cache}
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshEPSSArgs]{}))
	_, ok := cache.Score("CVE-2021-44228")
	require.False(t, ok)
}

// TestEPSSWorker_PopulatesCacheReadByEnrichSource proves the production wiring
// (cmd/graph/worker.go): the refresh job and the enrich source share ONE
// *epss.Cache instance. The job Sets a freshly-fetched catalog and the enrich
// EPSS source reads scores from that same cache and awards points. Before the
// job runs the cache is empty, so the source reports itself unmeasured — the
// dark state a fresh worker sits in until the periodic fires.
func TestEPSSWorker_PopulatesCacheReadByEnrichSource(t *testing.T) {
	cache := epss.NewCache()
	source := enrich.EPSS{Scores: cache} // same instance the worker writes
	cve := finding.Finding{Source: "supply_chain", CheckID: "CVE-2021-44228"}

	// Empty cache → the source is unmeasured, not "below 1%" (the dark state
	// before the first refresh).
	_, applied, err := source.Evaluate(context.Background(), cve)
	require.ErrorIs(t, err, enrich.ErrSourceNotReady)
	require.False(t, applied, "empty cache: EPSS must contribute nothing")

	// The periodic refresh fetches the feed and swaps it into the shared cache.
	w := &EPSSWorker{
		fetcher: fakeEPSSFetcher{cat: epss.NewCatalog(map[string]float64{"CVE-2021-44228": 0.97})},
		cache:   cache,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshEPSSArgs]{}))

	// Same source, same cache → now awards the high-band points.
	factor, applied, err := source.Evaluate(context.Background(), cve)
	require.NoError(t, err)
	require.True(t, applied, "after refresh: EPSS must score the CVE from the shared cache")
	require.Equal(t, 15, factor.Points)
	require.Equal(t, "epss", factor.Source)
}
