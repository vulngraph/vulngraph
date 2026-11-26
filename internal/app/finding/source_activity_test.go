package finding

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A source with zero live rows must still appear, reporting 0 — the whole
// reason mergeExpectedSources exists (ZERO IS A FINDING, obs.SourceActivityStat's
// doc comment). A ClickHouse GROUP BY has no row to report it from at all.
func TestMergeExpectedSourcesReportsZeroForNeverProduced(t *testing.T) {
	live := []SourceActivity{{Source: "cspm", LastActivityUnix: 1720000000}}
	expected := []string{"cspm", "supply_chain"}

	got := mergeExpectedSources(live, expected)

	byName := map[string]int64{}
	for _, sa := range got {
		byName[sa.Source] = sa.LastActivityUnix
	}
	assert.Equal(t, int64(1720000000), byName["cspm"])
	gotSupplyChain, ok := byName["supply_chain"]
	require.True(t, ok, "an expected source with no live rows must still be reported")
	assert.Zero(t, gotSupplyChain, "an expected source that has never produced must report 0, not be omitted")
}

// sourceActivityTimeout must stay at or below obsScrapeBudget, the same
// invariant TestCheckQualityTimeoutFitsTheScrapeBudget (quality_test.go)
// checks for its sibling, so the same class of drift (see obsScrapeBudget's
// comment) is caught independently here too.
func TestSourceActivityTimeoutFitsTheScrapeBudget(t *testing.T) {
	require.LessOrEqual(t, sourceActivityTimeout, obsScrapeBudget,
		"sourceActivityTimeout can never exceed the /metrics scrape budget that wraps it")
	require.Positive(t, sourceActivityTimeout, "a full-table aggregate needs its own deadline")
}

// A live source outside the expected list (e.g. one not yet triaged into
// ExpectedActivitySources) must still surface — this merge only ever adds
// rows, never hides real activity.
func TestMergeExpectedSourcesKeepsUnexpectedLiveSources(t *testing.T) {
	live := []SourceActivity{{Source: "some_new_source", LastActivityUnix: 42}}

	got := mergeExpectedSources(live, []string{"cspm"})

	byName := map[string]int64{}
	for _, sa := range got {
		byName[sa.Source] = sa.LastActivityUnix
	}
	assert.Equal(t, int64(42), byName["some_new_source"])
	assert.Zero(t, byName["cspm"])
}

// SourceActivity's Service-level passthrough must apply the merge, not just
// forward the repo's raw (zero-omitting) rows.
func TestServiceSourceActivityMergesExpected(t *testing.T) {
	observed, err := time.Parse(time.RFC3339, "2026-08-01T00:00:00Z")
	require.NoError(t, err)
	repo := &fakeRepo{stored: []Finding{
		{ID: "1", Source: "cspm", LastObservedAt: observed},
	}}
	svc := NewService(repo)

	got, err := svc.SourceActivity(context.Background())
	require.NoError(t, err)

	byName := map[string]int64{}
	for _, sa := range got {
		byName[sa.Source] = sa.LastActivityUnix
	}
	assert.NotZero(t, byName["cspm"])
	for _, expected := range ExpectedActivitySources {
		_, ok := byName[expected]
		assert.Truef(t, ok, "expected source %q missing from the merged result", expected)
	}
}

// erroringSourceActivityRepo embeds fakeRepo (satisfying the rest of Repo for
// free) and overrides only SourceActivity, so the repo error path can be
// exercised without adding an error-injection field to the shared fakeRepo
// fixture every other test in this package also uses.
type erroringSourceActivityRepo struct {
	*fakeRepo
}

func (erroringSourceActivityRepo) SourceActivity(context.Context) ([]SourceActivity, error) {
	return nil, errors.New("clickhouse: connection refused")
}

// Regression: Service.SourceActivity returned the repo's error bare (`return nil, err`) instead
// of wrapping it with context — CLAUDE.md: "Always wrap with context...
// never bare return err" — unlike every sibling method in this package
// (List/Get/ByIDs/ByResourceIDs/DistinctCheckIDs/CountByCheckID all wrap).
func TestServiceSourceActivity_WrapsRepoError(t *testing.T) {
	svc := NewService(erroringSourceActivityRepo{fakeRepo: &fakeRepo{}})

	_, err := svc.SourceActivity(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SourceActivity:", "must be wrapped with its own frame, matching every sibling method")
	assert.Contains(t, err.Error(), "connection refused", "the underlying repo error must still be visible, not swallowed")
}

func TestSourceActivityOmitsRetiredScanning(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{
		{ID: "old", Source: "nuclei", LastObservedAt: time.Now()},
		{ID: "import", Source: "custom", LastObservedAt: time.Now()},
		{ID: "new", Source: "new_supported_source", LastObservedAt: time.Now()},
	}}
	got, err := NewService(repo).SourceActivity(context.Background())
	require.NoError(t, err)
	sources := map[string]bool{}
	for _, s := range got {
		sources[s.Source] = true
	}
	require.NotContains(t, sources, "nuclei")
	require.NotContains(t, sources, "custom")
	require.Contains(t, sources, "new_supported_source")
}
