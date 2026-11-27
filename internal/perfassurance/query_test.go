package perfassurance

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryCostBudgetsRejectEachRegression(t *testing.T) {
	budget := QueryBudget{Queries: 1, ReadRows: 1000, ReadBytes: 10000, MemoryBytes: 100000}
	good := QuerySample{Name: "boundary", Queries: []QueryCost{{ReadRows: 1000, ReadBytes: 10000, Memory: 100000}}}
	require.NoError(t, budget.Check(good))
	for _, tc := range []struct {
		name    string
		queries []QueryCost
	}{
		{"query count", nil}, {"query count", []QueryCost{{}, {}}},
		{"read rows", []QueryCost{{ReadRows: 1001}}}, {"read bytes", []QueryCost{{ReadBytes: 10001}}},
		{"query memory", []QueryCost{{Memory: 100001}}},
	} {
		require.ErrorContains(t, budget.Check(QuerySample{Name: tc.name, Queries: tc.queries}), tc.name)
	}
}

func TestQueryBenchmarkRefusesNonIsolatedStores(t *testing.T) {
	for _, dsn := range []string{"clickhouse://example.invalid:9000/vg_query_perf", "clickhouse://127.0.0.1:9000/graph", "clickhouse://127.0.0.1/vg_query_perf", "postgres://127.0.0.1:5432/vg_query_perf", "not a URL"} {
		_, err := OpenQueryStore(t.Context(), dsn)
		require.ErrorContains(t, err, "isolated loopback")
	}
}
