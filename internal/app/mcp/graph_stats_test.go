package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/pkg/promptfence"
)

type fakeGraphStats struct{ health explore.GraphHealth }

func (fakeGraphStats) NodeCounts(context.Context) (assets, roles, repos int64, err error) {
	return 7, 2, 1, nil
}

func (f fakeGraphStats) GraphHealth(context.Context) (explore.GraphHealth, error) {
	return f.health, nil
}

func callGraphStats(t *testing.T, stats GraphStats) map[string]any {
	t.Helper()
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, stats, &fakeSuppress{}, nil, nil, nil).
		WithLimits(unlimited{}, unlimited{})
	resp := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_graph_stats","arguments":{}}}`)
	require.Nil(t, resp.Error)
	text := resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	body := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(text), promptfence.Open), promptfence.Close)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(body)), &out))
	return out
}

// get_graph_stats reports the engine's own build state: it used to answer
// ready: true whenever the counts query did not error, including for a graph
// that was never built.
func TestGetGraphStats_ReportsMeasuredReadiness(t *testing.T) {
	out := callGraphStats(t, fakeGraphStats{})
	require.Equal(t, false, out["ready"], "a never-built graph is not ready")
	require.Contains(t, out, "last_built_at")
	require.Nil(t, out["last_built_at"], "an unknown build time is null, never now")

	built := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	out = callGraphStats(t, fakeGraphStats{health: explore.GraphHealth{Ready: true, NodeCount: 7, LastBuiltAt: built}})
	require.Equal(t, true, out["ready"])
	require.Equal(t, built.Format(time.RFC3339), out["last_built_at"])
	require.Equal(t, map[string]any{"assets": 7.0, "roles": 2.0, "repos": 1.0}, out["nodes"])
}

// get_graph_stats carries the multi-hop guard: null until a build was
// measured, then the flag and the oversized tables.
func TestGetGraphStats_ReportsTheMultiHopGuard(t *testing.T) {
	out := callGraphStats(t, fakeGraphStats{})
	require.Contains(t, out, "multi_hop_may_be_incomplete")
	require.Nil(t, out["multi_hop_may_be_incomplete"], "unmeasured is null, never false")

	out = callGraphStats(t, fakeGraphStats{health: explore.GraphHealth{Ready: true, NodeTablesMeasured: true}})
	require.Equal(t, false, out["multi_hop_may_be_incomplete"])
	require.Equal(t, map[string]any{}, out["oversized_node_tables"])

	out = callGraphStats(t, fakeGraphStats{health: explore.GraphHealth{
		Ready: true, NodeTablesMeasured: true, OversizedNodeTables: map[string]int64{"Package": 131073},
	}})
	require.Equal(t, true, out["multi_hop_may_be_incomplete"])
	require.Equal(t, map[string]any{"Package": 131073.0}, out["oversized_node_tables"])
}
