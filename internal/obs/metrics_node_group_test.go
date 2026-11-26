package obs

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func multiHopGauge(t *testing.T, g GraphStats) (value float64, present bool) {
	t.Helper()
	m := New()
	m.RegisterSources(Sources{Graph: func() GraphStats { return g }})
	if testutil.CollectAndCount(m.Registry(), "graph_ladybug_multihop_may_be_incomplete") == 0 {
		return 0, false
	}
	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "graph_ladybug_multihop_may_be_incomplete" {
			return mf.GetMetric()[0].GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// The legacy signal is absent until a build is published. The fixed engine
// reports 0 even when a node table crosses a storage-group boundary.
func TestFixedEngineNodeTableGauge(t *testing.T) {
	_, present := multiHopGauge(t, GraphStats{NodeGroupRows: 131072})
	require.False(t, present, "no published build: no series")

	v, present := multiHopGauge(t, GraphStats{NodeGroupRows: 131072, NodeTableRows: map[string]int64{"Asset": 131072, "Package": 10}})
	require.True(t, present)
	require.Equal(t, 0.0, v, "exactly one full node group fits")

	v, present = multiHopGauge(t, GraphStats{NodeGroupRows: 131072, NodeTableRows: map[string]int64{"Asset": 5, "Package": 131073}})
	require.True(t, present)
	require.Equal(t, 0.0, v, "the engine fix removes the node-group correctness limit")

	m := New()
	m.RegisterSources(Sources{Graph: func() GraphStats {
		return GraphStats{NodeGroupRows: 131072, NodeTableRows: map[string]int64{"Asset": 5, "Package": 131073}}
	}})
	require.Equal(t, 2, testutil.CollectAndCount(m.Registry(), "graph_ladybug_node_table_rows"))
}
