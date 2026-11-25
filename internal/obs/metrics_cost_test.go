package obs

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// Without the cost metrics a dark integration looks identical to a healthy
// one. These assertions pin the three things that tell them apart:
// an outcome label per failure mode, a per-connector success timestamp, and a
// row counter that separates "collected ok" from "actually stored something".
func TestObserveCostCollect_CountsEveryOutcome(t *testing.T) {
	m := New()

	for _, outcome := range []string{
		"ok", "empty", "permission_denied", "config_error", "api_error",
		"store_error", "connector_list_error", "no_aws_connectors",
	} {
		m.ObserveCostCollect(outcome)
	}
	m.ObserveCostCollect("permission_denied") // twice — the common failure

	require.Equal(t, 2.0, testutil.ToFloat64(m.costCollect.WithLabelValues("permission_denied")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.costCollect.WithLabelValues("config_error")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.costCollect.WithLabelValues("connector_list_error")))
	// An outcome never observed must have NO series rather than a zero one: a
	// silent zero is what let "no anomalies" stand in for "never ran".
	families, err := m.Registry().Gather()
	require.NoError(t, err)
	var outcomes []string
	for _, f := range families {
		if f.GetName() != "graph_cost_collect_total" {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, l := range metric.GetLabel() {
				outcomes = append(outcomes, l.GetValue())
			}
		}
	}
	require.Len(t, outcomes, 8)
	require.NotContains(t, outcomes, "made_up_outcome")
}

func TestObserveCostCollectSuccess_StampsPerConnector(t *testing.T) {
	m := New()

	m.ObserveCostCollectSuccess("aws-prod", 1720000000, 120)
	m.ObserveCostCollectSuccess("aws-dev", 1720000600, 30)

	require.Equal(t, 1720000000.0, testutil.ToFloat64(m.costLastSuccess.WithLabelValues("aws-prod")))
	require.Equal(t, 1720000600.0, testutil.ToFloat64(m.costLastSuccess.WithLabelValues("aws-dev")))
	require.Equal(t, 150.0, testutil.ToFloat64(m.costSnapshotRows))

	// A connector that never succeeded has no series at all — that absence is the
	// signal, and it must not be papered over with a zero.
	require.Equal(t, 2, testutil.CollectAndCount(m.costLastSuccess))

	// Zero rows must not advance the row counter: a success that stores nothing
	// is exactly the case SaveSnapshots silently accepts.
	m.ObserveCostCollectSuccess("aws-empty", 1720001000, 0)
	require.Equal(t, 150.0, testutil.ToFloat64(m.costSnapshotRows))
}

// The whole obs package is nil-safe by convention (metrics are optional), and a
// nil-panic in the collect loop would take the cost integration dark again.
func TestCostMetrics_NilSafe(t *testing.T) {
	var m *Metrics
	require.NotPanics(t, func() {
		m.ObserveCostCollect("permission_denied")
		m.ObserveCostCollectSuccess("aws-prod", 1, 1)
	})
}
