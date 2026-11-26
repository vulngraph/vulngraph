//go:build integration

package throughput

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/db"
)

type benchmarkReach struct{ graph *graphstore.Service }

func (b benchmarkReach) InternetHops(ctx context.Context, id string) (int, bool, error) {
	n, err := b.graph.TryNodeSignals(ctx, id)
	return n.InternetHops, n.InternetHops != graphstore.ReachUnknown, err
}

type lineageMeasurement struct {
	Scenario  string      `json:"scenario"`
	Seconds   float64     `json:"seconds"`
	Truncated bool        `json:"truncated"`
	Queries   []queryCost `json:"queries"`
}

func measureLineage(t *testing.T, ctx context.Context, ch *db.CH, inv *asset.Service, graph *graphstore.Service, p profile) []lineageMeasurement {
	t.Helper()
	source := enrich.SupplyChainExposure{Graph: inv, Reach: benchmarkReach{graph}}
	var result []lineageMeasurement
	for _, scenario := range []string{"hot_package", "missing_package", "batched_images"} {
		comment := fmt.Sprintf("lineage-%s-%d", scenario, time.Now().UnixNano())
		qctx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
		m := lineageMeasurement{Scenario: scenario}
		start := time.Now()
		if scenario == "batched_images" {
			var ids []string
			for i := uint64(0); i < min(p.Images, 200); i++ {
				ids = append(ids, fmt.Sprintf("image-%d", i))
			}
			got, truncated, err := inv.LineageSources(qctx, ids, "runs_image", 200)
			require.NoError(t, err)
			require.Len(t, got, 200)
			require.True(t, truncated)
			m.Truncated = truncated
		} else {
			pkg := "pkg:generic/bench-0@1.0.0"
			if scenario == "missing_package" {
				pkg = "pkg:generic/absent@1"
			}
			deployed, exposed, truncated, err := source.PackageDeployExposure(qctx, pkg)
			require.NoError(t, err)
			if scenario == "hot_package" && p.Memberships > 0 {
				require.True(t, deployed)
				// Every image is used by both public and private workloads. The
				// cap may sample only private ones; then the answer must be unknown.
				require.True(t, exposed || truncated)
			} else {
				require.False(t, deployed)
				require.False(t, exposed)
				require.False(t, truncated)
			}
			m.Truncated = truncated
		}
		m.Seconds = time.Since(start).Seconds()
		var err error
		m.Queries, err = costs(ctx, ch, comment)
		require.NoError(t, err)
		require.NotEmpty(t, m.Queries)
		if scenario == "batched_images" {
			require.Len(t, m.Queries, 1)
		} else {
			require.LessOrEqual(t, len(m.Queries), 4)
		}
		for _, q := range m.Queries {
			require.Zero(t, q.ExceptionCode)
			require.LessOrEqual(t, q.ResultRows, uint64(401), "lineage response must be bounded in storage")
		}
		t.Logf("lineage %s: seconds=%.4f queries=%d truncated=%v", scenario, m.Seconds, len(m.Queries), m.Truncated)
		result = append(result, m)
	}
	return result
}
