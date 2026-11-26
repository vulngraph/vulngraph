package graphstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type packageRiskAssets struct {
	stubAssets
	risk map[string]uint8
	err  error
}

func (s packageRiskAssets) PackageRiskByRunner(context.Context) (map[string]uint8, error) {
	return s.risk, s.err
}

func TestPackageProjection_InventorySizeDoesNotGrowResidentGraph(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	assets := []asset.Asset{{ID: "vm", Type: "ec2_instance", RiskScore: 10}}
	var edges []asset.Edge
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("pkg:npm/lib-%d@1", i)
		assets = append(assets, asset.Asset{ID: id, Type: "package", RiskScore: 80})
		edges = append(edges, asset.Edge{SrcID: "vm", SrcType: "ec2_instance", DstID: id, DstType: "package", EdgeType: "runs_package"})
	}
	source := packageRiskAssets{stubAssets: stubAssets{assets}, risk: map[string]uint8{"vm": 80}}
	require.NoError(t, svc.SyncFromSources(ctx, 0, source, stubEdges{edges}, nil))
	require.Equal(t, []string{"vm"}, svc.lastNodeIDs)
	result, err := svc.RunCypher(ctx, "MATCH (a:Asset {id:'vm'}) RETURN a", 10, 10)
	require.NoError(t, err)
	require.Len(t, result.Nodes, 1)
	require.Equal(t, 80, result.Nodes[0].Score)
	// Failure cannot publish a graph that silently loses its package risk.
	source.err = errors.New("inventory unavailable")
	require.ErrorContains(t, svc.SyncFromSources(ctx, 0, source, stubEdges{}, nil), "package risk rollup")
	again, err := svc.RunCypher(ctx, "MATCH (a:Asset {id:'vm'}) RETURN a", 10, 10)
	require.NoError(t, err)
	require.Equal(t, result.Nodes, again.Nodes)
	_, err = svc.RunCypher(ctx, "MATCH (p:Package) RETURN p", 10, 10)
	require.ErrorContains(t, err, "queried on demand")
}

func TestPackageSeeds_BoundedAndPublishedAsSnapshot(t *testing.T) {
	require.Nil(t, kevPackageSeeds(nil))
	signals := map[string]NodeSignals{}
	require.NotNil(t, kevPackageSeeds(signals), "a successful empty rollup is a measured empty result")
	for i := 0; i < inventorySeedLimit+30; i++ {
		signals[fmt.Sprintf("pkg:npm/lib-%03d@1", i)] = NodeSignals{HasKEV: true, MaxScore: i}
	}
	signals["vm"] = NodeSignals{HasKEV: true, MaxScore: 1000}
	seeds := kevPackageSeeds(signals)
	require.True(t, seeds.truncated)
	require.Len(t, seeds.nodes, inventorySeedLimit)
	require.Equal(t, inventorySeedLimit+29, seeds.nodes[0].MaxScore)
	clear(signals)
	require.Len(t, seeds.nodes, inventorySeedLimit, "published snapshot must be independent of its source")
}

func TestSnapshotShape_ExcludesOnlyInventoryProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.snap")
	require.NoError(t, WriteSnapshot(path, GraphSnapshot{
		SchemaVersion: "v2",
		Assets:        []asset.Asset{{ID: "vm", Type: "ec2_instance"}, {ID: "pkg:npm/lib@1", Type: "package"}},
		Edges: []asset.Edge{
			{SrcID: "vm", DstID: InternetNodeID, EdgeType: "exposed_to_internet"},
			{SrcID: "vm", DstID: "pkg:npm/lib@1", EdgeType: "runs_package"},
			{SrcID: "repo", DstID: "pkg:npm/lib@1", EdgeType: "depends_on"},
			{SrcID: "vm", DstID: "role", EdgeType: "has_role"},
		},
	}))
	shape, ok := ReadSnapshotShapeAnyVersion(path)
	require.True(t, ok)
	require.Equal(t, 1, shape.Assets)
	require.Equal(t, 2, shape.TotalEdges)
	require.Equal(t, map[string]int{"exposed_to_internet": 1, "has_role": 1}, shape.ByType)
}
