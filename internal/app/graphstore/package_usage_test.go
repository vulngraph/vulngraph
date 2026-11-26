package graphstore

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

// packageUsageFixture is the supply-chain chain's shape, reduced to one instance
// of each hop. In graph_edges the deduped-fresh shapes are exactly:
//
//	depends_on   github_repo    → package          (largest)
//	runs_package container_image → package          (medium)
//	runs_image   k8s_pod        → container_image   (medium)
//
// The pod carries RiskScore 0 deliberately: pods with a runs_image edge are
// commonly score-0 with no other retention edge, so if runs_image is not
// in retentionEdgeTypes filterLadybugAssets prunes the pod and the edge disappears as
// endpointAbsent — the runtime half of the answer silently going missing for a large share of
// pods. This fixture fails that way if the retention entry is removed.
func packageUsageFixture() ([]asset.Asset, []asset.Edge) {
	assets := []asset.Asset{
		{ID: "pod-1", Name: "api-service-7d9", Type: "k8s_pod", Provider: "kubernetes", RiskScore: 0},
		{ID: "image/sha256:abc", Name: "eu.gcr.io/example-project/api-service", Type: "container_image", Provider: "kubernetes"},
		{ID: "pkg:npm/@example-corp/db-client@1.2.0", Name: "@example-corp/db-client", Type: "package",
			Metadata: map[string]string{"ecosystem": "npm", "version": "1.2.0"}},
		{ID: "example-corp/api-service", Name: "api-service", Type: "github_repo", Provider: "github"},
	}
	edges := []asset.Edge{
		{SrcID: "pod-1", SrcType: "k8s_pod", DstID: "image/sha256:abc", DstType: "container_image",
			EdgeType: "runs_image", Properties: map[string]string{"image_ref": "eu.gcr.io/example-project/api-service:v1"}},
		{SrcID: "image/sha256:abc", SrcType: "container_image", DstID: "pkg:npm/@example-corp/db-client@1.2.0",
			DstType: "package", EdgeType: "runs_package", Properties: map[string]string{}},
		{SrcID: "example-corp/api-service", SrcType: "github_repo", DstID: "pkg:npm/@example-corp/db-client@1.2.0",
			DstType: "package", EdgeType: "depends_on", Properties: map[string]string{}},
	}
	return assets, edges
}

// TestPackageUsage_InboundExpandNamesBothHalves spans resident runtime topology
// and inventory memberships without loading packages into Ladybug.
func TestPackageUsage_InboundExpandNamesBothHalves(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets, edges := packageUsageFixture()
	inventory := fixtureInventory{assets: slices.Clone(assets), edges: slices.Clone(edges)}
	svc.WithPackageInventory(inventory, inventory)
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	const pkgID = "pkg:npm/@example-corp/db-client@1.2.0"

	coreSeeds, err := svc.MatchSeed(ctx, explore.NodeMatch{IDs: []string{pkgID}}, 10)
	require.NoError(t, err)
	require.Empty(t, coreSeeds, "packages must not occupy the resident graph")
	repo := explore.NewFallbackRepo(svc, inventory)
	seeds, err := repo.MatchSeed(ctx, explore.NodeMatch{IDs: []string{pkgID}}, 10)
	require.NoError(t, err)
	require.Len(t, seeds, 1)
	require.Equal(t, "package", seeds[0].Type)
	require.Equal(t, "@example-corp/db-client", seeds[0].Name)
	pkgEdges, pkgNbrs, _, err := repo.Neighbors(ctx, []string{pkgID}, nil, explore.DirectionIn)
	require.NoError(t, err)
	inbound := map[string]string{}
	for _, e := range pkgEdges {
		require.Equal(t, pkgID, e.DstID)
		inbound[e.EdgeType] = e.SrcID
	}
	require.Equal(t, "example-corp/api-service", inbound["depends_on"])
	require.Equal(t, "image/sha256:abc", inbound["runs_package"])
	types := map[string]string{}
	for _, n := range pkgNbrs {
		types[n.ID] = n.Type
	}
	require.Equal(t, "github_repo", types["example-corp/api-service"])

	// 3. Inbound expand from the image names the pod — the hop that did not exist.
	imgEdges, _, _, err := svc.Neighbors(ctx, []string{"image/sha256:abc"}, nil, explore.DirectionIn)
	require.NoError(t, err)
	var sawPod bool
	for _, e := range imgEdges {
		if e.EdgeType == "RunsImage" && e.SrcID == "pod-1" {
			sawPod = true
		}
	}
	require.True(t, sawPod, "RunsImage must reach the pod running the image: %v", imgEdges)
}

// TestPackageUsage_NamedQueriesAnswerByName pins the two catalog entries a user
// actually reaches from the UI. They key on p.name, not p.id, so one query covers
// every version of a package — a purl commonly exists at several versions and
// nobody asking "where is db-client used" knows which one they mean.
func TestPackageUsage_NamedQueriesAnswerByName(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets, edges := packageUsageFixture()
	inventory := fixtureInventory{assets: slices.Clone(assets), edges: slices.Clone(edges)}
	svc.WithPackageInventory(inventory, inventory)
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	params := map[string]string{"name": "@example-corp/db-client"}

	repoRes, err := svc.RunNamedQuery(ctx, "package_source_repos", params)
	require.NoError(t, err)
	repoNodes := repoRes.Nodes
	require.True(t, nodeIDPresent(repoNodes, "example-corp/api-service"),
		"package_source_repos must name the depending repo: %v", nodeIDs(repoNodes))

	runRes, err := svc.RunNamedQuery(ctx, "package_running_workloads", params)
	require.NoError(t, err)
	runNodes := runRes.Nodes
	require.True(t, nodeIDPresent(runNodes, "pod-1"),
		"package_running_workloads must name the running pod: %v", nodeIDs(runNodes))
	require.True(t, nodeIDPresent(runNodes, "image/sha256:abc"),
		"package_running_workloads must name the image it runs in: %v", nodeIDs(runNodes))
}

// TestPackageUsage_NonK8sWorkloadsRunTheImage guards non-pod runtimes: an ECS service
// and a Cloud Run service run the same digest as the pod. Both carry the
// catch-all Asset label, so without the RunsImageAsset reroute their runs_image
// rows would be dropped at COPY against RunsImage's K8sWorkload source, and
// neither the expand view nor the named query could name them. Score 0 on
// purpose, same as the pod: runs_image retention must keep them.
func TestPackageUsage_NonK8sWorkloadsRunTheImage(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	const (
		ecsID = "arn:aws:ecs:eu-west-1:1:service/prod/api"
		runID = "proj/cloudrun/api"
	)
	assets, edges := packageUsageFixture()
	assets = append(assets,
		asset.Asset{ID: ecsID, Name: "api", Type: "ecs_service", Provider: asset.ProviderAWS},
		asset.Asset{ID: runID, Name: "api", Type: "cloudrun_service", Provider: asset.ProviderGCP},
	)
	for _, src := range []struct{ id, typ string }{{ecsID, "ecs_service"}, {runID, "cloudrun_service"}} {
		edges = append(edges, asset.Edge{
			SrcID: src.id, SrcType: src.typ, DstID: "image/sha256:abc", DstType: "container_image",
			EdgeType: "runs_image", Properties: map[string]string{"image_ref": "registry/api:v1"},
		})
	}
	inventory := fixtureInventory{assets: slices.Clone(assets), edges: slices.Clone(edges)}
	svc.WithPackageInventory(inventory, inventory)
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, nil))

	imgEdges, _, _, err := svc.Neighbors(ctx, []string{"image/sha256:abc"}, nil, explore.DirectionIn)
	require.NoError(t, err)
	runners := map[string]string{}
	for _, e := range imgEdges {
		runners[e.SrcID] = e.EdgeType
	}
	require.Equal(t, "RunsImage", runners["pod-1"], "%v", imgEdges)
	require.Equal(t, "RunsImageAsset", runners[ecsID], "%v", imgEdges)
	require.Equal(t, "RunsImageAsset", runners[runID], "%v", imgEdges)

	runRes, err := svc.RunNamedQuery(ctx, "package_running_workloads",
		map[string]string{"name": "@example-corp/db-client"})
	require.NoError(t, err)
	runNodes := runRes.Nodes
	for _, id := range []string{"pod-1", ecsID, runID} {
		require.True(t, nodeIDPresent(runNodes, id),
			"package_running_workloads must name %s: %v", id, nodeIDs(runNodes))
	}
}

func nodeIDs(nodes []explore.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.ID)
	}
	return out
}

func nodeIDPresent(nodes []explore.Node, id string) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// fixtureInventory emulates inventory lookup only; integration tests cover SQL.
type fixtureInventory struct {
	assets []asset.Asset
	edges  []asset.Edge
}

func (f fixtureInventory) MatchSeed(_ context.Context, m explore.NodeMatch, limit int) ([]explore.Node, error) {
	var out []explore.Node
	for _, a := range f.assets {
		if len(m.IDs) > 0 && !slices.Contains(m.IDs, a.ID) {
			continue
		}
		if len(m.IDs) == 0 && len(m.Types) > 0 && !slices.Contains(m.Types, a.Type) {
			continue
		}
		if m.Provider != "" && m.Provider != string(a.Provider) {
			continue
		}
		out = append(out, explore.Node{ID: a.ID, Name: a.Name, Type: a.Type, Score: int(a.RiskScore), InternetHops: ReachUnknown})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
func (f fixtureInventory) Neighbors(ctx context.Context, ids, types []string, dir explore.Direction) ([]explore.Edge, []explore.Node, bool, error) {
	var edges []explore.Edge
	var neighbors []string
	for _, e := range f.edges {
		if len(types) > 0 && !slices.Contains(types, e.EdgeType) {
			continue
		}
		if dir != explore.DirectionIn && slices.Contains(ids, e.SrcID) {
			neighbors = append(neighbors, e.DstID)
		} else if dir != explore.DirectionOut && slices.Contains(ids, e.DstID) {
			neighbors = append(neighbors, e.SrcID)
		} else {
			continue
		}
		edges = append(edges, explore.Edge{SrcID: e.SrcID, DstID: e.DstID, EdgeType: e.EdgeType})
	}
	if len(neighbors) == 0 {
		return edges, nil, false, nil
	}
	nodes, err := f.MatchSeed(ctx, explore.NodeMatch{IDs: neighbors}, len(neighbors))
	return edges, nodes, false, err
}
func (f fixtureInventory) FindPackageVersions(_ context.Context, name string, limit int) ([]asset.Asset, error) {
	var out []asset.Asset
	for _, a := range f.assets {
		if a.Type == "package" && a.Name == name {
			out = append(out, a)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
