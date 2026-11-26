package enrich

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeLineage maps a package's depends_on inbound edges and per-source outbound
// edges, so the traversal package ← repo → workload → internet can be exercised.
type fakeLineage struct {
	into map[string][]asset.Edge // dstID -> inbound edges (depends_on)
	from map[string][]asset.Edge // srcID -> outbound edges
}

func (f fakeLineage) LineageSources(ctx context.Context, ids []string, typ string, limit int) ([]asset.Edge, bool, error) {
	var edges []asset.Edge
	seen := map[string]bool{}
	for _, id := range ids {
		incoming, err := f.EdgesInto(ctx, id, typ)
		if err != nil {
			return nil, false, err
		}
		for _, e := range incoming {
			if !seen[e.SrcID] {
				edges = append(edges, e)
				seen[e.SrcID] = true
			}
		}
	}
	return edges[:min(len(edges), limit)], len(edges) > limit, nil
}

func (f fakeLineage) LineageTargets(ctx context.Context, ids []string, typ string, limit int) ([]asset.Edge, bool, error) {
	edges, err := f.EdgesOutBatch(ctx, ids, typ)
	seen := map[string]bool{}
	var out []asset.Edge
	for _, e := range edges {
		if !seen[e.DstID] {
			out = append(out, e)
			seen[e.DstID] = true
		}
	}
	return out[:min(len(out), limit)], len(out) > limit, err
}

func (f fakeLineage) AnyConfirmedExposure(ctx context.Context, ids []string) (bool, error) {
	edges, err := f.EdgesOutBatch(ctx, ids, "exposed_to_internet")
	for _, e := range edges {
		if e.Properties[asset.EdgePropPublicAccess] != asset.PublicAccessPossible {
			return true, err
		}
	}
	return false, err
}

func (f fakeLineage) EdgesInto(_ context.Context, dstID, edgeType string) ([]asset.Edge, error) {
	var out []asset.Edge
	for _, e := range f.into[dstID] {
		if e.EdgeType == edgeType {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f fakeLineage) EdgesOutBatch(_ context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error) {
	var out []asset.Edge
	for _, id := range srcIDs {
		for _, e := range f.from[id] {
			if e.EdgeType == edgeType {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

func pkgFinding() finding.Finding {
	return finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:npm/lodash@4.17.15"}
}

func TestSupplyChainExposure_InternetExposedPath(t *testing.T) {
	g := fakeLineage{
		into: map[string][]asset.Edge{
			"pkg:npm/lodash@4.17.15": {{SrcID: "org/web", DstID: "pkg:npm/lodash@4.17.15", EdgeType: "depends_on"}},
		},
		from: map[string][]asset.Edge{
			"org/web": {{SrcID: "org/web", DstID: "wl-1", EdgeType: "deploys_to"}},
			"wl-1":    {{SrcID: "wl-1", DstID: "internet", EdgeType: "exposed_to_internet"}},
		},
	}
	factor, applied, err := SupplyChainExposure{Graph: g}.Evaluate(context.Background(), pkgFinding())
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 20, factor.Points)
	require.Equal(t, ThresholdPipeline, factor.Floor)
}

func TestSupplyChainExposure_DeployedButNotExposed(t *testing.T) {
	g := fakeLineage{
		into: map[string][]asset.Edge{
			"pkg:npm/lodash@4.17.15": {{SrcID: "org/web", DstID: "pkg:npm/lodash@4.17.15", EdgeType: "depends_on"}},
		},
		from: map[string][]asset.Edge{
			"org/web": {{SrcID: "org/web", DstID: "wl-1", EdgeType: "deploys_to"}},
			"wl-1":    nil, // not exposed
		},
	}
	factor, applied, err := SupplyChainExposure{Graph: g}.Evaluate(context.Background(), pkgFinding())
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 10, factor.Points)
	require.Zero(t, factor.Floor)
}

func TestSupplyChainExposure_NoLineage(t *testing.T) {
	_, applied, err := SupplyChainExposure{Graph: fakeLineage{}}.Evaluate(context.Background(), pkgFinding())
	require.NoError(t, err)
	require.False(t, applied)
}

func TestSupplyChainExposure_NotAPackageFinding(t *testing.T) {
	f := finding.Finding{Source: "cspm", ResourceType: "ec2_instance"}
	_, applied, err := SupplyChainExposure{Graph: fakeLineage{}}.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.False(t, applied)
}

// TestPackageDeployExposure_CapsRepoFanout exercises the maxSupplyChainRepos
// cap: a heavily-depended-on package (hundreds of dependent repos, like
// golang.org/x/net) must not blow up the traversal. Only the first
// maxSupplyChainRepos repos are considered; as long as at least one of them
// (within the cap) deploys to an exposed workload, the finding still resolves.
func TestPackageDeployExposure_CapsRepoFanout(t *testing.T) {
	into := make([]asset.Edge, 0, maxSupplyChainRepos+50)
	from := map[string][]asset.Edge{}
	pkg := "pkg:golang/golang.org/x/net@0.0.0"
	for i := 0; i < maxSupplyChainRepos+50; i++ {
		repo := fmt.Sprintf("org/repo-%d", i)
		into = append(into, asset.Edge{SrcID: repo, DstID: pkg, EdgeType: "depends_on"})
		// Only the LAST repo (beyond the cap) deploys anywhere — proves the cap
		// actually truncates rather than just being decorative.
	}
	lastRepo := fmt.Sprintf("org/repo-%d", maxSupplyChainRepos+49)
	from[lastRepo] = []asset.Edge{{SrcID: lastRepo, DstID: "wl-1", EdgeType: "deploys_to"}}
	from["wl-1"] = []asset.Edge{{SrcID: "wl-1", DstID: "internet", EdgeType: "exposed_to_internet"}}

	g := fakeLineage{into: map[string][]asset.Edge{pkg: into}, from: from}
	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.False(t, anyDeployed, "the only deploying repo is beyond the cap, so it must not be seen")
	require.False(t, anyExposed)
}

// TestPackageDeployExposure_CapsWorkloadFanout exercises maxSupplyChainWorkloads:
// maxSupplyChainRepos bounds the FIRST hop's input (how many repos are
// considered), not how many workloads a single repo's deploys_to can fan out to
// — one repo can deploy to many CI/CD environments/regions. Only the
// LAST workload (beyond the cap) is exposed, proving the cap actually truncates
// the second EdgesFrom hop rather than being decorative.
func TestPackageDeployExposure_CapsWorkloadFanout(t *testing.T) {
	pkg := "pkg:golang/golang.org/x/net@0.0.0"
	repo := "org/web"
	var repoOut []asset.Edge
	for i := 0; i < maxSupplyChainWorkloads+50; i++ {
		wl := fmt.Sprintf("wl-%d", i)
		repoOut = append(repoOut, asset.Edge{SrcID: repo, DstID: wl, EdgeType: "deploys_to"})
	}
	lastWorkload := fmt.Sprintf("wl-%d", maxSupplyChainWorkloads+49)

	g := fakeLineage{
		into: map[string][]asset.Edge{pkg: {{SrcID: repo, DstID: pkg, EdgeType: "depends_on"}}},
		from: map[string][]asset.Edge{
			repo:         repoOut,
			lastWorkload: {{SrcID: lastWorkload, DstID: "internet", EdgeType: "exposed_to_internet"}},
		},
	}
	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, anyDeployed, "the repo does deploy — that hop is not capped")
	require.False(t, anyExposed, "the only exposed workload is beyond maxSupplyChainWorkloads, so it must not be seen")
}

// TestPackageDeployExposure_RepoDependsButNeverDeploys is the template-repo
// case: a repo depends
// on the vulnerable package but has zero deploys_to edges, so must-fix has no
// deployment evidence to reason over at all.
func TestPackageDeployExposure_RepoDependsButNeverDeploys(t *testing.T) {
	pkg := "pkg:golang/golang.org/x/net@0.0.0-20210813160813-60bc85c4be6d"
	g := fakeLineage{
		into: map[string][]asset.Edge{
			pkg: {{SrcID: "example-corp/app-template", DstID: pkg, EdgeType: "depends_on"}},
		},
		from: map[string][]asset.Edge{}, // no outbound deploys_to edges at all
	}
	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.False(t, anyDeployed)
	require.False(t, anyExposed)
}

// TestSupplyChainExposure_ImageLineageExposed exercises the container-image
// lineage: the package is linked to no repo, only to a container_image
// (runs_package) that an internet-exposed k8s_pod runs (runs_image). This is the
// exact path an imagevuln finding takes to reach must_fix — without it the repo
// path alone reports "no lineage" and the finding stays unclassified.
func TestSupplyChainExposure_ImageLineageExposed(t *testing.T) {
	pkg := "pkg:deb/debian/openssl@1.1.1n"
	img := "image/sha256:abc"
	g := fakeLineage{
		into: map[string][]asset.Edge{
			pkg: {{SrcID: img, DstID: pkg, EdgeType: "runs_package"}},
			img: {{SrcID: "cluster/pod/ns/web", DstID: img, EdgeType: "runs_image"}},
		},
		from: map[string][]asset.Edge{
			"cluster/pod/ns/web": {{SrcID: "cluster/pod/ns/web", DstID: "internet", EdgeType: "exposed_to_internet"}},
		},
	}
	f := finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: pkg}
	factor, applied, err := SupplyChainExposure{Graph: g}.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 20, factor.Points)
	require.Equal(t, ThresholdPipeline, factor.Floor)

	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, anyDeployed)
	require.True(t, anyExposed)
}

// TestSupplyChainExposure_ImageLineageNotExposed: the image runs on a pod that
// is not internet-exposed — deployed, but internal/lateral only.
func TestSupplyChainExposure_ImageLineageNotExposed(t *testing.T) {
	pkg := "pkg:apk/alpine/musl@1.2"
	img := "image/sha256:def"
	g := fakeLineage{
		into: map[string][]asset.Edge{
			pkg: {{SrcID: img, DstID: pkg, EdgeType: "runs_package"}},
			img: {{SrcID: "cluster/pod/ns/batch", DstID: img, EdgeType: "runs_image"}},
		},
		from: map[string][]asset.Edge{"cluster/pod/ns/batch": nil},
	}
	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, anyDeployed)
	require.False(t, anyExposed)
}

// TestSupplyChainExposure_ImageLinkedButNoPod: the package is on an image that
// no live pod runs (image inventoried but orphaned) — no deployment evidence.
func TestSupplyChainExposure_ImageLinkedButNoPod(t *testing.T) {
	pkg := "pkg:deb/debian/curl@7.74"
	img := "image/sha256:orphan"
	g := fakeLineage{
		into: map[string][]asset.Edge{
			pkg: {{SrcID: img, DstID: pkg, EdgeType: "runs_package"}},
			// no runs_image edge into the image
		},
	}
	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: g}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.False(t, anyDeployed)
	require.False(t, anyExposed)
}

func TestPackageDeployExposure_NoRepoDependents(t *testing.T) {
	anyDeployed, anyExposed, _, err := SupplyChainExposure{Graph: fakeLineage{}}.
		PackageDeployExposure(context.Background(), "pkg:npm/left-pad@1.0.0")
	require.NoError(t, err)
	require.False(t, anyDeployed)
	require.False(t, anyExposed)
}
