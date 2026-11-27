package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func liveWorkload(id, typ, cluster, ns string) asset.Asset {
	return asset.Asset{ID: id, Type: typ, Region: cluster, Metadata: map[string]string{"namespace": ns}}
}

func declared(repo, key, liveType, ns, path string) asset.Asset {
	return asset.Asset{
		ID: "declared_k8s_workload:" + repo + ":" + path + ":" + key, Type: "declared_k8s_workload",
		Metadata: map[string]string{
			"manifest_key": key, "live_type": liveType, "namespace": ns,
			"repo": repo, "path": path,
		},
	}
}

func TestK8sManifestOwnership_SingleClusterExactMatch(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/deployment/billing/api", "k8s_deployment", "prod-cluster", "billing"),
		declared("org/payments-repo", "deployment/billing/api", "k8s_deployment", "billing", "k8s/api.yaml"),
	})
	edges := K8sManifestOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	e := edges[0]
	require.Equal(t, "defined_in", e.EdgeType)
	require.Equal(t, "prod-cluster/deployment/billing/api", e.SrcID)
	require.Equal(t, "k8s_deployment", e.SrcType)
	require.Equal(t, "org/payments-repo", e.DstID)
	require.Equal(t, "github_repo", e.DstType)
	require.Equal(t, "high", e.Properties["confidence"])
	require.Equal(t, "iac_manifest", e.Properties["provenance"])
	require.Equal(t, "k8s/api.yaml", e.Properties["path"])
}

func TestK8sManifestOwnership_MultiClusterIsMediumAndFansOut(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/deployment/billing/api", "k8s_deployment", "prod-cluster", "billing"),
		liveWorkload("staging-cluster/deployment/billing/api", "k8s_deployment", "staging-cluster", "billing"),
		declared("org/repo", "deployment/billing/api", "k8s_deployment", "billing", "d.yaml"),
	})
	edges := K8sManifestOwnership{}.Correlate(g)
	require.Len(t, edges, 2, "one edge per matched cluster")
	for _, e := range edges {
		require.Equal(t, "medium", e.Properties["confidence"], ">1 cluster ⇒ medium")
	}
}

// TestK8sManifestOwnership_MultiClusterRegionFreeIsMedium pins the real
// production path: correlate's LoadView SELECT never scans region (repo.go
// scanAssets), so m.Region is always "" in production. Confidence must be
// derived from the cluster segment of the live asset ID, not m.Region — a
// region-based grade would read "high" because {""} has length 1.
func TestK8sManifestOwnership_MultiClusterRegionFreeIsMedium(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "prod-us/deployment/billing/api", Type: "k8s_deployment"},
		{ID: "prod-eu/deployment/billing/api", Type: "k8s_deployment"},
		declared("org/repo", "deployment/billing/api", "k8s_deployment", "billing", "d.yaml"),
	})
	edges := K8sManifestOwnership{}.Correlate(g)
	require.Len(t, edges, 2, "one edge per matched cluster")
	for _, e := range edges {
		require.Equal(t, "medium", e.Properties["confidence"], "distinct cluster ID prefixes ⇒ medium, even with Region unset")
	}
}

// TestK8sManifestOwnership_SuffixMatchIsExactNotSubstring guards against a
// substring match: "deployment/billing/api" must not match a live asset whose
// name is "x-billing" (different namespace), even though the manifest key is
// a substring of the live suffix.
func TestK8sManifestOwnership_SuffixMatchIsExactNotSubstring(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod/deployment/x-billing/api", "k8s_deployment", "prod", "x-billing"),
		declared("org/repo", "deployment/billing/api", "k8s_deployment", "billing", "d.yaml"),
	})
	require.Empty(t, K8sManifestOwnership{}.Correlate(g), "exact suffix match required, not substring")
}

// TestK8sManifestOwnership_EmptyRepoSkipsNoEdge verifies the repo=="" skip at
// the top of the rule: a declared workload with no repo metadata produces no
// edge even when a live match exists.
func TestK8sManifestOwnership_EmptyRepoSkipsNoEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/deployment/billing/api", "k8s_deployment", "prod-cluster", "billing"),
		declared("", "deployment/billing/api", "k8s_deployment", "billing", "d.yaml"),
	})
	require.Empty(t, K8sManifestOwnership{}.Correlate(g), "repo==\"\" must skip, no edge")
}

func TestK8sManifestOwnership_NamespaceAbsentUsesNameKeyFallbackMedium(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/deployment/billing/api", "k8s_deployment", "prod-cluster", "billing"),
		declared("org/repo", "deployment//api", "k8s_deployment", "", "d.yaml"),
	})
	edges := K8sManifestOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "prod-cluster/deployment/billing/api", edges[0].SrcID)
	require.Equal(t, "medium", edges[0].Properties["confidence"], "namespace-agnostic fallback ⇒ medium")
}

func TestK8sManifestOwnership_ServiceRoutesToServiceAssets(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/service/billing/api", "k8s_service", "prod-cluster", "billing"),
		declared("org/repo", "service/billing/api", "k8s_service", "billing", "svc.yaml"),
	})
	edges := K8sManifestOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "k8s_service", edges[0].SrcType)
}

func TestK8sManifestOwnership_NoLiveMatchNoEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		declared("org/repo", "deployment/ghost/none", "k8s_deployment", "ghost", "d.yaml"),
	})
	require.Empty(t, K8sManifestOwnership{}.Correlate(g))
}

// TestK8sManifestOwnership_CorrelateAssets_MatchedGetsNoDrift verifies a
// declared workload that resolves to a live asset is not flagged: drift is
// only a signal for manifests with zero live matches (the drift model).
func TestK8sManifestOwnership_CorrelateAssets_MatchedGetsNoDrift(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/deployment/billing/api", "k8s_deployment", "prod-cluster", "billing"),
		declared("org/payments-repo", "deployment/billing/api", "k8s_deployment", "billing", "k8s/api.yaml"),
	})
	annotations := K8sManifestOwnership{}.CorrelateAssets(g)
	require.Len(t, annotations, 1)
	require.Empty(t, annotations[0].Metadata["drift"], "live match explicitly clears older drift")
}

// TestK8sManifestOwnership_CorrelateAssets_OrphanGetsDrift verifies a
// declared workload with zero live matches gets flagged
// drift="declared_not_live", and that the original asset's Metadata map is
// untouched (annotation must not mutate the shared Graph view).
func TestK8sManifestOwnership_CorrelateAssets_OrphanGetsDrift(t *testing.T) {
	orphan := declared("org/repo", "deployment/ghost/none", "k8s_deployment", "ghost", "d.yaml")
	g := NewGraph([]asset.Asset{orphan})

	annotated := K8sManifestOwnership{}.CorrelateAssets(g)
	require.Len(t, annotated, 1)
	require.Equal(t, orphan.ID, annotated[0].ID)
	require.Equal(t, "declared_not_live", annotated[0].Metadata["drift"])
	require.Len(t, annotated[0].Metadata, 1, "annotation must carry only the changed key, not the whole view-projected map")
	require.Empty(t, orphan.Metadata["drift"], "original asset must not be mutated")
}

// TestK8sManifestOwnership_CorrelateAssets_AlreadyFlaggedIsNoop pins the
// idempotency invariant: re-running over the same Graph state must not
// re-emit the same annotation (avoids needless ClickHouse re-ingest churn on
// every 30-min sweep for an unresolved orphan).
func TestK8sManifestOwnership_CorrelateAssets_AlreadyFlaggedIsNoop(t *testing.T) {
	orphan := declared("org/repo", "deployment/ghost/none", "k8s_deployment", "ghost", "d.yaml")
	orphan.Metadata["drift"] = "declared_not_live"
	g := NewGraph([]asset.Asset{orphan})

	require.Len(t, K8sManifestOwnership{}.CorrelateAssets(g), 1, "unchanged intent still advances producer version against late replay")
}

// TestK8sManifestOwnership_CorrelateAssets_ResolvedDriftIsCleared verifies
// the other direction: a workload previously flagged drift that now resolves
// to a live match gets re-ingested with the drift key removed, not left
// stale forever.
func TestK8sManifestOwnership_CorrelateAssets_ResolvedDriftIsCleared(t *testing.T) {
	d := declared("org/repo", "deployment/billing/api", "k8s_deployment", "billing", "d.yaml")
	d.Metadata["drift"] = "declared_not_live"
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/deployment/billing/api", "k8s_deployment", "prod-cluster", "billing"),
		d,
	})

	annotated := K8sManifestOwnership{}.CorrelateAssets(g)
	require.Len(t, annotated, 1)
	require.Equal(t, d.ID, annotated[0].ID)
	// "" is the delete signal writeAnnotations' merge acts on (see withMetadata) —
	// CorrelateAssets' own output now carries ONLY the single changed key, so the
	// clear is represented as drift:"" rather than the key's absence.
	require.Equal(t, "", annotated[0].Metadata["drift"], "resolved drift must be cleared, not left stale")
	require.Len(t, annotated[0].Metadata, 1, "annotation must carry only the changed key, not the whole view-projected map")
}

func TestK8sManifestOwnership_LiveTypeMismatchNoEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveWorkload("prod-cluster/service/billing/api", "k8s_service", "prod-cluster", "billing"),
		declared("org/repo", "service/billing/api", "k8s_deployment", "billing", "d.yaml"),
	})
	require.Empty(t, K8sManifestOwnership{}.Correlate(g))
}
