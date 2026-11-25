package correlate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func gcpSA(id, project, perms string) asset.Asset {
	return asset.Asset{
		ID: id, Name: id, Type: "gcp_service_account", Provider: asset.ProviderGCP,
		AccountID: project, Metadata: map[string]string{"permissions": perms},
	}
}

func TestGCPImpersonation_TokenCreatorFansOutInProject(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:attacker@p1.iam", "p1", "iam.serviceAccounts.getAccessToken,storage.objects.get"),
		gcpSA("serviceAccount:victim1@p1.iam", "p1", ""),
		gcpSA("serviceAccount:victim2@p1.iam", "p1", ""),
	})

	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, 2, "token-creator SA reaches the other two SAs in its project")
	for _, e := range edges {
		require.Equal(t, EdgeCanAssume, e.EdgeType)
		require.Equal(t, "serviceAccount:attacker@p1.iam", e.SrcID)
		require.Equal(t, "gcp_service_account", e.DstType)
		require.Equal(t, "token_creator", e.Properties["technique"])
		require.Equal(t, "gcp_impersonation", e.Properties["rule"])
	}
}

func TestGCPImpersonation_ActAsTechnique(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:deployer@p1.iam", "p1", "iam.serviceAccounts.actAs"),
		gcpSA("serviceAccount:target@p1.iam", "p1", ""),
	})
	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "act_as", edges[0].Properties["technique"])
}

func TestGCPImpersonation_WildcardPermission(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:admin@p1.iam", "p1", "iam.serviceAccounts.*"),
		gcpSA("serviceAccount:target@p1.iam", "p1", ""),
	})
	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "token_creator", edges[0].Properties["technique"])
}

func TestGCPImpersonation_NonPrivilegedEmitsNothing(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:a@p1.iam", "p1", "storage.objects.get,compute.instances.list"),
		gcpSA("serviceAccount:b@p1.iam", "p1", ""),
	})
	require.Empty(t, GCPImpersonation{}.Correlate(g))
}

func TestGCPImpersonation_ProjectIsolation(t *testing.T) {
	// A grant in project p1 must not reach SAs in project p2.
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:attacker@p1.iam", "p1", "iam.serviceAccounts.getAccessToken"),
		gcpSA("serviceAccount:victim@p1.iam", "p1", ""),
		gcpSA("serviceAccount:elsewhere@p2.iam", "p2", ""),
	})
	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "serviceAccount:victim@p1.iam", edges[0].DstID)
}

// Regression for the cross-project can_assume explosion: the correlate view used
// to drop account_id, so every SA arrived with AccountID="". If such SAs were
// bucketed together, a single project-level grant fanned out across ALL projects.
// An SA with an unknown project must emit NO impersonation edges (fail-safe) —
// even if it holds a token-creator grant — rather than a cross-project mesh.
func TestGCPImpersonation_EmptyProjectEmitsNothing(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:attacker@unknown.iam", "", "iam.serviceAccounts.getAccessToken"),
		gcpSA("serviceAccount:victim1@unknown.iam", "", ""),
		gcpSA("serviceAccount:victim2@unknown.iam", "", ""),
		// A real, project-scoped grant still works alongside the skipped ones.
		gcpSA("serviceAccount:legit@p1.iam", "p1", "iam.serviceAccounts.getAccessToken"),
		gcpSA("serviceAccount:target@p1.iam", "p1", ""),
	})
	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, 1, "only the project-scoped grant emits an edge; empty-project SAs are skipped")
	require.Equal(t, "serviceAccount:legit@p1.iam", edges[0].SrcID)
	require.Equal(t, "serviceAccount:target@p1.iam", edges[0].DstID)
}

func TestGCPImpersonation_NoSelfEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:lonely@p1.iam", "p1", "iam.serviceAccounts.getAccessToken"),
		gcpSA("serviceAccount:other@p1.iam", "p1", ""),
	})
	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, 1)
	require.NotEqual(t, edges[0].SrcID, edges[0].DstID)
}

func TestGCPImpersonation_FanOutCapped(t *testing.T) {
	assets := []asset.Asset{
		gcpSA("serviceAccount:attacker@p1.iam", "p1", "iam.serviceAccounts.getAccessToken"),
	}
	for i := range maxImpersonationTargetsPerSA + 20 {
		assets = append(assets, gcpSA(fmt.Sprintf("serviceAccount:v%04d@p1.iam", i), "p1", ""))
	}
	g := NewGraph(assets)
	edges := GCPImpersonation{}.Correlate(g)
	require.Len(t, edges, maxImpersonationTargetsPerSA, "fan-out capped deterministically")
}

func TestGCPImpersonation_SingleSANoEdges(t *testing.T) {
	g := NewGraph([]asset.Asset{
		gcpSA("serviceAccount:solo@p1.iam", "p1", "iam.serviceAccounts.getAccessToken"),
	})
	require.Empty(t, GCPImpersonation{}.Correlate(g))
}
