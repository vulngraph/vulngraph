package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect/iac"
)

func declaredIdentity(repo, path, kind, value string) asset.Asset {
	return asset.Asset{
		ID:   "declared_cloud_identity:" + repo + ":" + path + ":" + value,
		Type: "declared_cloud_identity",
		Name: value,
		Metadata: map[string]string{
			"repo": repo, "path": path, "kind": kind, "value": value,
		},
	}
}

// TestDeclaredIdentityKindsMatchCollector pins the hand-copied contract. correlate
// does not import internal/collect (the convention tf_ownership follows), so the
// kind strings are restated here — this fails if either side renames one,
// instead of the rule silently matching nothing.
func TestDeclaredIdentityKindsMatchCollector(t *testing.T) {
	require.Equal(t, iac.IdentityIamRole, kindIamRole)
	require.Equal(t, iac.IdentityIamUser, kindIamUser)
	require.Equal(t, iac.IdentityGCPSA, kindGCPSA)
	require.Equal(t, iac.IdentityGitHubOIDC, kindGitHubOIDC)
}

// Ownership: whichever repo's text names a live identity declares it. One rule,
// no per-tool parser and no pinned repo — the identifier is the join.
func TestDeclaredIdentityOwnership_JoinsAnyRepoAnyTool(t *testing.T) {
	const roleARN = "arn:aws:iam::123456789012:role/messaging-api"
	const saID = "serviceAccount:app-publisher@example-project.iam.gserviceaccount.com"

	g := NewGraph([]asset.Asset{
		{ID: roleARN, Type: "iam_role", Name: "messaging-api"},
		{ID: saID, Type: "gcp_service_account", Name: "app-publisher@example-project.iam.gserviceaccount.com"},
		{ID: "example-corp/iam-config", Type: "github_repo"},
		{ID: "example-corp/infra-terraform", Type: "github_repo"},
		// Raw IAM policy JSON in one org…
		declaredIdentity("example-corp/iam-config", "policies/x.json", kindIamRole, roleARN),
		// …and a Terraform repo in another, whose state we cannot even read (GCS).
		declaredIdentity("example-corp/infra-terraform", "gcp/example-project/iam.tf", kindGCPSA, saID),
	})

	edges := DeclaredIdentityOwnership{}.Correlate(g)
	require.Len(t, edges, 2)

	byDst := map[string]asset.Edge{}
	for _, e := range edges {
		require.Equal(t, EdgeDefinedIn, e.EdgeType)
		require.Equal(t, "high", e.Properties["confidence"], "exact identifier equality — nothing reconstructed")
		require.Equal(t, "identifier_harvest", e.Properties["provenance"])
		byDst[e.DstID] = e
	}
	require.Equal(t, roleARN, byDst["example-corp/iam-config"].SrcID)
	require.Equal(t, "policies/x.json", byDst["example-corp/iam-config"].Properties["path"])
	require.Equal(t, saID, byDst["example-corp/infra-terraform"].SrcID)
}

// An identity nobody collected is skipped, never guessed at: no live node means
// either the account is not monitored or the reference is stale, and inventing an
// edge to a nonexistent node is how topology gets fabricated.
func TestDeclaredIdentityOwnership_SkipsUnknownIdentities(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "example-corp/iam-config", Type: "github_repo"},
		declaredIdentity("example-corp/iam-config", "policies/x.json", kindIamRole,
			"arn:aws:iam::999999999999:role/not-collected"),
	})
	require.Empty(t, DeclaredIdentityOwnership{}.Correlate(g))
}

// The federation half: a trust policy naming an OIDC subject grants THAT repo's CI
// the role the same file defines. This is the authoritative IAM-side version of
// the workflow-file heuristic — an IAM-config repo can hold hundreds of these.
func TestDeclaredIdentityOwnership_TrustPolicyGrantsSubjectRepo(t *testing.T) {
	const roleARN = "arn:aws:iam::555555555555:role/orders-api-build"
	g := NewGraph([]asset.Asset{
		{ID: roleARN, Type: "iam_role", Name: "orders-api-build"},
		{ID: "example-corp/iam-config", Type: "github_repo"},
		{ID: "example-corp/orders-api", Type: "github_repo"},
		declaredIdentity("example-corp/iam-config", "roles/orders-api-build.json", kindIamRole, roleARN),
		declaredIdentity("example-corp/iam-config", "roles/orders-api-build.json", kindGitHubOIDC, "example-corp/orders-api"),
	})

	var fed []asset.Edge
	for _, e := range (DeclaredIdentityOwnership{}).Correlate(g) {
		if e.EdgeType == EdgeFederatedAccess {
			fed = append(fed, e)
		}
	}
	require.Len(t, fed, 1)
	require.Equal(t, "example-corp/orders-api", fed[0].SrcID, "the app repo whose CI may assume the role")
	require.Equal(t, roleARN, fed[0].DstID)
	require.Equal(t, "iac_trust_policy", fed[0].Properties["provenance"])
	require.Equal(t, "example-corp/iam-config", fed[0].Properties["declared_in"], "which repo defines the grant")
}

// A subject with no role in the same file has no target to point at, and a
// subject naming a repo we do not collect cannot be an edge source.
func TestDeclaredIdentityOwnership_OIDCNeedsBothEnds(t *testing.T) {
	const roleARN = "arn:aws:iam::555555555555:role/r"

	noRole := NewGraph([]asset.Asset{
		{ID: "example-corp/iam-config", Type: "github_repo"},
		{ID: "example-corp/orders-api", Type: "github_repo"},
		declaredIdentity("example-corp/iam-config", "docs/README.md", kindGitHubOIDC, "example-corp/orders-api"),
	})
	require.Empty(t, DeclaredIdentityOwnership{}.Correlate(noRole))

	unknownRepo := NewGraph([]asset.Asset{
		{ID: roleARN, Type: "iam_role"},
		{ID: "example-corp/iam-config", Type: "github_repo"},
		declaredIdentity("example-corp/iam-config", "roles/x.json", kindIamRole, roleARN),
		declaredIdentity("example-corp/iam-config", "roles/x.json", kindGitHubOIDC, "example-corp/never-collected"),
	})
	for _, e := range (DeclaredIdentityOwnership{}).Correlate(unknownRepo) {
		require.NotEqual(t, EdgeFederatedAccess, e.EdgeType)
	}
}

// Two files naming the same role must not produce duplicate ownership edges.
func TestDeclaredIdentityOwnership_DedupesEdges(t *testing.T) {
	const roleARN = "arn:aws:iam::123456789012:role/app"
	g := NewGraph([]asset.Asset{
		{ID: roleARN, Type: "iam_role"},
		{ID: "org/repo", Type: "github_repo"},
		declaredIdentity("org/repo", "a.tf", kindIamRole, roleARN),
		declaredIdentity("org/repo", "b.tf", kindIamRole, roleARN),
	})
	require.Len(t, DeclaredIdentityOwnership{}.Correlate(g), 1)
}
