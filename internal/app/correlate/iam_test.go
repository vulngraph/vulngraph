package correlate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// roleWithTrust builds an iam_role asset whose policies metadata carries a trust
// policy allowing the given principal block.
func roleWithTrust(id string, principal any) asset.Asset {
	stmt := map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}
	doc, _ := json.Marshal(map[string]any{"Statement": []any{stmt}})
	pols, _ := json.Marshal([]map[string]string{{"type": "trust", "document": string(doc)}})
	return asset.Asset{ID: id, Type: "iam_role", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"policies": string(pols)}}
}

func TestIAMCanAssume_ConcretePrincipalEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithTrust("arn:aws:iam::1:role/target",
			map[string]any{"AWS": "arn:aws:iam::1:user/dev"}),
	})
	edges := IAMCanAssume{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "arn:aws:iam::1:user/dev", edges[0].SrcID)
	require.Equal(t, "iam_user", edges[0].SrcType)
	require.Equal(t, "arn:aws:iam::1:role/target", edges[0].DstID)
	require.Equal(t, EdgeCanAssume, edges[0].EdgeType)
}

func TestIAMCanAssume_MultiplePrincipalsAndRoleSrcType(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithTrust("arn:aws:iam::1:role/target",
			map[string]any{"AWS": []any{
				"arn:aws:iam::1:role/ci",
				"arn:aws:iam::2:root",
			}}),
	})
	edges := IAMCanAssume{}.Correlate(g)
	require.Len(t, edges, 2)
	byID := map[string]string{}
	for _, e := range edges {
		byID[e.SrcID] = e.SrcType
	}
	require.Equal(t, "iam_role", byID["arn:aws:iam::1:role/ci"])
	require.Equal(t, "aws_account", byID["arn:aws:iam::2:root"])
}

func TestIAMCanAssume_ServiceAndFederatedExcluded(t *testing.T) {
	// Service principals and OIDC/SAML federation have no principal node — no edge.
	g := NewGraph([]asset.Asset{
		roleWithTrust("arn:aws:iam::1:role/svc",
			map[string]any{"Service": "ec2.amazonaws.com"}),
		roleWithTrust("arn:aws:iam::1:role/oidc",
			map[string]any{"Federated": "arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"}),
	})
	require.Empty(t, IAMCanAssume{}.Correlate(g))
}

func TestIAMCanAssume_StringPrincipalWildcardIgnored(t *testing.T) {
	g := NewGraph([]asset.Asset{roleWithTrust("arn:aws:iam::1:role/open", "*")})
	require.Empty(t, IAMCanAssume{}.Correlate(g))
}

func TestIAMCanAssume_NoTrustPolicyNoEdges(t *testing.T) {
	// An iam_role with only identity policies (no trust) yields nothing.
	pols, _ := json.Marshal([]map[string]string{{"type": "identity", "document": `{"Statement":[]}`}})
	role := asset.Asset{ID: "arn:aws:iam::1:role/x", Type: "iam_role",
		Metadata: map[string]string{"policies": string(pols)}}
	require.Empty(t, IAMCanAssume{}.Correlate(NewGraph([]asset.Asset{role})))
}
