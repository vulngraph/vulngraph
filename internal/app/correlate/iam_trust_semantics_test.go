package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestIAMCanAssume_TaggingDenyPreservesAssumptionEdge(t *testing.T) {
	const source = "arn:aws:iam::111122223333:user/alice"
	const target = "arn:aws:iam::111122223333:role/target"
	for _, denyAction := range []string{"sts:TagSession", "sts:AssumeRoleWithSAML", "sts:AssumeRole"} {
		t.Run(denyAction, func(t *testing.T) {
			role := roleWithTrustStatements(target,
				map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": source}},
				map[string]any{"Effect": "Deny", "Action": denyAction, "Principal": map[string]any{"AWS": source}},
			)
			edges := IAMCanAssume{}.Correlate(NewGraph([]asset.Asset{role}))
			if denyAction == "sts:AssumeRole" {
				require.Empty(t, edges)
				return
			}
			require.Len(t, edges, 1)
			require.Equal(t, source, edges[0].SrcID)
			require.Equal(t, target, edges[0].DstID)
			require.Equal(t, EdgeCanAssume, edges[0].EdgeType)
		})
	}
}

func TestIAMCanAssume_SAMLActionCannotPreserveDeniedUser(t *testing.T) {
	const source = "arn:aws:iam::111122223333:user/alice"
	role := roleWithTrustStatements("arn:aws:iam::111122223333:role/target",
		map[string]any{"Effect": "Allow", "Action": []string{"sts:AssumeRole", "sts:AssumeRoleWithSAML"}, "Principal": map[string]any{"AWS": source, "Federated": "arn:aws:iam::111122223333:saml-provider/Okta"}},
		map[string]any{"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": map[string]any{"AWS": source}},
	)
	require.Empty(t, IAMCanAssume{}.Correlate(NewGraph([]asset.Asset{role})))
}
