package correlate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// roleWithTrustStatements builds an iam_role whose trust policy carries the given
// raw statements, so Deny statements can be expressed (roleWithTrust only emits a
// single Allow).
func roleWithTrustStatements(id string, statements ...map[string]any) asset.Asset {
	doc, _ := json.Marshal(map[string]any{"Statement": statements})
	pols, _ := json.Marshal([]map[string]string{{"type": "trust", "document": string(doc)}})
	return asset.Asset{ID: id, Type: "iam_role", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"policies": string(pols)}}
}

// A principal an explicit Deny has revoked must not get a can_assume edge. This
// correlator carried its own Allow-only trust parser, so the revoked principal
// still produced an edge — and because blast-radius and enrichment BFS traverse
// can_assume, that phantom edge became a phantom attack path.
func TestIAMCanAssume_ExplicitDenyRemovesTheEdge(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithTrustStatements("arn:aws:iam::1:role/target",
			map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"AWS": []any{
					"arn:aws:iam::1:role/allowed",
					"arn:aws:iam::1:role/revoked",
				}}},
			map[string]any{"Effect": "Deny", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"AWS": "arn:aws:iam::1:role/revoked"}},
		),
	})

	edges := IAMCanAssume{}.Correlate(g)
	require.Len(t, edges, 1, "the revoked principal must not produce an edge")
	require.Equal(t, "arn:aws:iam::1:role/allowed", edges[0].SrcID)
}

// A Deny statement's own principals must never be read as if they were granted
// entry — the inverse error, where a Deny is mistaken for a grant.
func TestIAMCanAssume_DenyPrincipalIsNotAGrant(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithTrustStatements("arn:aws:iam::1:role/target",
			map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"Service": "ec2.amazonaws.com"}},
			map[string]any{"Effect": "Deny", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"AWS": "arn:aws:iam::1:role/attacker"}},
		),
	})

	require.Empty(t, IAMCanAssume{}.Correlate(g),
		"a service-only trust grants no principal entry, and the Deny names no grantee")
}

// An unconditional global Deny blocks assumption outright, so no edges survive.
func TestIAMCanAssume_GlobalDenyBlocksAllEdges(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithTrustStatements("arn:aws:iam::1:role/target",
			map[string]any{"Effect": "Allow", "Action": "sts:AssumeRole",
				"Principal": map[string]any{"AWS": "arn:aws:iam::1:role/ci"}},
			map[string]any{"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": "*"},
		),
	})

	require.Empty(t, IAMCanAssume{}.Correlate(g))
}
