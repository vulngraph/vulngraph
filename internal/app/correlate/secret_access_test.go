package correlate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// roleWithSecretPolicy builds an iam_role whose identity policy grants
// secretsmanager:GetSecretValue on the given resource pattern.
func roleWithSecretPolicy(id string, resource any) asset.Asset {
	stmt := map[string]any{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": resource}
	doc, _ := json.Marshal(map[string]any{"Statement": []any{stmt}})
	pols, _ := json.Marshal([]map[string]string{{"type": "identity", "document": string(doc)}})
	return asset.Asset{ID: id, Type: "iam_role", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"policies": string(pols)}}
}

func smSecret(id string) asset.Asset {
	return asset.Asset{ID: id, Type: "secretsmanager_secret", Provider: asset.ProviderAWS}
}

// roleWithSecretPolicyAndDenyAll is roleWithSecretPolicy plus a sibling
// identity policy carrying an unconditional Effect:Deny, Action:*, Resource:*
// statement — the real AWS deny-wins case that must suppress the secret grant
// entirely, the same way it suppresses isAdminish/allows_action elsewhere.
func roleWithSecretPolicyAndDenyAll(id string, resource any) asset.Asset {
	stmt := map[string]any{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": resource}
	doc, _ := json.Marshal(map[string]any{"Statement": []any{stmt}})
	denyStmt := map[string]any{"Effect": "Deny", "Action": "*", "Resource": "*"}
	denyDoc, _ := json.Marshal(map[string]any{"Statement": []any{denyStmt}})
	pols, _ := json.Marshal([]map[string]string{
		{"type": "identity", "document": string(doc)},
		{"type": "identity", "document": string(denyDoc)},
	})
	return asset.Asset{ID: id, Type: "iam_role", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"policies": string(pols)}}
}

// A role granted secret read on "*" must collapse to ONE sentinel edge — NOT a
// fan-out to every secret (the combinatorial blowup that OOM'd the rebuild).
func TestSecretAccess_WildcardCollapsesToSentinel(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithSecretPolicy("arn:aws:iam::1:role/admin", "*"),
		smSecret("arn:aws:secretsmanager:us-east-1:1:secret:a"),
		smSecret("arn:aws:secretsmanager:us-east-1:1:secret:b"),
		smSecret("arn:aws:secretsmanager:us-east-1:1:secret:c"),
	})
	edges := SecretAccess{}.Correlate(g)
	require.Len(t, edges, 1, "wildcard role must collapse to one sentinel edge, not fan out to every secret")
	require.Equal(t, secretWildcardID, edges[0].DstID)
	require.Equal(t, "wildcard", edges[0].Properties["scope"])
	require.Equal(t, "arn:aws:iam::1:role/admin", edges[0].SrcID)
}

// A scoped grant (specific ARN) still emits a real per-secret edge — only the
// matching secret, not the others.
func TestSecretAccess_ScopedEmitsPerSecret(t *testing.T) {
	target := "arn:aws:secretsmanager:us-east-1:1:secret:a"
	g := NewGraph([]asset.Asset{
		roleWithSecretPolicy("arn:aws:iam::1:role/scoped", target),
		smSecret(target),
		smSecret("arn:aws:secretsmanager:us-east-1:1:secret:b"),
	})
	edges := SecretAccess{}.Correlate(g)
	require.Len(t, edges, 1, "scoped grant matches only its one secret")
	require.Equal(t, target, edges[0].DstID)
	require.NotEqual(t, "wildcard", edges[0].Properties["scope"])
}

// A sibling explicit deny-all policy neutralizes secret access the same way it
// neutralizes isAdminish/allows_action — a real AWS explicit deny wins
// globally, regardless of which attached policy declares the Allow.
func TestSecretAccess_DenyAllNeutralizesGrant(t *testing.T) {
	g := NewGraph([]asset.Asset{
		roleWithSecretPolicyAndDenyAll("arn:aws:iam::1:role/locked-down", "*"),
		smSecret("arn:aws:secretsmanager:us-east-1:1:secret:a"),
	})
	edges := SecretAccess{}.Correlate(g)
	require.Empty(t, edges, "a sibling explicit deny-all must suppress secret access entirely")
}

// SrcType was hardcoded "iam_role" on both branches while the loop iterates
// PermissionPrincipals, which includes iam_user — so every user's secret access
// was written to the graph as a role's.
func TestSecretAccess_IAMUserKeepsItsOwnSrcType(t *testing.T) {
	user := roleWithSecretPolicy("arn:aws:iam::1:user/deploy", "arn:aws:secretsmanager:us-east-1:1:secret:a")
	user.Type = "iam_user"
	wildcardUser := roleWithSecretPolicy("arn:aws:iam::1:user/admin", "*")
	wildcardUser.Type = "iam_user"

	edges := SecretAccess{}.Correlate(NewGraph([]asset.Asset{
		user, wildcardUser,
		smSecret("arn:aws:secretsmanager:us-east-1:1:secret:a"),
	}))
	require.Len(t, edges, 2)
	for _, e := range edges {
		require.Equal(t, "iam_user", e.SrcType, "edge from %s", e.SrcID)
	}
}

// The organization-level SCP cap must actually reach these edges: a role whose account is
// capped by an SCP denying secretsmanager:* gets no secret-access edge.
func TestSecretAccess_SCPCapSuppressesTheGrant(t *testing.T) {
	role := roleWithSecretPolicy("arn:aws:iam::1:role/app", "*")
	role.AccountID = "1"
	scpDoc := `{"Statement":[{"Effect":"Deny","Action":"secretsmanager:*","Resource":"*"}]}`
	scp := scpSetAsset("1", scpDoc)

	secrets := []asset.Asset{smSecret("arn:aws:secretsmanager:us-east-1:1:secret:a")}
	uncapped := SecretAccess{}.Correlate(NewGraph(append([]asset.Asset{role}, secrets...)))
	require.NotEmpty(t, uncapped, "without the SCP the grant stands")

	capped := SecretAccess{}.Correlate(NewGraph(append([]asset.Asset{role, scp}, secrets...)))
	require.Empty(t, capped, "the account's SCP denies secretsmanager:* — no edge")
}
