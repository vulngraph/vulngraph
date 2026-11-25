package correlate

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// principalWithPolicy builds an iam_role or iam_user carrying one identity policy.
func principalWithPolicy(id, assetType, accountID, doc string) asset.Asset {
	pols, _ := json.Marshal([]collectedPolicy{{Name: "inline", Type: "identity", Document: doc}})
	return asset.Asset{
		ID: id, Type: assetType, Provider: asset.ProviderAWS, AccountID: accountID,
		Metadata: map[string]string{"policies": string(pols)},
	}
}

// scpSetAsset builds the aws_scp_set asset the AWS management connector emits.
func scpSetAsset(accountID, doc string) asset.Asset {
	context, _ := json.Marshal(ciem.AWSOrganizationEvidence{
		ObservedAt: time.Now(), AccountID: accountID, ManagementAccountID: "management", RootID: "r-root", RootSCPStatus: "enabled", Applicability: "member", Complete: true,
		Levels: []ciem.SCPLevel{
			{TargetID: accountID, ParentID: "r-root", Complete: true, Policies: []ciem.SCPPolicyDocument{{Name: "scp", Document: doc}}},
			{TargetID: "r-root", Complete: true, Policies: []ciem.SCPPolicyDocument{{Name: "FullAWSAccess", Document: adminDoc}}},
		},
	})
	return asset.Asset{
		ID: "aws_scp:" + accountID, Type: "aws_scp_set", Provider: asset.ProviderAWS,
		AccountID: accountID, Metadata: map[string]string{ciem.MetaAWSOrganization: string(context)},
	}
}

const adminDoc = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// An IAM USER with admin permissions must produce allows_action edges. This rule
// declared iam_user in InterestedIn but iterated only iam_role, so users — the
// principals that hold long-lived access keys, and so the likeliest to be
// compromised — were entirely absent from the permission graph.
func TestIAMEffectivePermissions_CoversIAMUsers(t *testing.T) {
	g := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:user/admin-human", "iam_user", "1", adminDoc),
	})

	edges := IAMEffectivePermissions{}.Correlate(g)
	require.NotEmpty(t, edges, "an admin IAM user must produce allows_action edges")
	require.Equal(t, "iam_user", edges[0].SrcType)
	require.Equal(t, EdgeAllowsAction, edges[0].EdgeType)
}

// Roles must keep working alongside users.
func TestIAMEffectivePermissions_StillCoversRoles(t *testing.T) {
	g := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:role/admin", "iam_role", "1", adminDoc),
	})
	edges := IAMEffectivePermissions{}.Correlate(g)
	require.NotEmpty(t, edges)
	require.Equal(t, "iam_role", edges[0].SrcType)
}

// An SCP capping the account must cap these edges too. SCPs live on a separate
// aws_scp_set asset, so they reached CIEM privesc detection but never the
// correlators — findings were SCP-capped while the graph was not, the same
// question answered two different ways in two subsystems.
func TestIAMEffectivePermissions_SCPCapsEdges(t *testing.T) {
	denyAllSCP := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`

	uncapped := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:role/admin", "iam_role", "1", adminDoc),
	})
	require.NotEmpty(t, IAMEffectivePermissions{}.Correlate(uncapped),
		"baseline: the admin role does produce edges without an SCP")

	capped := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:role/admin", "iam_role", "1", adminDoc),
		scpSetAsset("1", denyAllSCP),
	})
	require.Empty(t, IAMEffectivePermissions{}.Correlate(capped),
		"an organization deny-all SCP removes the permission entirely")
}

// An SCP attached to a DIFFERENT account must not cap this principal.
func TestIAMEffectivePermissions_SCPScopedToItsOwnAccount(t *testing.T) {
	g := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:role/admin", "iam_role", "1", adminDoc),
		scpSetAsset("2", `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`),
	})
	require.NotEmpty(t, IAMEffectivePermissions{}.Correlate(g))
}

// "Allow NotAction" — an admin-except-IAM grant. Candidates were enumerated from
// stmt.Action alone, which is empty here, so the statement produced ZERO edges
// even though the evaluator correctly resolves the principal as holding "*".
func TestIAMEffectivePermissions_AllowNotActionProducesEdges(t *testing.T) {
	g := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:role/broad", "iam_role", "1",
			`{"Statement":[{"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"}]}`),
	})

	edges := IAMEffectivePermissions{}.Correlate(g)
	require.NotEmpty(t, edges,
		"a NotAction grant still confers dangerous actions and must be graphed")
}

// A secret grant held by an IAM user must produce an edge, for the same reason as
// the allows_action case above.
func TestSecretAccess_CoversIAMUsers(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:1:secret:prod-db"
	g := NewGraph([]asset.Asset{
		principalWithPolicy("arn:aws:iam::1:user/svc", "iam_user", "1",
			`{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"`+secretARN+`"}]}`),
		{ID: secretARN, Type: "secretsmanager_secret", Provider: asset.ProviderAWS, AccountID: "1"},
	})

	edges := SecretAccess{}.Correlate(g)
	require.NotEmpty(t, edges, "an IAM user with GetSecretValue must produce a secret-access edge")
}

// And an SCP must cap secret access too.
func TestSecretAccess_SCPCapsGrant(t *testing.T) {
	secretARN := "arn:aws:secretsmanager:us-east-1:1:secret:prod-db"
	assets := []asset.Asset{
		principalWithPolicy("arn:aws:iam::1:role/svc", "iam_role", "1",
			`{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"`+secretARN+`"}]}`),
		{ID: secretARN, Type: "secretsmanager_secret", Provider: asset.ProviderAWS, AccountID: "1"},
	}
	require.NotEmpty(t, SecretAccess{}.Correlate(NewGraph(assets)), "baseline")

	capped := append(assets, scpSetAsset("1",
		`{"Statement":[{"Effect":"Deny","Action":"secretsmanager:*","Resource":"*"}]}`))
	require.Empty(t, SecretAccess{}.Correlate(NewGraph(capped)),
		"an SCP denying secretsmanager removes the grant")
}
