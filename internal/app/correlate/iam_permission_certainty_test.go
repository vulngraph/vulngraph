package correlate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

func TestDangerousActions_ApproximationCannotProveAdmin(t *testing.T) {
	tests := []struct{ name, document string }{
		{"conditional allow", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"security"}}}]}`},
		{"conditional deny", `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"security"}}}]}`},
		{"negated allow", `{"Statement":[{"Effect":"Allow","NotAction":["iam:*","sts:*"],"Resource":"*"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms, err := ciem.EffectivePermissionsForPolicies([]ciem.Policy{{Type: ciem.PolicyIdentity, Document: tt.document}})
			require.NoError(t, err)
			found := dangerousActionsInPolicy(tt.document, perms)
			require.False(t, found["admin-wildcard"], "approximate candidates do not establish unrestricted authority")
			require.True(t, found["iam-admin"], "uncertainty must not erase the action candidate")
		})
	}
}

func TestIAMPermissionEdges_UnreadCapCannotProveAdmin(t *testing.T) {
	full := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	raw, err := json.Marshal([]collectedPolicy{{Type: "identity", Name: "admin", Document: full}})
	require.NoError(t, err)
	scpRaw, err := json.Marshal([]collectedPolicy{{Type: "scp", Document: full}})
	require.NoError(t, err)
	tests := []struct {
		name, boundaryComplete, scpJSON, scpComplete string
	}{
		{name: "legacy boundary missing"},
		{name: "boundary read failed", boundaryComplete: "false"},
		{name: "SCP metadata malformed", boundaryComplete: "true", scpJSON: "[broken", scpComplete: "true"},
		{name: "SCP partial", boundaryComplete: "true", scpJSON: string(scpRaw), scpComplete: "false"},
		{name: "SCP legacy", boundaryComplete: "true", scpJSON: string(scpRaw)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := asset.Asset{ID: "r", Type: "iam_role", Provider: asset.ProviderAWS,
				Metadata: map[string]string{"policies": string(raw), "permission_boundary_complete": tt.boundaryComplete}}
			var scps []collectedPolicy
			if tt.scpJSON != "" {
				scps = scpPoliciesOf(asset.Asset{Metadata: map[string]string{"policies": tt.scpJSON, "policies_complete": tt.scpComplete}})
			}
			categories := map[string]bool{}
			for _, edge := range iamPermissionEdges(principal, scps) {
				categories[edge.Properties["category"]] = true
			}
			require.False(t, categories["admin-wildcard"])
			require.True(t, categories["iam-admin"], "uncertainty preserves action candidates")
		})
	}
}

func TestSCPPoliciesOf_CannotTurnCapIntoIdentityGrant(t *testing.T) {
	for _, typ := range []string{"", "identity", "trust"} {
		raw, err := json.Marshal([]collectedPolicy{{Type: typ, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}})
		require.NoError(t, err)
		scps := scpPoliciesOf(asset.Asset{Metadata: map[string]string{"policies": string(raw), "policies_complete": "true"}})
		perms, err := effectivePermissionsForCollectedPolicies(scps)
		require.NoError(t, err)
		require.Empty(t, perms, "an SCP never grants by itself")
	}
}

func TestIAMPermissionEdges_LegacyReadableBoundaryStillCaps(t *testing.T) {
	raw, err := json.Marshal([]collectedPolicy{
		{Type: "identity", Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
		{Type: "boundary", Document: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`},
	})
	require.NoError(t, err)
	principal := asset.Asset{ID: "r", Type: "iam_role", Provider: asset.ProviderAWS, Metadata: map[string]string{"policies": string(raw)}}
	for _, edge := range iamPermissionEdges(principal, nil) {
		require.NotEqual(t, "iam-admin", edge.Properties["category"])
		require.NotEqual(t, "admin-wildcard", edge.Properties["category"])
	}
}
