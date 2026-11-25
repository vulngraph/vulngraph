package demo_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

func TestDemoOrganizationEvidenceCannotCertifyLiveAWSRole(t *testing.T) {
	assets, _ := collectDemo(t)
	const liveAccount = "111122223333"
	policies, err := json.Marshal([]ciem.Policy{{
		Name: "administrator", Type: ciem.PolicyIdentity,
		Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	}})
	require.NoError(t, err)
	liveRole := asset.Asset{
		ID: "arn:aws:iam::" + liveAccount + ":role/live-role", Type: "iam_role",
		Provider: asset.ProviderAWS, AccountID: liveAccount,
		Metadata: map[string]string{"policies": string(policies), "permission_boundary_complete": "true"},
	}

	// The live role's identity policies and boundary were read, but its
	// organization membership is unknown. Only Acme supplied a standalone observation.
	analysis := ciem.AnalyzeIAMAssets(t.Context(), append(assets, liveRole))
	require.True(t, analysis.OrganizationPolicyCoverage[adminRole])
	require.Equal(t, ciem.TierAdmin, analysis.Tiers[adminRole].Tier)
	require.Contains(t, analysis.OrganizationPolicyCoverage, liveRole.ID)
	require.False(t, analysis.OrganizationPolicyCoverage[liveRole.ID])
	require.Equal(t, ciem.TierUnknown, analysis.Tiers[liveRole.ID].Tier)
}
