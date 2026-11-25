package ciem

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestGCPTierNeverTreatsAllowCandidateOrHintAsAdminProof(t *testing.T) {
	for _, tc := range []struct {
		name, permissions, complete, want string
	}{
		{"legacy raw admin", "", "", TierUnknown},
		{"raw admin with complete empty permissions", "", "true", TierStandard},
		{"limited role changes", "resourcemanager.projects.setIamPolicy", "true", TierHigh},
		{"role update candidate", "iam.roles.update", "true", TierHigh},
		{"partial permissions", "resourcemanager.projects.setIamPolicy", "false", TierUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset.Asset{ID: "serviceAccount:worker@p.iam.gserviceaccount.com", Type: "gcp_service_account", Provider: asset.ProviderGCP, AccountID: "p", Metadata: map[string]string{
				"roles": "roles/owner", "admin": "true", "permissions": tc.permissions, "permissions_complete": tc.complete,
			}}
			result := AnalyzeIAMAssets(context.Background(), []asset.Asset{a})
			require.Equal(t, tc.want, result.Tiers[a.ID].Tier)
			for _, f := range result.Findings {
				require.Equal(t, SeverityCritical, f.Severity)
			}
		})
	}
}
