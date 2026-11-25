package jobs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func TestGCPHardening_CIEMResolutionRequiresCompleteObservation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		resolve  bool
	}{
		{"ancestor or role read failed", map[string]string{"permissions": "", "permissions_complete": "false"}, false},
		{"permission set absent", map[string]string{}, false},
		{"legacy completeness absent", map[string]string{"permissions": ""}, false},
		{"complete clean observation", map[string]string{"permissions": "", "permissions_complete": "true"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assets := []asset.Asset{{ID: "serviceAccount:worker@p.iam.gserviceaccount.com", Type: "gcp_service_account", Provider: asset.ProviderGCP, AccountID: "p", Metadata: tc.metadata}}
			result := ciem.AnalyzeIAMAssets(context.Background(), assets)
			ciem.StampTiers(assets, result.Tiers)
			old := finding.Finding{ID: "old-token-path", Source: "cspm", Type: "ciem_privesc", CheckID: "gcp-privesc-03", ResourceID: assets[0].ID}
			svc := &fakeLifecycler{stored: []finding.Finding{old}}
			// Ancestor/individual role failures keep the family collection alive;
			// the per-principal evidence must protect resolution on its own.
			reconcileResolvedFindings(context.Background(), svc, checks.Default(), assets, nil, false)
			t.Logf("tier=%v resolved=%v", result.Tiers[assets[0].ID], svc.resolved)
			require.Equal(t, tc.resolve, len(svc.resolved) != 0)
		})
	}
}
