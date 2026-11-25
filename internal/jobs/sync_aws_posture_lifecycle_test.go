package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func TestAWSOrganizationPostureLifecycle(t *testing.T) {
	reg := checks.Default()
	for _, tc := range []struct {
		name, coverage, tier, lastUse string
		resolves                      bool
	}{
		{"unknown organization preserves prior admin finding", "false", "unknown", "180", false},
		{"legacy organization preserves prior admin finding", "", "standard", "180", false},
		{"observed restriction removes admin claim", "true", "standard", "180", true},
		{"recent use disproves dormancy despite unknown permissions", "false", "unknown", "1", true},
		{"observed dormant admin remains open", "true", "admin", "180", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset.Asset{ID: "arn:aws:iam::111122223333:role/app", Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
				"admin": "true", "organization_policy_complete": tc.coverage, "privilege_tier": tc.tier,
				"last_used_observed": "true", "last_used_days": tc.lastUse, "created_days": "240", "path": "/",
			}}
			old := finding.Finding{ID: "prior", Source: "cspm", CheckID: "aws-iam-admin-role-dormant", ResourceID: a.ID, ResourceType: a.Type}
			svc := &fakeLifecycler{stored: []finding.Finding{old}}
			current := reg.Run([]asset.Asset{a}, time.Now())
			// Use the stored ID for the same observed check; this test concerns
			// evidence and reconciliation rather than finding ID construction.
			for i := range current {
				if current[i].CheckID == old.CheckID {
					current[i].ID = old.ID
				}
			}
			reconcileResolvedFindings(context.Background(), svc, reg, []asset.Asset{a}, current, false)
			require.Equal(t, tc.resolves, len(svc.resolved) == 1)
			if tc.lastUse == "180" && tc.tier != "admin" {
				found := false
				for _, f := range current {
					found = found || f.CheckID == "aws-iam-role-unused"
				}
				require.True(t, found, "ordinary observed dormancy remains reportable")
			}
		})
	}
}
