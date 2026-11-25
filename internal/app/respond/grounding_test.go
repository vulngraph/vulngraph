package respond

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestGroundingConcerns(t *testing.T) {
	pack := ContextPack{
		Finding: finding.Finding{ResourceID: "i-0aaaa1111bbbb2222"},
		Blast: BlastSummary{
			TopReachable: []AssetRef{{ID: "sg-0ccc3333dddd4444", Name: "web-sg"}},
			CanAssume:    []string{"i-0aaaa1111bbbb2222 -> arn:aws:iam::123456789012:role/admin"},
		},
		Identity:    &IdentityLinks{ExecutesAsID: "arn:aws:iam::123456789012:role/exec"},
		SupplyChain: &SupplyChainPath{Workloads: []WorkloadSummary{{ID: "vpc-0eeee5555ffff6666", Type: "vpc"}}},
	}

	tests := []struct {
		name        string
		plan        Plan
		wantConcern bool
	}{
		{
			name: "cites only shown IDs — grounded",
			plan: Plan{Summary: "isolate i-0aaaa1111bbbb2222",
				Rationale: "it can assume arn:aws:iam::123456789012:role/admin via sg-0ccc3333dddd4444"},
			wantConcern: false,
		},
		{
			name:        "cites an unseen instance ID — ungrounded",
			plan:        Plan{Summary: "observe", Rationale: "the compromised host i-0deadbeef1234567 reaches the internet"},
			wantConcern: true,
		},
		{
			name:        "cites an unseen ARN — ungrounded",
			plan:        Plan{Summary: "modify", Rationale: "escalates to arn:aws:iam::999999999999:role/superuser"},
			wantConcern: true,
		},
		{
			name:        "prose with no infra IDs — grounded",
			plan:        Plan{Summary: "observe", Rationale: "isolated, unprivileged, small blast radius — no meaningful risk"},
			wantConcern: false,
		},
		{
			name:        "workload ID shown in supply chain — grounded",
			plan:        Plan{Summary: "remediate", Rationale: "deployed into vpc-0eeee5555ffff6666"},
			wantConcern: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := groundingConcerns(tt.plan, pack)
			if tt.wantConcern {
				require.NotEmpty(t, got)
			} else {
				require.Empty(t, got)
			}
		})
	}
}

// A hallucinated ID must be reported exactly once even if cited repeatedly.
func TestGroundingConcerns_Dedup(t *testing.T) {
	pack := ContextPack{Finding: finding.Finding{ResourceID: "i-0aaaa1111bbbb2222"}}
	plan := Plan{Rationale: "host i-0deadbeef1234567 ... again i-0deadbeef1234567"}
	require.Len(t, groundingConcerns(plan, pack), 1)
}
