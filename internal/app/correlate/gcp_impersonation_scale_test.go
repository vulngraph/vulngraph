package correlate

import (
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestGCPImpersonationSharedOrderingPreservesTargets(t *testing.T) {
	for _, size := range []int{12, 501, 502, 700} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var assets []asset.Asset
			privileged := map[string]bool{}
			for _, project := range []string{"project-a", "project-b", ""} {
				for i := range size {
					a := gcpSA(fmt.Sprintf("%s-sa-%04d", project, size-i), project, "")
					if i == 0 || i == size/2 || i == size-1 {
						a.Metadata["permissions"] = "iam.serviceAccounts.getAccessToken"
						privileged[a.ID] = true
					}
					assets = append(assets, a)
				}
			}
			got := map[string][]string{}
			for _, e := range (GCPImpersonation{}).Correlate(NewGraph(assets)) {
				require.Equal(t, EdgeCanAssume, e.EdgeType)
				require.Equal(t, "token_creator", e.Properties["technique"])
				require.True(t, privileged[e.SrcID])
				got[e.SrcID] = append(got[e.SrcID], e.DstID)
			}
			for _, source := range assets {
				if !privileged[source.ID] {
					continue
				}
				var want []string
				if source.AccountID != "" {
					for _, target := range assets {
						if target.AccountID == source.AccountID && target.ID != source.ID {
							want = append(want, target.ID)
						}
					}
					if len(want) > maxImpersonationTargetsPerSA {
						slices.Sort(want)
						want = want[:maxImpersonationTargetsPerSA]
					}
				}
				require.Equal(t, want, got[source.ID], source.ID)
			}
		})
	}
}
