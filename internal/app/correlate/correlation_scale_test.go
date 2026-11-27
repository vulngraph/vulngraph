package correlate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// These fixtures exercise selective Kubernetes joins and a large GCP project.
// Building the inventory is outside the timed region; rule outputs are checked
// on every iteration so skipping work cannot appear as a throughput win.
func BenchmarkCorrelationScale(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("kubernetes/%d", size), func(b *testing.B) {
			assets := make([]asset.Asset, 0, size*2)
			for i := range size {
				cluster := fmt.Sprintf("org/cluster-%d", i%5)
				ns := fmt.Sprintf("ns-%d", i%7)
				app := fmt.Sprintf("app-%d", i)
				assets = append(assets,
					asset.Asset{ID: cluster + "/service/" + ns + "/" + app, Type: "k8s_service",
						Metadata: map[string]string{"namespace": ns, "selector": "tier=backend,app=" + app}},
					asset.Asset{ID: cluster + "/pod/" + ns + "/" + app, Type: "k8s_pod",
						Metadata: map[string]string{"namespace": ns}, Tags: map[string]string{"tier": "backend", "app": app}},
				)
			}
			g := NewGraph(assets)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				edges := (K8sServiceTargets{}).Correlate(g)
				require.Len(b, edges, size)
				for i, e := range edges {
					require.Equal(b, assets[2*i].ID, e.SrcID)
					require.Equal(b, assets[2*i+1].ID, e.DstID)
					require.Equal(b, EdgeTargets, e.EdgeType)
				}
			}
		})
		b.Run(fmt.Sprintf("gcp_impersonation/%d", size), func(b *testing.B) {
			assets := make([]asset.Asset, size)
			privileged := 0
			for i := range size {
				assets[i] = asset.Asset{ID: fmt.Sprintf("sa-%05d", size-i), Type: "gcp_service_account", AccountID: "project"}
				if i%100 == 0 {
					assets[i].Metadata = map[string]string{"permissions": "iam.serviceAccounts.getAccessToken"}
					privileged++
				}
			}
			g := NewGraph(assets)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				edges := (GCPImpersonation{}).Correlate(g)
				require.Len(b, edges, privileged*min(size-1, maxImpersonationTargetsPerSA))
				for _, e := range edges {
					require.NotEqual(b, e.SrcID, e.DstID)
					require.Equal(b, EdgeCanAssume, e.EdgeType)
				}
			}
		})
	}
}
