package correlate

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestDNSStreamStopsBeforeAccumulatingFanout(t *testing.T) {
	rows := make([]asset.Asset, 0, 10000+maxDNSTargetsPerValue)
	for i := range 10000 {
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("dns-%05d", i), Type: "dns_record", Metadata: map[string]string{"values": "203.0.113.9"}})
	}
	for i := range maxDNSTargetsPerValue {
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("target-%02d", i), Type: "ec2_instance", PublicIP: "203.0.113.9"})
	}
	graph := NewGraph(rows)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	count := 0
	for edge := range (DNSPointsTo{}).Edges(graph) {
		require.Equal(t, fmt.Sprintf("dns-%05d", count/maxDNSTargetsPerValue), edge.SrcID)
		count++
		if count == 1000 {
			break
		}
	}
	runtime.ReadMemStats(&after)
	require.Equal(t, 1000, count)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(4<<20), "a stopped consumer must not construct all 250,000 edges")
}

func TestFederationNestedStreamStopsBeforeAccumulatingFanout(t *testing.T) {
	rows := []asset.Asset{githubTrustRole("role", `,"Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example/*:*"}}`)}
	for i := range 10000 {
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("example/repo-%d", i), Type: "github_repo"})
	}
	graph := NewGraph(rows)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	count := 0
	for edge := range (FederationTrust{}).Edges(graph) {
		require.Equal(t, "role", edge.DstID)
		count++
		break
	}
	runtime.ReadMemStats(&after)
	require.Equal(t, 1, count)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(1<<20), "the nested trust helper must stop with its consumer")
}

func TestCIAccessStoppedStreamKeepsCompletedPendingState(t *testing.T) {
	rule := &CIAccess{pending: []PendingVerify{{TargetARN: "previous-complete"}}}
	rows := []asset.Asset{
		declaredCIAccessAsset("old", "aws", "missing.yml", map[string]string{"target_arn": "missing"}),
		declaredCIAccessAsset("live", "aws", "live.yml", map[string]string{"target_arn": "role"}),
		{ID: "role", Type: "iam_role"},
	}
	count := 0
	for range rule.Edges(NewGraph(rows)) {
		count++
		break
	}
	require.Equal(t, 1, count)
	require.Equal(t, []PendingVerify{{TargetARN: "previous-complete"}}, rule.PendingLiveVerify())
}
