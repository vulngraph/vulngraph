package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type expiredTraversalEdges struct{ stubEdges }

func (expiredTraversalEdges) VerifyDepartedAssets(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{"dead-pod": true}, nil
}

func TestExpiredPodDoesNotTransmitInternetReach(t *testing.T) {
	ctx := context.Background()
	s, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	t.Cleanup(s.Close)
	as := []asset.Asset{
		{ID: "svc", Type: "k8s_service", Provider: asset.ProviderKubernetes},
		{ID: "role", Type: "iam_role", Provider: asset.ProviderAWS},
	}
	es := []asset.Edge{
		{SrcID: "svc", SrcType: "k8s_service", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet"},
		{SrcID: "svc", SrcType: "k8s_service", DstID: "dead-pod", DstType: "k8s_pod", EdgeType: "targets"},
		{SrcID: "dead-pod", SrcType: "k8s_pod", DstID: "role", DstType: "iam_role", EdgeType: "executes_as"},
	}
	require.NoError(t, s.SyncFromSources(ctx, 0, stubAssets{as}, expiredTraversalEdges{stubEdges{es}}, stubSignals{}))
	sig, err := s.NodeSignals(ctx, "role")
	require.NoError(t, err)
	require.Equal(t, ReachNone, sig.InternetHops, "a confirmed departed intermediate cannot transmit reach")
	r, err := s.RunCypher(ctx, "MATCH (n:K8sWorkload {id: 'dead-pod'}) RETURN n", 10, 10)
	require.NoError(t, err)
	require.Empty(t, r.Nodes)
}
