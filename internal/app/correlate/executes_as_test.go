package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestExecutesAs_AWSLambdaAndGCEServiceAccount(t *testing.T) {
	g := NewGraph([]asset.Asset{
		// AWS: lambda runs as a role ARN that is in inventory.
		{ID: "arn:aws:lambda::1:function:f", Type: "lambda_function", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"exec_role": "arn:aws:iam::1:role/fn"}},
		{ID: "arn:aws:iam::1:role/fn", Type: "iam_role", Provider: asset.ProviderAWS},
		// GCP: gce instance runs as a service account in inventory.
		{ID: "proj/vm", Type: "gce_instance", Provider: asset.ProviderGCP,
			Metadata: map[string]string{"exec_role": "serviceAccount:sa@proj.iam.gserviceaccount.com"}},
		{ID: "serviceAccount:sa@proj.iam.gserviceaccount.com", Type: "gcp_service_account", Provider: asset.ProviderGCP},
	})

	edges := ExecutesAs{}.Correlate(g)
	require.Len(t, edges, 2)

	bySrc := map[string]asset.Edge{}
	for _, e := range edges {
		bySrc[e.SrcID] = e
		require.Equal(t, EdgeExecutesAs, e.EdgeType)
	}
	require.Equal(t, "arn:aws:iam::1:role/fn", bySrc["arn:aws:lambda::1:function:f"].DstID)
	require.Equal(t, "iam_role", bySrc["arn:aws:lambda::1:function:f"].DstType)
	require.Equal(t, "serviceAccount:sa@proj.iam.gserviceaccount.com", bySrc["proj/vm"].DstID)
	require.Equal(t, "gcp_service_account", bySrc["proj/vm"].DstType)
}

func TestExecutesAs_NoEdgeWhenTargetMissing(t *testing.T) {
	// exec_role names a role that isn't in inventory → no dangling edge.
	g := NewGraph([]asset.Asset{
		{ID: "fn", Type: "lambda_function", Provider: asset.ProviderAWS,
			Metadata: map[string]string{"exec_role": "arn:aws:iam::1:role/absent"}},
	})
	require.Empty(t, ExecutesAs{}.Correlate(g))
}
