package alertctx

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// The lookups read the assets table for the API, so they must carry the same
// liveness gate as every other inventory reader (asset.TestAssetReadersApplyLiveness
// covers that package only) and must not use FINAL on a filtered lookup.
func TestAssetQueries_LivenessGateAndNoFinal(t *testing.T) {
	for name, q := range map[string]string{
		"liveAssetIDsByID":        liveAssetIDsByID,
		"liveAssetIDsByAttribute": liveAssetIDsByAttribute,
	} {
		require.Contains(t, q, asset.EphemeralLivenessCond, "%s must exclude dead ephemeral resources", name)
		require.Contains(t, q, "declared_cloud_identity", "%s must exclude IaC declarations", name)
		require.NotContains(t, q, "FINAL", "%s is a filtered lookup; FINAL would full-scan", name)
		require.NotContains(t, fmt.Sprintf(q, "?"), "%!", "%s has a stray format verb", name)
	}
}
