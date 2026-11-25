package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

func TestGlueMLTransformDenialJudgedAgainstProof(t *testing.T) {
	denied := apiErr{code: "AccessDeniedException"}
	unproven := map[string]string{}
	proven := map[string]string{collect.ProvenCapabilitiesConfigKey: "sso_admin," + capabilityGlueMLTransforms}

	_, partial, err := gateGlueMLTransforms(context.Background(), unproven, "eu-west-1")(nil, denied)
	require.ErrorIs(t, err, errCapabilityUnproven, "a role that never had the supplemental statement skips quietly")
	require.False(t, partial)

	_, _, err = gateGlueMLTransforms(context.Background(), proven, "eu-west-1")(nil, denied)
	require.Error(t, err)
	require.NotErrorIs(t, err, errCapabilityUnproven, "a denial after the permission once worked is a regression")

	_, _, err = gateGlueMLTransforms(context.Background(), unproven, "eu-west-1")(nil, errAnalyticsDenied)
	require.Error(t, err)
	require.NotErrorIs(t, err, errCapabilityUnproven, "a non-authorization failure is never skipped")

	got, _, err := gateGlueMLTransforms(context.Background(), unproven, "eu-west-1")([]asset.Asset{{ID: "t"}}, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
}

func TestGlueMLTransformsProveTheirCapability(t *testing.T) {
	var proving []string
	for _, c := range regionalServices {
		if c.proves != "" {
			proving = append(proving, c.name+"="+c.proves)
		}
	}
	require.Equal(t, []string{"glue ml transforms=" + capabilityGlueMLTransforms}, proving)
}
