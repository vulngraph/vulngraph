package reason

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
)

// translate_prompt_test.go covers the prompt content (schema/rel coverage);
// these tests cover the parser.

func TestParseSpec_ValidJSON(t *testing.T) {
	spec, err := parseSpec(`{"seed":{"types":["ec2_instance"],"provider":"aws"},"traverse":[{"edge_types":["ProtectedBy"],"direction":"out","max_hops":1}]}`)
	require.NoError(t, err)
	require.Equal(t, []string{"ec2_instance"}, spec.Seed.Types)
	require.Equal(t, "aws", spec.Seed.Provider)
}

// A trailing sentence with its own brace pair must not corrupt the parse —
// parseSpec uses decodeJSONReply (json.Decoder), not a brace-slice, for the
// same reason parsePlan/parseVerdict do.
func TestParseSpec_TolerantOfTrailingProseContainingBraces(t *testing.T) {
	spec, err := parseSpec(`{"seed":{"ids":["i-123"]}} Note: this also covers {ec2 and s3} resources.`)
	require.NoError(t, err)
	require.Equal(t, []string{"i-123"}, spec.Seed.IDs)
}

func TestParseSpec_NoSeedFieldsIsErrNoSeed(t *testing.T) {
	_, err := parseSpec(`{"seed":{},"traverse":[]}`)
	require.ErrorIs(t, err, explore.ErrNoSeed)
}

func TestParseSpec_InvalidJSONIsAnError(t *testing.T) {
	_, err := parseSpec(`not json at all`)
	require.Error(t, err)
}
