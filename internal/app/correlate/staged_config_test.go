package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStagedResourceConfiguration(t *testing.T) {
	limits, err := StagedViewLimitsFromEnv(func(string) string { return "" })
	require.NoError(t, err)
	require.Equal(t, DefaultStagedViewLimits(), limits)
	require.Zero(t, limits.Rows, "production input is byte-budgeted, not capped at an estate row count")
	require.Zero(t, limits.OutputRows)
	for _, value := range []string{"0", "-1", "lots", "4294967296"} {
		_, err := StagedViewLimitsFromEnv(func(key string) string {
			if key == "CORRELATE_INDEX_MIB" {
				return value
			}
			return ""
		})
		require.ErrorContains(t, err, "CORRELATE_INDEX_MIB")
	}
	_, err = StagedViewLimitsFromEnv(func(key string) string {
		if key == "CORRELATE_SPOOL_MIB" {
			return "16"
		}
		return ""
	})
	require.ErrorContains(t, err, "CORRELATE_SPOOL_MIB")
}
