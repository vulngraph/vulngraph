package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunCypher_ResultConversionBudget(t *testing.T) {
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	for _, tc := range []struct {
		name, query string
		truncated   bool
	}{
		{"oversized scalar list", "RETURN range(1, 10000) AS xs", true},
		{"oversized nested list", "RETURN [range(1, 10000)] AS xs", true},
		{"oversized string", "RETURN repeat('a', 65537) AS s", true},
		{"ordinary containers", "RETURN {name: 'ok', xs: [1, 2, 3]} AS value", false},
		{"ordinary scalar", "RETURN 42 AS value", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.RunCypher(context.Background(), tc.query, 10, 10)
			require.NoError(t, err)
			require.Equal(t, tc.truncated, res.Truncated)
			if tc.truncated {
				require.Empty(t, res.Rows)
			} else {
				require.Len(t, res.Rows, 1)
			}
		})
	}
}
