//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// A re-scored finding must not get a second decide while the first is pending;
// a different finding must.
func TestDecideArgs_DedupesByFindingIDInRiver(t *testing.T) {
	ctx := context.Background()
	client, countByArgs := isolatedRiverClient(t)

	for _, f := range []finding.Finding{{ID: "f1", Score: 40}, {ID: "f1", Score: 90}, {ID: "f2", Score: 40}} {
		_, err := client.Insert(ctx, DecideArgs{Finding: f}, nil)
		require.NoError(t, err)
	}
	total := 0
	for _, n := range countByArgs(DecideArgs{}.Kind()) {
		total += n
	}
	require.Equal(t, 2, total, "one decide per finding ID")
}
