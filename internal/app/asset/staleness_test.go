package asset

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The per-provider staleness gauge counts assets, not rows: an asset whose
// type changed keeps a frozen second row under ORDER BY (type, id), which a
// row count would report as stale forever. IaC declarations are not resources
// and stay out of both counts.
func TestAssetStalenessByProvider_CountsDistinctInventoryIDs(t *testing.T) {
	require.Contains(t, assetStalenessByProvider, "uniqExact(id) AS total")
	require.Contains(t, assetStalenessByProvider, "uniqExactIf(id, last_seen >= high_water")
	require.NotContains(t, assetStalenessByProvider, "count()")
	require.NotContains(t, assetStalenessByProvider, "countIf(")
	require.Contains(t, assetStalenessByProvider, inventoryReadCond)
	for _, ty := range NonInventoryTypes {
		require.Contains(t, assetStalenessByProvider, "'"+ty+"'")
	}
}
