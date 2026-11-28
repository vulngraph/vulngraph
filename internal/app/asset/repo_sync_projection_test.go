package asset

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncAssetQueryPreservesUnprojectedRead(t *testing.T) {
	q, args := syncAssetQuery(SyncProjection{})
	require.Equal(t, listAllForSyncQ, q)
	require.Empty(t, args)
}

func TestSyncAssetQueryProjectsOnlyRequestedFields(t *testing.T) {
	for _, tc := range []struct {
		name       string
		projection SyncProjection
	}{
		{"metadata", SyncProjection{MetadataKeys: []string{"public", "key'with quote"}}},
		{"tags", SyncProjection{SkipTags: true}},
		{"both", SyncProjection{MetadataKeys: []string{"public"}, SkipTags: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, args := syncAssetQuery(tc.projection)
			require.Contains(t, q, listAllForSyncKeys)
			require.Contains(t, q, "greatest(a.current.11,r.risk_score)")
			require.Contains(t, q, "aggregation_in_order_max_block_bytes=4194304")
			if len(tc.projection.MetadataKeys) > 0 {
				require.Equal(t, []any{tc.projection.MetadataKeys}, args)
				require.NotContains(t, q, "key'with quote")
				require.Contains(t, q, syncMetadataProjection)
				require.Less(t, strings.Index(q, syncMetadataProjection), strings.Index(q, "AS current"))
			} else {
				require.Empty(t, args)
				require.Contains(t, q, "metadata,risk_score")
			}
			if tc.projection.SkipTags {
				require.Contains(t, q, "CAST(map(),'Map(String,String)')")
			} else {
				require.Contains(t, q, " tags,"+syncMetadataProjection)
			}
		})
	}
}
