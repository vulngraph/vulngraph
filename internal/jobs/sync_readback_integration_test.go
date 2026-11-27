//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type scaleEdgeKey struct{ source, kind, destination string }

func verifySyncReadback(t *testing.T, ctx context.Context, inv *asset.Service, want map[string]asset.Asset, edges map[scaleEdgeKey]asset.Edge) {
	t.Helper()
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += 500 {
		chunk := ids[start:min(start+500, len(ids))]
		got, err := inv.ByIDs(ctx, chunk)
		require.NoError(t, err)
		require.Len(t, got, len(chunk))
		for _, a := range got {
			expected, ok := want[a.ID]
			require.True(t, ok, a.ID)
			require.Equal(t, expected.Name, a.Name, a.ID)
			require.Equal(t, expected.Type, a.Type, a.ID)
			require.Equal(t, expected.Provider, a.Provider, a.ID)
			require.Equal(t, expected.Region, a.Region, a.ID)
			for k, v := range expected.Metadata {
				require.Equal(t, v, a.Metadata[k], "%s metadata %s", a.ID, k)
			}
			for k, v := range expected.Tags {
				require.Equal(t, v, a.Tags[k], "%s tag %s", a.ID, k)
			}
		}
	}
	sources := map[string]bool{}
	for key := range edges {
		sources[key.source] = true
	}
	ids = ids[:0]
	for id := range sources {
		ids = append(ids, id)
	}
	remaining := make(map[scaleEdgeKey]asset.Edge, len(edges))
	for k, v := range edges {
		remaining[k] = v
	}
	for start := 0; start < len(ids); start += 500 {
		got, err := inv.EdgesFrom(ctx, ids[start:min(start+500, len(ids))])
		require.NoError(t, err)
		for _, e := range got {
			key := scaleEdgeKey{e.SrcID, e.EdgeType, e.DstID}
			if expected, ok := remaining[key]; ok {
				require.Equal(t, expected.SrcType, e.SrcType, "%v", key)
				require.Equal(t, expected.DstType, e.DstType, "%v", key)
				for k, v := range expected.Properties {
					require.Equal(t, v, e.Properties[k], "%v property %s", key, k)
				}
				delete(remaining, key)
			}
		}
	}
	require.Empty(t, remaining, "persisted topology lost expected relationships")
}
