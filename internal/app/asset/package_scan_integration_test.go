//go:build integration

package asset

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestScanLivePackages_GrowthMidPassSkipsNothing: packages written while a
// pass is under way, with ids sorting BEFORE its cursor, must not shift the
// rest of the walk. An OFFSET walk skips exactly that many live packages
// further on — and a skipped live package reads as having left the inventory,
// so its findings resolve as resource_gone and reopen on the next run.
func TestScanLivePackages_GrowthMidPassSkipsNothing(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	svc := NewService(NewCHRepo(ch))

	stamp := time.Now().Format("150405.000000")
	prefix := "pkg:npm/it-keyset-" + stamp + "-"
	early := "pkg:!it-keyset-" + stamp + "-" // '!' sorts before every real purl type
	total := packagePageSize + 1000
	now := time.Now().Truncate(time.Second)
	ingest := func(idPrefix string, n int) {
		pkgs := make([]Asset, n)
		edges := make([]Edge, n)
		for i := range n {
			id := fmt.Sprintf("%s%05d@1.0.0", idPrefix, i)
			pkgs[i] = Asset{ID: id, Name: id, Type: "package", Provider: ProviderGitHub,
				Metadata:     map[string]string{"ecosystem": "npm", "package": id, "version": "1.0.0"},
				DiscoveredAt: now, LastSeen: now}
			edges[i] = Edge{SrcID: idPrefix + "repo", SrcType: "github_repo", DstID: id, DstType: "package", EdgeType: "depends_on"}
		}
		require.NoError(t, svc.Ingest(ctx, pkgs, edges))
	}
	ingest(prefix, total)
	t.Cleanup(func() {
		for _, p := range []string{prefix, early} {
			_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
			_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE dst_id LIKE ?", p+"%")
		}
	})

	seen := map[string]bool{}
	grown := false
	_, err = svc.ScanLivePackages(ctx, func(page []PackageCoord) error {
		for _, c := range page {
			if strings.HasPrefix(c.ID, prefix) {
				require.False(t, seen[c.ID], "listed twice: %s", c.ID)
				seen[c.ID] = true
			}
		}
		if len(seen) > 0 && !grown {
			grown = true
			ingest(early, 500) // lands before the cursor, mid-pass
		}
		return nil
	})
	require.NoError(t, err)
	require.True(t, grown)
	require.Len(t, seen, total, "every package live at the start of the pass is listed exactly once")
}
