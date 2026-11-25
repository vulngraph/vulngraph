//go:build integration

package asset

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestScanLivePackages_FullPageOfLongIDsDoesNotExceedQuerySize is the
// regression guard for a refresh_osv failure: a full
// packagePageSize page of package purls, long enough that a version building the
// page's ids into a literal SQL `WHERE id IN (...)` list would exceed
// ClickHouse's max_query_size (256KB) — e.g. with long Go module purls
// like "pkg:golang/github.com/example-corp/lib-go-logging@0.10.2".
// The page query (packageCoordsAfter) fixed it by moving id selection into a server-side
// subquery instead of a client-built literal list; this test would fail
// with "code: 62, Max query size exceeded" if that regressed.
func TestScanLivePackages_FullPageOfLongIDsDoesNotExceedQuerySize(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	// Namespace this run's rows, and pick an id long enough (~180 chars) that
	// packagePageSize (5,000) of them totals well over 256KB (~900KB) if ever
	// inlined as literal SQL text again.
	prefix := "pkg:golang/github.com/it-longid-" + time.Now().Format("150405.000000") + "/"
	now := time.Now().Truncate(time.Second)
	pkgs := make([]Asset, packagePageSize)
	edges := make([]Edge, packagePageSize)
	for i := 0; i < packagePageSize; i++ {
		id := fmt.Sprintf("%s%0130d@v1.0.%d", prefix, i, i)
		pkgs[i] = Asset{
			ID: id, Name: fmt.Sprintf("longid-%d", i), Type: "package", Provider: ProviderGitHub,
			Metadata:     map[string]string{"ecosystem": "golang", "package": fmt.Sprintf("longid-%d", i), "version": fmt.Sprintf("v1.0.%d", i)},
			DiscoveredAt: now, LastSeen: now,
		}
		// The fresh edge that makes the package live (livePackageIDs).
		edges[i] = Edge{SrcID: prefix + "repo", SrcType: "github_repo", DstID: id, DstType: "package", EdgeType: "depends_on"}
	}

	svc := NewService(repo)
	require.NoError(t, svc.Ingest(ctx, pkgs, edges))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE id LIKE ?", prefix+"%")
		_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE dst_id LIKE ?", prefix+"%")
	})

	// Page through until this fixture's ids are exhausted, asserting no
	// error on any page — the failure manifested at the FIRST oversized
	// page, not a later one, but page fully to also confirm the total count
	// matches what was ingested.
	seen := 0
	_, err = svc.ScanLivePackages(ctx, func(page []PackageCoord) error {
		for _, c := range page {
			if len(c.ID) > len(prefix) && c.ID[:len(prefix)] == prefix {
				seen++
			}
		}
		return nil
	})
	require.NoError(t, err, "a query-size regression fails here, not at the Go level")
	require.Equal(t, packagePageSize, seen, "every ingested long-id package must be returned exactly once across pages")
}
