//go:build integration

package asset

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestPackageRunners_ReadsLapsedEdgesAndInventoryStamps: the departure evidence
// for a package includes the runners whose edge into it has LAPSED (the whole
// point — a live edge would keep it live), each with that edge's newest stamp
// and the runner's newest stamp on any edge of the same type.
func TestPackageRunners_ReadsLapsedEdgesAndInventoryStamps(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	p := "it-pkgrunners-" + time.Now().Format("150405.000000") + "-"
	gone, upgraded := "pkg:npm/"+p+"lib@1.0.0", "pkg:npm/"+p+"lib@2.0.0"
	host := p + "i-1"
	old := time.Now().Add(-96 * time.Hour).Truncate(time.Second)
	older := old.Add(-24 * time.Hour)
	recent := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, ch.Batch(ctx,
		`INSERT INTO graph_edges (src_id, src_type, dst_id, dst_type, edge_type, properties, synced_at)`,
		func(b driver.Batch) error {
			for _, r := range []struct {
				dst string
				at  time.Time
			}{{gone, older}, {gone, old}, {upgraded, recent}} {
				if err := b.Append(host, "ec2_instance", r.dst, "package", "runs_package", "{}", r.at); err != nil {
					return err
				}
			}
			return nil
		}))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE src_id LIKE ?", p+"%")
	})

	runners, err := repo.PackageRunners(ctx, []string{gone})
	require.NoError(t, err)
	require.Len(t, runners, 1)
	r := runners[0]
	require.Equal(t, host, r.RunnerID)
	require.Equal(t, "ec2_instance", r.RunnerType)
	require.Equal(t, "runs_package", r.EdgeType)
	require.WithinDuration(t, old, r.EdgeAt, time.Second, "the lapsed edge's NEWEST stamp")
	require.WithinDuration(t, recent, r.InventoryAt, time.Second, "the runner's latest inventory read")
}

// A base-image package upgraded across a fleet has thousands of image runners
// inside the edge TTL. Their ids (~80 bytes each) in one IN list exceed
// ClickHouse's max_query_size (code 62), and one failed read would stall
// every departure judgement; the runner reads are chunked.
func TestPackageRunners_ThousandsOfRunnersFitTheQuerySize(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	p := "it-pkgrunners-many-" + time.Now().Format("150405.000000") + "-"
	purl := "pkg:deb/debian/" + p + "openssl@3.0.11-1"
	const runners = 4000
	stamp := time.Now().Add(-72 * time.Hour).Truncate(time.Second)
	require.NoError(t, ch.Batch(ctx,
		`INSERT INTO graph_edges (src_id, src_type, dst_id, dst_type, edge_type, properties, synced_at)`,
		func(b driver.Batch) error {
			for i := range runners {
				img := fmt.Sprintf("image/sha256:%s%064d", p, i)
				if err := b.Append(img, "container_image", purl, "package", "runs_package", "{}", stamp); err != nil {
					return err
				}
			}
			return nil
		}))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE dst_id = ?", purl)
	})

	got, err := repo.PackageRunners(ctx, []string{purl})
	require.NoError(t, err, "a code-62 regression fails here")
	require.Len(t, got, runners)
	for _, r := range got {
		require.WithinDuration(t, stamp, r.InventoryAt, time.Second, "every chunk's stamps are merged")
	}
}
