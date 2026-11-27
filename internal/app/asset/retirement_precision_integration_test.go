//go:build integration

package asset

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestRetirementPreservesPreciseAndLegacyObservations(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires an isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	prefix := "retire-precision-" + uuid.NewString()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		require.NoError(t, ch.Exec(ctx, "DELETE FROM assets WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM graph_edges WHERE startsWith(src_id,?) OR startsWith(dst_id,?) SETTINGS mutations_sync=1", prefix, prefix))
	})
	base := time.Now().Add(-time.Minute).Truncate(time.Second)
	cutoff := base.Add(500 * time.Millisecond)
	repo := NewCHRepo(ch)
	for _, tc := range []struct {
		name    string
		seen    time.Time
		retired bool
	}{
		{"before", base.Add(100 * time.Millisecond), true},
		{"equal", cutoff, false},
		{"after", base.Add(900 * time.Millisecond), false},
		{"legacy_same_second", base, false},
		{"legacy_older", base.Add(-time.Second), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := prefix + tc.name
			require.NoError(t, repo.UpsertAssets(ctx, []Asset{{ID: id, Type: "ec2_instance", LastSeen: tc.seen}}))
			// Seed both directions at the observation time, including legacy
			// whole-second versions. A later edge must survive an older proof.
			for _, edge := range [][2]string{{id, id + "-target"}, {id + "-source", id}} {
				require.NoError(t, ch.Exec(ctx, `INSERT INTO graph_edges(src_id,dst_id,edge_type,synced_at) VALUES(?,?,'runs_on',parseDateTime64BestEffort(?,9))`, edge[0], edge[1], tc.seen.Format(time.RFC3339Nano)))
			}
			proof := map[string]time.Time{id: cutoff}
			svc := NewService(repo).WithDeletionProofs(testDeletionProofs{proofs: proof})
			departed, err := svc.VerifyDepartedAssets(ctx, []string{id})
			require.NoError(t, err)
			require.Equal(t, tc.retired, departed[id])
			for range 2 { // retries apply the same proof idempotently
				retired, err := repo.RetireAssets(ctx, proof)
				require.NoError(t, err)
				require.Equal(t, tc.retired, len(retired) == 1)
				assets, err := repo.ByIDs(ctx, []string{id})
				require.NoError(t, err)
				require.Equal(t, !tc.retired, len(assets) == 1)
				edges, err := repo.EdgesFrom(ctx, []string{id, id + "-source"})
				require.NoError(t, err)
				if tc.retired {
					require.Empty(t, edges)
				} else {
					require.Len(t, edges, 2)
				}
			}
		})
	}
	t.Run("resurfaced_version", func(t *testing.T) {
		id := prefix + "resurfaced"
		for _, seen := range []time.Time{base.Add(100 * time.Millisecond), base.Add(900 * time.Millisecond)} {
			require.NoError(t, repo.UpsertAssets(ctx, []Asset{{ID: id, Name: seen.Format(time.RFC3339Nano), Type: "ec2_instance", LastSeen: seen}}))
			require.NoError(t, ch.Exec(ctx, `INSERT INTO graph_edges(src_id,dst_id,edge_type,synced_at) VALUES(?,?,'runs_on',parseDateTime64BestEffort(?,9))`, id, id+"-target", seen.Format(time.RFC3339Nano)))
		}
		retired, err := repo.RetireAssets(ctx, map[string]time.Time{id: cutoff})
		require.NoError(t, err)
		require.Empty(t, retired)
		got, err := repo.ByIDs(ctx, []string{id})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, base.Add(900*time.Millisecond).Format(time.RFC3339Nano), got[0].Name)
		edges, err := repo.EdgesFrom(ctx, []string{id})
		require.NoError(t, err)
		require.Len(t, edges, 1)
	})
}
