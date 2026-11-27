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

func TestCancelledInventoryPreservesFirstObservation(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	prefix := "cancel-inventory-" + uuid.NewString()
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, ch.Exec(cleanup, "DELETE FROM assets WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix))
	})
	repo := NewCHRepo(ch)
	svc := NewService(repo)
	for _, mode := range []string{"assets", "assets and edges"} {
		t.Run(mode, func(t *testing.T) {
			original := Asset{ID: prefix + mode, Name: "original", Type: "ec2_instance", Provider: ProviderAWS, DiscoveredAt: time.Now().Add(-24 * time.Hour), LastSeen: time.Now()}
			require.NoError(t, svc.IngestAssets(ctx, []Asset{original}))
			before, err := svc.Get(ctx, original.ID)
			require.NoError(t, err)
			changed := original
			changed.Name = "changed"
			changed.DiscoveredAt = time.Now()
			cancelled, stop := context.WithCancel(ctx)
			defer stop()
			interrupted := NewService(cancelledHistoryRepo{repo, stop})
			if mode == "assets" {
				err = interrupted.IngestAssets(cancelled, []Asset{changed})
			} else {
				err = interrupted.Ingest(cancelled, []Asset{changed}, nil)
			}
			require.ErrorIs(t, err, context.Canceled)
			after, err := svc.Get(ctx, original.ID)
			require.NoError(t, err)
			require.Equal(t, before.Name, after.Name)
			require.Equal(t, before.FirstDiscoveredAt, after.FirstDiscoveredAt)
			require.NoError(t, svc.IngestAssets(ctx, []Asset{changed}))
			retry, err := svc.Get(ctx, original.ID)
			require.NoError(t, err)
			require.Equal(t, "changed", retry.Name)
			require.Equal(t, before.FirstDiscoveredAt, retry.FirstDiscoveredAt)
		})
	}
}
