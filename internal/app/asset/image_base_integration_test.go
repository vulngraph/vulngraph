//go:build integration

package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// A re-scan replaces an image's identity by scanned_at, and the read collapses
// versions to one row per image without FINAL.
func TestImageBases_LatestScanWins(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	id := "image/sha256:it-imagebase-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE image_bases DELETE WHERE image_id = ?", id)
	})
	first := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	require.NoError(t, repo.UpsertImageBases(ctx, []ImageBase{
		{ImageID: id, BaseImageSource: "os_release", BaseOS: "Debian:12", ScannedAt: first},
	}))
	second := first.Add(30 * time.Minute)
	require.NoError(t, repo.UpsertImageBases(ctx, []ImageBase{
		{ImageID: id, BaseImage: "debian:bookworm-slim", BaseImageDigest: "sha256:abc",
			BaseImageSource: "annotation", BaseOS: "Debian:12", ScannedAt: second},
	}))

	all, err := repo.ImageBases(ctx)
	require.NoError(t, err)
	var got []ImageBase
	for _, ib := range all {
		if ib.ImageID == id {
			got = append(got, ib)
		}
	}
	require.Len(t, got, 1, "one row per image")
	require.Equal(t, "annotation", got[0].BaseImageSource)
	require.Equal(t, "debian:bookworm-slim", got[0].BaseImage)
	require.Equal(t, "sha256:abc", got[0].BaseImageDigest)
	require.True(t, got[0].ScannedAt.Equal(second), "scanned_at is the latest scan")
}
