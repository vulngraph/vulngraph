//go:build integration

package finding

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Exercise the production writer and reader with distinct versions inside one
// second. Advancing the clock by whole seconds would conceal precision loss.
func TestRapidFindingUpdatesReadBack(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("requires isolated ClickHouse with current migrations")
	}
	ctx := context.Background()
	ch, err := db.NewCH(ctx, dsn, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	id := "rapid-" + uuid.NewString()
	t.Cleanup(func() { _ = ch.Exec(ctx, "DELETE FROM findings WHERE id = ? SETTINGS mutations_sync=1", id) })
	base := time.Now().UTC().Truncate(time.Second)
	now := base.Add(100 * time.Millisecond)
	repo := NewCHRepo(ch, WithClock(func() time.Time { return now }))
	f := Finding{ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "original", ResourceID: id, ResourceType: "ec2_instance", CheckID: "rapid",
		DetectedAt: base, FirstDetectedAt: base.Add(-24 * time.Hour), LastObservedAt: base}
	for _, title := range []string{"original", "changed", "resolved", "reopened"} {
		f.Title = title
		f.Metadata = map[string]string{"state": title}
		if title == "resolved" {
			f.ResolvedAt = base
			f.ResolutionReason = ResolutionReason("resource_deleted")
		} else {
			f.ResolvedAt = time.Time{}
			f.ResolutionReason = ""
		}
		require.NoError(t, repo.Upsert(ctx, []Finding{f}))
		got, err := repo.Get(ctx, id)
		require.NoError(t, err)
		require.Equal(t, title, got.Title)
		require.Equal(t, f.Metadata, got.Metadata)
		require.Equal(t, title == "resolved", !got.ResolvedAt.IsZero() && got.ResolvedAt.Unix() > 0)
		require.Equal(t, f.FirstDetectedAt.Unix(), got.FirstDetectedAt.Unix())
		now = now.Add(100 * time.Millisecond)
	}
	require.NoError(t, ch.Exec(ctx, "OPTIMIZE TABLE findings FINAL"))
	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "reopened", got.Title)
	require.Equal(t, f.FirstDetectedAt.Unix(), got.FirstDetectedAt.Unix())
}
