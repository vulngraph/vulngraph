//go:build integration

package enrich

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

const chDSN = "clickhouse://graph:graph@localhost:9000/graph"

// enrichHarness wires a real finding service and enrich service against live
// ClickHouse. synced_at (the findings ReplacingMergeTree version) has
// one-second granularity and these tests write the same row several times in
// well under a second, so the repo clock advances a second per write to keep
// latest-write-wins deterministic.
func enrichHarness(t *testing.T) (context.Context, *finding.Service, *Service, string) {
	t.Helper()
	ctx := context.Background()
	ch, err := db.NewCH(ctx, chDSN, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	base := time.Now().Truncate(time.Second)
	var ticks int64
	clock := func() time.Time { ticks++; return base.Add(time.Duration(ticks) * time.Second) }
	findingSvc := finding.NewService(finding.NewCHRepo(ch, finding.WithClock(clock)))
	svc := NewService(findingSvc, NewSignalCHRepo(ch), []Source{BaseSeverity{}})

	id := "enrich-it-" + time.Now().Format("150405.000000000")
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", id)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", id)
		_ = ch.Exec(ctx, "ALTER TABLE signals DELETE WHERE id = ?", id)
	})
	return ctx, findingSvc, svc, id
}
