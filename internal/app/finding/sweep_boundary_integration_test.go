//go:build integration

package finding

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestCHRepo_EnrichmentPassCutoffSurvivesMovingAndDeletedCursor(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	defer ch.Close()
	repo := NewCHRepo(ch)
	service := NewService(repo)
	prefix := fmt.Sprintf("sweep-boundary-%d", time.Now().UnixNano())
	second := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id=?", prefix)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE startsWith(id,?)", prefix)
	})
	rows := make([]Finding, 3)
	for i := range rows {
		rows[i] = Finding{ID: fmt.Sprintf("%s-%d", prefix, i), Source: "cspm", ResourceID: prefix, Severity: SeverityHigh, Score: 30, EnrichedAt: second.Add(time.Duration(i+1) * 100 * time.Millisecond)}
	}
	recordEnriched(t, ch, rows)
	cutoff := second.Add(200 * time.Millisecond)
	page, err := repo.EnrichmentCandidates(ctx, Filter{ResourceID: prefix, StaleFirst: true, EnrichedBefore: cutoff, Limit: 1})
	require.NoError(t, err)
	require.Len(t, page.IDs, 1)
	require.Equal(t, rows[0].ID, page.IDs[0])
	cursor := page.Cursor
	moved := EnrichmentOf(rows[0])
	moved.EnrichedAt = second.Add(500 * time.Millisecond)
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{moved}))
	page, err = repo.EnrichmentCandidates(ctx, Filter{ResourceID: prefix, StaleFirst: true, EnrichedBefore: cutoff, Cursor: cursor, Limit: 10})
	require.NoError(t, err)
	require.Len(t, page.IDs, 1)
	require.Equal(t, rows[1].ID, page.IDs[0])
	require.NoError(t, service.Resolve(ctx, []Finding{rows[1]}, ReasonResourceGone))
	filter := Filter{ResourceID: prefix, StaleFirst: true, EnrichedBefore: second.Add(400 * time.Millisecond), Cursor: cursor, Limit: 10}
	page, err = repo.EnrichmentCandidates(ctx, filter)
	require.NoError(t, err)
	require.Len(t, page.IDs, 1)
	require.Equal(t, rows[2].ID, page.IDs[0])
	require.NoError(t, ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id=? SETTINGS mutations_sync=2", rows[0].ID))
	page, err = repo.EnrichmentCandidates(ctx, filter)
	require.NoError(t, err)
	require.Len(t, page.IDs, 1)
	require.Equal(t, rows[2].ID, page.IDs[0], "cursor is a seek key, not a required live row")
}
