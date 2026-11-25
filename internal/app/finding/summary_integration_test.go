//go:build integration

package finding

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Verifies the summary aggregation against real ClickHouse, scoped to a unique
// source so counts are deterministic in the shared table.
//
// Band comes from finding_enrichment now, not
// findings.score_band (which is no longer written at all). s1 is given a
// DIFFERENT legacy score_band from its finding_enrichment band on purpose —
// writing the same value to both, as an earlier version of this test did,
// cannot distinguish "Summary reads the join" from "Summary still reads the
// legacy column and happens to agree", the exact test-quality gap this
// test exists to catch. If Summary ever regresses back to the legacy column, this
// assertion fails loudly with the stale value ("legacy-stale-band") instead
// of silently passing.
func TestCHRepo_Summary(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	src := "sum-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE source = ?", src) })
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "s%-"+suffix) })

	s1 := Finding{ID: "s1-" + suffix, Source: src, Type: "exposure", Severity: SeverityCritical,
		ScoreBand: "legacy-stale-band", ResourceID: "r1", DetectedAt: now, EnrichedAt: now}
	s2 := Finding{ID: "s2-" + suffix, Source: src, Type: "exposure", Severity: SeverityCritical,
		ScoreBand: "page", ResourceID: "r2", DetectedAt: now, EnrichedAt: now}
	s3 := Finding{ID: "s3-" + suffix, Source: src, Type: "exposure", Severity: SeverityLow,
		ResourceID: "r3", DetectedAt: now} // unenriched: empty band, no finding_enrichment row
	require.NoError(t, NewService(repo).Record(ctx, []Finding{s1, s2, s3}))
	// Only s1/s2 get a finding_enrichment row; s2's dual-write matches its
	// legacy value (the realistic case: enrich writes both from the same
	// struct), s1's deliberately does not (the regression-detecting case).
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{
		{ID: s1.ID, ScoreBand: "page", EnrichedAt: now},
		{ID: s2.ID, ScoreBand: "page", EnrichedAt: now},
	}))

	sum, err := repo.Summary(ctx, Filter{Source: src})
	require.NoError(t, err)
	require.Equal(t, 3, sum.Total)
	require.Equal(t, 2, sum.BySeverity[SeverityCritical])
	require.Equal(t, 1, sum.BySeverity[SeverityLow])
	require.Equal(t, 2, sum.ByBand["page"], "both s1 and s2 must report the finding_enrichment band, not findings.score_band")
	require.NotContains(t, sum.ByBand, "legacy-stale-band", "Summary must not read the legacy score_band column")
	require.NotContains(t, sum.ByBand, "", "unenriched findings (empty band) are excluded from the band breakdown")
}
