//go:build integration

package finding

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// These three exercise the join rewrite of unenrichedOpenFindings,
// mustFixCoverageBySource, and openIDsBehindCutoffQ — enriched_at and
// must_fix_class now come from finding_enrichment via a LEFT JOIN, not
// findings' own legacy columns. Requires `docker compose up` and applied
// migrations (graph migrate), same as repo_integration_test.go.

// TestUnenrichedCounts_JoinExcludesEnrichedAndResolved proves the join form
// still counts only OPEN, NEVER-ENRICHED findings by severity: a finding
// with a finding_enrichment row (dual-written by RecordEnrichment) must not
// appear, and neither must a resolved one — only the true backlog does.
func TestUnenrichedCounts_JoinExcludesEnrichedAndResolved(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	suffix := time.Now().Format("150405.000000")
	res := "unenr-res-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "unenr-%-"+suffix)
	})

	before, err := svc.UnenrichedCounts(ctx)
	require.NoError(t, err)
	baseline := countsBySeverity(before)

	neverEnriched := Finding{
		ID: "unenr-a-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityCritical,
		Title: "t", ResourceID: res, DetectedAt: now,
	}
	enriched := Finding{
		ID: "unenr-b-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityCritical,
		Title: "t", ResourceID: res, DetectedAt: now, Score: 40, EnrichedAt: now,
	}
	resolved := Finding{
		ID: "unenr-c-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityCritical,
		Title: "t", ResourceID: res, DetectedAt: now, ResolvedAt: now,
	}
	require.NoError(t, svc.Record(ctx, []Finding{neverEnriched, enriched, resolved}))
	require.NoError(t, svc.RecordEnrichment(ctx, []Enrichment{EnrichmentOf(enriched)}))

	after, err := svc.UnenrichedCounts(ctx)
	require.NoError(t, err)
	got := countsBySeverity(after)

	require.Equal(t, baseline[SeverityCritical]+1, got[SeverityCritical],
		"only the never-enriched, unresolved finding joins the backlog count")
}

func countsBySeverity(cs []SeverityCount) map[Severity]int {
	m := make(map[Severity]int, len(cs))
	for _, c := range cs {
		m[c.Severity] = c.N
	}
	return m
}

// TestMustFixCoverage_JoinSplitsClassifiedFromBlank proves the join form
// still scopes to OPEN AND ENRICHED findings only: a never-enriched finding
// must not appear in either bucket (that's UnenrichedCounts' job), and a
// resolved one must not appear at all.
func TestMustFixCoverage_JoinSplitsClassifiedFromBlank(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	suffix := time.Now().Format("150405.000000")
	src := "mfc-src-" + suffix
	res := "mfc-res-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "mfc-%-"+suffix)
	})

	classified := Finding{
		ID: "mfc-a-" + suffix, Source: src, Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceID: res, DetectedAt: now, Score: 80,
		EnrichedAt: now, MustFixClass: "must_fix",
	}
	blank := Finding{
		ID: "mfc-b-" + suffix, Source: src, Type: "exposure", Severity: SeverityLow,
		Title: "t", ResourceID: res, DetectedAt: now, Score: 10, EnrichedAt: now,
	}
	neverEnriched := Finding{
		ID: "mfc-c-" + suffix, Source: src, Type: "exposure", Severity: SeverityLow,
		Title: "t", ResourceID: res, DetectedAt: now,
	}
	resolved := Finding{
		ID: "mfc-d-" + suffix, Source: src, Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceID: res, DetectedAt: now, Score: 90,
		EnrichedAt: now, MustFixClass: "must_fix", ResolvedAt: now,
	}
	all := []Finding{classified, blank, neverEnriched, resolved}
	require.NoError(t, svc.Record(ctx, all))
	require.NoError(t, svc.RecordEnrichment(ctx, []Enrichment{
		EnrichmentOf(classified), EnrichmentOf(blank), EnrichmentOf(resolved),
	}))

	got, err := svc.MustFixCoverage(ctx)
	require.NoError(t, err)
	var mine *ClassificationCoverage
	for i := range got {
		if got[i].Source == src {
			mine = &got[i]
		}
	}
	require.NotNil(t, mine, "the src this test just wrote must appear")
	require.EqualValues(t, 1, mine.Classified, "only the enriched+classified finding counts")
	require.EqualValues(t, 1, mine.Blank, "only the enriched+blank finding counts — not the never-enriched or resolved ones")
}

// TestOpenIDsBehindCutoff_JoinFindsTheEpochCohort proves the join form still
// surfaces open findings whose enrichment (now in finding_enrichment) predates
// a cutoff — including a finding with no finding_enrichment row at all, which
// must read back as the epoch (join_use_nulls=0's type-default sentinel) and
// so still counts as "behind" any real cutoff.
func TestOpenIDsBehindCutoff_JoinFindsTheEpochCohort(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	suffix := time.Now().Format("150405.000000")
	res := "cutoff-res-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "cutoff-%-"+suffix)
	})

	neverEnriched := Finding{ // no finding_enrichment row at all — the epoch cohort
		ID: "cutoff-a-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityLow,
		Title: "t", ResourceID: res, DetectedAt: now,
	}
	recentlyEnriched := Finding{ // enriched after cutoff — must NOT appear
		ID: "cutoff-b-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityLow,
		Title: "t", ResourceID: res, DetectedAt: now, Score: 20, EnrichedAt: now,
	}
	resolved := Finding{ // resolved — must NOT appear regardless of enrichment
		ID: "cutoff-c-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityLow,
		Title: "t", ResourceID: res, DetectedAt: now, ResolvedAt: now,
	}
	require.NoError(t, svc.Record(ctx, []Finding{neverEnriched, recentlyEnriched, resolved}))
	require.NoError(t, svc.RecordEnrichment(ctx, []Enrichment{EnrichmentOf(recentlyEnriched)}))

	// afterID "" walks from the beginning; the corpus is large in a shared dev
	// DB, so page until either our own ids are found or the walk ends.
	cutoff := now
	var found []string
	afterID := ""
	for range 50 {
		page, err := repo.OpenIDsBehindCutoff(ctx, cutoff, afterID, 5000)
		require.NoError(t, err)
		if len(page) == 0 {
			break
		}
		for _, id := range page {
			if id == neverEnriched.ID || id == recentlyEnriched.ID || id == resolved.ID {
				found = append(found, id)
			}
		}
		afterID = page[len(page)-1]
	}
	require.Contains(t, found, neverEnriched.ID, "no finding_enrichment row reads back as the epoch — behind any cutoff")
	require.NotContains(t, found, recentlyEnriched.ID, "enriched at/after cutoff is not behind it")
	require.NotContains(t, found, resolved.ID, "resolved findings never appear, regardless of enrichment")
}
