//go:build integration

package finding

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// recordEnriched writes findings via Record AND dual-writes their enrichment
// fields to finding_enrichment via RecordEnrichment — real enrich/KEV always
// do both. A test that writes only via Record now gets back
// zero-valued Score/ScoreBand/EnrichedAt/etc. from Get/ByIDs/ByResourceIDs
// (their read is flipped to finding_enrichment), which reads as
// "never enriched" regardless of what the Finding literal actually set — this
// helper is the fix, applied identically to every affected test in this file.
// Requires EnrichedAt already set on each finding: a zero EnrichedAt gives
// finding_enrichment's TTL an already-expired anchor (toDateTime(0) + 365 days).
func recordEnriched(t *testing.T, ch *db.CH, findings []Finding) {
	t.Helper()
	repo := NewCHRepo(ch)
	require.NoError(t, NewService(repo).Record(context.Background(), findings))
	enrichments := make([]Enrichment, len(findings))
	for i, f := range findings {
		require.False(t, f.EnrichedAt.IsZero(), "recordEnriched requires EnrichedAt set on %s, or finding_enrichment's TTL underflows", f.ID)
		enrichments[i] = EnrichmentOf(f)
	}
	require.NoError(t, repo.UpsertEnrichment(context.Background(), enrichments))
}

// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_UpsertListAndFilter(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	svc := NewService(NewCHRepo(ch))

	suffix := time.Now().Format("150405.000000")
	res := "res-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
	})

	findings := []Finding{
		{ID: "f1-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityMedium,
			Title: "public ip", ResourceType: "ec2_instance", ResourceID: res, CheckID: "aws-ec2-public-ip", DetectedAt: now},
		{ID: "f2-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityLow,
			Title: "public repo", ResourceType: "github_repo", ResourceID: res, CheckID: "github-public-repo", DetectedAt: now},
	}
	require.NoError(t, svc.Record(ctx, findings))

	// Idempotent: re-recording the same IDs must not duplicate (ReplacingMergeTree).
	require.NoError(t, svc.Record(ctx, findings))

	mine := func(fs []Finding) []Finding {
		var out []Finding
		for _, f := range fs {
			if f.ResourceID == res {
				out = append(out, f)
			}
		}
		return out
	}

	all, err := svc.List(ctx, Filter{})
	require.NoError(t, err)
	require.Len(t, mine(all), 2, "two distinct findings, no duplicates after re-record")

	med, err := svc.List(ctx, Filter{Severity: SeverityMedium})
	require.NoError(t, err)
	got := mine(med)
	require.Len(t, got, 1)
	require.Equal(t, "aws-ec2-public-ip", got[0].CheckID)
	require.Equal(t, SeverityMedium, got[0].Severity)
}

// SignalsByResource rolls findings up into the per-resource signal set the graph
// projects onto asset nodes (max_score / has_kev / privesc_count / exploitable).
func TestCHRepo_SignalsByResource(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	res := "sig-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res) })
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "sg%-"+suffix) })

	sig1 := Finding{ID: "sg1-" + suffix, Source: "cspm", Type: "ciem_privesc", Severity: SeverityHigh,
		Title: "privesc", ResourceID: res, Score: 70, EnrichedAt: now, DetectedAt: now}
	sig2 := Finding{ID: "sg2-" + suffix, Source: "cspm", Type: "ciem_privesc", Severity: SeverityHigh,
		Title: "privesc 2", ResourceID: res, Score: 60, EnrichedAt: now, DetectedAt: now}
	sig3 := Finding{ID: "sg3-" + suffix, Source: "nuclei", Type: "nuclei", Severity: SeverityCritical,
		Title: "rce", ResourceID: res, Score: 90, KnownExploited: true, EnrichedAt: now, DetectedAt: now}
	svc := NewService(repo)
	require.NoError(t, svc.Record(ctx, []Finding{sig1, sig2, sig3}))
	// SignalsByResource reads score/known_exploited from finding_enrichment —
	// dual-write it so this test exercises real data.
	require.NoError(t, svc.RecordEnrichment(ctx, []Enrichment{
		EnrichmentOf(sig1), EnrichmentOf(sig2), EnrichmentOf(sig3),
	}))

	all, err := repo.SignalsByResource(ctx)
	require.NoError(t, err)
	s, ok := all[res]
	require.True(t, ok, "resource has a signal rollup")
	require.Equal(t, uint8(90), s.MaxScore)
	require.True(t, s.HasKEV, "a known-exploited finding sets has_kev")
	require.Equal(t, 2, s.PrivescCount, "two ciem_privesc findings")
	require.True(t, s.Exploitable, "a critical nuclei finding sets exploitable")
}

// Pages through findings by score with the keyset cursor, asserting
// each row appears once, in descending order, across page boundaries.
func TestCHRepo_KeysetPagination(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	res := "pg-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res) })

	scores := []uint8{90, 70, 50, 30, 10}
	recs := make([]Finding, len(scores))
	for i, s := range scores {
		recs[i] = Finding{
			ID: fmt.Sprintf("pg%d-%s", i, suffix), Source: "cspm", Type: "exposure",
			Severity: SeverityHigh, Title: "t", ResourceID: res, Score: s, DetectedAt: now, EnrichedAt: now,
		}
	}
	// Score is hydrated from finding_enrichment (ByIDs), so the
	// pagination cursor (built from the hydrated Finding) must match what the
	// SAME test's finding_enrichment rows say, or the cursor and the selection
	// query's legacy-column HAVING disagree — dual-write, per recordEnriched.
	recordEnriched(t, ch, recs)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "pg%-"+suffix) })

	// Walk pages of 2, seeded by each page's last-row cursor.
	var gotScores []uint8
	cursor := ""
	for page := 0; page < 10; page++ {
		items, err := repo.List(ctx, Filter{ResourceID: res, SortByScore: true, Limit: 2, Cursor: cursor})
		require.NoError(t, err)
		for _, f := range items {
			gotScores = append(gotScores, f.Score)
		}
		if len(items) < 2 {
			break
		}
		cursor = EncodeCursor(items[len(items)-1], true)
	}

	require.Equal(t, []uint8{90, 70, 50, 30, 10}, gotScores, "every finding once, descending, no gaps or repeats across pages")
}

// StaleFirst must sort already-enriched findings by enriched_at ascending (not
// detected_at descending) and page correctly with EncodeStaleCursor — this is
// the drift-pass sweep's fix for a corpus tail that a plain Filter{} (detected_at
// desc, cursor resetting every tick) could never reach: findings enriched before
// a new classification feature shipped (e.g. must_fix_class) got stuck
// on their stale classification because the sweep only ever re-covered the
// newest-detected slice. Also proves never-enriched (zero enriched_at) findings
// are excluded — that backlog belongs to the Unenriched (backfill) filter.
func TestCHRepo_StaleFirstPagination(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	res := "stale-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res) })

	// enriched_at deliberately out of detected_at order: oldest-enriched (f2) was
	// detected most recently, so a detected_at-desc sweep would visit it LAST —
	// exactly the scenario that starves a must-fix backlog.
	oldest := now.Add(-72 * time.Hour)
	mid := now.Add(-24 * time.Hour)
	newest := now.Add(-1 * time.Hour)
	recs := []Finding{
		{ID: "sf1-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
			Title: "t1", ResourceID: res, DetectedAt: now, EnrichedAt: mid, Score: 40},
		{ID: "sf2-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
			Title: "t2", ResourceID: res, DetectedAt: now.Add(time.Hour), EnrichedAt: oldest, Score: 40},
		{ID: "sf3-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
			Title: "t3", ResourceID: res, DetectedAt: now.Add(-time.Hour), EnrichedAt: newest, Score: 40},
	}
	// sf1-sf3 dual-write to finding_enrichment (List's
	// hydration/cursor now reads EnrichedAt from there) — sf4 stays legacy-only
	// on purpose, it's the never-enriched case this test must still exclude.
	recordEnriched(t, ch, recs)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "sf%-"+suffix) })

	sf4 := Finding{ID: "sf4-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "t4", ResourceID: res, DetectedAt: now}
	require.NoError(t, NewService(repo).Record(ctx, []Finding{sf4}))

	var gotIDs []string
	cursor := ""
	for page := 0; page < 10; page++ {
		items, err := repo.List(ctx, Filter{ResourceID: res, StaleFirst: true, Limit: 2, Cursor: cursor})
		require.NoError(t, err)
		for _, f := range items {
			gotIDs = append(gotIDs, f.ID)
		}
		if len(items) < 2 {
			break
		}
		cursor = EncodeStaleCursor(items[len(items)-1])
	}

	require.Equal(t, []string{"sf2-" + suffix, "sf1-" + suffix, "sf3-" + suffix}, gotIDs,
		"oldest-enriched first, never-enriched sf4 excluded, no gaps/repeats across pages")
}

// Get uses the non-FINAL argMax point lookup (selectFindingByID). This proves it
// returns the latest ReplacingMergeTree version — identical to FINAL semantics —
// so the CPU-hot-path optimization didn't change what Get returns.
func TestCHRepo_GetReturnsLatestVersion(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	// synced_at has one-second granularity; an advancing clock makes the second
	// Upsert deterministically win over the first.
	base := time.Now().Truncate(time.Second)
	tick := 0
	repo := NewCHRepo(ch, WithClock(func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}))

	suffix := time.Now().Format("150405.000000")
	id := "get-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", id) })

	v1 := Finding{ID: id, Source: "cspm", Type: "exposure", Severity: SeverityLow,
		Title: "v1", ResourceID: "r-" + suffix, Score: 10, EnrichedAt: base, DetectedAt: base}
	v2 := v1
	v2.Title, v2.Score, v2.Severity, v2.KnownExploited = "v2", 90, SeverityCritical, true
	v2.EnrichedAt = base.Add(time.Second)

	require.NoError(t, repo.Upsert(ctx, []Finding{v1}))
	require.NoError(t, repo.Upsert(ctx, []Finding{v2}))
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", id) })
	// Score/KnownExploited now come from finding_enrichment,
	// versioned by enriched_at rather than synced_at — dual-write both
	// versions here too, so this test still exercises "the latest version
	// wins" for the enrichment fields, just via finding_enrichment's own
	// argMax(..., enriched_at) instead of the legacy columns' argMax(...,
	// synced_at). Without this, Get() correctly reads back the zero value
	// (no finding_enrichment row exists at all), which would look like this
	// test caught a regression when it actually just stopped writing what it
	// asserts on.
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{EnrichmentOf(v1)}))
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{EnrichmentOf(v2)}))

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "v2", got.Title, "argMax must surface the latest synced_at version")
	require.Equal(t, uint8(90), got.Score, "finding_enrichment's argMax(score, enriched_at) must surface the latest version")
	require.Equal(t, SeverityCritical, got.Severity)
	require.True(t, got.KnownExploited)

	_, err = repo.Get(ctx, "does-not-exist-"+suffix)
	require.ErrorIs(t, err, ErrNotFound)
}

// List's HAVING filters must match a finding's LATEST ReplacingMergeTree
// version, not a stale historical one — the exact correctness property
// argMax/GROUP BY has to preserve over the old FINAL query. This is the
// regression a naive "keep every filter as a pre-aggregation WHERE on the raw
// column" rewrite would introduce: a filtered WHERE runs before GROUP BY
// collapses versions, so it can match against ANY physical row ClickHouse
// hasn't merged away yet, old or new.
func TestCHRepo_List_FiltersMatchLatestVersion(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	// synced_at has one-second granularity; an advancing clock makes the
	// second Upsert deterministically win over the first.
	base := time.Now().Truncate(time.Second)
	tick := 0
	repo := NewCHRepo(ch, WithClock(func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}))

	suffix := time.Now().Format("150405.000000")
	id := "mv-" + suffix
	res := "mv-res-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", id) })

	// Old version: unenriched, medium severity, not must-fix, unresolved.
	v1 := Finding{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityMedium,
		Title: "v1", ResourceID: res, CheckID: "aws-ec2-public-ip", DetectedAt: base,
	}
	// New version: enriched high, must-fix, resolved — same id, same
	// source/resource_id/check_id (carried by the deterministic ID).
	v2 := v1
	v2.Severity = SeverityHigh
	v2.Score, v2.ScoreBand, v2.EnrichedAt = 80, "high", base
	v2.SafetyClass = "risky"
	v2.MustFixClass = "must_fix"
	v2.ResolvedAt = base

	require.NoError(t, repo.Upsert(ctx, []Finding{v1}))
	require.NoError(t, repo.Upsert(ctx, []Finding{v2}))
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", id) })
	// List's HAVING filters (score/safety_class/must_fix_class/
	// enriched_at) now read finding_enrichment via selectFindingKeysArgMax
	// (severity/detected_at/resolved_at stay on the legacy columns — not
	// enrich:"output" fields). v1 was never enriched, so it gets no
	// dual-write; v2 gets one matching its own legacy values, so the
	// filter/hydrate paths agree for THIS pair — a genuinely discriminating
	// case (legacy and finding_enrichment DISAGREE) follows below.
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{EnrichmentOf(v2)}))

	findID := func(fs []Finding, wantID string) (Finding, bool) {
		for _, f := range fs {
			if f.ID == wantID {
				return f, true
			}
		}
		return Finding{}, false
	}
	find := func(fs []Finding) (Finding, bool) { return findID(fs, id) }

	// v2 is resolved, so every query below except the final default-visibility
	// check must opt in with IncludeResolved to see it at all.

	// Pre-aggregation WHERE fields (source/resource_id/check_id) still match —
	// they're identical across both versions.
	bySource, err := repo.List(ctx, Filter{Source: "cspm", ResourceID: res, IncludeResolved: true})
	require.NoError(t, err)
	got, ok := find(bySource)
	require.True(t, ok, "source/resource_id pre-aggregation filter must still find the id")
	require.Equal(t, SeverityHigh, got.Severity, "must reflect the latest version, not v1's medium")

	// MinScore: only the NEW version's score (80) satisfies; the old score (0,
	// unset) never did. A stale-WHERE bug would either miss this row (filtered
	// pre-agg on the OLD score=0) or coincidentally pass — assert the value is
	// actually the new one, not just that a row came back.
	byScore, err := repo.List(ctx, Filter{ResourceID: res, MinScore: 50, IncludeResolved: true})
	require.NoError(t, err)
	got, ok = find(byScore)
	require.True(t, ok, "MinScore must match against the current (new) score")
	require.Equal(t, uint8(80), got.Score)

	// Severity changed medium -> high (a real signal, never carried forward).
	// Filtering by the OLD value must NOT match;
	// filtering by the NEW value must.
	byOldSeverity, err := repo.List(ctx, Filter{ResourceID: res, Severity: SeverityMedium, IncludeResolved: true})
	require.NoError(t, err)
	_, ok = find(byOldSeverity)
	require.False(t, ok, "must not match the stale v1 severity")

	byNewSeverity, err := repo.List(ctx, Filter{ResourceID: res, Severity: SeverityHigh, IncludeResolved: true})
	require.NoError(t, err)
	got, ok = find(byNewSeverity)
	require.True(t, ok, "must match the current severity")
	require.Equal(t, uint8(80), got.Score)

	// MustFixOnly: only true after enrichment (v2).
	byMustFix, err := repo.List(ctx, Filter{ResourceID: res, MustFixOnly: true, IncludeResolved: true})
	require.NoError(t, err)
	_, ok = find(byMustFix)
	require.True(t, ok, "must_fix_class must reflect the latest version")

	// IncludeResolved default (false) must hide it now that v2 resolved it;
	// IncludeResolved:true must surface it.
	open, err := repo.List(ctx, Filter{ResourceID: res})
	require.NoError(t, err)
	_, ok = find(open)
	require.False(t, ok, "resolved_at from the latest version must hide it by default")

	withResolved, err := repo.List(ctx, Filter{ResourceID: res, IncludeResolved: true})
	require.NoError(t, err)
	_, ok = find(withResolved)
	require.True(t, ok, "IncludeResolved must still surface it")

	// Genuinely discriminating case (every case above writes the SAME
	// value to both findings and finding_enrichment, so it can't tell
	// "List filters on finding_enrichment" apart from "List still filters on
	// the legacy column" — both would pass identically either way). Here the
	// two DISAGREE: findings.score/must_fix_class say this finding fails
	// MinScore/MustFixOnly; finding_enrichment says it passes. If
	// selectFindingKeysArgMax ever regresses back to argMax(f.score,
	// f.synced_at)-style legacy reads, this is the assertion that fails.
	discID := "mv-disagree-" + suffix
	discRes := "mv-disagree-res-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", discID) })
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", discID) })
	disc := Finding{
		ID: discID, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "disagree", ResourceID: discRes, CheckID: "aws-ec2-public-ip", DetectedAt: base,
		Score: 5, MustFixClass: "routine", EnrichedAt: base, // legacy: fails both filters below
	}
	require.NoError(t, repo.Upsert(ctx, []Finding{disc}))
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{{
		ID: discID, Score: 90, MustFixClass: "must_fix", EnrichedAt: base, // real: passes both
	}}))

	byRealScore, err := repo.List(ctx, Filter{ResourceID: discRes, MinScore: 50})
	require.NoError(t, err)
	_, ok = findID(byRealScore, discID)
	require.True(t, ok, "MinScore must follow finding_enrichment's score (90), not the legacy column's (5)")

	byRealMustFix, err := repo.List(ctx, Filter{ResourceID: discRes, MustFixOnly: true})
	require.NoError(t, err)
	_, ok = findID(byRealMustFix, discID)
	require.True(t, ok, "MustFixOnly must follow finding_enrichment's must_fix_class, not the legacy column's 'routine'")
}

// ByIDs and ByResourceIDs must return a finding's LATEST ReplacingMergeTree
// version, not a stale historical one — same correctness property as List()
// and Get(), for the same reason: both used to read via a filtered FINAL
// (`... FINAL WHERE id IN (...)` / `... FINAL WHERE resource_id IN (...)`),
// and a filtered FINAL can full-scan instead of pruning via the id/resource_id
// bloom indexes. ByIDs sits on the sync hot path: RecordObserved's
// pinFirstDetectedAt calls it before overwriting the row, comparing the NEW
// finding's severity against the stored one. If ByIDs surfaced a stale
// version, that comparison could wrongly conclude "unchanged" (pinning an age
// that does not belong to the finding's real prior state) or "changed"
// (resetting an age that should have been kept), silently skewing
// prioritisation under load.
func TestCHRepo_ByIDsAndByResourceIDs_ReturnLatestVersion(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	// synced_at has one-second granularity; an advancing clock makes the
	// second Upsert deterministically win over the first.
	base := time.Now().Truncate(time.Second)
	tick := 0
	repo := NewCHRepo(ch, WithClock(func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}))

	suffix := time.Now().Format("150405.000000")
	id := "byid-" + suffix
	res := "byid-res-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", id) })

	// Old version: unenriched, low severity.
	v1 := Finding{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityLow,
		Title: "v1", ResourceID: res, CheckID: "aws-ec2-public-ip", DetectedAt: base,
	}
	// New version: same identity (source/resource_id/check_id, so same
	// deterministic id), enriched high severity — the shape
	// pinFirstDetectedAt compares against.
	v2 := v1
	v2.Severity = SeverityHigh
	v2.Title = "v2"
	v2.Score, v2.ScoreBand, v2.EnrichedAt = 85, "high", base
	v2.SafetyClass = "risky"
	v2.MustFixClass = "must_fix"

	require.NoError(t, repo.Upsert(ctx, []Finding{v1}))
	require.NoError(t, repo.Upsert(ctx, []Finding{v2}))
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", id) })
	// ByIDs/ByResourceIDs now hydrate Score/ScoreBand/
	// MustFixClass/etc. from finding_enrichment — v1 was never enriched, so
	// only v2 (the version these assertions check) needs the dual-write.
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{EnrichmentOf(v2)}))

	byIDs, err := repo.ByIDs(ctx, []string{id})
	require.NoError(t, err)
	require.Len(t, byIDs, 1, "id IN (...) pre-aggregation filter must still find exactly one row")
	require.Equal(t, "v2", byIDs[0].Title, "ByIDs must surface the latest synced_at version, not v1")
	require.Equal(t, SeverityHigh, byIDs[0].Severity)
	require.Equal(t, uint8(85), byIDs[0].Score)
	require.Equal(t, "must_fix", byIDs[0].MustFixClass)

	byResourceIDs, err := repo.ByResourceIDs(ctx, []string{res})
	require.NoError(t, err)
	require.Len(t, byResourceIDs, 1, "resource_id IN (...) pre-aggregation filter must still find exactly one row")
	require.Equal(t, "v2", byResourceIDs[0].Title, "ByResourceIDs must surface the latest synced_at version, not v1")
	require.Equal(t, SeverityHigh, byResourceIDs[0].Severity)
	require.Equal(t, uint8(85), byResourceIDs[0].Score)

	missing, err := repo.ByIDs(ctx, []string{"does-not-exist-" + suffix})
	require.NoError(t, err)
	require.Empty(t, missing, "a missing id must come back absent, not error")
}

// A resolved finding must vanish from EVERY aggregate risk surface,
// not just the list view. Summary, Clusters, SignalsByResource and the
// per-resource risk rollups all used to keep counting resolved findings, so a
// fixed KEV/critical kept has_kev=true and a high max_score on its graph node
// and dashboard indefinitely. The resolved finding here carries the scarier
// signals (critical, KEV, score 95) so any reader still counting it fails loud.
func TestCHRepo_ResolvedFindingsExcludedFromAggregates(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	src := "aggsrc-" + suffix // unique source isolates Summary/Clusters from other rows
	res := "agg-res-" + suffix
	checkID := "agg-check-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res) })
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "agg-%-"+suffix) })

	// open/fixed carry a DIFFERENT legacy score/score_band/known_exploited
	// from what gets dual-written to finding_enrichment below — writing the
	// same value to both, as an earlier version of this test did, cannot
	// distinguish "Summary/Clusters/RiskByResource read the join" from "they
	// still read the legacy findings columns and happen to agree").
	// findings.score/score_band/known_exploited are
	// not even written by Upsert any more (insertFindings omits them), so
	// they read back at their schema DEFAULT (0/''/0) regardless of what the
	// Finding struct below carries — asserting against THAT, not a
	// coincidentally-matching legacy value, is what actually proves the
	// join.
	open := Finding{ID: "agg-open-" + suffix, Source: src, Type: "nuclei", Severity: SeverityHigh,
		Title: "open", ResourceID: res, CheckID: checkID,
		Score: 11, ScoreBand: "legacy-stale", DetectedAt: now}
	fixed := Finding{ID: "agg-fixed-" + suffix, Source: src, Type: "nuclei", Severity: SeverityCritical,
		Title: "fixed", ResourceID: res, CheckID: checkID,
		Score: 22, ScoreBand: "legacy-stale", KnownExploited: false,
		DetectedAt: now, ResolvedAt: now}
	require.NoError(t, repo.Upsert(ctx, []Finding{open, fixed}))
	// RiskByResource/RiskiestResources/Summary/Clusters read score/score_band/
	// known_exploited from finding_enrichment ONLY — this
	// dual-write carries the REAL values these assertions check against, and
	// they deliberately diverge from open/fixed's legacy fields above.
	require.NoError(t, repo.UpsertEnrichment(ctx, []Enrichment{
		{ID: open.ID, Score: 60, ScoreBand: "high", EnrichedAt: now},
		{ID: fixed.ID, Score: 95, ScoreBand: "page", KnownExploited: true, EnrichedAt: now},
	}))

	sum, err := repo.Summary(ctx, Filter{Source: src})
	require.NoError(t, err)
	require.Equal(t, 1, sum.Total, "summary counts only the open finding")
	require.Zero(t, sum.BySeverity[SeverityCritical], "the resolved critical must not linger in the dashboard")
	require.Equal(t, 1, sum.BySeverity[SeverityHigh])

	clusters, totalChecks, err := repo.Clusters(ctx, Filter{Source: src})
	require.NoError(t, err)
	require.Len(t, clusters, 1)
	require.Equal(t, 1, totalChecks, "total_checks counts post-HAVING clusters, before the LIMIT")
	require.Equal(t, 1, clusters[0].Instances, "the resolved instance must leave the cluster")
	require.Equal(t, uint8(60), clusters[0].MaxScore, "max_score must come from finding_enrichment, not the legacy score=11/22 or the resolved 95")
	require.Equal(t, "high", clusters[0].WorstBand, "worst_band must come from finding_enrichment, not the legacy score_band='legacy-stale'")
	require.False(t, clusters[0].KnownExploited, "a resolved KEV must not flag the whole cluster")

	signals, err := repo.SignalsByResource(ctx)
	require.NoError(t, err)
	s, ok := signals[res]
	require.True(t, ok, "the open finding still projects signals")
	require.Equal(t, uint8(60), s.MaxScore, "graph node max_score must drop once the worst finding resolves")
	require.False(t, s.HasKEV, "has_kev must clear on the graph node once the KEV finding resolves")

	risk, err := repo.RiskByResource(ctx, []string{res})
	require.NoError(t, err)
	require.Equal(t, 1, risk[res].Count)
	require.Equal(t, uint8(60), risk[res].MaxScore)

	// riskiestResources shares the same inner HAVING; assert via the ranked list
	// when the resource is inside the window (a generous limit makes that certain
	// only for our max_score ordering — find it and check, don't assume position).
	ranked, err := repo.RiskiestResources(ctx, 100000)
	require.NoError(t, err)
	for _, rr := range ranked {
		if rr.ResourceID == res {
			require.Equal(t, uint8(60), rr.MaxScore, "ranking must use the open finding's score")
			require.Equal(t, 1, rr.Count)
		}
	}
}

func TestCHRepo_DistinctCheckIDs_ExcludesResolved(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	// synced_at has one-second granularity: without an advancing clock both
	// Upserts usually land in the same second, argMax ties, and the open row
	// can win (this flaked ~10% of runs).
	base := time.Now().Truncate(time.Second)
	tick := 0
	repo := NewCHRepo(ch, WithClock(func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}))

	suffix := time.Now().Format("150405.000000")
	src := "checkidsrc-" + suffix // unique source isolates this check_id from other rows
	res := "checkid-res-" + suffix
	checkID := "checkid-check-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res) })

	require.NoError(t, repo.Upsert(ctx, []Finding{
		{ID: "checkid-open-" + suffix, Source: src, Type: "cspm", Severity: SeverityHigh,
			Title: "open", ResourceID: res, CheckID: checkID,
			Score: 60, ScoreBand: "high", EnrichedAt: now, DetectedAt: now},
	}))

	ids, err := repo.DistinctCheckIDs(ctx, src)
	require.NoError(t, err)
	require.Contains(t, ids, checkID, "an open finding's check_id must be reported")

	// Re-upsert the same (source, resource_id, check_id) with a later synced_at
	// marking it resolved — this is what enrich does when a violation clears.
	require.NoError(t, repo.Upsert(ctx, []Finding{
		{ID: "checkid-open-" + suffix, Source: src, Type: "cspm", Severity: SeverityHigh,
			Title: "open", ResourceID: res, CheckID: checkID,
			Score: 60, ScoreBand: "high", EnrichedAt: now, DetectedAt: now,
			ResolvedAt: now.Add(time.Second)},
	}))

	ids, err = repo.DistinctCheckIDs(ctx, src)
	require.NoError(t, err)
	require.NotContains(t, ids, checkID, "a resolved finding's check_id must not keep a compliance control failing forever")
}

// A finding set larger than findingBatchSize must all land, none dropped at a
// chunk boundary — the chunking loop exists so a large sync's RecordObserved
// doesn't run as one unchunked batch insert (the bottleneck behind
// "RecordObserved: Upsert: Batch: context deadline exceeded" failures on
// very large accounts). This proves no rows are lost
// across a boundary; against a healthy local ClickHouse it does NOT prove
// chunking happened at all (the pre-fix unchunked code passes this same
// assertion at this row count). It exists to catch an off-by-one at the boundary if the loop bounds
// are ever touched again, not to catch a reversion to one unchunked batch.
func TestCHRepo_Upsert_ChunksLargeFindingSets(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	res := "chunk-res-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
	})

	const n = dbutil.CHWriteMaxRows + 137 // spans two native inserts
	findings := make([]Finding, n)
	for i := range n {
		findings[i] = Finding{
			ID: fmt.Sprintf("chunk-%s-%d", suffix, i), Source: "cspm", Type: "exposure",
			Severity: SeverityLow, Title: "t", ResourceType: "ec2_instance",
			ResourceID: res, CheckID: "aws-ec2-public-ip", DetectedAt: now,
		}
	}
	require.NoError(t, repo.Upsert(ctx, findings))

	// ByResourceIDs is unpaginated (unlike List's DefaultLimit-capped pages),
	// so it can actually confirm all n rows, not just the first page.
	got, err := repo.ByResourceIDs(ctx, []string{res})
	require.NoError(t, err)
	require.Len(t, got, n, "every finding across both batches must land, none dropped by the chunking loop")
}

func TestCHRepo_CostAtRisk(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	suffix := time.Now().Format("150405.000000")
	resourceID := "cost-res-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", resourceID)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "cost-%-"+suffix)
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", resourceID)
	})

	// A cost-bearing asset type (ec2_instance) so the INNER JOIN to assets matches.
	insertAsset := `INSERT INTO assets
		(id, name, type, provider, region, account_id, discovered_at, last_seen, synced_at)
		VALUES (?, ?, 'ec2_instance', 'aws', 'eu-west-1', 'acct', ?, ?, ?)`
	require.NoError(t, ch.Exec(ctx, insertAsset, resourceID, "web-"+suffix, now, now, now))

	f := Finding{
		ID: "cost-a-" + suffix, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceID: resourceID, DetectedAt: now,
		// Legacy score deliberately BELOW the minScore threshold used below —
		// a regression to the legacy query would exclude this resource entirely.
		Score: 10, EnrichedAt: now,
	}
	require.NoError(t, svc.Record(ctx, []Finding{f}))
	require.NoError(t, svc.RecordEnrichment(ctx, []Enrichment{{
		ID: f.ID, Score: 90, EnrichedAt: now,
	}}))

	res, err := repo.CostAtRisk(ctx, 60, 200)
	require.NoError(t, err)
	var mine *CostAtRiskResource
	for i := range res.Resources {
		if res.Resources[i].ResourceID == resourceID {
			mine = &res.Resources[i]
		}
	}
	require.NotNil(t, mine, "the cost-bearing resource this test wrote must appear at minScore=60 — "+
		"only finding_enrichment's score (90) clears that bar, not the legacy column's (10)")
	require.Equal(t, uint8(90), mine.MaxScore, "score must come from finding_enrichment, not the legacy column")
	require.Equal(t, "ec2_instance", mine.Type)
	require.Equal(t, "aws", mine.Provider)
}

// TestCHRepo_List_CVEInMatchesCheckIDOrTagsCVE is the ClickHouse-backed half of
// TestListKeysQueryCVEInPrunesPreAggregation (list_query_test.go): the SQL
// shape is pinned there without a network call, this proves ClickHouse
// actually executes it as intended — the whole point of adding it
// was to stop refresh_kev's exact query from timing out, so a
// syntax or matching mistake here would silently reintroduce that.
// check_id is baked into the deterministic finding id, so
// it must prune in the outer WHERE before ClickHouse's GROUP BY, and the
// match must cover BOTH of kev.findingCVE's two lineages (scanner/OSV
// findings key check_id on the CVE directly; nuclei findings key on a
// template slug and carry the CVE in tags["cve"] instead) case-insensitively.
func TestCHRepo_List_CVEInMatchesCheckIDOrTagsCVE(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	now := time.Now()
	ids := []string{
		"cve-check-" + suffix, // check_id IS the CVE, matches by check_id
		"cve-meta-" + suffix,  // check_id is a template slug, CVE lives in tags["cve"]
		"cve-miss-" + suffix,  // matches neither — must NOT come back
	}
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id IN (?, ?, ?)", ids[0], ids[1], ids[2])
	})

	findings := []Finding{
		{
			ID: ids[0], Source: "supply_chain", Type: "vuln", Severity: SeverityHigh,
			Title: "check_id match", ResourceID: "res-" + suffix,
			CheckID: "CVE-2021-44228", DetectedAt: now,
		},
		{
			ID: ids[1], Source: "nuclei", Type: "vuln", Severity: SeverityHigh,
			Title: "tags[cve] match", ResourceID: "res-" + suffix,
			CheckID: "log4j-rce-template", DetectedAt: now,
			Metadata: map[string]string{"cve": "cve-2024-0001"}, // deliberately lowercase
		},
		{
			ID: ids[2], Source: "nuclei", Type: "vuln", Severity: SeverityHigh,
			Title: "no match", ResourceID: "res-" + suffix,
			CheckID: "unrelated-template", DetectedAt: now,
			Metadata: map[string]string{"cve": "CVE-9999-9999"},
		},
	}
	require.NoError(t, NewService(repo).Record(ctx, findings))

	got, err := repo.List(ctx, Filter{CVEIn: []string{"CVE-2021-44228", "cve-2024-0001"}, Limit: 10})
	require.NoError(t, err)

	gotIDs := make(map[string]bool, len(got))
	for _, f := range got {
		gotIDs[f.ID] = true
	}
	require.True(t, gotIDs[ids[0]], "must match via check_id")
	require.True(t, gotIDs[ids[1]], "must match via tags['cve'], case-insensitively, even though the filter arg is upper and the stored value is lower")
	require.False(t, gotIDs[ids[2]], "a finding matching neither check_id nor tags['cve'] must not be returned")
}

// enriched_at is DateTime64(3); the StaleFirst seek used to bind the cursor as
// a seconds-precision DateTime, so findings enriched within the same second as
// a page's last row were served again on the next page (or the walk stalled).
func TestCHRepo_StaleFirstPagination_SubSecondEnrichedAt(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	res := "stalems-" + suffix
	second := time.Now().Add(-time.Hour).Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "ms%-"+suffix)
	})
	var recs []Finding
	var want []string
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("ms%d-%s", i, suffix)
		recs = append(recs, Finding{ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
			Title: id, ResourceID: res, DetectedAt: second, Score: 40,
			EnrichedAt: second.Add(time.Duration(i*100) * time.Millisecond)})
		want = append(want, id)
	}
	recordEnriched(t, ch, recs)

	var got []string
	cursor := ""
	for page := 0; page < 10; page++ {
		items, err := repo.List(ctx, Filter{ResourceID: res, StaleFirst: true, Limit: 1, Cursor: cursor})
		require.NoError(t, err)
		if len(items) == 0 {
			break
		}
		got = append(got, items[0].ID)
		cursor = EncodeStaleCursor(items[0])
	}
	require.Equal(t, want, got, "each finding exactly once, in millisecond order")
}

// CountByCheckID is the CrossCluster "is this systemic?" denominator; a fixed
// (resolved) finding must not count toward it.
func TestCHRepo_CountByCheckID_ExcludesResolved(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	base := time.Now().Truncate(time.Second)
	tick := 0
	repo := NewCHRepo(ch, WithClock(func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}))

	suffix := time.Now().Format("150405.000000")
	src := "countsrc-" + suffix
	checkID := "count-check-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE source = ?", src) })

	mk := func(n int) Finding {
		return Finding{ID: fmt.Sprintf("count-%d-%s", n, suffix), Source: src, Type: "cspm", Severity: SeverityHigh,
			Title: "t", ResourceID: fmt.Sprintf("count-res-%d-%s", n, suffix), CheckID: checkID, DetectedAt: now}
	}
	require.NoError(t, repo.Upsert(ctx, []Finding{mk(1), mk(2), mk(3)}))
	n, err := repo.CountByCheckID(ctx, src, checkID)
	require.NoError(t, err)
	require.Equal(t, 3, n)

	resolved := mk(2)
	resolved.ResolvedAt = now.Add(time.Second)
	require.NoError(t, repo.Upsert(ctx, []Finding{resolved}))
	n, err = repo.CountByCheckID(ctx, src, checkID)
	require.NoError(t, err)
	require.Equal(t, 2, n, "a resolved finding no longer counts")
}
