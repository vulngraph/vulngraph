//go:build integration

package belief

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	r := NewCHRepo(ch)
	suffix := time.Now().Format("150405.000000")
	fid := "f-" + suffix
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE beliefs DELETE WHERE finding_id = ?", fid) })

	b := Belief{
		FindingID: fid, ResourceID: "role/admin", Claim: "controlled",
		Severity: finding.SeverityLow, Confidence: ConfidenceHigh, Status: StatusConfirmed,
		Provenance: "deterministic",
		Evidence:   []Evidence{{Clause: "gated by IdP", Source: "must_fix", Fact: "controlled"}},
		CreatedAt:  time.Now().Truncate(time.Second),
	}
	require.NoError(t, r.Upsert(ctx, []Belief{b}))

	got, err := r.GetByFinding(ctx, fid)
	require.NoError(t, err)
	require.Equal(t, finding.SeverityLow, got.Severity)
	require.Equal(t, "role/admin", got.ResourceID)
	require.Len(t, got.Evidence, 1)
	require.Equal(t, "must_fix", got.Evidence[0].Source)

	_, err = r.GetByFinding(ctx, "missing-"+suffix)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestCHRepo_AdjudicationCandidates proves the coverage cursor over real
// ClickHouse: an eligible, never-adjudicated finding is returned; once it has a
// fresh adjudicator belief it is excluded; re-enriching it (bumping enriched_at
// past the belief) makes it reappear.
func TestCHRepo_AdjudicationCandidates(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	r := NewCHRepo(ch)
	suffix := time.Now().Format("150405.000000")
	fid := "cand-" + suffix

	// An advancing clock so successive finding Upserts get distinct synced_at
	// versions (one-second RMT granularity) and argMax deterministically picks the
	// latest.
	tick := time.Now().Truncate(time.Second)
	clock := func() time.Time { tick = tick.Add(time.Second); return tick }
	fr := finding.NewCHRepo(ch, finding.WithClock(clock))

	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", fid)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", fid)
		_ = ch.Exec(ctx, "ALTER TABLE beliefs DELETE WHERE finding_id = ?", fid)
	})

	enrichedAt := time.Now().Add(-time.Hour).Truncate(time.Second)
	// Legacy score deliberately BELOW minScore (10 < 61) — only
	// finding_enrichment's score (90) clears the eligibility bar. A
	// regression reading the legacy column would exclude this finding from
	// the candidate set entirely, failing the very first assertion below
	// instead of passing by coincidence (if both writes carried the same
	// value, this test could pass even reading the legacy columns straight
	// through).
	f := finding.Finding{
		ID: fid, Source: "cspm", Type: "exposure", Severity: finding.SeverityHigh,
		Title: "open bucket", ResourceType: "s3_bucket", ResourceID: "arn:" + suffix,
		Score: 10, ScoreBand: "routine", EnrichedAt: enrichedAt, DetectedAt: enrichedAt,
	}
	require.NoError(t, fr.Upsert(ctx, []finding.Finding{f}))
	// AdjudicationCandidates reads score/must_fix_class/enriched_at from
	// finding_enrichment — dual-write the REAL eligible
	// score here, distinct from the legacy column above.
	require.NoError(t, fr.UpsertEnrichment(ctx, []finding.Enrichment{
		{ID: fid, Score: 90, ScoreBand: "page", EnrichedAt: enrichedAt},
	}))

	staleBefore := time.Now().Add(-7 * 24 * time.Hour)

	// Never adjudicated → in the candidate set.
	ids, err := r.AdjudicationCandidates(ctx, 61, staleBefore, 500)
	require.NoError(t, err)
	require.Contains(t, ids, fid, "eligible never-adjudicated finding is a candidate")

	// A fresh adjudicator belief (created after enriched_at, within the revalidation
	// window) → excluded.
	require.NoError(t, r.Upsert(ctx, []Belief{{
		FindingID: fid, ResourceID: f.ResourceID, Claim: "confirmed high", Severity: finding.SeverityHigh,
		Confidence: ConfidenceMedium, Status: StatusConfirmed, Provenance: ProvenanceAdjudicator,
		Evidence:  []Evidence{{Clause: "reachable", Source: "reachability", Fact: "1 hop"}},
		CreatedAt: time.Now().Truncate(time.Second),
	}}))
	ids, err = r.AdjudicationCandidates(ctx, 61, staleBefore, 500)
	require.NoError(t, err)
	require.NotContains(t, ids, fid, "a freshly-adjudicated finding is excluded from the cursor")

	// Re-enrich: bump enriched_at past the belief → the evidence changed, so it
	// re-enters the candidate set. Legacy score again deliberately below the
	// eligibility bar; finding_enrichment carries the real one.
	f.EnrichedAt = time.Now().Add(time.Hour).Truncate(time.Second)
	f.Score = 5
	require.NoError(t, fr.Upsert(ctx, []finding.Finding{f}))
	require.NoError(t, fr.UpsertEnrichment(ctx, []finding.Enrichment{
		{ID: fid, Score: 88, ScoreBand: "page", EnrichedAt: f.EnrichedAt},
	}))
	ids, err = r.AdjudicationCandidates(ctx, 61, staleBefore, 500)
	require.NoError(t, err)
	require.Contains(t, ids, fid, "re-enriched finding (enriched_at past its belief) is a candidate again")

	// Sweep cache hit: the same verdict re-written with a checked_at past the
	// re-enrich → out of the set until the next enrichment. Before checked_at
	// existed this finding stayed in the cursor forever.
	prior, err := r.GetByProvenance(ctx, fid, ProvenanceAdjudicator)
	require.NoError(t, err)
	prior.CheckedAt = f.EnrichedAt.Add(time.Minute)
	require.NoError(t, r.Upsert(ctx, []Belief{prior}))
	ids, err = r.AdjudicationCandidates(ctx, 61, staleBefore, 500)
	require.NoError(t, err)
	require.NotContains(t, ids, fid, "a verdict re-affirmed since the last enrichment is not re-offered")

	// The revalidation horizon still runs from created_at, not checked_at.
	ids, err = r.AdjudicationCandidates(ctx, 61, time.Now().Add(time.Minute), 500)
	require.NoError(t, err)
	require.Contains(t, ids, fid, "a re-affirmed verdict past the horizon is re-validated")
}

// GetByFinding returns the most recent belief, the adjudicator's counted as of
// its last check: a stale verdict must not shadow a newer deterministic belief,
// and a verdict re-affirmed after that deterministic re-form wins again.
func TestCHRepo_GetByFinding_NewestWins(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	r := NewCHRepo(ch)
	fid := "newest-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE beliefs DELETE WHERE finding_id = ?", fid) })

	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	adj := Belief{
		FindingID: fid, ResourceID: "r", Claim: "demoted", Severity: finding.SeverityLow,
		Confidence: ConfidenceMedium, Status: StatusConfirmed, Provenance: ProvenanceAdjudicator,
		Evidence:    []Evidence{{Clause: "not reachable", Source: "reachability", Fact: "0 paths"}},
		Fingerprint: "fp", CreatedAt: t0,
	}
	det := Belief{
		FindingID: fid, ResourceID: "r", Claim: "must-fix", Severity: finding.SeverityCritical,
		Confidence: ConfidenceHigh, Status: StatusConfirmed, Provenance: ProvenanceDeterministic,
		Evidence:  []Evidence{{Clause: "reachable", Source: "must_fix", Fact: "internet-exposed"}},
		CreatedAt: t0.Add(10 * time.Minute),
	}
	require.NoError(t, r.Upsert(ctx, []Belief{adj, det}))

	got, err := r.GetByFinding(ctx, fid)
	require.NoError(t, err)
	require.Equal(t, ProvenanceDeterministic, got.Provenance, "a newer deterministic belief beats a stale verdict")
	require.Equal(t, finding.SeverityCritical, got.Severity)

	own, err := r.GetByProvenance(ctx, fid, ProvenanceAdjudicator)
	require.NoError(t, err)
	require.Equal(t, "fp", own.Fingerprint, "the sweep can still read its own verdict")

	reaffirmed := adj
	reaffirmed.CheckedAt = t0.Add(20 * time.Minute).Add(123 * time.Millisecond)
	require.NoError(t, r.Upsert(ctx, []Belief{reaffirmed}))
	got, err = r.GetByFinding(ctx, fid)
	require.NoError(t, err)
	require.Equal(t, ProvenanceAdjudicator, got.Provenance, "a verdict re-affirmed after the re-form wins")
	require.Equal(t, t0, got.CreatedAt.Local(), "the stamp keeps created_at")
	require.WithinDuration(t, reaffirmed.CheckedAt, got.CheckedAt, time.Millisecond, "checked_at round-trips at ms precision")

	_, err = r.GetByProvenance(ctx, "missing-"+fid, ProvenanceAdjudicator)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestCHRepo_CrystallizationInputs proves selectCrystallizationInputs
// reads score_band/must_fix_class from finding_enrichment, not
// findings' legacy columns — writing a deliberately different value to each so
// a regression to the legacy column fails loud rather than passing by
// coincidence.
func TestCHRepo_CrystallizationInputs(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	r := NewCHRepo(ch)
	fr := finding.NewCHRepo(ch)
	suffix := time.Now().Format("150405.000000")
	fid := "cryst-" + suffix
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id = ?", fid)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id = ?", fid)
		_ = ch.Exec(ctx, "ALTER TABLE beliefs DELETE WHERE finding_id = ?", fid)
	})

	resourceType := "cryst-test-type-" + suffix // unique so this row can't be mistaken for unrelated corpus data
	f := finding.Finding{
		ID: fid, Source: "cspm", Type: "exposure", Severity: finding.SeverityHigh,
		Title: "open bucket", ResourceType: resourceType, ResourceID: "arn:" + suffix,
		// Legacy columns deliberately hold a DIFFERENT band/class than
		// finding_enrichment below — a stand-in for the classic
		// lost-update corruption this rewrite fixes. If the query regresses
		// to reading findings directly, it reads these ("stale") values.
		Score: 40, ScoreBand: "routine", MustFixClass: "controlled",
		EnrichedAt: now, DetectedAt: now,
	}
	require.NoError(t, fr.Upsert(ctx, []finding.Finding{f}))
	require.NoError(t, fr.UpsertEnrichment(ctx, []finding.Enrichment{
		{ID: fid, Score: 90, ScoreBand: "page", MustFixClass: "must_fix", EnrichedAt: now},
	}))

	require.NoError(t, r.Upsert(ctx, []Belief{{
		FindingID: fid, ResourceID: f.ResourceID, Claim: "confirmed high",
		Severity: finding.SeverityCritical, Confidence: ConfidenceHigh,
		Status: StatusConfirmed, Provenance: ProvenanceAdjudicator,
		Evidence:  []Evidence{{Clause: "reachable", Source: "reachability", Fact: "1 hop"}},
		CreatedAt: now,
	}}))

	inputs, err := r.CrystallizationInputs(ctx)
	require.NoError(t, err)
	var mine *CrystallizationInput
	for i := range inputs {
		if inputs[i].Sig.ResourceType == resourceType {
			mine = &inputs[i]
		}
	}
	require.NotNil(t, mine, "the confirmed adjudicator belief this test wrote must appear")
	require.Equal(t, "page", mine.Sig.Band, "band must come from finding_enrichment, not the legacy 'routine'")
	require.Equal(t, "must_fix", mine.Sig.MustFixClass, "must_fix_class must come from finding_enrichment, not the legacy 'controlled'")
	require.Equal(t, finding.SeverityCritical, mine.Severity)
}
