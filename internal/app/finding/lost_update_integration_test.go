//go:build integration

package finding

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// These tests exercise the lost-update race window, deterministically,
// against real ClickHouse ReplacingMergeTree semantics: an enrichment write
// landing between RecordObserved's read (R) and its Upsert (W) must survive
// the sync row.
//
// The two enrichment writers that race every producer's RecordObserved are
// enrich (internal/app/enrich/service.go) and the KEV refresh
// (internal/jobs/kev.go's KEVWorker.Work). Both write only RecordEnrichment
// (finding_enrichment), which these tests mirror. finding.Get joins that table
// and the sync write never touches it, so the enrich outputs and KEV's
// KnownExploited survive. Severity is a `findings`-only column owned by the
// producer; neither writer sets it.

// steppingClock is an explicitly-advanced synced_at source. The race being
// modeled has explicit ordering, so an injected clock makes each write version
// deterministic (see WithClock).
type steppingClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *steppingClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *steppingClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// raceRepo delegates to CHRepo but fires a hook after the observation-history
// read, inside RecordObserved's (R, W] window before Upsert. This is the deterministic stand-in for an enrich
// write-back landing mid-sync.
type raceRepo struct {
	*CHRepo
	afterHistoryRead func()
}

func (r *raceRepo) FirstObservationsByIDs(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out, err := r.CHRepo.FirstObservationsByIDs(ctx, ids)
	if r.afterHistoryRead != nil {
		r.afterHistoryRead()
	}
	return out, err
}

func raceTestClickHouseURL() string {
	if dsn := os.Getenv("TEST_CLICKHOUSE_URL"); dsn != "" {
		return dsn
	}
	return "clickhouse://graph:graph@localhost:9000/graph"
}

// TestRecordObserved_EnrichWriteInWindowSurvives drives an enrich write-back
// landing between RecordObserved's read (R) and its Upsert (W) on a finding
// that was never enriched at R. The sync row wins on synced_at in `findings`,
// but the enrichment lives in finding_enrichment, so the finding must still
// read as enriched afterwards.
func TestRecordObserved_EnrichWriteInWindowSurvives(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, raceTestClickHouseURL(), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	res := "race-" + suffix
	id := "rf1-" + suffix
	t.Cleanup(func() {
		require.NoError(t, ch.Exec(ctx, "DELETE FROM findings WHERE resource_id = ? SETTINGS mutations_sync=1", res))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM finding_enrichment WHERE id = ? SETTINGS mutations_sync=1", id))
	})

	clock := &steppingClock{}
	t0 := time.Now().Truncate(time.Second)
	clock.set(t0)
	repo := NewCHRepo(ch, WithClock(clock.now))

	producer := Finding{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "public bucket", ResourceType: "s3_bucket", ResourceID: res,
		CheckID: "aws-s3-public", DetectedAt: t0,
	}

	// t0: first observation — never enriched.
	svc := NewService(repo)
	require.NoError(t, svc.RecordObserved(ctx, []Finding{producer}))

	// Re-observation whose (R, W] window an enrich write-back lands in.
	enrichedAt := t0.Add(1 * time.Second)
	raced := &raceRepo{CHRepo: repo, afterHistoryRead: func() {
		// t0+1s: enrich finishes and writes its outputs through
		// RecordEnrichment, as internal/app/enrich/service.go does.
		clock.set(enrichedAt)
		scored := producer
		scored.Score = 90
		scored.ScoreBand = "act"
		scored.EnrichedAt = enrichedAt
		scored.MustFixClass = "elevated"
		scored.MustFixReason = "internet-reachable (2 hops)"
		require.NoError(t, NewService(repo).RecordEnrichment(ctx, []Enrichment{EnrichmentOf(scored)}))
		// t0+2s: the sync write (W) lands after the enrich write.
		clock.set(t0.Add(2 * time.Second))
	}}
	require.NoError(t, NewService(raced).RecordObserved(ctx, []Finding{{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "public bucket", ResourceType: "s3_bucket", ResourceID: res,
		CheckID: "aws-s3-public", DetectedAt: t0.Add(2 * time.Second),
	}}))

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)

	// finding.Get reads score/etc. from finding_enrichment, which the
	// sync write never touches — so the enrich write survives the race.
	require.Equal(t, uint8(90), got.Score)
	require.Equal(t, "act", got.ScoreBand)
	require.WithinDuration(t, enrichedAt, got.EnrichedAt, time.Millisecond)
	require.Equal(t, "elevated", got.MustFixClass)
}

// TestRecordObserved_KEVWriteInWindowKeepsKnownExploited is the same race for
// the second enrichment writer: internal/jobs/kev.go's KEVWorker.Work flags
// KnownExploited through RecordEnrichment with no serialization against
// RecordObserved. The flag survives the sync row; Severity stays the
// producer's.
func TestRecordObserved_KEVWriteInWindowKeepsKnownExploited(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, raceTestClickHouseURL(), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	res := "race-kev-" + suffix
	id := "rfkev-" + suffix
	t.Cleanup(func() {
		require.NoError(t, ch.Exec(ctx, "DELETE FROM findings WHERE resource_id = ? SETTINGS mutations_sync=1", res))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM finding_enrichment WHERE id = ? SETTINGS mutations_sync=1", id))
	})

	clock := &steppingClock{}
	t0 := time.Now().Truncate(time.Second)
	clock.set(t0)
	repo := NewCHRepo(ch, WithClock(clock.now))

	producer := Finding{
		ID: id, Source: "supply_chain", Type: "vulnerable_dependency", Severity: SeverityHigh,
		Title: "vulnerable package", ResourceType: "package", ResourceID: res,
		CheckID: "CVE-2024-3094", DetectedAt: t0,
	}

	// t0: first observation — not yet KEV-listed.
	svc := NewService(repo)
	require.NoError(t, svc.RecordObserved(ctx, []Finding{producer}))

	// Re-observation whose (R, W] window the KEV flag write lands in, shaped as
	// KEVWorker.flag writes it: KnownExploited through RecordEnrichment.
	kevAt := t0.Add(1 * time.Second)
	raced := &raceRepo{CHRepo: repo, afterHistoryRead: func() {
		clock.set(kevAt)
		flagged := producer
		flagged.KnownExploited = true
		// EnrichedAt must be set before EnrichmentOf: finding_enrichment's TTL
		// is toDateTime(enriched_at) + 365 DAY, so a zero EnrichedAt (the Go
		// zero value, 0001-01-01, decoded as epoch by the driver) computes an
		// ALREADY-EXPIRED TTL and the row can be dropped on the next merge
		// (see TestCHRepo_SignalsByResource).
		flagged.EnrichedAt = kevAt
		require.NoError(t, NewService(repo).RecordEnrichment(ctx, []Enrichment{EnrichmentOf(flagged)}))
		// t0+2s: the sync write (W) lands after the KEV write.
		clock.set(t0.Add(2 * time.Second))
	}}
	require.NoError(t, NewService(raced).RecordObserved(ctx, []Finding{{
		ID: id, Source: "supply_chain", Type: "vulnerable_dependency", Severity: SeverityHigh,
		Title: "vulnerable package", ResourceType: "package", ResourceID: res,
		CheckID: "CVE-2024-3094", DetectedAt: t0.Add(2 * time.Second),
	}}))

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)

	// finding.Get reads KnownExploited from finding_enrichment, so the flag
	// survives the race; Severity is the producer's.
	require.True(t, got.KnownExploited)
	require.Equal(t, SeverityHigh, got.Severity)
}

// TestRecordObserved_NewerEnrichWinsOverStaleRead covers the subtler variant:
// the finding HAD old enrichment at R and a NEWER enrich lands in the window.
// The newer score must win, not the stale values read at R — otherwise the
// finding silently runs on an outdated score/classification.
func TestRecordObserved_NewerEnrichWinsOverStaleRead(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, raceTestClickHouseURL(), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	res := "race2-" + suffix
	id := "rf2-" + suffix
	t.Cleanup(func() {
		require.NoError(t, ch.Exec(ctx, "DELETE FROM findings WHERE resource_id = ? SETTINGS mutations_sync=1", res))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM finding_enrichment WHERE id = ? SETTINGS mutations_sync=1", id))
	})

	clock := &steppingClock{}
	t0 := time.Now().Truncate(time.Second)
	clock.set(t0)
	repo := NewCHRepo(ch, WithClock(clock.now))

	oldEnrichedAt := t0
	base := Finding{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceType: "ec2_instance", ResourceID: res,
		CheckID: "aws-ec2-public-ip", DetectedAt: t0,
		Score: 40, ScoreBand: "monitor", EnrichedAt: oldEnrichedAt,
	}
	require.NoError(t, NewService(repo).Record(ctx, []Finding{base}))
	require.NoError(t, NewService(repo).RecordEnrichment(ctx, []Enrichment{EnrichmentOf(base)}))

	newEnrichedAt := t0.Add(1 * time.Second)
	raced := &raceRepo{CHRepo: repo, afterHistoryRead: func() {
		clock.set(newEnrichedAt)
		rescored := base
		rescored.Score = 85
		rescored.ScoreBand = "act"
		rescored.EnrichedAt = newEnrichedAt
		require.NoError(t, NewService(repo).Record(ctx, []Finding{rescored}))
		require.NoError(t, NewService(repo).RecordEnrichment(ctx, []Enrichment{EnrichmentOf(rescored)}))
		clock.set(t0.Add(2 * time.Second))
	}}
	require.NoError(t, NewService(raced).RecordObserved(ctx, []Finding{{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceType: "ec2_instance", ResourceID: res,
		CheckID: "aws-ec2-public-ip", DetectedAt: t0.Add(2 * time.Second),
	}}))

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)

	// finding.Get reads score/enriched_at from
	// finding_enrichment's argMax(..., enriched_at) — the NEWER enrich write
	// (enriched_at = newEnrichedAt) wins there regardless of the sync write.
	require.Equal(t, uint8(85), got.Score)
	require.WithinDuration(t, newEnrichedAt, got.EnrichedAt, time.Millisecond)
}

// TestRecordObserved_FirstDetectionSurvivesReobservation covers a related
// defect: every producer re-stamps detected_at on re-observation, so without a
// carried-forward value a finding's age would reset on every sweep. Age is a must-fix input, so
// prioritisation was skewed for everything re-observed.
//
// The fix does NOT make detected_at immutable — see the assertions at the end
// for why that would have broken the TTL and the source-liveness signal — it
// adds first_detected_at, pinned by RecordObserved and read as a min across
// row versions. This test drives the real ClickHouse round trip because the
// min-over-nonzero read is half the mechanism and a fake cannot exercise it.
func TestRecordObserved_FirstDetectionSurvivesReobservation(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, raceTestClickHouseURL(), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	suffix := time.Now().Format("150405.000000")
	res := "age-" + suffix
	id := "af1-" + suffix
	t.Cleanup(func() {
		require.NoError(t, ch.Exec(ctx, "DELETE FROM findings WHERE resource_id = ? SETTINGS mutations_sync=1", res))
		require.NoError(t, ch.Exec(ctx, "DELETE FROM finding_enrichment WHERE id = ? SETTINGS mutations_sync=1", id))
	})

	clock := &steppingClock{}
	t0 := time.Now().Truncate(time.Second)
	clock.set(t0)
	repo := NewCHRepo(ch, WithClock(clock.now))
	svc := NewService(repo)

	firstDetected := t0.Add(-30 * 24 * time.Hour) // a month-old finding
	require.NoError(t, svc.RecordObserved(ctx, []Finding{{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceType: "ec2_instance", ResourceID: res,
		CheckID: "aws-ec2-public-ip", DetectedAt: firstDetected,
	}}))

	// The producer re-observes and, as checks.eval does, stamps detected_at = now.
	clock.set(t0.Add(1 * time.Second))
	require.NoError(t, svc.RecordObserved(ctx, []Finding{{
		ID: id, Source: "cspm", Type: "exposure", Severity: SeverityHigh,
		Title: "t", ResourceType: "ec2_instance", ResourceID: res,
		CheckID: "aws-ec2-public-ip", DetectedAt: t0,
	}}))

	got, err := repo.Get(ctx, id)
	require.NoError(t, err)

	// detected_at STILL tracks the latest observation — that is
	// deliberate and unchanged: it is the list sort key and the TTL anchor, and
	// coverage's qFindingSourceLiveness reads max(detected_at) as "when did this
	// source last produce anything", which is only true while it re-stamps.
	require.WithinDuration(t, t0, got.DetectedAt, time.Second,
		"detected_at is 'last detected' by design; the age fix added a separate column rather than repurposing it")
	// The age input is first_detected_at, and it survived the re-observation.
	require.WithinDuration(t, firstDetected, got.FirstDetectedAt, time.Second,
		"first_detected_at must survive re-observation — this is the age input")
}
