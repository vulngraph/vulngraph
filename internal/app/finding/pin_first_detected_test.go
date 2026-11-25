package finding

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// pinFirstDetectedAt is what a producer re-observation still carries forward.
// The ten enrich:"output" fields need no carrying: insertFindings (repo.go)
// does not write them, and finding_enrichment (Service.RecordEnrichment) is
// their sole store. What remains is pinning FirstDetectedAt (the age input).

// A producer re-confirming an unchanged violation (same severity) must not
// reset its recorded first observation.
func TestPinFirstDetectedAt_UnchangedSeverityPinsAge(t *testing.T) {
	firstSeen := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	reobserved := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	repo := &fakeRepo{stored: []Finding{{
		ID: "f1", Severity: SeverityHigh,
		DetectedAt: firstSeen, FirstDetectedAt: firstSeen,
	}}}
	svc := NewService(repo)
	found := []Finding{{ID: "f1", Severity: SeverityHigh, DetectedAt: reobserved}}

	require.NoError(t, svc.pinFirstDetectedAt(context.Background(), found))

	require.Equal(t, firstSeen, found[0].FirstDetectedAt, "the pin must survive re-observation")
	require.Equal(t, reobserved, found[0].DetectedAt, "detected_at is untouched by the pin -- it tracks the latest observation")
}

// A genuine severity change must not affect the age pin either way -- age and
// severity are independent facts, and a later change removed the only logic
// (the old enrichment carry-forward) that used to couple them.
func TestPinFirstDetectedAt_SeverityChangeDoesNotAffectAgePin(t *testing.T) {
	firstSeen := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	repo := &fakeRepo{stored: []Finding{{
		ID: "f1", Severity: SeverityMedium, DetectedAt: firstSeen, FirstDetectedAt: firstSeen,
	}}}
	svc := NewService(repo)
	found := []Finding{{ID: "f1", Severity: SeverityCritical, DetectedAt: firstSeen}} // severity changed

	require.NoError(t, svc.pinFirstDetectedAt(context.Background(), found))

	require.Equal(t, firstSeen, found[0].FirstDetectedAt, "age pin runs regardless of a severity change")
	require.Equal(t, SeverityCritical, found[0].Severity, "a genuine (non-KEV) severity change is never overridden")
}

// KEV never writes Severity (kev.Enrich sets only KnownExploited), so a
// known-exploited finding the producer now reports at a lower severity is
// recorded as reported. The KEV signal lives in KnownExploited and the
// enrichment page floor, not in a carried-forward severity.
func TestPinFirstDetectedAt_KnownExploitedDowngradeIsRecordedAsReported(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{
		ID: "f1", Severity: SeverityCritical, KnownExploited: true,
		Score: 90, ScoreBand: "page",
	}}}
	svc := NewService(repo)
	found := []Finding{{ID: "f1", Severity: SeverityHigh}}

	require.NoError(t, svc.pinFirstDetectedAt(context.Background(), found))

	require.Equal(t, SeverityHigh, found[0].Severity, "the producer's severity is recorded as reported")
	require.Zero(t, found[0].Score, "enrichment outputs are not carried forward -- finding_enrichment owns them")
	require.Empty(t, found[0].ScoreBand)
}

// A stored critical whose severity genuinely dropped is recorded as reported.
func TestPinFirstDetectedAt_NonKEVCriticalDowngradeIsNotOverridden(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "f1", Severity: SeverityCritical}}} // no KnownExploited
	svc := NewService(repo)
	found := []Finding{{ID: "f1", Severity: SeverityHigh}}

	require.NoError(t, svc.pinFirstDetectedAt(context.Background(), found))

	require.Equal(t, SeverityHigh, found[0].Severity, "source severity wins on a genuine, non-KEV change")
}

// A brand-new finding (no stored version) has nothing to pin -- it must be
// left exactly as the producer built it.
func TestPinFirstDetectedAt_NewFindingUntouched(t *testing.T) {
	svc := NewService(&fakeRepo{})
	detected := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	found := []Finding{{ID: "f-new", Severity: SeverityHigh, DetectedAt: detected}}

	require.NoError(t, svc.pinFirstDetectedAt(context.Background(), found))

	require.True(t, found[0].FirstDetectedAt.IsZero(), "with no stored version there is nothing to pin from -- the repo's own firstDetectedAt floors it to DetectedAt on write, not this function")
	require.Equal(t, SeverityHigh, found[0].Severity)
}

// fakeErrRepo wraps fakeRepo to script a ByIDs failure.
type fakeErrRepo struct {
	fakeRepo
	byIDsErr error
}

func (f *fakeErrRepo) ByIDs(ctx context.Context, ids []string) ([]Finding, error) {
	if f.byIDsErr != nil {
		return nil, f.byIDsErr
	}
	return f.fakeRepo.ByIDs(ctx, ids)
}

// A failed lookup of the stored versions must not let RecordObserved write:
// the row would reset first-seen to now, presenting a finding with lost history as a fresh observation.
func TestRecordObserved_PinLookupFailureWritesNothing(t *testing.T) {
	repo := &fakeErrRepo{byIDsErr: context.DeadlineExceeded}
	svc := NewService(repo)
	found := []Finding{{ID: "f1", Severity: SeverityHigh}}

	err := svc.RecordObserved(context.Background(), found)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Empty(t, repo.stored, "nothing written without the stored history")
}

func TestPinFirstDetectedAt_EmptyInputNoop(t *testing.T) {
	svc := NewService(&fakeRepo{})
	require.NoError(t, svc.pinFirstDetectedAt(context.Background(), nil))
}

// TestRecordObserved_PinsFirstDetectedAtViaPublicPath confirms the pin
// actually runs as part of the PUBLIC RecordObserved path (not just the
// private helper in isolation) -- the whole point of moving it there was so
// every RecordObserved caller gets this by construction.
func TestRecordObserved_PinsFirstDetectedAtViaPublicPath(t *testing.T) {
	firstSeen := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	repo := &fakeRepo{stored: []Finding{{
		ID: "f1", Severity: SeverityHigh, DetectedAt: firstSeen, FirstDetectedAt: firstSeen,
	}}}
	svc := NewService(repo)
	reobserved := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	found := []Finding{{ID: "f1", Severity: SeverityHigh, DetectedAt: reobserved}} // simulates a re-observing producer

	require.NoError(t, svc.RecordObserved(context.Background(), found))

	require.Equal(t, firstSeen, found[0].FirstDetectedAt, "RecordObserved must pin the age forward before writing")
	require.False(t, found[0].LastObservedAt.IsZero(), "RecordObserved must still stamp LastObservedAt")
}

// The pin must NOT be gated on prior enrichment state -- an unenriched
// finding, or one whose severity genuinely changed, has been present exactly
// as long either way. Gating it is how the age reset would survive for the
// never-enriched backlog, which is precisely the set that most needs correct
// age.
func TestRecordObserved_PinsFirstDetectedAtRegardlessOfEnrichmentState(t *testing.T) {
	firstSeen := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	reobserved := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	cases := map[string]Finding{
		"never enriched":   {ID: "f1", Severity: SeverityHigh, DetectedAt: firstSeen, FirstDetectedAt: firstSeen},
		"severity changed": {ID: "f1", Severity: SeverityMedium, DetectedAt: firstSeen, FirstDetectedAt: firstSeen},
	}
	for name, stored := range cases {
		t.Run(name, func(t *testing.T) {
			svc := NewService(&fakeRepo{stored: []Finding{stored}})
			found := []Finding{{ID: "f1", Severity: SeverityHigh, DetectedAt: reobserved}}

			require.NoError(t, svc.RecordObserved(context.Background(), found))

			require.Equal(t, firstSeen, found[0].FirstDetectedAt)
		})
	}
}

// A pre-migration row has first_detected_at at the column DEFAULT (its own
// detected_at) -- or, if a writer bypassed the column entirely, zero. Either way
// the oldest real timestamp available for the id must win, and a zero must never
// win: zero is "unknown", and a 1970 first observation would demote the finding
// to the floor forever.
func TestRecordObserved_FirstDetectedAtFallsBackToOldestKnownTimestamp(t *testing.T) {
	firstSeen := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	reobserved := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	svc := NewService(&fakeRepo{stored: []Finding{{
		ID: "f1", Severity: SeverityHigh, DetectedAt: firstSeen, // no FirstDetectedAt at all
	}}})
	found := []Finding{{ID: "f1", Severity: SeverityHigh, DetectedAt: reobserved}}

	require.NoError(t, svc.RecordObserved(context.Background(), found))

	require.Equal(t, firstSeen, found[0].FirstDetectedAt)
}

// A finding nobody has ever seen before gets no pin from the store -- the repo's
// own floor writes its DetectedAt -- but the pin must not manufacture a zero
// where the producer supplied a real timestamp either.
func TestRecordObserved_NewFindingKeepsProducerTimestamps(t *testing.T) {
	detected := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	svc := NewService(&fakeRepo{})
	found := []Finding{{ID: "new", Severity: SeverityHigh, DetectedAt: detected}}

	require.NoError(t, svc.RecordObserved(context.Background(), found))

	require.Equal(t, detected, firstDetectedAt(found[0]),
		"a brand-new finding's first observation is its own detected_at, never zero")
}
