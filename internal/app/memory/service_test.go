package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

// outcomes builds n outcomes at the same instant with the given success flag.
func outcomes(n int, success bool, at time.Time) []Outcome {
	out := make([]Outcome, n)
	for i := range out {
		out[i] = Outcome{Success: success, OccurredAt: at}
	}
	return out
}

func TestComputeConfidence_InsufficientEvidence(t *testing.T) {
	// Two recent successes — below minEffectiveN (3) — must escalate.
	c := computeConfidence(outcomes(2, true, now), now)
	require.Equal(t, BandInsufficient, c.Band)
	require.Equal(t, 2, c.SampleCount)
}

func TestComputeConfidence_NoOutcomes(t *testing.T) {
	c := computeConfidence(nil, now)
	require.Equal(t, BandInsufficient, c.Band)
	require.Zero(t, c.EffectiveN)
}

func TestComputeConfidence_HighWhenMostlySucceed(t *testing.T) {
	var os []Outcome
	os = append(os, outcomes(9, true, now)...)
	os = append(os, outcomes(1, false, now)...)
	c := computeConfidence(os, now)
	require.Equal(t, BandHigh, c.Band)
	require.InDelta(t, 0.9, c.Score, 0.001)
}

func TestComputeConfidence_MediumBand(t *testing.T) {
	var os []Outcome
	os = append(os, outcomes(6, true, now)...)
	os = append(os, outcomes(4, false, now)...)
	c := computeConfidence(os, now)
	require.Equal(t, BandMedium, c.Band)
	require.InDelta(t, 0.6, c.Score, 0.001)
}

func TestComputeConfidence_LowWhenMostlyFail(t *testing.T) {
	var os []Outcome
	os = append(os, outcomes(2, true, now)...)
	os = append(os, outcomes(8, false, now)...)
	c := computeConfidence(os, now)
	require.Equal(t, BandLow, c.Band)
}

func TestComputeConfidence_RecentOutcomesDominate(t *testing.T) {
	// Many old failures, fewer recent successes. With a 30-day half-life, old
	// outcomes decay so the recent successes should pull the score up.
	old := now.Add(-180 * 24 * time.Hour) // ~6 half-lives ago → tiny weight
	var os []Outcome
	os = append(os, outcomes(50, false, old)...)
	os = append(os, outcomes(10, true, now)...)
	c := computeConfidence(os, now)
	require.Equal(t, BandHigh, c.Band, "recent successes outweigh decayed old failures")
	require.Greater(t, c.Score, highThreshold)
}

// TestComputeConfidence_ExactHalfLifeWeight pins the decay formula itself: an
// outcome exactly one half-life (30 days) old must weigh exactly 0.5
// (w = e^(-lambda*age), lambda = ln2/halfLife, so age=halfLife -> e^-ln2 = 0.5).
// This is an exact assertion, not a band check — the whole point is to catch a
// formula regression a band-only test would hide.
func TestComputeConfidence_ExactHalfLifeWeight(t *testing.T) {
	old := now.Add(-halfLife)
	c := computeConfidence(outcomes(1, true, old), now)
	require.InDelta(t, 0.5, c.EffectiveN, 1e-9, "an outcome exactly one half-life old weighs exactly 0.5")
}

// TestComputeConfidence_ExactDecayedScore pins the combined score for a mixed
// ledger: 2 fresh successes (weight 1.0 each) plus 2 half-life-old failures
// (weight 0.5 each) give totalWeight=3.0 (at MinEffectiveN, so Score is
// actually computed rather than left at its insufficient-evidence zero) and
// score = 2.0/3.0, exactly — not a loose band. This is the same
// fresh-success/half-life-old-failure ratio (1.0 : 0.5) the half-life decay
// defines, scaled up to clear the evidence gate.
func TestComputeConfidence_ExactDecayedScore(t *testing.T) {
	old := now.Add(-halfLife)
	os := []Outcome{
		{Success: true, OccurredAt: now},
		{Success: true, OccurredAt: now},
		{Success: false, OccurredAt: old},
		{Success: false, OccurredAt: old},
	}
	c := computeConfidence(os, now)
	require.NotEqual(t, BandInsufficient, c.Band)
	require.InDelta(t, 3.0, c.EffectiveN, 1e-9)
	require.InDelta(t, 2.0/3.0, c.Score, 1e-9,
		"2 fresh successes (weight 1 each) + 2 half-life-old failures (weight 0.5 each) -> 2/3")
}

// TestComputeConfidence_MinEffectiveNBoundary pins the insufficient-evidence
// gate at the exact MinEffectiveN boundary: totalWeight < MinEffectiveN is a
// strict inequality, so weight exactly at 3.0 already clears it, and weight
// just under 3.0 does not.
func TestComputeConfidence_MinEffectiveNBoundary(t *testing.T) {
	// Exactly at MinEffectiveN: 3 fresh outcomes, weight 1.0 each, sum 3.0.
	atThreshold := computeConfidence(outcomes(3, true, now), now)
	require.InDelta(t, 3.0, atThreshold.EffectiveN, 1e-9)
	require.NotEqual(t, BandInsufficient, atThreshold.Band, "weight exactly at MinEffectiveN must not escalate")

	// Just under: 2 fresh (weight 1.0 each) + 1 half-life-old (weight 0.5) = 2.5.
	old := now.Add(-halfLife)
	var os []Outcome
	os = append(os, outcomes(2, true, now)...)
	os = append(os, outcomes(1, true, old)...)
	underThreshold := computeConfidence(os, now)
	require.InDelta(t, 2.5, underThreshold.EffectiveN, 1e-9)
	require.Equal(t, BandInsufficient, underThreshold.Band, "weight just under MinEffectiveN must still escalate")
}

func TestComputeConfidence_FutureTimestampClampedToZeroAge(t *testing.T) {
	// A clock-skewed future outcome must not get a weight > 1 or panic.
	c := computeConfidence(outcomes(5, true, now.Add(time.Hour)), now)
	require.Equal(t, BandHigh, c.Band)
	require.InDelta(t, 5.0, c.EffectiveN, 0.001, "zero-age weight is exactly 1 each")
}

// fakeRepo exercises the service wiring around the pure math.
type fakeRepo struct {
	recorded    []Outcome
	recent      []Outcome
	byAsset     []Outcome
	byAssetType string
}

func (f *fakeRepo) Record(_ context.Context, o Outcome) error {
	f.recorded = append(f.recorded, o)
	return nil
}
func (f *fakeRepo) Recent(_ context.Context, _, _ string, _ int) ([]Outcome, error) {
	return f.recent, nil
}
func (f *fakeRepo) RecentByAsset(_ context.Context, assetType string, _ int) ([]Outcome, error) {
	f.byAssetType = assetType
	return f.byAsset, nil
}

func TestService_RecordSetsTimestamp(t *testing.T) {
	repo := &fakeRepo{}
	svc := &Service{repo: repo, now: func() time.Time { return now }}

	require.NoError(t, svc.Record(context.Background(), Outcome{ActionClass: "patch", Success: true}))
	require.Len(t, repo.recorded, 1)
	require.Equal(t, now, repo.recorded[0].OccurredAt, "zero timestamp is stamped with now")
}

func TestService_ConfidenceUsesRepo(t *testing.T) {
	repo := &fakeRepo{recent: outcomes(10, true, now)}
	svc := &Service{repo: repo, now: func() time.Time { return now }}

	c, err := svc.Confidence(context.Background(), "patch", "ec2_instance")
	require.NoError(t, err)
	require.Equal(t, BandHigh, c.Band)
}

func TestService_AssetConfidenceUsesByAsset(t *testing.T) {
	repo := &fakeRepo{byAsset: outcomes(10, true, now)}
	svc := &Service{repo: repo, now: func() time.Time { return now }}

	c, err := svc.AssetConfidence(context.Background(), "ec2_instance")
	require.NoError(t, err)
	require.Equal(t, BandHigh, c.Band)
	require.Equal(t, "ec2_instance", repo.byAssetType, "asset type is passed through, no action class")
}
