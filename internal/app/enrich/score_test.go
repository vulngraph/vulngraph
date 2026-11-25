package enrich

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAggregate_ValueAndBand(t *testing.T) {
	tests := []struct {
		name      string
		factors   []Factor
		wantValue uint8
		wantBand  Band
	}{
		{"no factors", nil, 0, BandMonitor},
		{"bare info stays monitor", []Factor{{Points: 2}}, 2, BandMonitor},
		{"bare low stays monitor", []Factor{{Points: 8}}, 8, BandMonitor},
		{"just below pipeline", []Factor{{Points: ThresholdPipeline - 1}}, ThresholdPipeline - 1, BandMonitor},
		{"pipeline boundary", []Factor{{Points: ThresholdPipeline}}, ThresholdPipeline, BandPipeline},
		{"above pipeline", []Factor{{Points: ThresholdPipeline + 4}}, ThresholdPipeline + 4, BandPipeline},
		{"high boundary", []Factor{{Points: 61}}, 61, BandHigh},
		{"page boundary", []Factor{{Points: 81}}, 81, BandPage},
		{"sum clamps at 100", []Factor{{Points: 80}, {Points: 80}}, 100, BandPage},
		{"negative clamps at 0", []Factor{{Points: -5}}, 0, BandMonitor},
		{"floor raises a low sum", []Factor{{Points: 30, Floor: ThresholdPage}}, 81, BandPage},
		{"floor ignored when sum higher", []Factor{{Points: 90, Floor: ThresholdPage}}, 90, BandPage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Aggregate(tt.factors)
			require.Equal(t, tt.wantValue, got.Value)
			require.Equal(t, tt.wantBand, got.Band)
		})
	}
}

// THE INVARIANT: adding a negative factor must ALWAYS produce a strictly lower
// final score than the same factor set without it — unless the score is already
// 0, or an explicit Floor pins it. Regression for the clamp-order bug: positives
// used to be summed together with negatives and clamped only at the end, so any
// finding whose positives already exceeded 100 absorbed every demote (e.g. a
// staging SA with principal_class -10 and factors summing above 100 scored
// exactly the same as a prod SA with no demote at the same raw total).
func TestAggregate_NegativeFactorAlwaysLowersScore(t *testing.T) {
	positiveSets := [][]Factor{
		{{Source: "a", Points: 5}},
		{{Source: "a", Points: 55}},
		{{Source: "a", Points: 60}, {Source: "b", Points: 30}},
		{{Source: "a", Points: 80}, {Source: "b", Points: 20}},   // exactly 100
		{{Source: "a", Points: 80}, {Source: "b", Points: 25}},   // 105, over the clamp
		{{Source: "a", Points: 100}, {Source: "b", Points: 100}}, // 200, way over
		// A representative gcp-privesc factor set: 20+30+20+12+10+20 = 112.
		{
			{Source: sourceBaseSeverity, Points: 20},
			{Source: "blast_radius", Points: 30},
			{Source: "internet_reach", Points: 20},
			{Source: "epss", Points: 12},
			{Source: "finding_age", Points: 10},
			{Source: "toxic_combo", Points: 20},
		},
	}
	negatives := []int{-1, -5, -10, -25}

	for _, base := range positiveSets {
		for _, neg := range negatives {
			t.Run("", func(t *testing.T) {
				without := Aggregate(append([]Factor(nil), base...))
				demoted := append([]Factor(nil), base...)
				demoted = append(demoted, Factor{Source: sourcePrincipalClass, Points: neg})
				with := Aggregate(demoted)

				if without.Value == 0 {
					require.Equal(t, uint8(0), with.Value)
					return
				}
				require.Less(t, with.Value, without.Value,
					"negative factor %d must lower the score (was %d, with demote %d)",
					neg, without.Value, with.Value)
			})
		}
	}
}

// The precise case, spelled out: 112 raw with and without a -10 must differ.
func TestAggregate_Sum112HonoursDemote(t *testing.T) {
	base := []Factor{
		{Source: sourceBaseSeverity, Points: 20},
		{Source: "blast_radius", Points: 30},
		{Source: "internet_reach", Points: 20},
		{Source: "epss", Points: 12},
		{Source: "finding_age", Points: 10},
		{Source: "toxic_combo", Points: 20},
	}
	prod := Aggregate(append([]Factor(nil), base...))
	staging := Aggregate(append(append([]Factor(nil), base...),
		Factor{Source: sourcePrincipalClass, Points: -10, Detail: "non-production principal (test/staging)"}))

	require.Equal(t, uint8(100), prod.Value, "positives clamp to 100")
	require.Equal(t, uint8(90), staging.Value, "the -10 demote is spent against the clamped subtotal")
	require.Less(t, staging.Value, prod.Value)
}

// A staging-demoted finding must score below an otherwise-identical production
// one — the two only differ by the principal_class factor.
func TestAggregate_StagingScoresBelowProduction(t *testing.T) {
	shared := []Factor{
		{Source: sourceBaseSeverity, Points: 40},
		{Source: "blast_radius", Points: 35},
		{Source: "internet_reach", Points: 30},
		{Source: "toxic_combo", Points: 20},
	}
	production := Aggregate(append([]Factor(nil), shared...))
	staging := Aggregate(append(append([]Factor(nil), shared...),
		Factor{Source: sourcePrincipalClass, Points: -10, Detail: "non-production principal (test/staging)"}))

	require.Less(t, staging.Value, production.Value)
}

// The -25 unreachable penalty must bite even on a finding whose positives blow
// far past the clamp (the old order discarded it above a raw sum of 125).
func TestAggregate_UnreachablePenaltyBitesAboveClamp(t *testing.T) {
	base := []Factor{
		{Source: sourceBaseSeverity, Points: 60},
		{Source: "blast_radius", Points: 40},
		{Source: "toxic_combo", Points: 30},
	}
	reachable := Aggregate(append([]Factor(nil), base...))
	unreachable := Aggregate(append(append([]Factor(nil), base...),
		Factor{Source: "reach", Points: -25}))

	require.Equal(t, uint8(100), reachable.Value)
	require.Equal(t, uint8(75), unreachable.Value)
}

// An explicit Floor still wins over a demote: a demote moves the score inside
// the headroom above the floor but can never push it below.
func TestAggregate_FloorBeatsDemote(t *testing.T) {
	// Positives clamp to 100, -25 lands at 75, but the page floor pins it to 81.
	pinned := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 60},
		{Source: sourceKEV, Points: 60, Floor: ThresholdPage},
		{Source: "reach", Points: -25},
	})
	require.Equal(t, uint8(ThresholdPage), pinned.Value)
	require.Equal(t, BandPage, pinned.Band)

	// Above the floor there is headroom, so the demote is honoured in full.
	free := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 60},
		{Source: sourceKEV, Points: 60, Floor: ThresholdPage},
		{Source: "reach", Points: -10},
	})
	require.Equal(t, uint8(90), free.Value)
}

// A KEV hit pages regardless of how low the other signals are (unless its page
// is delegated to root-cause findings; see Factor.RootCause).
func TestAggregate_KEVFloorAlwaysPages(t *testing.T) {
	got := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 2},               // info
		{Source: sourceKEV, Points: 30, Floor: ThresholdPage}, // but known-exploited
	})
	require.GreaterOrEqual(t, got.Value, uint8(ThresholdPage))
	require.Equal(t, BandPage, got.Band)
}

// A suppress factor must NOT be able to demote a known-exploited (KEV-floored)
// finding out of the actionable band — the hard floor wins over suppression.
func TestAggregate_SuppressCannotBreachKEVFloor(t *testing.T) {
	got := Aggregate([]Factor{
		{Source: sourceKEV, Points: 30, Floor: ThresholdPage},  // known-exploited
		{Source: "principal_class", Points: 0, Suppress: true}, // tries to suppress
	})
	require.GreaterOrEqual(t, got.Value, uint8(ThresholdPage), "KEV floor must survive suppression")
	require.Equal(t, BandPage, got.Band)
}

// A suppress factor on a finding with no hard floor still caps to monitor.
func TestAggregate_SuppressCapsWhenNoFloor(t *testing.T) {
	got := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 70},
		{Source: "principal_class", Points: 0, Suppress: true},
	})
	require.Less(t, got.Value, uint8(ThresholdPipeline))
	require.Equal(t, BandMonitor, got.Band)
}

// A ceiling caps a high additive sum below the page band even though the raw
// sum alone would cross it.
func TestAggregate_CeilingCapsBelowPage(t *testing.T) {
	got := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 90},
		{Source: sourceHygieneCeiling, Ceiling: ThresholdPage},
	})
	require.Less(t, got.Value, uint8(ThresholdPage))
	require.NotEqual(t, BandPage, got.Band)
}

// A ceiling never lowers a score that is already below it.
func TestAggregate_CeilingNoopWhenAlreadyBelow(t *testing.T) {
	got := Aggregate([]Factor{
		{Source: sourceBaseSeverity, Points: 55},
		{Source: sourceHygieneCeiling, Ceiling: ThresholdPage},
	})
	require.Equal(t, uint8(55), got.Value)
	require.Equal(t, BandPipeline, got.Band)
}

func TestAggregate_SortsFactorsDeterministically(t *testing.T) {
	got := Aggregate([]Factor{
		{Source: sourceTeamHistory}, {Source: sourceBaseSeverity}, {Source: sourceKEV},
	})
	require.Equal(t,
		[]string{sourceBaseSeverity, sourceKEV, sourceTeamHistory},
		[]string{got.Factors[0].Source, got.Factors[1].Source, got.Factors[2].Source},
	)
}
