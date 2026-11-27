package enrich

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
)

func TestBaseSeverity(t *testing.T) {
	tests := []struct {
		sev  finding.Severity
		want int
	}{
		{finding.SeverityCritical, 40},
		{finding.SeverityHigh, 30},
		{finding.SeverityMedium, 18},
		{finding.SeverityLow, 8},
		{finding.SeverityInfo, 2},
		{finding.Severity("garbage"), 2}, // unknown defaults to info weight
		{finding.Severity(""), 2},
	}
	for _, tt := range tests {
		t.Run(string(tt.sev), func(t *testing.T) {
			f, applied, err := BaseSeverity{}.Evaluate(context.Background(), finding.Finding{Severity: tt.sev})
			require.NoError(t, err)
			require.True(t, applied)
			require.Equal(t, tt.want, f.Points)
			require.Zero(t, f.Floor)
		})
	}
}

func TestKEV(t *testing.T) {
	hit, applied, err := KEV{}.Evaluate(context.Background(), finding.Finding{KnownExploited: true})
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 30, hit.Points)
	require.Equal(t, ThresholdPage, hit.Floor)

	_, applied, err = KEV{}.Evaluate(context.Background(), finding.Finding{KnownExploited: false})
	require.NoError(t, err)
	require.False(t, applied, "no KEV hit means the source contributes nothing")
}

type fakeBlast struct {
	count     int
	err       error
	truncated bool
	// accountIDs, when set, overrides count: one asset per entry, each
	// stamped with the given AccountID. Lets tests build a specific
	// same-account or cross-account shape.
	accountIDs []string
}

func (f fakeBlast) BlastRadius(_ context.Context, _ string, _ int) (asset.BlastRadius, error) {
	if f.err != nil {
		return asset.BlastRadius{}, f.err
	}
	if f.accountIDs != nil {
		assets := make([]asset.Asset, len(f.accountIDs))
		for i, acct := range f.accountIDs {
			assets[i] = asset.Asset{ID: fmt.Sprintf("a-%d", i), AccountID: acct}
		}
		return asset.BlastRadius{Assets: assets, Truncated: f.truncated}, nil
	}
	return asset.BlastRadius{Assets: make([]asset.Asset, f.count), Truncated: f.truncated}, nil
}

func TestBlastRadiusTruncatedAccountSampleCannotDiscount(t *testing.T) {
	accounts := make([]string, 499)
	for i := range accounts {
		accounts[i] = "one-account"
	}
	for _, counter := range []BlastRadiusCounter{nil, fakeCounter{count: 500}} {
		src := BlastRadius{Counter: counter, Provider: fakeBlast{accountIDs: accounts, truncated: true}}
		f, applied, err := src.Evaluate(t.Context(), finding.Finding{ResourceID: "seed"})
		require.NoError(t, err)
		require.True(t, applied)
		require.Equal(t, 20, f.Points, "a partial same-account sample cannot establish a blast discount")
	}
}

func TestBlastRadius_Buckets(t *testing.T) {
	tests := []struct {
		count int
		want  int
	}{
		{0, 0}, {1, 4}, {3, 4}, {4, 10}, {10, 10}, {11, 16}, {50, 16}, {51, 20}, {500, 20},
	}
	for _, tt := range tests {
		src := BlastRadius{Provider: fakeBlast{count: tt.count}}
		f, applied, err := src.Evaluate(context.Background(), finding.Finding{ResourceID: "r-1"})
		require.NoError(t, err)
		require.True(t, applied)
		require.Equal(t, tt.want, f.Points, "count=%d", tt.count)
	}
}

func TestBlastRadius_NoResourceSkips(t *testing.T) {
	_, applied, err := BlastRadius{Provider: fakeBlast{count: 5}}.Evaluate(context.Background(), finding.Finding{ResourceID: ""})
	require.NoError(t, err)
	require.False(t, applied)
}

func TestBlastRadius_ProviderErrorDegrades(t *testing.T) {
	_, _, err := BlastRadius{Provider: fakeBlast{err: errors.New("ch down")}}.Evaluate(context.Background(), finding.Finding{ResourceID: "r-1"})
	require.Error(t, err, "an error lets the service degrade gracefully")
}

type fakeCounter struct {
	count int
	err   error
}

func (f fakeCounter) BlastRadiusCount(_ context.Context, _ string, _ int) (int, error) {
	return f.count, f.err
}

// Below blastAccountCap, no breakdown could possibly change the score (see
// blastAccountCap doc) — Ladybug's raw count is used directly and the
// ClickHouse confirmatory call is skipped entirely.
func TestBlastRadius_LadybugBelowCap_NoConfirmationCall(t *testing.T) {
	src := BlastRadius{
		Counter:  fakeCounter{count: blastAccountCap},
		Provider: fakeBlast{err: errors.New("should never be called")},
	}
	f, applied, err := src.Evaluate(context.Background(), finding.Finding{ResourceID: "r-1"})
	require.NoError(t, err)
	require.True(t, applied)
	want, _ := blastPoints(blastAccountCap, nil)
	require.Equal(t, want, f.Points)
}

// Above blastAccountCap, ClickHouse's OWN breakdown (and its own total) is
// authoritative — a mismatched Ladybug count is never rescaled onto it or
// trusted over it. Otherwise a dominant cluster from a DIFFERENT engine's walk than the one that
// produced n would wrongly discount (or, as scaled here, fail to discount) a
// finding whose own reach never had that cluster.
func TestBlastRadius_ClickHouseAuthoritativeAboveCap(t *testing.T) {
	f := finding.Finding{ResourceID: "r-1"}

	// ClickHouse-only, no Ladybug: 5 reachable assets, no shared account (each a
	// singleton) — nothing over the cap, so the score reflects the raw count.
	chOnly, _, err := BlastRadius{Provider: fakeBlast{count: 5}}.Evaluate(context.Background(), f)
	require.NoError(t, err)

	// Ladybug reports a totally different count (11, itself above the cap so a
	// confirmation IS fetched) but ClickHouse's own walk resolves the same 5
	// singleton assets as above. The finding must score exactly as the
	// ClickHouse-only case did — Ladybug's mismatched 11 must never leak into
	// the score once ClickHouse's own breakdown is available.
	mismatched, applied, err := BlastRadius{
		Provider: fakeBlast{count: 5},
		Counter:  fakeCounter{count: 11},
	}.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, chOnly.Points, mismatched.Points,
		"ClickHouse's own total must replace Ladybug's mismatched count, not be rescaled against it")
}

// Counter errors: fall back to the full ClickHouse walk (fail-open), which
// stands on its own — no separate "was this a fallback" scoring path.
func TestBlastRadius_CounterErrorFallsBackToCH(t *testing.T) {
	f := finding.Finding{ResourceID: "r-1"}
	chOnly, _, err := BlastRadius{Provider: fakeBlast{count: 5}}.Evaluate(context.Background(), f)
	require.NoError(t, err)

	fallback, applied, err := BlastRadius{
		Provider: fakeBlast{count: 5},
		Counter:  fakeCounter{err: errors.New("ladybug down")},
	}.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, chOnly.Points, fallback.Points, "Ladybug error must fall back to the CH count")
}

// TestBlastRadius_BlastRadiusCountFallsBackToCH proves BlastRadius itself
// satisfies BlastRadiusCounter through the same Ladybug-primary/CH-fallback path
// Evaluate uses, not a bare, fallback-less count — this is what lets
// cmd/graph/worker.go wire the whole BlastRadius source into
// enrich.WithMustFixProviders instead of its bare Ladybug Counter, so must-fix
// classification inherits the same resilience scoring already has.
func TestBlastRadius_BlastRadiusCountFallsBackToCH(t *testing.T) {
	b := BlastRadius{
		Provider: fakeBlast{count: 7},
		Counter:  fakeCounter{err: errors.New("ladybug down")},
	}
	n, err := b.BlastRadiusCount(context.Background(), "r-1", 2)
	require.NoError(t, err, "a Counter error must fall back to Provider, not surface")
	require.Equal(t, 7, n)
}

// TestBlastRadius_BlastRadiusCountPropagatesFailure proves the caller sees a
// real error (and can therefore keep blastKnown=false) when BOTH the Ladybug
// counter and its ClickHouse fallback fail — the must-fix classifier must
// never read this as "0 reachable assets".
func TestBlastRadius_BlastRadiusCountPropagatesFailure(t *testing.T) {
	b := BlastRadius{
		Provider: fakeBlast{err: errors.New("ch down")},
		Counter:  fakeCounter{err: errors.New("ladybug down")},
	}
	_, err := b.BlastRadiusCount(context.Background(), "r-1", 2)
	require.Error(t, err)
}

// TestBlastPoints_AccountBreakdown exercises blastPoints directly across the
// breakdown shapes that distinguish a same-account identity mesh from a
// genuinely broad, multi-account blast radius. bd.Total always equals n
// (the invariant countWithBreakdown enforces — a breakdown is never paired
// with a different walk's count), so every case below keeps them equal.
func TestBlastPoints_AccountBreakdown(t *testing.T) {
	tests := []struct {
		name string
		n    int
		bd   *BlastBreakdown
		want int
	}{
		{
			name: "no breakdown available: scores on raw count (fail-safe, no discount fabricated)",
			n:    60,
			bd:   nil,
			want: 20,
		},
		{
			// The regression: a privesc finding in a GCP project with, say,
			// 60 service accounts, all reachable via the impersonation
			// mesh at blastDepth=2. Before any fix: blastPoints(60) = 20 (top
			// tier), indistinguishable from a genuinely broad blast radius.
			name: "60 assets, one account (GCP SA impersonation mesh): capped, not top tier",
			n:    60,
			bd:   &BlastBreakdown{Total: 60, ByAccount: map[string]int{"gcp-project-x": 60}},
			want: 4, // capped to blastAccountCap (3) => effective 3 => lowest tier
		},
		{
			name: "60 assets spread across many accounts, none over the cap: stays top tier",
			bd: &BlastBreakdown{Total: 60, ByAccount: func() map[string]int {
				m := make(map[string]int, 20)
				for i := 0; i < 20; i++ {
					m[fmt.Sprintf("acct-%d", i)] = 3 // at the cap, not over it: 20*3 = 60
				}
				return m
			}()},
			n:    60,
			want: 20,
		},
		{
			// Dominant-only capping under-discounts multiple large clusters:
			// TWO independent 30-account meshes, each individually as large as
			// the single-account regression case above. Every account is capped
			// independently: 2 * blastAccountCap(3) = 6, not just the one
			// "dominant" cluster — a dominant-only cap would have left one of
			// these two clusters uncapped and scored this far too high.
			name: "two independent over-cap clusters: every account capped, not just the dominant one",
			n:    60,
			bd: &BlastBreakdown{Total: 60, ByAccount: map[string]int{
				"gcp-project-a": 30,
				"gcp-project-b": 30,
			}},
			want: 10, // capped sum = 3 + 3 = 6 -> tier "<=10"
		},
		{
			name: "one dominant account (30) plus a genuinely spread remainder (30 across two accounts): every account capped",
			n:    60,
			bd: &BlastBreakdown{Total: 60, ByAccount: map[string]int{
				"gcp-project-x": 30,
				"acct-a":        15,
				"acct-b":        15,
			}},
			// capped sum = 3 + 3 + 3 = 9 -> tier "<=10"
			want: 10,
		},
		{
			name: "every account already at or below cap: no discount at all",
			n:    11,
			bd:   &BlastBreakdown{Total: 11, ByAccount: map[string]int{"a": 3, "b": 3, "c": 3, "d": 2}},
			want: 16,
		},
		{
			name: "zero count, no breakdown",
			n:    0,
			bd:   nil,
			want: 0,
		},
		{
			name: "zero count, empty breakdown",
			n:    0,
			bd:   &BlastBreakdown{Total: 0, ByAccount: map[string]int{}},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := blastPoints(tt.n, tt.bd)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestBlastPoints_Monotonic pins monotonicity: for
// a fixed breakdown shape (always one dominant account), increasing the
// reachable count must never DECREASE the score. The old breakdownThreshold
// design failed this exact property at n=10 -> n=11.
func TestBlastPoints_Monotonic(t *testing.T) {
	prev := 0
	for n := 0; n <= 60; n++ {
		bd := &BlastBreakdown{Total: n, ByAccount: map[string]int{"one-account": n}}
		got, _ := blastPoints(n, bd)
		require.GreaterOrEqualf(t, got, prev, "score decreased going from n=%d to n=%d (one-account shape)", n-1, n)
		prev = got
	}
}

// TestBlastRadius_GCPServiceAccountMeshRegression reproduces the exact
// reported scenario end to end through Evaluate: a privesc finding whose seed
// reaches many (here 60) service accounts, all within one GCP project, via Ladybug as the
// primary count. Before any fix the finding scored blast_radius=20 (top
// tier, indistinguishable from a genuinely broad cross-account blast
// radius); after, the same-account fan-out is capped.
func TestBlastRadius_GCPServiceAccountMeshRegression(t *testing.T) {
	accountIDs := make([]string, 60)
	for i := range accountIDs {
		accountIDs[i] = "gcp-project-x"
	}
	src := BlastRadius{
		Counter:  fakeCounter{count: 60},
		Provider: fakeBlast{accountIDs: accountIDs},
	}
	f, applied, err := src.Evaluate(context.Background(), finding.Finding{ResourceID: "sa-seed"})
	require.NoError(t, err)
	require.True(t, applied)

	before, _ := blastPoints(60, nil) // what the breakdown-blind code produced
	require.Equal(t, 20, before, "sanity: the pre-fix behavior really was top tier")
	require.Equal(t, 4, f.Points, "same-account mesh must no longer score top tier")
	require.Less(t, f.Points, before)
	require.Contains(t, f.Detail, "capped as shared identity mesh")
}

// TestBlastRadius_BroadCrossAccountStaysHigh proves the fix does not
// overcorrect: a finding that genuinely reaches many independent accounts,
// SOME of which individually exceed the cap, must still keep scoring top
// tier — the cap discounts each account's fan-out, it does not flatten a
// broad blast radius just because individual clusters are non-trivial.
func TestBlastRadius_BroadCrossAccountStaysHigh(t *testing.T) {
	const accounts = 30
	const perAccount = 4 // over blastAccountCap(3): each account is itself a small cluster
	accountIDs := make([]string, 0, accounts*perAccount)
	for i := 0; i < accounts; i++ {
		for j := 0; j < perAccount; j++ {
			accountIDs = append(accountIDs, fmt.Sprintf("account-%d", i))
		}
	}
	n := len(accountIDs) // 120
	src := BlastRadius{
		Counter:  fakeCounter{count: n},
		Provider: fakeBlast{accountIDs: accountIDs},
	}
	f, applied, err := src.Evaluate(context.Background(), finding.Finding{ResourceID: "broad-seed"})
	require.NoError(t, err)
	require.True(t, applied)
	// capped sum = 30 accounts * min(4, 3) = 90 -> tier "<=50 or more" -> top tier
	require.Equal(t, 20, f.Points, "a genuinely broad, multi-account blast radius must still score top tier")
}

// TestBlastRadius_Determinism pins engine independence:
// identical underlying reachability data must score identically whether it
// is reached via the Ladybug-primary path or the ClickHouse-only fallback path.
func TestBlastRadius_Determinism(t *testing.T) {
	accountIDs := make([]string, 60)
	for i := range accountIDs {
		accountIDs[i] = "gcp-project-x"
	}

	viaLadybug, _, err := BlastRadius{
		Counter:  fakeCounter{count: 60},
		Provider: fakeBlast{accountIDs: accountIDs},
	}.Evaluate(context.Background(), finding.Finding{ResourceID: "sa-seed"})
	require.NoError(t, err)

	viaCHOnly, _, err := BlastRadius{
		Provider: fakeBlast{accountIDs: accountIDs},
	}.Evaluate(context.Background(), finding.Finding{ResourceID: "sa-seed"})
	require.NoError(t, err)

	require.Equal(t, viaCHOnly.Points, viaLadybug.Points,
		"identical data must score identically whether Ladybug was up or down")

	// Also true below the cap, where Ladybug's raw count is used without any CH
	// confirmation at all — the CH-only path (which must fetch to learn n)
	// still agrees, because no breakdown shape below the cap can differ.
	smallIDs := []string{"acct-x", "acct-x"}
	viaLadybugSmall, _, err := BlastRadius{
		Counter:  fakeCounter{count: len(smallIDs)},
		Provider: fakeBlast{accountIDs: smallIDs},
	}.Evaluate(context.Background(), finding.Finding{ResourceID: "small-seed"})
	require.NoError(t, err)
	viaCHOnlySmall, _, err := BlastRadius{
		Provider: fakeBlast{accountIDs: smallIDs},
	}.Evaluate(context.Background(), finding.Finding{ResourceID: "small-seed"})
	require.NoError(t, err)
	require.Equal(t, viaCHOnlySmall.Points, viaLadybugSmall.Points)
}

type fakeConf struct {
	band memory.Band
	err  error
}

func (f fakeConf) AssetConfidence(_ context.Context, _ string) (memory.Confidence, error) {
	if f.err != nil {
		return memory.Confidence{}, f.err
	}
	return memory.Confidence{Band: f.band}, nil
}

func TestTeamHistory_BandsInverted(t *testing.T) {
	tests := []struct {
		band memory.Band
		want int
	}{
		{memory.BandInsufficient, 0}, // no track record is not evidence of risk (ADR 087: almost nothing accrues one)
		{memory.BandLow, 8},
		{memory.BandMedium, 4},
		{memory.BandHigh, 0}, // reliably handled = no added risk
	}
	for _, tt := range tests {
		f, applied, err := TeamHistory{Provider: fakeConf{band: tt.band}}.Evaluate(context.Background(), finding.Finding{ResourceType: "ec2"})
		require.NoError(t, err)
		require.True(t, applied)
		require.Equal(t, tt.want, f.Points, "band=%s", tt.band)
	}
}

func TestTeamHistory_ProviderErrorDegrades(t *testing.T) {
	_, _, err := TeamHistory{Provider: fakeConf{err: errors.New("pg down")}}.Evaluate(context.Background(), finding.Finding{ResourceType: "ec2"})
	require.Error(t, err)
}
