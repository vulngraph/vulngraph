package enrich

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeFindings returns a fixed finding set, ignoring the filter except for the
// ResourceID/Source predicates the sources rely on.
type fakeFindings struct{ all []finding.Finding }

func (f fakeFindings) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, fd := range f.all {
		if flt.ResourceID != "" && fd.ResourceID != flt.ResourceID {
			continue
		}
		if flt.Source != "" && fd.Source != flt.Source {
			continue
		}
		out = append(out, fd)
	}
	return out, nil
}

func (f fakeFindings) CountByCheckID(_ context.Context, source, checkID string) (int, error) {
	seen := map[string]bool{}
	for _, fd := range f.all {
		if fd.Source == source && fd.CheckID == checkID && fd.ResourceID != "" {
			seen[fd.ResourceID] = true
		}
	}
	return len(seen), nil
}

func priv(resource string) finding.Finding {
	return finding.Finding{Type: "ciem_privesc", ResourceID: resource, Source: "cspm", CheckID: "aws-privesc-11"}
}
func expo(resource string) finding.Finding {
	return finding.Finding{Type: "exposure", ResourceID: resource, Source: "cspm", CheckID: "aws-ec2-public-ip"}
}

func TestAttackPaths_CountsPrivescTechniques(t *testing.T) {
	fp := fakeFindings{all: []finding.Finding{
		{Type: "ciem_privesc", ResourceID: "r1", CheckID: "aws-privesc-01"},
		{Type: "ciem_privesc", ResourceID: "r1", CheckID: "aws-privesc-11"},
		{Type: "exposure", ResourceID: "r1"}, // not a privesc — ignored
	}}
	f, applied, err := AttackPaths{Findings: fp}.Evaluate(context.Background(),
		finding.Finding{ResourceID: "r1"})
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 14, f.Points) // 2 techniques → mid band
	require.Equal(t, sourceAttackPaths, f.Source)
}

func TestAttackPaths_NoPrivescNotApplied(t *testing.T) {
	fp := fakeFindings{all: []finding.Finding{{Type: "exposure", ResourceID: "r1"}}}
	_, applied, err := AttackPaths{Findings: fp}.Evaluate(context.Background(),
		finding.Finding{ResourceID: "r1"})
	require.NoError(t, err)
	require.False(t, applied)
}

// TestAttackPaths_ExcludesTheFindingBeingScored pins the self-reinforcement fix:
// the peer list is every finding on the resource, which includes f itself, so a
// lone privesc finding used to award itself the 1-technique tier.
func TestAttackPaths_ExcludesTheFindingBeingScored(t *testing.T) {
	self := finding.Finding{ID: "f1", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-07"}
	fp := fakeFindings{all: []finding.Finding{self}}
	_, applied, err := AttackPaths{Findings: fp}.Evaluate(context.Background(), self)
	require.NoError(t, err)
	require.False(t, applied, "a finding must not count itself as an escalation technique")
}

// TestAttackPaths_DedupesTechniquesNotFindings is the gcp-privesc case: one
// over-permissioned grant trips many checks, and multiple bindings trip the same
// check repeatedly. Counting findings gave every member of that clique the top
// tier; counting distinct CheckIDs reports the techniques that actually exist.
func TestAttackPaths_DedupesTechniquesNotFindings(t *testing.T) {
	all := []finding.Finding{}
	for i := 0; i < 18; i++ {
		all = append(all, finding.Finding{
			ID: fmt.Sprintf("f%d", i), Type: "ciem_privesc",
			ResourceID: "sa:over-permissioned", CheckID: "gcp-privesc-07",
		})
	}
	f, applied, err := AttackPaths{Findings: fakeFindings{all: all}}.Evaluate(
		context.Background(), all[0])
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, attackPathPoints(1), f.Points,
		"18 findings from ONE check are one technique, not the top tier")
	require.Contains(t, f.Detail, "1 other privilege-escalation technique")
}

func TestAttackPaths_DistinctTechniquesStillEscalate(t *testing.T) {
	self := finding.Finding{ID: "f0", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-01"}
	fp := fakeFindings{all: []finding.Finding{
		self,
		{ID: "f1", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-02"},
		{ID: "f2", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-03"},
		{ID: "f3", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-04"},
		{ID: "f4", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-05"},
	}}
	f, applied, err := AttackPaths{Findings: fp}.Evaluate(context.Background(), self)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, 20, f.Points, "four genuinely distinct techniques still top out")
}

func TestAttackPaths_PeerWithoutCheckIDNotCollapsed(t *testing.T) {
	self := finding.Finding{ID: "f0", ResourceID: "r1"}
	fp := fakeFindings{all: []finding.Finding{
		self,
		{ID: "f1", Type: "ciem_privesc", ResourceID: "r1"},
		{ID: "f2", Type: "ciem_privesc", ResourceID: "r1"},
	}}
	f, applied, err := AttackPaths{Findings: fp}.Evaluate(context.Background(), self)
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, attackPathPoints(2), f.Points, "unkeyed peers fail toward counting, not silence")
}

func TestToxicCombo_ExposurePlusPrivescFloorsToPipeline(t *testing.T) {
	fp := fakeFindings{all: []finding.Finding{priv("r1"), expo("r1")}}
	f, applied, err := ToxicCombo{Findings: fp}.Evaluate(context.Background(),
		finding.Finding{ResourceID: "r1"})
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, ThresholdPipeline, f.Floor)
}

func TestToxicCombo_ExposureOnlyNotApplied(t *testing.T) {
	fp := fakeFindings{all: []finding.Finding{expo("r1")}}
	_, applied, err := ToxicCombo{Findings: fp}.Evaluate(context.Background(),
		finding.Finding{ResourceID: "r1"})
	require.NoError(t, err)
	require.False(t, applied, "exposure without a privesc path is not a toxic combo")
}

// TestToxicCombo_NoDoubleCountWithInternetReach is the regression test for the
// verified double-count: ToxicCombo and InternetReach both keyed off the same
// two facts ("has privesc peers" + a hop count), so the reach fact was worth
// ~20 extra points on every gcp-privesc finding with a path. ToxicCombo now
// contributes Floor only when InternetReach is scoring that distance.
func TestToxicCombo_NoDoubleCountWithInternetReach(t *testing.T) {
	ctx := context.Background()
	for _, hops := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("%d hop(s)", hops), func(t *testing.T) {
			self := finding.Finding{
				ID: "f0", Type: "ciem_privesc", ResourceID: "sa:x",
				ResourceType: "gcp_service_account", CheckID: "gcp-privesc-07",
			}
			fp := fakeFindings{all: []finding.Finding{self}}
			reach := fakeReach{hops: hops, ok: true}

			combo, comboApplied, err := ToxicCombo{Findings: fp, Reach: reach}.Evaluate(ctx, self)
			require.NoError(t, err)
			require.True(t, comboApplied, "privesc within 2 hops of the internet is still a toxic combo")
			require.Equal(t, ThresholdPipeline, combo.Floor, "the must-always-be-actioned floor is preserved")
			require.Equal(t, 0, combo.Points, "reach is scored once, by internet_reach")

			ir, irApplied, err := InternetReach{Reach: reach}.Evaluate(ctx, self)
			require.NoError(t, err)
			require.True(t, irApplied, "internet_reach still carries the reach signal")
			require.Positive(t, ir.Points)

			// The union of the two sources contributes exactly one reach award.
			require.Equal(t, ir.Points, combo.Points+ir.Points)
		})
	}
}

func TestToxicCombo_KeepsPointsWhenInternetReachCannotScoreIt(t *testing.T) {
	ctx := context.Background()
	privescSelf := finding.Finding{ID: "f0", Type: "ciem_privesc", ResourceID: "r1", CheckID: "gcp-privesc-07"}
	// Config hygiene on a non-network resource: reachabilityMeaningful is false,
	// so InternetReach never runs and nothing else scores the exposure.
	hygieneSelf := finding.Finding{ID: "f0", Type: "misconfiguration", ResourceID: "r1",
		ResourceType: "s3_bucket", CheckID: "s3-versioning-disabled"}

	cases := []struct {
		name  string
		f     finding.Finding
		reach ReachProvider
		peers []finding.Finding
	}{
		{"no reach provider wired", privescSelf, nil, []finding.Finding{privescSelf, expo("r1")}},
		{"reachability unknown for this resource", privescSelf, fakeReach{ok: false}, []finding.Finding{privescSelf, expo("r1")}},
		{"reachability not a meaningful axis for this finding class", hygieneSelf,
			fakeReach{hops: 1, ok: true}, []finding.Finding{hygieneSelf, priv("r1"), expo("r1")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, applied, err := ToxicCombo{Findings: fakeFindings{all: c.peers}, Reach: c.reach}.Evaluate(ctx, c.f)
			require.NoError(t, err)
			require.True(t, applied)
			require.Equal(t, 20, got.Points, "the combination signal must not be silently dropped")
			require.Equal(t, ThresholdPipeline, got.Floor)

			if c.reach != nil {
				_, irApplied, err := InternetReach{Reach: c.reach}.Evaluate(ctx, c.f)
				require.NoError(t, err)
				require.False(t, irApplied, "precondition: internet_reach contributes nothing here")
			}
		})
	}
}

func TestInternetReachCovers(t *testing.T) {
	privesc := finding.Finding{Type: "ciem_privesc", CheckID: "gcp-privesc-07"}
	cases := []struct {
		name   string
		f      finding.Finding
		hops   int
		hopsOK bool
		want   bool
	}{
		{"0 hop covered (internet_reach or exposure_type scores it)", privesc, 0, true, true},
		{"1 hop covered", privesc, 1, true, true},
		{"3 hops covered", privesc, 3, true, true},
		{"unreachable is a demote, not an award", privesc, reachNone, true, false},
		{"unknown hops not covered", privesc, 0, false, false},
		{"non-reachability-meaningful class not covered",
			finding.Finding{Type: "misconfiguration", ResourceType: "s3_bucket", CheckID: "s3-versioning-disabled"}, 1, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, internetReachCovers(c.f, c.hops, c.hopsOK))
		})
	}
}

func TestCrossClusterPoints_CappedAndGraded(t *testing.T) {
	cases := []struct{ n, want int }{
		{0, 0}, {2, 0}, {3, 2}, {10, 2}, {11, 4}, {50, 4}, {51, 6}, {474, 6}, {10000, 6},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, crossClusterPoints(c.n), "crossClusterPoints(%d)", c.n)
	}
	// The whole point of the cap: a saturating count must not consume more of the
	// score range than the per-finding signals it sits beside.
	require.LessOrEqual(t, crossClusterPoints(1_000_000), 6)
}

func TestCrossCluster_SystemicAboveThreshold(t *testing.T) {
	fp := fakeFindings{all: []finding.Finding{
		{CheckID: "aws-ec2-public-ip", ResourceID: "i-1", Source: "cspm"},
		{CheckID: "aws-ec2-public-ip", ResourceID: "i-2", Source: "cspm"},
		{CheckID: "aws-ec2-public-ip", ResourceID: "i-3", Source: "cspm"},
	}}
	f, applied, err := (&CrossCluster{Findings: fp}).Evaluate(context.Background(),
		finding.Finding{CheckID: "aws-ec2-public-ip", Source: "cspm"})
	require.NoError(t, err)
	require.True(t, applied)
	// Capped tier: 3 resources is the low "systemic" band (was 6 before the
	// cross_cluster cap — see crossClusterPoints).
	require.Equal(t, 2, f.Points)
}

func TestCrossCluster_BelowThresholdNotApplied(t *testing.T) {
	fp := fakeFindings{all: []finding.Finding{
		{CheckID: "x", ResourceID: "i-1", Source: "cspm"},
		{CheckID: "x", ResourceID: "i-2", Source: "cspm"},
	}}
	_, applied, err := (&CrossCluster{Findings: fp}).Evaluate(context.Background(),
		finding.Finding{CheckID: "x", Source: "cspm"})
	require.NoError(t, err)
	require.False(t, applied, "two resources is not yet systemic")
}
