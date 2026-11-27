package forget

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// base is a scope/type that WOULD be forgettable: an audited family, a complete
// non-partial sweep, healthy edges, a confirmed previous enumeration, a
// population well over the floor, a stable enumerated count, and a handful of
// confirmed-absent assets. Every case below is this minus one thing.
func base(now time.Time) Input {
	sc, _ := ParseScope("eu-west-1/ec2:instances")
	return Input{
		Scope:           sc,
		AssetType:       "ec2_instance",
		Enumerated:      1000,
		Population:      Population{Stored: 1000, Absent: 12, Confirmed: 10},
		PrevCompleteAt:  now.Add(-3 * time.Hour),
		HighWater:       1000,
		HighWaterAt:     now.Add(-time.Hour),
		EdgeHealthKnown: true,
		Now:             now,
	}
}

func TestDecide(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		mutate  func(*Input)
		refusal string
		forget  int
	}{
		{name: "audited scope, everything confirmed", mutate: func(*Input) {}, refusal: RefusalNone, forget: 10},
		{
			name:    "unaudited family",
			mutate:  func(in *Input) { in.Scope = Scope{Key: "eu-west-1/ec2:snapshots"}; in.AssetType = "snapshot" },
			refusal: RefusalNotEnforceable,
		},
		{
			name:    "scope key with no family at all",
			mutate:  func(in *Input) { in.Scope = Scope{Key: "some-opaque-scope"} },
			refusal: RefusalNotEnforceable,
		},
		{
			name:    "edge health unknown",
			mutate:  func(in *Input) { in.EdgeHealthKnown = false },
			refusal: RefusalEdgeHealthUnknown,
		},
		{
			name:    "an edge type was truncated",
			mutate:  func(in *Input) { in.TruncatedEdgeTypes = []string{"depends_on"} },
			refusal: RefusalEdgeTruncated,
		},
		{
			name:    "scope has never completed before",
			mutate:  func(in *Input) { in.PrevCompleteAt = time.Time{} },
			refusal: RefusalUnconfirmed,
		},
		{
			name:    "previous completion is inside the confirmation window",
			mutate:  func(in *Input) { in.PrevCompleteAt = now.Add(-ConfirmWindow + time.Minute) },
			refusal: RefusalUnconfirmed,
		},
		{
			name:    "population under the floor",
			mutate:  func(in *Input) { in.Population = Population{Stored: 9, Absent: 5, Confirmed: 5} },
			refusal: RefusalTooSmall,
		},
		{
			name: "enumeration returned half its own high-water",
			mutate: func(in *Input) {
				in.Enumerated = 400
				in.HighWater = 1000
			},
			refusal: RefusalEnumerationShrank,
		},
		{
			name: "enumeration shrank but the high-water has expired",
			mutate: func(in *Input) {
				in.Enumerated = 400
				in.HighWater = 1000
				in.HighWaterAt = now.Add(-HighWaterTTL - time.Minute)
			},
			refusal: RefusalNone,
			forget:  10,
		},
		{
			name: "over a third of the scope",
			mutate: func(in *Input) {
				in.Population = Population{Stored: 300, Absent: 120, Confirmed: 120}
			},
			refusal: RefusalRelativeCap,
		},
		{
			name: "exactly a third is permitted",
			mutate: func(in *Input) {
				in.Population = Population{Stored: 300, Absent: 100, Confirmed: 100}
			},
			refusal: RefusalNone,
			forget:  100,
		},
		{
			name: "over the absolute ceiling even at a small fraction",
			mutate: func(in *Input) {
				in.Enumerated = 100_000
				in.HighWater = 100_000
				in.Population = Population{Stored: 100_000, Absent: 600, Confirmed: 600}
			},
			refusal: RefusalAbsoluteCap,
		},
		{
			name: "nothing absent is not a refusal",
			mutate: func(in *Input) {
				in.Population = Population{Stored: 1000}
			},
			refusal: RefusalNone,
		},
		{
			name: "absent but not yet confirmed",
			mutate: func(in *Input) {
				in.Population = Population{Stored: 1000, Absent: 40, Confirmed: 0}
			},
			refusal: RefusalNone,
		},
		{
			name: "a large backlog: the vast majority of the population absent",
			mutate: func(in *Input) {
				in.Enumerated = 4500
				in.HighWater = 4500
				in.Population = Population{Stored: 150_000, Absent: 145_000, Confirmed: 144_000}
			},
			refusal: RefusalRelativeCap,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base(now)
			tc.mutate(&in)
			v := Decide(in)
			require.Equal(t, tc.refusal, v.Refusal)
			require.Equal(t, tc.forget, v.Forgettable)
			if v.Refusal != RefusalNone {
				require.Zero(t, v.Forgettable, "a refused scope must never forget anything")
			}
		})
	}
}

// TestForgetNeverActsWithoutProvenCompleteness is the guard behind the whole
// mechanism: an unaudited family, a scope key that is not "<region>/<family>",
// and a scope with no prior proven-complete enumeration must all produce ZERO
// forgettable assets, whatever their populations look like.
//
// It is asserted over a deliberately extreme population — the whole scope
// absent — because that is the shape a long-accumulated backlog has, and a
// guard that only holds for small numbers would not prove the mass-deletion
// case this mechanism exists to prevent.
func TestForgetNeverActsWithoutProvenCompleteness(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	everythingGone := Population{Stored: 20_000, Absent: 20_000, Confirmed: 20_000}

	for _, key := range []string{
		"eu-west-1/ec2:snapshots", // declares completeness, deliberately unaudited
		"eu-west-1/s3:buckets",    // declares nothing
		"global/container.pods",   // declares nothing
		"ec2:instances",           // no region component
		"eu-west-1/",              // empty family
		"/ec2:instances",          // empty region
		"eu-west-1/ec2:instance",  // one character off an audited family
		"EU-WEST-1/EC2:INSTANCES", // case is not normalised anywhere
	} {
		sc, ok := ParseScope(key)
		require.False(t, ok, "%s must not parse as an enforceable scope", key)

		in := base(now)
		in.Scope = sc
		in.Population = everythingGone
		in.Enumerated = 0
		v := Decide(in)
		require.Equal(t, RefusalNotEnforceable, v.Refusal, "scope %s", key)
		require.Zero(t, v.Forgettable, "scope %s must forget nothing", key)
	}

	// And an audited family with no proven-complete history behind it.
	in := base(now)
	in.Population = everythingGone
	in.PrevCompleteAt = time.Time{}
	require.Zero(t, Decide(in).Forgettable)
}

// TestEnforceableFamiliesAreDeclaredByACollector pins the allow-list against
// the collectors. A family listed here that no collector declares complete is
// authority over nothing — and, worse, a one-character drift in a family key
// would silently disable enforcement for a scope while the list still claims to
// cover it.
//
// Textual, on the collector source, for the same reason the other structural
// guards in this repo are: the point is to notice an edit someone makes to the
// far side of the seam, which no amount of running the code can do.
func TestEnforceableFamiliesAreDeclaredByACollector(t *testing.T) {
	sources := map[string]string{}
	for _, f := range []string{"../../collect/aws/aws.go", "../../collect/gcp/gcp.go", "../../collect/azure/azure.go", "../../collect/github/github.go", "../../collect/kubernetes/kubernetes.go"} {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		sources[f] = string(b)
	}
	for family := range enforceableFamilies {
		found := false
		for _, src := range sources {
			// AWS builds the key as region+"/"+family, GCP passes it whole.
			if strings.Contains(src, `"`+family+`"`) || strings.Contains(src, `/`+family+`"`) {
				found = true
			}
		}
		require.True(t, found,
			"family %q is allow-listed for deletion but no collector declares it complete — "+
				"either a collector stopped declaring it or the key drifted", family)
	}
}

func TestEnforceableTypes(t *testing.T) {
	require.Equal(t,
		[]string{"azure_vm", "ec2_instance", "elastic_ip", "gce_instance", "github_repo", "k8s_pod", "security_group", "subnet", "vpc"},
		EnforceableTypes(),
		"the audited type set is a deliberate, reviewed list — widening it is a considered decision")
}

func TestParseMode(t *testing.T) {
	for _, in := range []string{"", "shadow", "SHADOW", " shadow "} {
		m, err := ParseMode(in)
		require.NoError(t, err)
		require.Equal(t, ModeShadow, m)
	}
	m, err := ParseMode("enforce")
	require.NoError(t, err)
	require.Equal(t, ModeEnforce, m)

	// A typo must fail loudly AND fall back to the safe mode.
	m, err = ParseMode("enfroce")
	require.ErrorIs(t, err, ErrUnknownMode)
	require.Equal(t, ModeShadow, m)
}

// TestNextConfirmAnchor_StaysStickyUntilItMatures is the guard for a bug found on
// review: the anchor Decide's confirm-window check compares
// against must stay FIXED across many sweeps until it has actually aged
// ConfirmWindow, or the window never elapses at the collector's sync
// cadence (tens of minutes — far under the 2h window). The bug this
// replaces re-derived the anchor as "the previous sweep's own completion time"
// every sweep, which is NEVER more than one sync interval old, so
// RefusalUnconfirmed could never clear.
func TestNextConfirmAnchor_StaysStickyUntilItMatures(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	in := base(now)

	// First completion ever: no anchor yet. Seeds at this sweep — the confirm
	// check for THIS evaluation still correctly refuses (age 0 < ConfirmWindow).
	in.PrevCompleteAt = time.Time{}
	require.Equal(t, now, nextConfirmAnchor(in))

	// Simulate the real sync cadence: repeated sweeps well inside the window
	// must NOT advance the anchor, or it can never mature. Ages chosen to stay
	// strictly under the 2h ConfirmWindow.
	anchor := now.Add(-30 * time.Minute)
	for _, age := range []time.Duration{65 * time.Minute, 100 * time.Minute, 115 * time.Minute} {
		in.PrevCompleteAt = anchor
		in.Now = anchor.Add(age)
		require.Equalf(t, anchor, nextConfirmAnchor(in),
			"the anchor must stay fixed at %s while age (%s) is under ConfirmWindow (%s)",
			anchor, age, ConfirmWindow)
	}

	// Once the anchor has genuinely aged past ConfirmWindow, it rolls forward —
	// starting a fresh window from the sweep that just consumed it.
	in.PrevCompleteAt = anchor
	in.Now = anchor.Add(ConfirmWindow + time.Minute)
	require.Equal(t, in.Now, nextConfirmAnchor(in),
		"a matured anchor must roll forward to start the next window, or a confirmed scope could never be re-evaluated")
}

// TestConfirmWindow_MaturesUnderRealSyncCadence is the end-to-end regression:
// wire nextConfirmAnchor's output back into the NEXT sweep's Input.PrevCompleteAt
// (exactly as service.go does) and confirm that, purely from repeated sweeps at
// a realistic sync cadence, RefusalUnconfirmed eventually clears. Before the fix
// this loop ran forever without ever clearing it.
func TestConfirmWindow_MaturesUnderRealSyncCadence(t *testing.T) {
	start := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	const syncInterval = 30 * time.Minute

	in := base(start)
	in.PrevCompleteAt = time.Time{} // never completed before
	in.Now = start

	var cleared bool
	for sweep := 0; sweep < 12; sweep++ { // 12 * 30m > 2 * ConfirmWindow, generous margin
		v := Decide(in)
		if v.Refusal != RefusalUnconfirmed {
			cleared = true
			break
		}
		in.PrevCompleteAt = v.NextConfirmAnchor
		in.Now = in.Now.Add(syncInterval)
	}
	require.True(t, cleared, "RefusalUnconfirmed must clear within a bounded number of sweeps at a realistic sync cadence")
}

func TestNextHighWaterDecays(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	in := base(now)

	// Rises immediately.
	in.Enumerated, in.HighWater = 1200, 1000
	hw, at := nextHighWater(in)
	require.Equal(t, 1200, hw)
	require.Equal(t, now, at)

	// Holds while fresh.
	in.Enumerated, in.HighWater, in.HighWaterAt = 900, 1000, now.Add(-time.Hour)
	hw, at = nextHighWater(in)
	require.Equal(t, 1000, hw)
	require.Equal(t, now.Add(-time.Hour), at)

	// Retires once stale, so a genuinely shrunken scope stops being refused by
	// its own history.
	in.HighWaterAt = now.Add(-HighWaterTTL - time.Second)
	hw, at = nextHighWater(in)
	require.Equal(t, 900, hw)
	require.Equal(t, now, at)
}

// TestParseEnforceTypes pins the failsafe: an unset or blank value parses to a
// nil map, whose lookups are always false, and any type outside
// TombstoneEligibleTypes is refused rather than kept.
func TestParseEnforceTypes(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    map[string]bool
		wantErr bool
	}{
		{name: "unset", in: "", want: nil},
		{name: "blank", in: "   ", want: nil},
		{name: "all commas and blanks", in: " , , ", want: nil},
		{name: "single type", in: "security_group", want: map[string]bool{"security_group": true}},
		{
			name: "two types, whitespace tolerated",
			in:   "security_group, vpc ",
			want: map[string]bool{"security_group": true, "vpc": true},
		},
		{
			name: "duplicate entries collapse",
			in:   "vpc,vpc,vpc",
			want: map[string]bool{"vpc": true},
		},
		{name: "a typo is refused", in: "security_grup", wantErr: true},
		{name: "an audited type not cleared for enforcement is refused", in: "vpc,ec2_instance", wantErr: true},
		{name: "gce_instance is refused", in: "gce_instance", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEnforceTypes(tt.in)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrNotTombstoneEligible)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// Every tombstone-eligible type is one an audited family enumerates, so the
// allow-list can never name a type the evaluator does not see.
func TestTombstoneEligibleTypesAreAudited(t *testing.T) {
	audited := map[string]bool{}
	for _, at := range EnforceableTypes() {
		audited[at] = true
	}
	for _, at := range TombstoneEligibleTypes() {
		require.True(t, audited[at], "%s is tombstone-eligible but no audited family enumerates it", at)
	}
}
