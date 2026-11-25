package forget

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── fakes for TestEvaluate_EnforceScoping ────────────────────────────────────

// fakePopulationReader serves a fixed population read and records every
// ScopeCandidateIDs call it receives, keyed by asset type — the test's proof
// that a non-scoped type's ids are never even fetched, not merely that they
// are fetched and discarded.
type fakePopulationReader struct {
	staleness      []StoredCount
	candidates     map[string][]Candidate
	candidateCalls map[string]int
}

func (f *fakePopulationReader) ScopeStaleness(context.Context, string, []string, time.Time, time.Time) ([]StoredCount, error) {
	return f.staleness, nil
}

func (f *fakePopulationReader) ScopeCandidateIDs(_ context.Context, _, assetType, _ string, _ time.Time, _ int) ([]Candidate, error) {
	if f.candidateCalls == nil {
		f.candidateCalls = map[string]int{}
	}
	f.candidateCalls[assetType]++
	return f.candidates[assetType], nil
}

// fakeStore records every tombstone actually written, keyed by asset type,
// which is the behaviour under test — not just what Decide() permitted.
type fakeStore struct {
	states           map[ScopeKey]ScopeState
	tombstonesByType map[string]int
}

func (f *fakeStore) ScopeStates(context.Context, string) (map[ScopeKey]ScopeState, error) {
	return f.states, nil
}

func (f *fakeStore) SaveRecords(context.Context, string, []Record) error { return nil }

func (f *fakeStore) SaveTombstones(_ context.Context, _ string, ts []Tombstone) (int, error) {
	if f.tombstonesByType == nil {
		f.tombstonesByType = map[string]int{}
	}
	for _, t := range ts {
		f.tombstonesByType[t.AssetType]++
	}
	return len(ts), nil
}

type fakeEdgeHealth struct{}

func (fakeEdgeHealth) EdgeSyncHealth() (bool, []string) { return true, nil }

// verdictCall is one recorded ObserveForgetVerdict invocation.
type verdictCall struct {
	scope, assetType, refusal string
	confirmed, forgettable    int
	enforceScoped             bool
}

type fakeMetrics struct{ verdicts []verdictCall }

func (f *fakeMetrics) ObserveForgetVerdict(_, scope, assetType, refusal string, confirmed, forgettable int, enforceScoped bool) {
	f.verdicts = append(f.verdicts, verdictCall{scope, assetType, refusal, confirmed, forgettable, enforceScoped})
}

func (f *fakeMetrics) ObserveForgetTombstones(string, int) {}

// TestEvaluate_EnforceScoping is the amendment's central
// guarantee: FORGET_ENFORCE_TYPES decides which forgettable type actually gets
// a tombstone WRITTEN, independent of everything Decide() itself computed —
// and has no effect at all outside ModeEnforce.
//
// Both scopes in every case below are individually forgettable (Decide()
// returns Forgettable: 5, RefusalNone for each) — the only thing that varies
// is mode and the allow-list, so a passing case proves the gate under test,
// not a refusal upstream of it doing the work by accident.
func TestEvaluate_EnforceScoping(t *testing.T) {
	sweepAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	prevComplete := sweepAt.Add(-3 * time.Hour) // older than ConfirmWindow (2h)

	sgScope := "us-east-1/ec2:security-groups"
	vpcScope := "us-east-1/ec2:vpcs"

	newFixtures := func() (*fakePopulationReader, *fakeStore) {
		pop := &fakePopulationReader{
			staleness: []StoredCount{
				{Region: "us-east-1", Type: "security_group", Stored: 20, Absent: 5, Confirmed: 5},
				{Region: "us-east-1", Type: "vpc", Stored: 20, Absent: 5, Confirmed: 5},
			},
			candidates: map[string][]Candidate{
				"security_group": {{ID: "sg-1", LastSeen: sweepAt.Add(-3 * time.Hour)}},
				"vpc":            {{ID: "vpc-1", LastSeen: sweepAt.Add(-3 * time.Hour)}},
			},
		}
		store := &fakeStore{states: map[ScopeKey]ScopeState{
			{Scope: sgScope, AssetType: "security_group"}: {LastCompleteAt: prevComplete, PrevCompleteAt: prevComplete},
			{Scope: vpcScope, AssetType: "vpc"}:           {LastCompleteAt: prevComplete, PrevCompleteAt: prevComplete},
		}}
		return pop, store
	}

	sweep := Sweep{
		ConnectorID: "conn-1",
		At:          sweepAt,
		Scope: []ScopeEnumeration{
			{Scope: sgScope, Types: []string{"security_group"}, Count: 20},
			{Scope: vpcScope, Types: []string{"vpc"}, Count: 20},
		},
	}

	tests := []struct {
		name             string
		mode             Mode
		enforceTypes     map[string]bool
		wantTombstoned   map[string]int // asset_type -> tombstones written
		wantCandidateHit map[string]int // asset_type -> ScopeCandidateIDs calls
		wantEnforceScope map[string]bool
	}{
		{
			name:             "enforce mode, security_group scoped in, vpc not: only security_group is tombstoned",
			mode:             ModeEnforce,
			enforceTypes:     map[string]bool{"security_group": true},
			wantTombstoned:   map[string]int{"security_group": 1},
			wantCandidateHit: map[string]int{"security_group": 1},
			wantEnforceScope: map[string]bool{"security_group": true, "vpc": false},
		},
		{
			name:             "enforce mode, FORGET_ENFORCE_TYPES unset: fails closed, nothing tombstoned",
			mode:             ModeEnforce,
			enforceTypes:     nil,
			wantTombstoned:   map[string]int{},
			wantCandidateHit: map[string]int{},
			wantEnforceScope: map[string]bool{"security_group": false, "vpc": false},
		},
		{
			name:             "shadow mode: allow-list is purely additive, nothing tombstoned even though both types are listed",
			mode:             ModeShadow,
			enforceTypes:     map[string]bool{"security_group": true, "vpc": true},
			wantTombstoned:   map[string]int{},
			wantCandidateHit: map[string]int{},
			wantEnforceScope: map[string]bool{"security_group": false, "vpc": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pop, store := newFixtures()
			m := &fakeMetrics{}
			svc := NewService(tt.mode, tt.enforceTypes, pop, store, fakeEdgeHealth{}, m)

			total, err := svc.Evaluate(context.Background(), sweep)
			require.NoError(t, err)
			// The forgettable total is what Decide() permits, unconditionally —
			// it must read the same in every case here, proving the scoping only
			// gates the WRITE, never the decision or its visibility.
			require.Equal(t, 10, total, "forgettable total must not depend on mode or the allow-list")

			for _, typ := range []string{"security_group", "vpc"} {
				require.Equalf(t, tt.wantTombstoned[typ], store.tombstonesByType[typ],
					"tombstones written for %s", typ)
				require.Equalf(t, tt.wantCandidateHit[typ], pop.candidateCalls[typ],
					"ScopeCandidateIDs calls for %s — a non-scoped type's ids must never even be fetched", typ)
			}

			byType := map[string]verdictCall{}
			for _, v := range m.verdicts {
				byType[v.assetType] = v
			}
			require.Len(t, m.verdicts, 2, "both scopes must still be evaluated and published for visibility")
			for typ, wantScoped := range tt.wantEnforceScope {
				v, ok := byType[typ]
				require.Truef(t, ok, "no verdict published for %s", typ)
				require.Equal(t, RefusalNone, v.refusal, "fixture is designed to be unrefused")
				require.Equal(t, 5, v.forgettable,
					"would_forget must stay 5 regardless of enforce scoping — it is not gated by the allow-list")
				require.Equal(t, wantScoped, v.enforceScoped,
					"enforceScoped (would_enforce) must distinguish %s's allow-list membership", typ)
			}
		})
	}
}

// TestIndexCounts_EmptyRegionDoesNotDoubleCount is the guard for a bug found on
// review: a genuinely region-less StoredCount row (Region == "", exactly the
// shape GCP's aggregatedList produces — compute.instances rows carry an empty
// region) used to share its
// per-region key with the cross-region accumulator's key, because both were
// folded into one map under the convention "empty region = the totals bucket".
// Writing the per-region entry then overwrote the accumulator, and the
// read-then-add that followed doubled that row's own contribution into the
// total. Two separate maps (perRegion, allRegions) make the collision
// structurally impossible rather than avoided by convention.
func TestIndexCounts_EmptyRegionDoesNotDoubleCount(t *testing.T) {
	// A single region-less row — the GCP compute.instances shape.
	idx := indexCounts([]StoredCount{
		{Region: "", Type: "gce_instance", Stored: 40000, Absent: 1200, Confirmed: 900},
	})

	sc, ok := ParseScope("global/compute.instances")
	require.True(t, ok)
	pop := idx.lookup(sc, "gce_instance")

	require.Equal(t, 40000, pop.Stored, "a single region-less row must not be counted twice")
	require.Equal(t, 1200, pop.Absent)
	require.Equal(t, 900, pop.Confirmed)
}

// TestIndexCounts_RegionScopedAndRegionLessDoNotCollide covers the mixed case: a
// region-scoped family's per-region rows must accumulate into allRegions exactly
// once each, independently of whatever region-less rows for OTHER types are also
// present in the same sweep.
func TestIndexCounts_RegionScopedAndRegionLessDoNotCollide(t *testing.T) {
	idx := indexCounts([]StoredCount{
		{Region: "eu-west-1", Type: "ec2_instance", Stored: 100, Absent: 5, Confirmed: 3},
		{Region: "us-east-1", Type: "ec2_instance", Stored: 200, Absent: 10, Confirmed: 6},
		{Region: "", Type: "gce_instance", Stored: 500, Absent: 20, Confirmed: 15},
	})

	ec2, ok := ParseScope("eu-west-1/ec2:instances")
	require.True(t, ok)
	require.Equal(t, Population{Stored: 100, Absent: 5, Confirmed: 3}, idx.lookup(ec2, "ec2_instance"),
		"a region-scoped lookup must read its own region only")

	gce, ok := ParseScope("global/compute.instances")
	require.True(t, ok)
	require.Equal(t, Population{Stored: 500, Absent: 20, Confirmed: 15}, idx.lookup(gce, "gce_instance"),
		"the region-less family's total must be exactly its one row, unaffected by the region-scoped rows")
}

// A type outside TombstoneEligibleTypes is never enforced, even when a caller
// builds the Service with it on the list directly.
func TestEnforceScoped_RefusesTypesNotTombstoneEligible(t *testing.T) {
	svc := NewService(ModeEnforce, map[string]bool{"ec2_instance": true, "gce_instance": true, "vpc": true}, nil, nil, nil, nil)
	require.False(t, svc.enforceScoped("ec2_instance"))
	require.False(t, svc.enforceScoped("gce_instance"))
	require.True(t, svc.enforceScoped("vpc"))
}
