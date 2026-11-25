package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// fakeSyncRecorder implements syncRecorder to check what context recordSync
// actually hands to the write.
type fakeSyncRecorder struct {
	sawExpiredCtx bool
	runErr        error
	cleanNoOp     bool
	partial       bool
}

func (f *fakeSyncRecorder) RecordSync(ctx context.Context, _ string, runErr error, _ time.Time, cleanNoOp, partial bool) error {
	if ctx.Err() != nil {
		f.sawExpiredCtx = true
	}
	f.runErr = runErr
	f.cleanNoOp = cleanNoOp
	f.partial = partial
	return nil
}

// A sync failure caused by a context-deadline error (the dominant real-world
// failure mode — Collect/Ingest/RecordObserved all inherit the job's ctx) must
// still be recorded: handing the same, already-expired ctx to the write would
// silently lose it every time — a connector could run (and fail) repeatedly
// with sync_error staying empty and last_synced_at frozen at creation.
func TestRecordSync_SucceedsEvenWithAnAlreadyExpiredContext(t *testing.T) {
	rec := &fakeSyncRecorder{}

	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-expired.Done() // guarantee it has actually tripped before use

	wantErr := errors.New("Ingest: UpsertAssets: Batch: context deadline exceeded")
	err := recordSync(expired, rec, "conn-1", wantErr, false, false)
	require.NoError(t, err, "recordSync must not itself fail just because the incoming ctx already expired")
	require.False(t, rec.sawExpiredCtx, "the write must run on a fresh context, not the expired one it was handed")
	require.Equal(t, wantErr, rec.runErr)
}

// TestCleanNoOp_AllEightCombinations pins the exact gate that decides whether
// a sync advances or resets the connector's backoff streak (SyncStreak) — the
// one place the adaptive backoff can go wrong silently: an
// over-permissive gate lets a connector back off on unreliable evidence and
// go stale past its intended ceiling; an over-restrictive one just costs a
// few extra syncs, safe but pointless. Table-tests every boolean combination
// rather than trusting the &&/! chain by inspection.
func TestCleanNoOp_AllEightCombinations(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name                                 string
		runErr                               error
		skipped, partial, needBackfill, want bool
	}{
		{"clean match, complete, no backfill — the only true case", nil, true, false, false, true},
		{"hard failure never advances the streak, even if skipped were somehow true", boom, true, false, false, false},
		{"hard failure, not skipped", boom, false, false, false, false},
		{"a real diff (not skipped) never advances it", nil, false, false, false, false},
		{"partial collection makes a fingerprint match untrustworthy", nil, true, true, false, false},
		{"pending check-registry backfill must re-run everything, not skip", nil, true, false, true, false},
		{"partial AND backfill", nil, true, true, true, false},
		{"failure with partial and backfill too — still just false", boom, true, true, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, cleanNoOp(tc.runErr, tc.skipped, tc.partial, tc.needBackfill))
		})
	}
}

// TestFindDeletedAssets is the pin for the scope-aware deletion narrowing
// layered on top of the flat set-difference: an absent
// stored asset is only a deletion CANDIDATE when its stored (region, type)
// was proven fully enumerated by a completed scope THIS sweep
// (collect.Result.CompletedEnumerations, via coveredScopes/isCovered) —
// never on an empty/unknown stored type, never on a region that does not
// match the exact completed scope, and never when nothing at all was proven
// complete.
func TestFindDeletedAssets(t *testing.T) {
	tests := []struct {
		name              string
		stored            map[string]connector.StoredAssetHash
		collected         []asset.Asset
		covered           map[coverageKey]bool
		wantDeleted       []string
		wantConsider      int
		wantUnscopedType  int
		wantUnscopedCover int
	}{
		{
			name: "stored (region,type) IS covered and absent -> deletion candidate",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "ec2_instance", Region: "eu-west-1"},
			},
			collected:    nil,
			covered:      map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true},
			wantDeleted:  []string{"i-1"},
			wantConsider: 1,
		},
		{
			name: "stored type is NOT in any completed scope and absent -> not a candidate",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "gce_instance"},
			},
			collected:         nil,
			covered:           map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true}, // a different type completed
			wantDeleted:       nil,
			wantConsider:      1,
			wantUnscopedCover: 1,
		},
		{
			name: "SAME type, SIBLING region not completed -> not a candidate (the scope-collapse defect this pins)",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "ec2_instance", Region: "eu-west-2"},
			},
			collected: nil,
			// eu-west-1's scope completed for ec2_instance; eu-west-2's did not.
			// A flat type-only covered set would wrongly treat i-1 as covered.
			covered:           map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true},
			wantDeleted:       nil,
			wantConsider:      1,
			wantUnscopedCover: 1,
		},
		{
			name: "region-independent (non-region-scoped) family coverage matches any region",
			stored: map[string]connector.StoredAssetHash{
				"g-1": {Hash: "h1", AssetType: "gce_instance", Region: "europe-west4"},
			},
			collected: nil,
			// wildcard entry: a non-region-scoped family's coverage (compute.instances)
			covered:      map[coverageKey]bool{{region: "", typ: "gce_instance"}: true},
			wantDeleted:  []string{"g-1"},
			wantConsider: 1,
		},
		{
			name: "empty CompletedEnumerations (covered nil) -> nothing is a candidate",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "ec2_instance", Region: "eu-west-1"},
				"i-2": {Hash: "h2", AssetType: "gce_instance"},
			},
			collected:         nil,
			covered:           nil,
			wantDeleted:       nil,
			wantConsider:      2,
			wantUnscopedCover: 2,
		},
		{
			name: "empty/unknown stored type -> never a candidate, even if a pathological covered set has an empty-type entry",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "", Region: "eu-west-1"},
			},
			collected:        nil,
			covered:          map[coverageKey]bool{{region: "eu-west-1", typ: ""}: true, {region: "eu-west-1", typ: "ec2_instance"}: true},
			wantDeleted:      nil,
			wantConsider:     1,
			wantUnscopedType: 1,
		},
		{
			name: "empty/unrecorded stored region under a region-scoped completed type -> never a candidate",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "ec2_instance", Region: ""},
			},
			collected:         nil,
			covered:           map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true},
			wantDeleted:       nil,
			wantConsider:      1,
			wantUnscopedCover: 1,
		},
		{
			name: "present in this sweep's collected set -> not absent, not considered at all",
			stored: map[string]connector.StoredAssetHash{
				"i-1": {Hash: "h1", AssetType: "ec2_instance", Region: "eu-west-1"},
			},
			collected:    []asset.Asset{{ID: "i-1", Type: "ec2_instance", Region: "eu-west-1"}},
			covered:      map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true},
			wantDeleted:  nil,
			wantConsider: 0,
		},
		{
			name:         "no stored hashes at all -> zero-value decision",
			stored:       nil,
			collected:    nil,
			covered:      map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true},
			wantDeleted:  nil,
			wantConsider: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := findDeletedAssets(tc.stored, tc.collected, tc.covered)
			require.ElementsMatch(t, tc.wantDeleted, d.Deleted)
			require.Equal(t, tc.wantConsider, d.Considered, "Considered")
			require.Equal(t, tc.wantUnscopedType, d.UnscopedNoType, "UnscopedNoType")
			require.Equal(t, tc.wantUnscopedCover, d.UnscopedUncovered, "UnscopedUncovered")
			require.Equal(t, 0, d.Refused, "Refused (not exercised by this table)")
		})
	}
}

// TestFindDeletedAssets_AbsoluteCapRefusesEntirely pins the cap's REFUSE, not
// trim, behaviour: a candidate set larger
// than deletionCap must result in NOTHING being acted on this sweep, with
// the full count reported as Refused — never a deterministically-trimmed
// subset. Trimming would still act on up to deletionCap PER SWEEP with no
// cross-sweep bound, and the survivors would be an arbitrary subset with no
// operator-visible "N of M" meaning.
func TestFindDeletedAssets_AbsoluteCapRefusesEntirely(t *testing.T) {
	stored := make(map[string]connector.StoredAssetHash, deletionCap+5)
	for i := 0; i < deletionCap+5; i++ {
		stored[fmt.Sprintf("i-%04d", i)] = connector.StoredAssetHash{
			Hash: "h", AssetType: "ec2_instance", Region: "eu-west-1",
		}
	}
	covered := map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true}

	d := findDeletedAssets(stored, nil, covered)

	require.Empty(t, d.Deleted, "over-cap must refuse ALL candidates, not act on a trimmed subset")
	require.Equal(t, deletionCap+5, d.Refused, "Refused must be the FULL candidate count, both numbers observable")
	require.Equal(t, deletionCap+5, d.Considered)
	require.Equal(t, 0, d.UnscopedNoType)
	require.Equal(t, 0, d.UnscopedUncovered)

	// Under the cap: acts normally, Refused stays 0.
	small := map[string]connector.StoredAssetHash{
		"i-1": {Hash: "h", AssetType: "ec2_instance", Region: "eu-west-1"},
	}
	d2 := findDeletedAssets(small, nil, covered)
	require.Equal(t, []string{"i-1"}, d2.Deleted)
	require.Equal(t, 0, d2.Refused)
}

// TestFindDeletedAssets_PartialDoesNotChangeTheDecision pins that
// findDeletedAssets itself takes no opinion on res.Partial — the
// sweep-completeness gate stays entirely in Work, as the outer guard. It
// asserts something concrete about the boundary: Work must be the one
// deciding whether to call DeleteAssetHashes/resolveFindingsForDeletedAssets
// at all, which this test pins by confirming findDeletedAssets returns a
// non-empty, ready-to-act decision even though a caller gating on Partial
// would never act on it — i.e. the refusal is a caller-side branch, not
// something findDeletedAssets can be asked to apply itself (it has no
// Partial parameter to pass).
func TestFindDeletedAssets_PartialDoesNotChangeTheDecision(t *testing.T) {
	stored := map[string]connector.StoredAssetHash{
		"i-1": {Hash: "h1", AssetType: "ec2_instance", Region: "eu-west-1"},
	}
	covered := map[coverageKey]bool{{region: "eu-west-1", typ: "ec2_instance"}: true}

	d := findDeletedAssets(stored, nil, covered)
	require.Equal(t, []string{"i-1"}, d.Deleted,
		"findDeletedAssets has no Partial parameter — it always returns its scope-aware decision; "+
			"Work's own `if !res.Partial { ... }` around DeleteAssetHashes/resolveFindingsForDeletedAssets "+
			"is the only place Partial is allowed to suppress action")
}

// TestCoveredScopes pins coveredScopes' safety properties: no
// CompletedEnumerations means no covered scopes, an unaudited/malformed
// scope key contributes nothing, and two scopes of the SAME type in DIFFERENT
// regions produce two DISTINCT coverage entries, not one collapsed type-only
// entry.
func TestCoveredScopes(t *testing.T) {
	require.Nil(t, coveredScopes(nil))
	require.Nil(t, coveredScopes([]collect.ScopeEnumeration{}))

	// Same type (ec2_instance), two different regions: this is exactly the
	// case a flat type-only set collapses, and why coveredScopes keys on
	// scope+type instead. Both must be present as SEPARATE keys.
	got := coveredScopes([]collect.ScopeEnumeration{
		{Scope: "eu-west-1/ec2:instances", Types: []string{"ec2_instance"}, Count: 3},
		{Scope: "eu-west-2/ec2:instances", Types: []string{"ec2_instance"}, Count: 7},
		{Scope: "global/unaudited-family", Types: []string{"whatever"}, Count: 99}, // ParseScope rejects -> no entry
	})
	require.Equal(t, map[coverageKey]bool{
		{region: "eu-west-1", typ: "ec2_instance"}: true,
		{region: "eu-west-2", typ: "ec2_instance"}: true,
	}, got)

	// isCovered must tell the two regions apart: eu-west-1 covered, eu-west-2
	// NOT covered by a scope that only completed for eu-west-1.
	oneRegion := coveredScopes([]collect.ScopeEnumeration{
		{Scope: "eu-west-1/ec2:instances", Types: []string{"ec2_instance"}, Count: 3},
	})
	require.True(t, isCovered(oneRegion, "eu-west-1", "ec2_instance"))
	require.False(t, isCovered(oneRegion, "eu-west-2", "ec2_instance"),
		"a sibling region's un-completed scope must NOT be covered by another region's completion")
	require.False(t, isCovered(oneRegion, "", "ec2_instance"),
		"an unrecorded/empty stored region must not match a region-scoped family's coverage")

	// Non-region-scoped family (compute.instances, RegionScoped: false):
	// coverage is region-independent, so ANY region (or none) matches.
	wildcard := coveredScopes([]collect.ScopeEnumeration{
		{Scope: "global/compute.instances", Types: []string{"gce_instance"}, Count: 5},
	})
	require.True(t, isCovered(wildcard, "europe-west4", "gce_instance"))
	require.True(t, isCovered(wildcard, "", "gce_instance"))
}
