package enrich

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// The reach factor an identity must never carry: a 0-hop "directly reachable from
// the internet" contribution (the exact shape the cache-poisoning bug produced).
func directExposureFactor() Factor {
	return Factor{Source: sourceInternetReach, Points: directExposurePoints, Detail: "directly reachable from the internet (0-hop)"}
}

func TestReconcileConsistency_INV1_IdentityZeroHop(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		factors      []Factor
		mustFixClass string
		mustFixReas  string
		wantFlagged  bool
		wantClass    string // expected must-fix class after the gate
		wantHasReach bool   // whether the reach factor should survive
	}{
		{
			// The canonical bug: an IAM role scored as directly internet-exposed and
			// promoted to must_fix on that (false) reachability evidence. The gate
			// must strip the reach factor and demote the class.
			name:         "iam_role 0-hop must_fix is stripped and demoted",
			resourceType: "iam_role",
			factors: []Factor{
				{Source: "severity", Points: 40},
				directExposureFactor(),
			},
			mustFixClass: MustFix,
			mustFixReas:  "assumable from an internet-exposed asset; blast radius 12",
			wantFlagged:  true,
			wantClass:    MustFixRoutine,
			wantHasReach: false,
		},
		{
			name:         "gcp_service_account 0-hop elevated is stripped and demoted",
			resourceType: "gcp_service_account",
			factors:      []Factor{{Source: "severity", Points: 30}, directExposureFactor()},
			mustFixClass: MustFixElevated,
			mustFixReas:  "assumable from an internet-exposed asset",
			wantFlagged:  true,
			wantClass:    MustFixRoutine,
			wantHasReach: false,
		},
		{
			// A legitimate transitive reach on an identity (assumable from an exposed
			// asset, 2 hops) carries NO 0-hop direct-exposure factor — it must be left
			// completely alone.
			name:         "iam_role transitive reach is untouched",
			resourceType: "iam_role",
			factors: []Factor{
				{Source: "severity", Points: 40},
				{Source: sourceInternetReach, Points: reachPoints(2), Detail: "reachable from the internet via a 2-hop attack path"},
			},
			mustFixClass: MustFixElevated,
			mustFixReas:  "reachable from an internet-exposed asset (2 hops)",
			wantFlagged:  false,
			wantClass:    MustFixElevated,
			wantHasReach: true,
		},
		{
			// A non-identity resource (EC2) legitimately IS directly internet-exposed
			// at 0-hop — the gate must never touch it.
			name:         "ec2_instance 0-hop is legitimate and untouched",
			resourceType: "ec2_instance",
			factors:      []Factor{{Source: "severity", Points: 40}, directExposureFactor()},
			mustFixClass: MustFix,
			mustFixReas:  "internet-exposed; blast radius 20",
			wantFlagged:  false,
			wantClass:    MustFix,
			wantHasReach: true,
		},
		{
			// A KEV-floored must_fix on an identity that ALSO carries a bogus 0-hop
			// factor: strip the factor, but the class was not reach-evidenced
			// (reason is KEV, not "internet-exposed/reachable"), so it stays.
			name:         "identity 0-hop factor stripped but non-reach class preserved",
			resourceType: "iam_role",
			factors:      []Factor{{Source: "kev", Points: 0, Floor: ThresholdPage}, directExposureFactor()},
			mustFixClass: MustFix,
			mustFixReas:  "known-exploited (KEV) with active exploitation",
			wantFlagged:  true,
			wantClass:    MustFix,
			wantHasReach: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := Aggregate(tt.factors)
			res := reconcileConsistency(
				finding.Finding{ResourceType: tt.resourceType},
				score, tt.mustFixClass, tt.mustFixReas,
			)

			require.Equal(t, tt.wantFlagged, res.Flagged(), "flagged")
			require.Equal(t, tt.wantClass, res.MustFixClass, "must-fix class")

			hasReach := false
			for _, f := range res.Score.Factors {
				if f.Source == sourceInternetReach {
					hasReach = true
				}
			}
			require.Equal(t, tt.wantHasReach, hasReach, "reach factor survival")

			// Fail-safe invariant: the gate never RAISES the score.
			require.LessOrEqual(t, res.Score.Value, score.Value, "gate must never inflate the score")
		})
	}
}

// The gate must be a no-op on the overwhelming steady-state case: a finding with
// no identity/reach contradiction passes through byte-for-byte.
func TestReconcileConsistency_NoOpOnCleanFinding(t *testing.T) {
	score := Aggregate([]Factor{{Source: "severity", Points: 55}})
	res := reconcileConsistency(finding.Finding{ResourceType: "s3_bucket"}, score, MustFixContained, "not internet-reachable")
	require.False(t, res.Flagged())
	require.Equal(t, score.Value, res.Score.Value)
	require.Equal(t, MustFixContained, res.MustFixClass)
}

// INV-2: a source said "expected/benign" (Suppress) and the must-fix tier said
// "act on this now". Both cannot be true; the class is what gives way.
func TestReconcileConsistency_INV2_SuppressedMustFix(t *testing.T) {
	tests := []struct {
		name         string
		factors      []Factor
		mustFixClass string
		wantFlagged  bool
		wantClass    string
	}{
		{
			name:         "suppressed must_fix is demoted to routine",
			factors:      []Factor{{Source: "severity", Points: 60}, {Source: "principal_class", Suppress: true}},
			mustFixClass: MustFix,
			wantFlagged:  true,
			wantClass:    MustFixRoutine,
		},
		{
			name:         "suppressed elevated is demoted to routine",
			factors:      []Factor{{Source: "severity", Points: 40}, {Source: "identity_hygiene", Suppress: true}},
			mustFixClass: MustFixElevated,
			wantFlagged:  true,
			wantClass:    MustFixRoutine,
		},
		{
			// KEV declares "this always pages", which Aggregate already lets win over
			// suppression — so the must-fix class is NOT contradicted and must stand.
			name: "page floor outranks the suppression, class stands",
			factors: []Factor{
				{Source: "kev", Floor: ThresholdPage},
				{Source: "principal_class", Suppress: true},
			},
			mustFixClass: MustFix,
			wantFlagged:  false,
			wantClass:    MustFix,
		},
		{
			name:         "suppressed contained is not a contradiction",
			factors:      []Factor{{Source: "severity", Points: 40}, {Source: "principal_class", Suppress: true}},
			mustFixClass: MustFixContained,
			wantFlagged:  false,
			wantClass:    MustFixContained,
		},
		{
			name:         "suppressed blank class is not a contradiction",
			factors:      []Factor{{Source: "severity", Points: 40}, {Source: "principal_class", Suppress: true}},
			mustFixClass: "",
			wantFlagged:  false,
			wantClass:    "",
		},
		{
			name:         "unsuppressed must_fix is untouched",
			factors:      []Factor{{Source: "severity", Points: 70}},
			mustFixClass: MustFix,
			wantFlagged:  false,
			wantClass:    MustFix,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := Aggregate(tt.factors)
			res := reconcileConsistency(finding.Finding{ResourceType: "s3_bucket"}, score, tt.mustFixClass, "because")

			require.Equal(t, tt.wantFlagged, res.Flagged(), "flagged")
			require.Equal(t, tt.wantClass, res.MustFixClass, "must-fix class")
			require.LessOrEqual(t, res.Score.Value, score.Value, "gate must never inflate the score")
		})
	}
}

// TestEnrich_INV3SparesAGuardDutyBackdoorOnAnInternalHost runs the real
// sources end to end: a Backdoor detection on an EC2 the graph proves is not
// internet-reachable is contained, and must still score in the high band.
func TestEnrich_INV3SparesAGuardDutyBackdoorOnAnInternalHost(t *testing.T) {
	seed := asset.Asset{ID: "i-internal", Type: "ec2_instance", LastSeen: time.Now()}
	fw := &fakeFindingWriter{}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{BaseSeverity{}, ThreatFloor{}},
		WithSafetyProvider(fakeSafetyProvider{seed: seed}),
		WithMustFixProviders(fakeReach{hops: reachNone, ok: true}, fakeCounter{count: 1}),
	)
	f := finding.Finding{
		ID: "f-backdoor", Source: "aws_guardduty", Type: "threat", Severity: finding.SeverityHigh,
		CheckID: "Backdoor:EC2/C&CActivity.B", ResourceType: "ec2_instance", ResourceID: "i-internal",
	}

	score, err := svc.Enrich(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, fw.recorded, 1)
	require.Equal(t, MustFixContained, fw.recorded[0].MustFixClass)
	require.Equal(t, BandHigh, score.Band, "the threat floor must survive INV-3")
}

// INV-3: "contained" is the definitive not-internet-reachable statement, so the
// score must not sit in a band whose whole purpose is to page or demand a fix soon.
func TestReconcileConsistency_INV3_ContainedHighBand(t *testing.T) {
	tests := []struct {
		name         string
		factors      []Factor
		mustFixClass string
		wantFlagged  bool
		wantBand     Band
	}{
		{
			name:         "contained in the page band is capped to pipeline",
			factors:      []Factor{{Source: "severity", Points: 90}},
			mustFixClass: MustFixContained,
			wantFlagged:  true,
			wantBand:     BandPipeline,
		},
		{
			name:         "contained in the high band is capped to pipeline",
			factors:      []Factor{{Source: "severity", Points: 65}},
			mustFixClass: MustFixContained,
			wantFlagged:  true,
			wantBand:     BandPipeline,
		},
		{
			name:         "contained already in pipeline is untouched",
			factors:      []Factor{{Source: "severity", Points: 55}},
			mustFixClass: MustFixContained,
			wantFlagged:  false,
			wantBand:     BandPipeline,
		},
		{
			name:         "contained in monitor is untouched",
			factors:      []Factor{{Source: "severity", Points: 10}},
			mustFixClass: MustFixContained,
			wantFlagged:  false,
			wantBand:     BandMonitor,
		},
		{
			// A known-exploited vulnerability on an internal host still pages: KEV's
			// page floor is the strongest assertion in the scorer and the gate must
			// never bury it.
			name:         "KEV page floor keeps a contained finding paging",
			factors:      []Factor{{Source: "kev", Floor: ThresholdPage}},
			mustFixClass: MustFixContained,
			wantFlagged:  false,
			wantBand:     BandPage,
		},
		{
			// A GuardDuty Backdoor detection on an internal EC2: the threat floor
			// lifts it to high, and "not internet-reachable" does not make an
			// active C&C beacon any less of an active compromise.
			name:         "threat floor in the high band keeps a contained finding actionable",
			factors:      []Factor{{Source: "severity", Points: 25}, {Source: sourceThreatFloor, Floor: ThresholdHigh}},
			mustFixClass: MustFixContained,
			wantFlagged:  false,
			wantBand:     BandHigh,
		},
		{
			name:         "signal floor (leaked live secret) keeps a contained finding actionable",
			factors:      []Factor{{Source: sourceSignalFloor, Floor: ThresholdHigh}},
			mustFixClass: MustFixContained,
			wantFlagged:  false,
			wantBand:     BandHigh,
		},
		{
			name:         "a pipeline-level signal floor does not exempt points-driven high band",
			factors:      []Factor{{Source: "severity", Points: 70}, {Source: sourceSignalFloor, Floor: ThresholdPipeline}},
			mustFixClass: MustFixContained,
			wantFlagged:  true,
			wantBand:     BandPipeline,
		},
		{
			name:         "a page-band must_fix is not a contradiction",
			factors:      []Factor{{Source: "severity", Points: 90}},
			mustFixClass: MustFix,
			wantFlagged:  false,
			wantBand:     BandPage,
		},
		{
			name:         "controlled is a different demotion and is untouched",
			factors:      []Factor{{Source: "severity", Points: 90}},
			mustFixClass: MustFixControlled,
			wantFlagged:  false,
			wantBand:     BandPage,
		},
		{
			// Documents WHY INV-3 can never re-cap a malicious-package finding:
			// assessSupplyChainMustFix (mustfix.go) now returns MustFixElevated for
			// any MAL-* finding, never MustFixContained, so this gate — which only
			// acts on MustFixContained — structurally cannot see one. Regression
			// guard against a future change accidentally reintroducing the
			// deploy-exposure gate for this class and letting INV-3 undo the
			// CriticalFloor floor (sources_critical_floor.go) the same way it once
			// would have undone the severity fix for MAL-* findings.
			name:         "malicious package (elevated, floored to page) is never re-capped",
			factors:      []Factor{{Source: sourceCriticalFloor, Floor: ThresholdPage}},
			mustFixClass: MustFixElevated,
			wantFlagged:  false,
			wantBand:     BandPage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := Aggregate(tt.factors)
			res := reconcileConsistency(finding.Finding{ResourceType: "ec2_instance"}, score, tt.mustFixClass, "not internet-reachable")

			require.Equal(t, tt.wantFlagged, res.Flagged(), "flagged")
			require.Equal(t, tt.wantBand, res.Score.Band, "band")
			require.LessOrEqual(t, res.Score.Value, score.Value, "gate must never inflate the score")

			// The breakdown must explain the cap. A signals row whose factors sum
			// higher than the stored score with nothing accounting for the gap is
			// exactly the kind of unexplainable number this platform keeps producing.
			var capFactor bool
			for _, f := range res.Score.Factors {
				if f.Source == sourceConsistencyGate {
					capFactor = true
					require.NotEmpty(t, f.Detail, "the cap factor must say why")
				}
			}
			require.Equalf(t, tt.wantFlagged, capFactor,
				"a capped score must carry the %s factor, and only a capped one", sourceConsistencyGate)
		})
	}
}

// INV-4: "safe to fix" drives the Start-here worklist. Claiming a must-fix
// resource is safe to delete is the one contradiction with real operator risk.
func TestReconcileConsistency_INV4_SafeMustFix(t *testing.T) {
	tests := []struct {
		name         string
		safetyClass  string
		mustFixClass string
		wantFlagged  bool
		wantSafety   string
		wantMustFix  string
	}{
		{
			name:        "safe + must_fix demotes the safety claim, not the finding",
			safetyClass: SafetySafe, mustFixClass: MustFix,
			wantFlagged: true, wantSafety: SafetyCaution, wantMustFix: MustFix,
		},
		{
			name:        "safe + elevated demotes the safety claim",
			safetyClass: SafetySafe, mustFixClass: MustFixElevated,
			wantFlagged: true, wantSafety: SafetyCaution, wantMustFix: MustFixElevated,
		},
		{
			name:        "safe + contained is coherent",
			safetyClass: SafetySafe, mustFixClass: MustFixContained,
			wantFlagged: false, wantSafety: SafetySafe, wantMustFix: MustFixContained,
		},
		{
			name:        "safe + controlled is coherent",
			safetyClass: SafetySafe, mustFixClass: MustFixControlled,
			wantFlagged: false, wantSafety: SafetySafe, wantMustFix: MustFixControlled,
		},
		{
			name:        "safe + unknown class is coherent",
			safetyClass: SafetySafe, mustFixClass: "",
			wantFlagged: false, wantSafety: SafetySafe, wantMustFix: "",
		},
		{
			name:        "risky + must_fix is coherent",
			safetyClass: SafetyRisky, mustFixClass: MustFix,
			wantFlagged: false, wantSafety: SafetyRisky, wantMustFix: MustFix,
		},
		{
			name:        "caution + must_fix is coherent",
			safetyClass: SafetyCaution, mustFixClass: MustFix,
			wantFlagged: false, wantSafety: SafetyCaution, wantMustFix: MustFix,
		},
		{
			name:        "unknown safety + must_fix is coherent",
			safetyClass: "", mustFixClass: MustFix,
			wantFlagged: false, wantSafety: "", wantMustFix: MustFix,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := Aggregate([]Factor{{Source: "severity", Points: 55}})
			f := finding.Finding{ResourceType: "s3_bucket", SafetyClass: tt.safetyClass}

			res := reconcileConsistency(f, score, tt.mustFixClass, "reachable and exploitable")

			require.Equal(t, tt.wantFlagged, res.Flagged(), "flagged")
			require.Equal(t, tt.wantSafety, res.SafetyClass, "safety class")
			require.Equal(t, tt.wantMustFix, res.MustFixClass, "must-fix class must never be demoted by INV-4")
		})
	}
}

// The repairs compose: an identity carrying every contradiction at once must come
// out the far side coherent, and never with a higher score than it went in.
func TestReconcileConsistency_InvariantsCompose(t *testing.T) {
	score := Aggregate([]Factor{
		{Source: "severity", Points: 50},
		directExposureFactor(),
		{Source: "principal_class", Suppress: true},
	})
	f := finding.Finding{ResourceType: "iam_role", SafetyClass: SafetySafe}

	res := reconcileConsistency(f, score, MustFix, "assumable from an internet-exposed asset; blast radius 12")

	// INV-1 strips the 0-hop reach factor and unwinds the reach-evidenced class.
	require.Contains(t, res.Violations, consistencyInvIdentityZeroHop)
	require.Equal(t, MustFixRoutine, res.MustFixClass)
	// With the class down to routine there is no actionable tier left for INV-2/INV-4
	// to contradict.
	require.NotContains(t, res.Violations, consistencyInvSuppressedMustFix)
	require.NotContains(t, res.Violations, consistencyInvSafeMustFix)
	require.Equal(t, SafetySafe, res.SafetyClass)
	require.LessOrEqual(t, res.Score.Value, score.Value)
}

// Every invariant label is a Prometheus label value and a log field: they must be
// unique and stable, or two invariants share a counter series.
func TestConsistencyInvariantLabelsAreDistinct(t *testing.T) {
	labels := []string{
		consistencyInvIdentityZeroHop,
		consistencyInvSuppressedMustFix,
		consistencyInvContainedHighBand,
		consistencyInvSafeMustFix,
	}
	seen := map[string]bool{}
	for _, l := range labels {
		require.NotEmpty(t, l)
		require.False(t, seen[l], "duplicate invariant label %q", l)
		seen[l] = true
	}
}

// The gate demotes; it must never write the RETIRED value. Since MustFixRoutine
// shipped, "" on must_fix_class means exactly one thing — enrichment has not run —
// and that meaning is relied on by the openapi contract, by the frontend badge's
// enrichment_state split, and by obs.descUnclassified, which is now expected to
// read ~0 and is the only proof the change took. A gate that clears the class puts
// enriched rows back into that bucket every sweep, so the
// gauge stops meaning anything and the ambiguity is back for the population the
// class was introduced to name.
//
// Asserted on the source text rather than by behaviour because the risk is a NEW
// invariant added later reaching for the old idiom: a behavioural table only covers
// the invariants someone remembered to add a case for.
func TestConsistencyGateNeverClearsMustFixClass(t *testing.T) {
	src, err := os.ReadFile("consistency.go")
	require.NoError(t, err)
	for i, line := range strings.Split(string(src), "\n") {
		code := line
		if idx := strings.Index(code, "//"); idx >= 0 {
			code = code[:idx]
		}
		require.NotContains(t, code, `MustFixClass = ""`,
			"consistency.go:%d clears must_fix_class; demote to MustFixRoutine instead — \"\" now means only \"never enriched\"", i+1)
	}
}
