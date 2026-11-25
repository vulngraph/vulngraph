package belief

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestReconcile(t *testing.T) {
	now := time.Unix(0, 0)

	// The incoherent case: score 92 (page) but must-fix says controlled → true Low.
	controlled := Reconcile(SeverityInputs{
		FindingID: "f1", ResourceID: "role/admin", Score: 92, Band: "page",
		MustFixClass: "controlled", MustFixReason: "assumption gated by IdP federation",
		TrustEntry: "federated",
	}, now)
	require.NoError(t, controlled.Validate())
	require.Equal(t, finding.SeverityLow, controlled.Severity)
	require.Equal(t, StatusConfirmed, controlled.Status)
	require.Equal(t, "deterministic", controlled.Provenance)
	srcs := map[string]bool{}
	for _, e := range controlled.Evidence {
		srcs[e.Source] = true
	}
	require.True(t, srcs["enrich_score"], "cites the raw score")
	require.True(t, srcs["must_fix"], "cites the must-fix control")
	require.True(t, srcs["trust_entry"], "cites the inbound assumability")

	mustFix := Reconcile(SeverityInputs{
		FindingID: "f2", ResourceID: "x", Score: 61, Band: "high",
		MustFixClass: "must_fix", MustFixReason: "internet-exposed · active privilege-escalation path · blast radius 12",
	}, now)
	require.Equal(t, finding.SeverityCritical, mustFix.Severity)
	var mustFixClause string
	for _, e := range mustFix.Evidence {
		if e.Source == "must_fix" {
			mustFixClause = e.Clause
		}
	}
	require.Equal(t, "internet-exposed · active privilege-escalation path · blast radius 12", mustFixClause,
		"must_fix's evidence clause must cite the finding's own must-fix reason verbatim")
	require.NotContains(t, mustFixClause, "reachable=",
		"must never render the old synthesized reachable=%t hops=%d clause — its inputs were never populated")

	// A must_fix classification with no reason string must still produce a
	// clause, not a blank/fabricated one.
	mustFixNoReason := Reconcile(SeverityInputs{
		FindingID: "f2b", ResourceID: "x", Score: 61, Band: "high", MustFixClass: "must_fix",
	}, now)
	for _, e := range mustFixNoReason.Evidence {
		if e.Source == "must_fix" {
			require.Equal(t, "must-fix evidence recorded without a reason string", e.Clause)
		}
	}

	contained := Reconcile(SeverityInputs{
		FindingID: "f3", ResourceID: "y", Score: 80, Band: "page", MustFixClass: "contained",
	}, now)
	require.Equal(t, finding.SeverityLow, contained.Severity)

	// elevated is the ONLY class that can carry the "blast radius unmeasured"
	// fragment (must_fix itself requires blastKnown — mustfix.go's promotion
	// condition) — its evidence must cite the real reason string, not a
	// static generic clause that would discard that disclosure.
	elevated := Reconcile(SeverityInputs{
		FindingID: "f5", ResourceID: "w", Score: 65, Band: "high",
		MustFixClass: "elevated", MustFixReason: "assumable from an internet-exposed asset · blast radius unmeasured",
	}, now)
	var elevatedClause string
	for _, e := range elevated.Evidence {
		if e.Source == "must_fix" {
			elevatedClause = e.Clause
		}
	}
	require.Equal(t, "assumable from an internet-exposed asset · blast radius unmeasured", elevatedClause,
		"elevated's evidence clause must cite the finding's own must-fix reason, including the blast-unmeasured disclosure")

	// No must-fix signal → band-derived, still grounded on the score.
	plain := Reconcile(SeverityInputs{FindingID: "f4", ResourceID: "z", Score: 55, Band: "pipeline"}, now)
	require.Equal(t, finding.SeverityMedium, plain.Severity)
	require.NoError(t, plain.Validate())
}

// TestReconcile_MustFixFactIsInstanceSpecific is the instance-specific-Fact
// fix: reconcile.go's must_fix/controlled branches used to
// emit the coarse class label ("must_fix"/"controlled") as Evidence.Fact —
// which violates dedupeEvidence's contract that Fact IS the observed value,
// not a category (see its doc comment). Two genuinely different findings'
// must_fix evidence, both citing the coarse "must_fix" Fact, would have
// silently DROPPED one of them if ever combined through dedupeEvidence
// (which drops on a key collision, not merges). Fact must now be the
// instance-specific reason string, so two different findings' evidence
// survives being combined.
func TestReconcile_MustFixFactIsInstanceSpecific(t *testing.T) {
	now := time.Unix(0, 0)
	a := Reconcile(SeverityInputs{
		FindingID: "f1", ResourceID: "x", Score: 61, Band: "high",
		MustFixClass: "must_fix", MustFixReason: "internet-exposed · blast radius 12",
	}, now)
	b := Reconcile(SeverityInputs{
		FindingID: "f2", ResourceID: "y", Score: 88, Band: "page",
		MustFixClass: "must_fix", MustFixReason: "assumable from an internet-exposed asset (2 hops) · blast radius 40",
	}, now)

	var factA, factB string
	for _, e := range a.Evidence {
		if e.Source == "must_fix" {
			factA = e.Fact
		}
	}
	for _, e := range b.Evidence {
		if e.Source == "must_fix" {
			factB = e.Fact
		}
	}
	require.NotEqual(t, factA, factB, "two different findings' must_fix reasons must not share a coarse Fact")

	// Simulate what would happen if the two beliefs' evidence were ever
	// combined (e.g. a shared corroboration pass): both must survive.
	combined := dedupeEvidence(append(append([]Evidence{}, a.Evidence...), b.Evidence...))
	require.Len(t, combined, 4, "enrich_score + must_fix from EACH finding — nothing dropped")
}

// TestReconcile_PageFloorNeverGroundsBelowCritical pins the "confirmed Low KEV"
// hole: whatever must-fix demotion arrives, a page-floored finding (KEV, active
// compromise) is never grounded below the page band's severity.
func TestReconcile_PageFloorNeverGroundsBelowCritical(t *testing.T) {
	now := time.Unix(0, 0)
	for _, class := range []string{"contained", "controlled", "routine", "elevated", "must_fix", ""} {
		b := Reconcile(SeverityInputs{
			FindingID: "f-kev", ResourceID: "i-internal", Score: 85, Band: "page",
			MustFixClass: class, MustFixReason: "no internet-reachable attack path", PageFloor: true,
		}, now)
		require.NoError(t, b.Validate())
		require.Equalf(t, finding.SeverityCritical, b.Severity, "class %q", class)
	}

	contained := Reconcile(SeverityInputs{
		FindingID: "f-plain", ResourceID: "i-internal", Score: 85, Band: "page", MustFixClass: "contained",
	}, now)
	require.Equal(t, finding.SeverityLow, contained.Severity, "without a page floor contained still demotes")
}

// TestReconcile_HighFloorNeverGroundsBelowHigh: a GuardDuty Backdoor/C&C
// detection on an internal EC2 (reach-independent floor at the high band) was
// grounded as a confirmed Low because its host was "contained". The floor says
// "urgent regardless of the internet path", so contained/controlled cannot
// ground it below High — and it never lowers anything already higher.
func TestReconcile_HighFloorNeverGroundsBelowHigh(t *testing.T) {
	now := time.Unix(0, 0)
	for _, class := range []string{"contained", "controlled"} {
		b := Reconcile(SeverityInputs{
			FindingID: "f-cc", ResourceID: "i-internal", Score: 70, Band: "high",
			MustFixClass: class, MustFixReason: "no internet-reachable attack path", HighFloor: true,
		}, now)
		require.NoError(t, b.Validate())
		require.Equalf(t, finding.SeverityHigh, b.Severity, "class %q", class)
	}
	mf := Reconcile(SeverityInputs{FindingID: "f", ResourceID: "r", Score: 90, Band: "page", MustFixClass: "must_fix", HighFloor: true}, now)
	require.Equal(t, finding.SeverityCritical, mf.Severity)
}
