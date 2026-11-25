package belief

import "github.com/vulngraph/vulngraph/internal/app/enrich"

// Attention gate: deep LLM adjudication is expensive, so it runs only
// where the concrete evidence sources genuinely disagree — NOT on cases the deterministic
// reconciler already resolves. controlled/contained (demoted to Low) and must_fix
// (raised to Critical) are decided facts; the ambiguous set is a HIGH raw signal
// with NO decisive must-fix verdict, where the band-derived severity is a guess
// the LLM should ground or refute.

// highBands are the raw enrich bands worth the cost of adjudication when unresolved.
var highBands = map[string]bool{string(enrich.BandPage): true, string(enrich.BandHigh): true}

// decisiveMustFixClasses are the must-fix classes Reconcile already grounds into a
// severity of its own: must_fix (→ Critical), controlled and contained (→ Low).
// Declared as data because the SQL backlog cursor (repo.go) has to enumerate the
// COMPLEMENT of this set, and the two drifting apart makes the sweep select
// nothing while the Go gate still says "adjudicate" — see
// TestAdjudicationBacklogSQLMirrorsNeedsAdjudication for the guard.
var decisiveMustFixClasses = map[string]bool{
	"must_fix": true, "controlled": true, "contained": true,
}

// NeedsAdjudication reports whether a finding is ambiguous enough to warrant
// the N-sample adversarial adjudicator: a high raw band whose must-fix class
// is not one Reconcile already decides — "" (unenriched), "elevated" (partial
// signal), or "routine" (the classifier found no urgency evidence, which a
// high raw band contradicts).
//
// The default arm is deliberately "adjudicate": an unrecognized class costs
// LLM budget, while the other direction silently drops a whole population out
// of the sweep.
//
// must_fix is deliberately excluded here — not because a poisoned false-high
// couldn't slip through, but because that risk is closed upstream: the enrich
// consistency gate demotes a reach-poisoned must_fix to `routine` before it is
// persisted, so anything still classed must_fix here is genuinely
// reachable+exploitable and its Critical severity is correct. Adjudicating
// those would burn budget on already-grounded verdicts.
func NeedsAdjudication(in SeverityInputs) bool {
	if !highBands[in.Band] {
		return false
	}
	return !decisiveMustFixClasses[in.MustFixClass]
}
