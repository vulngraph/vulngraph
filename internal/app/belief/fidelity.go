package belief

import (
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// GroundingFacts are independent, passive witnesses of a finding's exposure —
// signals of a DIFFERENT lineage than the reachability/must-fix context the
// adjudicator reasoned over (corroboration is first-class). The
// corroboration gate cross-checks a demotion against them: a verdict that demotes
// a finding while an independent witness says it is genuinely publicly exposed is
// not trusted — it is flagged for review, not silently accepted.
type GroundingFacts struct {
	// PublicAccessConfirmed: the resource is confirmed publicly accessible by
	// config (asset public_tier = confirmed) — the strongest witness, and one
	// not included in the adjudicator's context, so it is a true external
	// cross-check.
	PublicAccessConfirmed bool
	// ExposedEdgePresent: a fresh re-query of the resource's own
	// exposed_to_internet edge from the graph, of a different lineage than the
	// cached internet-hops signal the must-fix layer rode on. This is the
	// independent witness that makes a reachability veto trustworthy: a
	// network resource with a live exposed edge really is reachable; an
	// identity never has one.
	ExposedEdgePresent bool
	// ExposureConfirmed: a co-located internet-exposure signal (peer exposure
	// finding) exists — weaker (the adjudicator may already have seen it),
	// used only as a secondary witness.
	ExposureConfirmed bool
	// ReachabilityEvidenced: the deterministic must-fix layer holds positive
	// internet-reachability evidence for this finding, computed from the Ladybug
	// internet-hops BFS. Deliberately not a standalone veto witness: alone it
	// is the same (poisonable) signal the verdict already reasoned over, so
	// vetoing a demotion with it would make the gate defend false-highs. It
	// only strengthens the cited fact when an independent witness
	// (ExposedEdgePresent / PublicAccessConfirmed) also fires.
	ReachabilityEvidenced bool
	// ReachabilityReason is the compact must_fix_reason evidence behind
	// ReachabilityEvidenced (e.g. "assumable from an internet-exposed asset"),
	// cited as the conflict's Fact.
	ReachabilityReason string
	// PublicAccessKnown / ExposedEdgeKnown / ExposurePeersKnown: false (the
	// ZERO VALUE) means the corresponding witness lookup either was never
	// attempted (provider not wired — a legitimate, deliberate no-op) or WAS
	// attempted and failed — either way, the paired Confirmed/Present field
	// must not be trusted as a real negative. That is this field's CONTRACT,
	// not a claim about what "unwired" specifically produces: jobs/adjudicate.go
	// defaults PublicAccessKnown/ExposedEdgeKnown to true for the not-wired
	// case (a deliberate escalation-relevant choice, documented there);
	// ExposurePeersKnown instead passes through respond.ContextPack's own
	// PeersKnown, which already makes the identical "goroutine never ran"
	// case true one layer upstream (respond/service.go's Context). Different
	// mechanisms, same result — this field's contract just describes what
	// false must mean, not which caller enforces true. This follows this codebase's
	// standard known-ness polarity (policy.Input, BlastSummary.Known,
	// Decision.BlastRadiusKnown all have the safe value as the zero value):
	// a witness added without wiring its field fails closed (untrusted),
	// never open. Without these bits a failed lookup would leave
	// PublicAccessConfirmed/ExposedEdgePresent at their zero value, silently
	// agreeing with "not exposed" — the zero-value-as-measurement class the
	// "Degraded input" rule exists to catch, on the one gate built to catch an
	// adjudicator demoting a finding that is actually still exposed.
	PublicAccessKnown  bool
	ExposedEdgeKnown   bool
	ExposurePeersKnown bool
	// BlastKnown is false when the blast-radius walk behind the context the
	// adjudicator read failed: the rendered radius is then "unknown", not 0,
	// and a demotion that may have leaned on a small radius cannot be
	// corroborated as safe. Same polarity as the three bits above.
	BlastKnown bool
}

// corroborationGateSource marks an Evidence clause as authored by this
// deterministic gate, never by an adjudication sample — the LLM's own
// evidence sources are a separate constrained enum, so a shared tag would
// make a persisted belief read as if the model contradicted its own verdict
// in its own audit trail. This gate clause is bolted on afterward, in Go,
// once the verdict has already converged; a distinct source keeps that
// provenance unambiguous.
const corroborationGateSource = "corroboration_gate"

// corroborationConflict reports whether an adjudicated verdict conflicts with
// an independent witness, and if so returns a grounded Evidence clause naming
// the conflict. High-precision / low-recall by design: it fires only on the
// dangerous direction — a demotion (verdict below High) contradicted by a
// witness of a different lineage than the reachability context the verdict
// already reasoned over. Holding high needs no corroboration, and a demotion
// with no independent witness — the common, correct case — is left untouched.
//
// The witnesses are ordered strongest-first and are all independent of the
// cached internet-hops signal:
//   - PublicAccessConfirmed: config-lineage, not in the LLM context.
//   - ExposedEdgePresent: a fresh graph re-query of the resource's own exposed edge.
//   - ExposureConfirmed: a co-located peer internet-exposure signal.
//
// ReachabilityEvidenced is deliberately not a standalone witness here (see its
// own doc comment); when an independent witness above fires alongside it, its
// reason is cited as the fact.
func corroborationConflict(verdict finding.Severity, f GroundingFacts) (bool, Evidence) {
	if !isDemotion(verdict) {
		return false, Evidence{}
	}
	switch {
	case f.PublicAccessConfirmed:
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): this demotion is contradicted by a confirmed public-access signal, independent of the context the verdict reasoned over",
			Source: corroborationGateSource,
			Fact:   "public_access=confirmed",
		}
	case f.ExposedEdgePresent:
		// A fresh, independent re-query: the resource itself has a live
		// exposed_to_internet edge. Cite the reachability reason if present.
		fact := "exposed_to_internet_edge=present"
		if f.ReachabilityEvidenced && f.ReachabilityReason != "" {
			fact = f.ReachabilityReason + "; exposed_to_internet_edge=present"
		}
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): this demotion is contradicted by a live exposed_to_internet edge re-queried directly from the graph — an independent witness of a different lineage than the cached reachability signal",
			Source: corroborationGateSource,
			Fact:   fact,
		}
	case f.ExposureConfirmed:
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): this demotion is contradicted by a co-located internet-exposure signal on this resource",
			Source: corroborationGateSource,
			Fact:   "exposure=internet_facing",
		}
	case !f.ExposurePeersKnown:
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): the peer-exposure witness lookup failed — this demotion cannot be corroborated as safe and is flagged for review rather than read as 'no exposure peer'",
			Source: corroborationGateSource,
			Fact:   "exposure_peers_lookup=failed",
		}
	case !f.PublicAccessKnown:
		// A failed (or never-attempted) lookup is NOT the same as a
		// confirmed "not publicly exposed" — it means the strongest witness
		// could not be checked at all. Flagging for review here is the
		// fail-closed answer; silently falling through to "no conflict"
		// would let an unmeasured witness look identical to a genuinely
		// negative one.
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): the public-access witness lookup failed — this demotion cannot be corroborated as safe and is flagged for review rather than read as 'not publicly exposed'",
			Source: corroborationGateSource,
			Fact:   "public_access_lookup=failed",
		}
	case !f.ExposedEdgeKnown:
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): the exposed-edge witness lookup failed — this demotion cannot be corroborated as safe and is flagged for review rather than read as 'no exposed edge'",
			Source: corroborationGateSource,
			Fact:   "exposed_edge_lookup=failed",
		}
	case !f.BlastKnown:
		return true, Evidence{
			Clause: "CORROBORATION GATE (not part of the adjudicator's own reasoning): the blast-radius walk failed — this demotion cannot be corroborated as safe and is flagged for review rather than read as 'reaches nothing'",
			Source: corroborationGateSource,
			Fact:   "blast_radius_lookup=failed",
		}
	}
	return false, Evidence{}
}

// isDemotion reports whether a verdict lands below High — i.e. the adjudicator is
// asserting the finding is less severe than a high/critical, the only direction a
// wrong verdict silently hides real risk.
func isDemotion(s finding.Severity) bool {
	switch s {
	case finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo:
		return true
	default: // high, critical
		return false
	}
}

// downgradeForConflict rewrites a demoted belief that an independent witness
// contradicts into a low-confidence, human-review belief — corroboration-first:
// this must not silently demote a finding whose demotion its own signals
// dispute. The verdict's evidence is preserved and the cited conflict appended,
// so the belief stays grounded (Validate-clean).
func downgradeForConflict(b Belief, conflict Evidence) Belief {
	b.Confidence = ConfidenceLow
	b.Status = StatusProposed
	b.Claim = "needs review — " + b.Claim + " (conflicts with an independent exposure/reachability witness)"
	b.Evidence = dedupeEvidence(append(b.Evidence, conflict))
	return b
}
