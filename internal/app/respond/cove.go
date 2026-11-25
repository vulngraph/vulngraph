package respond

// cove.go — Chain-of-Verification guardrail layer. After the LLM proposes a
// plan and before the policy gate decides, CoVe inspects the plan against
// structural guardrails. Any concern escalates to human review — fail-closed,
// regardless of what the gate would allow.
//
// Implemented here are the guardrails the current graph supports: weighted
// blast radius, blast + high score, destructive-on-public, production +
// destructive + high score, marginal (medium) confidence for destructive
// (isolate/destroy) actions, and an observe floor for urgent findings. Guardrails needing data sources that don't exist yet (denial
// history, identity pedigree, coordinated-attack correlation) are
// deliberately not stubbed, so the layer never claims to enforce a guardrail
// it doesn't.

import (
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
)

// blastScoreThreshold is the weighted blast-radius circuit-breaker limit; at
// or above it, human review is mandatory. Calibrated against
// blastRelWeights below — moving either one without the other changes when
// the breaker trips; TestCoVe_Check0_WeightedBlastCircuitBreaker pins the
// trip point against a concrete edge-count scenario for exactly this reason.
const blastScoreThreshold = 10.0

// blastRelWeights is the lateral-risk magnitude per edge type for this
// circuit breaker — deliberately not graphschema.WeightFor, which is a per-hop
// decay factor for propagating a resource's own risk score, not a magnitude.
// Calibrated with blastScoreThreshold; TestCoVe_Check0_WeightedBlastCircuitBreaker
// pins the trip point, so change both together.
var blastRelWeights = map[string]float64{
	"protected_by":  0.9, // shares a security group
	"can_assume":    0.85,
	"runs_in":       0.7, // shared subnet / network / namespace
	"dns_points_to": 0.7,
	"binds":         0.6,
	"depends_on":    0.5,
}

// coveResult is the outcome of the verification pass.
type coveResult struct {
	escalate bool
	concerns []string
}

// destructive reports whether an action class is irreversible/high-impact.
func destructive(c ActionClass) bool { return c == ClassIsolate || c == ClassDestroy }

// verify runs the CoVe guardrails over a planned action in its graph context.
func verify(plan Plan, f finding.Finding, br asset.BlastRadius, conf memory.Confidence) coveResult {
	var concerns []string

	// Check 0 — circuit breaker: weighted blast radius.
	if score := weightedBlastScore(br); score >= blastScoreThreshold {
		concerns = append(concerns, fmt.Sprintf(
			"weighted blast radius %.1f ≥ %.1f — human review mandatory", score, blastScoreThreshold))
	}

	// Check 2 — wide reach on a high-score finding. Excludes the seed asset
	// itself (reachableAssets) — "reachable assets" means what the
	// action can reach, not the resource it targets.
	if reachable := len(reachableAssets(br.Assets)); reachable >= 5 && f.Score >= 80 {
		concerns = append(concerns, fmt.Sprintf(
			"%d reachable assets with enriched score %d", reachable, f.Score))
	}

	// Check 3 — destructive action on an internet-facing asset.
	if destructive(plan.ActionClass) && seedPublicIP(br) != "" {
		concerns = append(concerns, fmt.Sprintf(
			"%s action on an internet-facing asset (%s)", plan.ActionClass, seedPublicIP(br)))
	}

	// Check 4 — production + destructive + high score. Unknown environment
	// counts as production: only a positive staging/dev classification escapes.
	if env := seedEnvironment(br); env.Env.TreatAsProd() && destructive(plan.ActionClass) && f.Score >= 70 {
		concerns = append(concerns, fmt.Sprintf(
			"destructive action on a %s asset with high enriched score", envConcernLabel(env)))
	}

	// Check 7 — marginal confidence for a destructive action. The gate parks
	// high/medium-confidence proposals for approval and escalates
	// low/insufficient; CoVe additionally refuses to let a medium-confidence
	// destructive action merely park — it must reach a human.
	if destructive(plan.ActionClass) && conf.Band == memory.BandMedium {
		concerns = append(concerns,
			"medium-confidence destructive action — human confirmation required")
	}

	// Check 8 — observe floor. An observe plan sends a finding to no queue and
	// no person, and the class comes from the LLM, reading finding text that
	// is attacker-influenceable: an injection that lands "observe" would
	// quietly drop a finding the evidence calls urgent. So when the score band
	// or the evidence-backed must_fix tier says act, observe-only is a human's
	// call, not the model's.
	if plan.ActionClass == ClassObserve {
		if why := UrgentEvidence(f); why != "" {
			concerns = append(concerns, "observe-only plan for a "+why+" finding — a human must confirm nothing needs doing")
		}
	}

	return coveResult{escalate: len(concerns) > 0, concerns: concerns}
}

// UrgentEvidence names the enrich verdict that makes a finding urgent
// regardless of the plan ("" when none does). An urgent finding always
// reaches a person: CoVe escalates an observe plan for it, a denied pattern
// verdict does not suppress it, and the queue's "disabled" rule does not hide
// it.
func UrgentEvidence(f finding.Finding) string {
	switch {
	case f.MustFixClass == enrich.MustFix:
		return "must_fix"
	case f.ScoreBand == string(enrich.BandPage):
		return "page-band"
	case f.ScoreBand == string(enrich.BandHigh):
		return "high-band"
	}
	return ""
}

// weightedBlastScore sums the per-edge weights of the blast-radius edges,
// approximating a relationship-weighted circuit breaker — see
// blastRelWeights' doc comment for why this is its own table, not
// graphschema.WeightFor.
func weightedBlastScore(br asset.BlastRadius) float64 {
	var score float64
	for _, e := range br.Edges {
		w, ok := blastRelWeights[e.EdgeType]
		if !ok {
			w = 0.2 // unknown relationship still carries some lateral risk
		}
		score += w
	}
	return score
}

// seedPublicIP returns the public IP of the blast-radius seed (the asset the
// finding is about), if it has one. The seed is the first asset (depth 0).
func seedPublicIP(br asset.BlastRadius) string {
	if len(br.Assets) == 0 {
		return ""
	}
	return br.Assets[0].PublicIP
}

// seedEnvironment classifies the blast-radius seed (the asset the finding is
// about). No seed means nothing is known about it: EnvUnknown.
func seedEnvironment(br asset.BlastRadius) asset.EnvClassification {
	if len(br.Assets) == 0 {
		return asset.EnvClassification{Env: asset.EnvUnknown}
	}
	return asset.ClassifyEnvironment(br.Assets[0])
}

// envConcernLabel names the environment in a CoVe concern, so a human can tell
// "tagged production" from "we could not tell, so treated as production".
func envConcernLabel(c asset.EnvClassification) string {
	if c.Env == asset.EnvProd {
		return "production"
	}
	return "unknown-environment (treated as production)"
}

func envTag(a asset.Asset) string {
	return tagOf(a, "environment", "env", "Environment", "Env")
}

// tagOf returns the first non-empty value among the given tag or metadata keys,
// checking tags before metadata for each key. The shared reader for the handful
// of "what does the owner call this" lookups (environment, owner, team).
func tagOf(a asset.Asset, keys ...string) string {
	for _, k := range keys {
		if v := a.Tags[k]; v != "" {
			return v
		}
		if v := a.Metadata[k]; v != "" {
			return v
		}
	}
	return ""
}
