// Package findingctx assembles the full per-finding detail: the connected-graph
// context (finding + blast radius + peers + exposure + provenance, reused from
// respond) plus the reasoning decision and the score-factor breakdown. It is a
// read-only composition over other domains' services (no repo of its own —
// precedent: compliance), and is the single source for both the finding-detail
// UI and the MCP get_finding_context tool.
package findingctx

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
)

// FindingContext is the assembled detail for one finding. It embeds respond's
// ContextPack (Finding, Blast, Peers, Exposure, Provenance) and layers the
// reasoning decision and the per-source score factors on top.
type FindingContext struct {
	respond.ContextPack
	Reasoning *Reasoning      // nil when the finding has not been reasoned yet
	Factors   []enrich.Factor // per-source score breakdown — the "why" behind the score
	// Narrative is a deterministic plain-English risk story built from the graph
	// signals (exposure, blast, identity, supply-chain) — the readable "why this
	// matters (or doesn't)" rendered above the reasoning trace and returned by the
	// MCP get_finding_context tool. See narrative.go.
	Narrative string
	// Suppression is the finding's suppression standing; SuppressionKnown is
	// false when it could not be read (or no reader is wired), in which case
	// Suppression is the zero value and must not be read as "not suppressed".
	Suppression      suppress.State
	SuppressionKnown bool
}

// Reasoning is the cached 7-step layered decision for a finding:
// the plan (reason), the confidence from decaying memory, the blast radius, the
// CoVe guardrail concerns, and the resolved outcome — the full
// reason -> confidence -> gate -> verify trace, surfaced for the detail view.
type Reasoning struct {
	ActionClass string
	Summary     string
	Rationale   string
	Outcome     string
	// Confidence (step 4 — decaying memory).
	ConfidenceBand  string
	ConfidenceScore float64
	EffectiveN      float64
	SampleCount     int
	// BlastRadius is the action's reach (step 1).
	BlastRadius int
	// BlastRadiusKnown pairs with BlastRadius: false means the decision's
	// walk failed and BlastRadius is left at its zero value — render
	// "unmeasured", never a measured "0 reachable assets".
	BlastRadiusKnown bool
	// CoVeConcerns are the chain-of-verification guardrail concerns (step 6).
	CoVeConcerns []string
	// SafetyBand rates how likely applying the plan is to break something —
	// safe|caution|risky (respond/impact.go). Empty when not yet reasoned.
	SafetyBand string
	DecidedAt  time.Time
}
