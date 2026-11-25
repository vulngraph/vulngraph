// Package respond turns a finding into a gated remediation proposal: it reasons
// about the finding (LLM), scores confidence from human verdicts (decaying
// memory), computes blast radius (asset graph), and runs the policy gate
// (internal/policy) to decide whether to park the proposal for a human's approval
// or escalate it. It never executes anything: a remediation runs only after a
// human approves it (ADR 087). Every new or changed decision is audited; an
// identical repeat increments a repeat counter instead.
package respond

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ActionClass is the kind of remediation an action performs — the axis the
// policy gate keys on.
type ActionClass string

const (
	ClassObserve   ActionClass = "observe"
	ClassRemediate ActionClass = "remediate"
	ClassModify    ActionClass = "modify"
	ClassIsolate   ActionClass = "isolate"
	ClassDestroy   ActionClass = "destroy"
)

// Plan is the reasoner's proposed response to a finding.
type Plan struct {
	ActionClass ActionClass
	Summary     string
	Rationale   string
}

// Outcome is what the decision resolved to.
type Outcome string

const (
	// OutcomeObserved is a read-only observe plan: nothing to change, so
	// nothing to approve and nothing executed.
	OutcomeObserved  Outcome = "observed"
	OutcomeParked    Outcome = "parked_for_approval"
	OutcomeEscalated Outcome = "escalated"
	// OutcomeSuppressedByVerdict is terminal: the finding's (check_id,
	// action_class) pattern already carries a governor DENIED verdict (see
	// internal/app/govern.PatternVerdict), so re-escalating the same question
	// for every new finding of the pattern would be pure noise. Excluded from
	// ListPendingReasoning's parked_for_approval/escalated filter, and never
	// notified or fed into memory: the human's ruling is recorded once, in
	// pattern_verdicts, not per finding.
	OutcomeSuppressedByVerdict Outcome = "suppressed_by_verdict"
)

// AwaitingHuman reports whether a decision with this outcome is asking a
// person for a verdict.
func (o Outcome) AwaitingHuman() bool {
	return o == OutcomeParked || o == OutcomeEscalated
}

// Notifiable reports whether a decision is worth sending to the decision
// notifiers. An observe plan normally is not ("nothing to do"), but one a
// guardrail escalated (an urgent finding the model called observe-only) is
// precisely what a person must see, wherever they look.
func (d Decision) Notifiable() bool {
	return d.Plan.ActionClass != ClassObserve || d.Outcome.AwaitingHuman()
}

// DecisionDetails is the part of a decision's audit details other code reads:
// the plan's action class and the outcome.
type DecisionDetails struct {
	ActionClass string  `json:"action_class"`
	Outcome     Outcome `json:"outcome"`
}

// ParseDecisionDetails reads a decision audit row's details JSON.
func ParseDecisionDetails(details string) (DecisionDetails, error) {
	var d DecisionDetails
	if err := json.Unmarshal([]byte(details), &d); err != nil {
		return DecisionDetails{}, fmt.Errorf("ParseDecisionDetails: %w", err)
	}
	return d, nil
}

// Decision is the full record of how a finding was handled.
type Decision struct {
	FindingID       string
	Plan            Plan
	ConfidenceBand  string
	ConfidenceScore float64
	EffectiveN      float64
	SampleCount     int
	BlastRadius     int
	// BlastRadiusKnown pairs with BlastRadius: false means the walk that
	// produced it failed (or nothing walked at all), so BlastRadius is left at
	// its zero value and must be displayed as "unmeasured", never as a
	// measured "0 reachable assets" — the display-layer half of the same
	// known-ness discipline blastRadiusFor applies wherever the radius goes.
	BlastRadiusKnown bool
	// CoVeConcerns are the chain-of-verification guardrail concerns. A
	// non-empty list forced the outcome to escalation regardless of the gate.
	CoVeConcerns []string
	// PlanNotes are informational annotations attached to the plan that do NOT
	// affect the outcome — unlike CoVeConcerns, a non-empty PlanNotes never
	// forces escalation. Used for triage context, e.g. noting that a
	// remediate/modify plan targets a resource type with no wired executor
	// action.
	PlanNotes []string
	// EscalationReason explains WHY a decision escalated or was suppressed.
	// For Outcome == OutcomeEscalated: "policy_blocked" when the gate itself
	// escalated a destroy/isolate action, "verification_concern" when CoVe
	// forced escalation, otherwise "insufficient_confidence". For
	// Outcome == OutcomeSuppressedByVerdict it is always "pattern_denied".
	// Empty for any other outcome.
	EscalationReason string
	// SafetyBand rates how likely applying the plan is to break something —
	// safe|caution|risky (see impact.go). Advisory: surfaced for triage, not (yet)
	// a gate input.
	SafetyBand string
	// FixLocation is where the remediation should be applied (deploying repo, or
	// the cloud console when there is no IaC owner).
	FixLocation FixLocation
	Outcome     Outcome
	DecidedAt   time.Time
	// Fingerprint is the context fingerprint this decision was made under —
	// the same value the reasoning cache stores. A human approval (an email
	// link) binds to it, so the approval lapses if the context changes.
	Fingerprint string
}

// PatternVerdictMaxAge bounds how long a pattern verdict is trusted. A human
// ruling is evidence about the world AS IT WAS at the moment they made it;
// the estate changes underneath it, so the question gets re-asked
// periodically rather than never. A verdict older than this falls through to
// the normal gate path exactly as if none had ever been recorded.
const PatternVerdictMaxAge = 90 * 24 * time.Hour

// AuditEvent is the durable trail entry for a decision (and later, executions).
type AuditEvent struct {
	ID         string
	TS         time.Time
	Actor      string // "agent" for pipeline decisions
	Action     string // e.g. "decision"
	TargetType string
	TargetID   string
	Details    string // JSON
}

var ErrNotFound = errors.New("respond: not found")

// Remediation is how a proposed fix would be carried out, shown to the person
// deciding whether to approve it: the exact change, whether it needs a second
// admin, whether and how it can be undone, and the CLI that does the same by
// hand. respond never imports executor (layering); cmd/graph adapts
// executor.GuideFor into a RemediationGuide.
type Remediation struct {
	Action      string
	Change      string
	Destructive bool
	Reversible  bool
	Rollback    string
	CLI         string
}

// DecisionsSummary aggregates the WHOLE decision trail server-side, so the
// Decisions page banner reflects every decision rather than only the pages
// the client happened to load.
type DecisionsSummary struct {
	Total     int
	Observed  int // read-only observe decisions: nothing to approve
	Escalated int
	Parked    int
	// SuppressedByVerdict tallies OutcomeSuppressedByVerdict decisions — the
	// count a human already answered as a pattern, so the UI can say "N
	// questions a human already answered" instead of leaving them invisible.
	SuppressedByVerdict int
	QuickWins           int // safety_band=safe and action_class!=observe
	UniqueResources     int // distinct resources behind the targeted findings
	ActionClasses       map[string]int
	ConfidenceBands     map[string]int
	// EscalationReasons tallies Decision.EscalationReason over the trail,
	// excluding empty (a row without a reason is not counted as any reason
	// rather than miscounted as one).
	EscalationReasons map[string]int
	Hotspots          []EscalationHotspot
}

// EscalationHotspot is a finding escalated repeatedly (>=3 times) — a signal
// that it needs a direct fix rather than another approval round.
type EscalationHotspot struct {
	TargetID string
	Count    int
	Latest   time.Time
}

// OutcomeNeedsAction and OutcomeSafeToFix are UI-derived filter values for
// ListDecisions' outcome param — not raw Outcome values written to the audit
// trail, but computed groupings over them. They live here, next to the real
// Outcome consts, so the handler's accepted-value set and the repo's
// predicate mapping both read off one definition.
const (
	OutcomeNeedsAction = "needs_action"
	OutcomeSafeToFix   = "safe_to_fix"
)

// ValidOutcomeFilters are every value GET /api/decisions accepts for its
// outcome query param: the real outcomes plus the two derived groupings above.
// An unrecognized value must 400, not silently match zero rows.
var ValidOutcomeFilters = map[string]bool{
	string(OutcomeObserved):            true,
	string(OutcomeParked):              true,
	string(OutcomeEscalated):           true,
	string(OutcomeSuppressedByVerdict): true,
	OutcomeNeedsAction:                 true,
	OutcomeSafeToFix:                   true,
}

// ValidActionClassFilters are every value GET /api/decisions accepts for its
// action_class query param.
var ValidActionClassFilters = map[string]bool{
	string(ClassObserve):   true,
	string(ClassRemediate): true,
	string(ClassModify):    true,
	string(ClassIsolate):   true,
	string(ClassDestroy):   true,
}

// DecisionFilter narrows ListDecisions to a subset of the decision trail.
// Zero value (both fields empty) means unfiltered.
type DecisionFilter struct {
	// Outcome is one of ValidOutcomeFilters' keys, or "" for no filter.
	Outcome string
	// ActionClass is one of ValidActionClassFilters' keys, or "" for no filter.
	ActionClass string
}
