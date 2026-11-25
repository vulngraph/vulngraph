// Package reasoncache stores, per finding, the context fingerprint and plan from
// the last LLM reasoning pass. respond.Decide reuses the cached plan
// and skips the LLM when the fingerprint is unchanged, so the periodic enrich
// sweep stops re-reasoning identical findings every cycle. The plan is held as
// primitive fields (not respond.Plan) so the dependency stays one-way:
// respond -> reasoncache.
//
// Fingerprint carries a LogicVersion prefix (fingerprint.go) so a change to
// respond's reasoning semantics can force recomputation instead of serving a
// stale plan forever — see that constant's doc comment for the version
// scheme, and Service.InvalidateAll for the purge path a version bump needs
// to actually reach every finding, not just the ones a later Decide happens
// to re-enqueue.
package reasoncache

import (
	"errors"
	"time"
)

// Entry is one finding's last decision snapshot keyed by its context fingerprint.
// It holds the whole 7-step layered trace respond.Decide produced — the plan plus the
// confidence (decaying memory), blast radius, and CoVe concerns — so the
// finding-detail view can render the full reason -> confidence -> gate -> verify
// pipeline from one read.
type Entry struct {
	FindingID   string
	Fingerprint string
	ActionClass string
	Summary     string
	Rationale   string
	Outcome     string
	// Confidence trace (step 4 — decaying memory).
	ConfidenceBand  string
	ConfidenceScore float64 // decayed weighted success rate, 0..1
	EffectiveN      float64 // decay-weighted evidence amount
	SampleCount     int     // raw outcomes considered
	// BlastRadius is the action's reach (step 1).
	BlastRadius int
	// BlastRadiusKnown pairs with BlastRadius: false means the walk that
	// produced it failed, so BlastRadius is left at its zero value and must
	// render as "unmeasured", not a measured "0 reachable assets".
	BlastRadiusKnown bool
	// CoVeConcerns are the chain-of-verification guardrail concerns (step 6).
	CoVeConcerns []string
	// SafetyBand rates how likely applying the plan is to break something —
	// safe|caution|risky (respond/impact.go). The queue treats empty as
	// unknown.
	SafetyBand string
	DecidedAt  time.Time
	// RepeatCount is how many times respond.Decide reused this entry via the
	// repeat-decision skip path (a byte-identical repeat: same outcome, action class,
	// confidence band and CoVe concerns) since it was last freshly recorded.
	// The skip path means those repeats never land their own audit_events row,
	// so this counter — not a COUNT over the audit trail — is the escalation-
	// hotspot signal. Zero for a decision that has never repeated.
	RepeatCount int
	// LastRepeatedAt is when RepeatCount was last incremented. Zero if it never
	// has been.
	LastRepeatedAt time.Time
	// EscalationReason mirrors respond.Decision.EscalationReason —
	// stored so the entry alone (as read by findingctx / govern) explains why
	// an escalated decision escalated without recomputing it.
	EscalationReason string
}

var ErrNotFound = errors.New("reasoncache: not found")
