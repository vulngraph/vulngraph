// Package belief holds the system's unit of judgment: a durable, grounded
// Belief about a finding's true severity, formed either by deterministic rules
// (Reconcile) or, when ADJUDICATOR_ENABLED is set, by an adversarial LLM
// adjudicator (adjudicate.go) whose samples must converge. domain.go is pure:
// no infrastructure imports.
package belief

import (
	"errors"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Belief status lifecycle.
const (
	StatusProposed  = "proposed"
	StatusConfirmed = "confirmed"
	StatusRefuted   = "refuted"
	StatusStale     = "stale"
)

// Confidence bands. Deterministic beliefs are high-confidence by construction;
// the adjudicator sets the band from sample convergence.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// Provenance — how a belief was formed.
const (
	ProvenanceDeterministic = "deterministic" // grounded rules (Reconcile), no LLM
	ProvenanceAdjudicator   = "adjudicator"   // adversarial LLM adjudication
)

var (
	// ErrNoClaim — a belief must state a verdict.
	ErrNoClaim = errors.New("belief: claim is required")
	// ErrUngrounded — the grounding contract: every evidence clause must cite a
	// concrete source-observed fact, and a belief needs at least one.
	ErrUngrounded = errors.New("belief: every evidence clause must cite a source fact, and at least one is required")
)

// Evidence is one grounded clause: a human-readable statement (Clause) that MUST
// point at a concrete source-observed fact — Source names the evidence source,
// Fact is the observed value. The grounding contract forbids a clause without both.
type Evidence struct {
	Clause string `json:"clause"`
	Source string `json:"source"` // e.g. "must_fix", "trust_entry", "reachability", "enrich_score"
	Fact   string `json:"fact"`   // observed value, e.g. "controlled", "federated", "92/page"
}

// Belief is the true-severity verdict for a finding, with its cited evidence.
type Belief struct {
	FindingID  string
	ResourceID string
	Claim      string           // the verdict + optional re-frame
	Severity   finding.Severity // the reconciled true-severity band
	Confidence string
	Status     string
	Evidence   []Evidence
	Provenance string // ProvenanceDeterministic | ProvenanceAdjudicator
	// Fingerprint hashes the grounding inputs (score, band, deterministic
	// severity, context) an adjudicator belief was formed from. The sweep skips
	// re-adjudicating a finding whose fresh belief carries the same fingerprint —
	// the verdict stands until the evidence actually changes. Empty for
	// deterministic beliefs (enrich re-forms those on its own change-gate).
	Fingerprint string
	CreatedAt   time.Time
	// CheckedAt is when the adjudication sweep last confirmed this belief still
	// covers the finding's current inputs (a cache hit: same Fingerprint, inside
	// the revalidation window). Zero means "when it was created".
	CheckedAt time.Time
}

// LastChecked is when the belief was last known to cover its inputs: the later
// of CreatedAt and CheckedAt.
func (b Belief) LastChecked() time.Time {
	if b.CheckedAt.After(b.CreatedAt) {
		return b.CheckedAt
	}
	return b.CreatedAt
}

// Effective picks a finding's current belief from its per-provenance beliefs:
// the most recent wins. An adjudicator verdict counts as current as of its last
// check (LastChecked), so a re-affirmed verdict keeps superseding the
// score-derived floor, while a deterministic belief re-formed AFTER the verdict
// was last checked (the finding's inputs changed, e.g. it became decisively
// must_fix) is not shadowed by a stale verdict. Ties go to the adjudicator.
// Any other provenance is a fallback only. ok is false when bs is empty.
func Effective(bs []Belief) (b Belief, ok bool) {
	var adj, det, other *Belief
	for i := range bs {
		switch bs[i].Provenance {
		case ProvenanceAdjudicator:
			adj = &bs[i]
		case ProvenanceDeterministic:
			det = &bs[i]
		default:
			other = &bs[i]
		}
	}
	switch {
	case adj != nil && (det == nil || !adj.LastChecked().Before(det.CreatedAt)):
		return *adj, true
	case det != nil:
		return *det, true
	case other != nil:
		return *other, true
	}
	return Belief{}, false
}

// Validate enforces the grounding contract: a claim plus at least one fully-cited
// evidence clause.
func (b Belief) Validate() error {
	if b.Claim == "" {
		return ErrNoClaim
	}
	if len(b.Evidence) == 0 {
		return ErrUngrounded
	}
	for _, e := range b.Evidence {
		if e.Source == "" || e.Fact == "" {
			return ErrUngrounded
		}
	}
	return nil
}
