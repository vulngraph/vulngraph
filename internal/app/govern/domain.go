// Package govern is the human-governance seam over the agent's decisions: the
// "user is governor, not operator" model. A finding whose decision is parked or
// escalated waits in the queue until a human approves it, accepts the risk, or
// denies it. govern reads reasoncache (the pending decisions) and finding
// (their context); it writes verdicts, pattern verdicts and email-link
// nonces, and records outcomes (denials and executed fixes) in memory and
// audit rows in the respond trail.
package govern

import (
	"errors"
	"time"
)

// Verdict is a governor's standing authorization on a decision.
type Verdict string

const (
	VerdictApproved     Verdict = "approved"      // authorize the agent's plan
	VerdictRiskAccepted Verdict = "risk_accepted" // leave as-is, accept the risk
	VerdictDenied       Verdict = "denied"        // reject the plan
)

// ValidVerdict reports whether v is a recognized verdict.
func ValidVerdict(v Verdict) bool {
	switch v {
	case VerdictApproved, VerdictRiskAccepted, VerdictDenied:
		return true
	default:
		return false
	}
}

// QueueItem is a pending agent decision awaiting a human governor, clustered by
// check + action class — one card authorizes a whole class of action (e.g. "trim
// privesc on 7 human users") rather than one principal at a time.
type QueueItem struct {
	ClusterKey     string // check_id|action_class — the resolve target
	Title          string // human-readable (the finding title)
	CheckID        string
	ActionClass    string
	Summary        string // the agent's plan summary (representative)
	Outcome        string // parked_for_approval | escalated
	ConfidenceBand string
	WorstScore     uint8
	WorstBand      string
	BlastRadius    int
	// BlastRadiusKnown reports whether every finding in this cluster had a
	// SUCCESSFULLY MEASURED blast-radius walk at decision time. False (the
	// zero value) means at least one walk failed — BlastRadius is then a
	// max over a mix of real and unmeasured-zero values, and must never be
	// read as "small," the same "a zero value is not a measurement" rule
	// this package's own ConfidenceKnown field already follows. An
	// unmeasured cluster is shown to the governor as unmeasured, never as the
	// smallest possible reach.
	BlastRadiusKnown bool
	CoVeConcerns     []string
	// SafetyBand is the most cautious "safe to fix" band across the cluster —
	// safe|caution|risky (respond/impact.go). Advisory context for the approver.
	SafetyBand string
	// UnusedCount is how many of the cluster's findings sit on a resource that
	// looks decommissioned (finding.Unused: stale / inactive / orphaned). "17 of
	// 23 targets unused" is the evidence a governor bulk-approves on.
	UnusedCount   int
	Count         int      // findings in this cluster
	Resources     int      // distinct resources affected
	FindingIDs    []string // the decisions a resolve applies to
	SampleTargets []string // a few resource ids, for display
	// DecidedAt is the MOST RECENT fresh-reasoning timestamp across every
	// finding in this cluster (clusterQueue takes the max) — not when this
	// specific card was created, and not a per-finding "decided at" (a cluster
	// bundles many findings under one card). Render it labeled as such; an
	// unlabeled timestamp here reads as "this decision was made at", which
	// is a different and narrower claim than what the field actually holds.
	DecidedAt time.Time
	// ConfidenceScore is the minimum confidence score (0..1) across all findings
	// in this cluster, used by policy rule enforcement to determine outcome.
	ConfidenceScore float64
	// ConfidenceEffectiveN is the decay-weighted evidence (memory.Confidence.EffectiveN)
	// accrued so far for this cluster's (action class, dominant resource type)
	// confidence key. Zero when no confidence reader is wired or no evidence exists.
	ConfidenceEffectiveN float64
	// ConfidenceGap is how much more effective-n is needed to reach
	// memory.MinEffectiveN for this cluster's confidence key — 0 once sufficient.
	// Only meaningful when ConfidenceBand at lookup time was BandInsufficient;
	// for low/medium/high keys it is always 0 and carries no ordering weight.
	// Resolving the insufficient cluster with the smallest gap — by denying it
	// or running its fix (an approval alone records no evidence) — makes the
	// most teaching progress.
	ConfidenceGap float64
	// Unlocks counts the OTHER pending clusters that share this cluster's
	// confidence key (action class + dominant resource type) — evidence from
	// this cluster counts for all of them too. Zero (and meaningless) when
	// ConfidenceKnown is false.
	Unlocks int
	// ConfidenceKnown reports whether the confidence lookup for this cluster's
	// key succeeded. False (the zero value) means the lookup errored or no
	// ConfidenceReader is wired — a failed lookup is not "zero
	// evidence", so it must not be indistinguishable from a real, sufficient
	// confidence. Clusters with ConfidenceKnown=false carry no teaching signal
	// and sort after every cluster with a known confidence.
	ConfidenceKnown bool
	// Urgent is true when any finding in the cluster is page/high-band or
	// must_fix (respond.UrgentEvidence). The "disabled" policy rule never
	// hides an urgent cluster.
	Urgent bool
}

// ResolveInput is a governor's verdict on a queued cluster. Only FindingIDs
// choose what is resolved; the action class, cluster key and fingerprints are
// derived from the pending decisions server-side.
type ResolveInput struct {
	FindingIDs []string
	// ActionClass is what the queue card showed. Optional: when set it must
	// match the pending decisions' action class, so a stale card fails loudly
	// instead of resolving something the governor did not see.
	ActionClass string
	Verdict     Verdict
	Actor       string
	Note        string
}

// ExecutedFix is a decision's fix the executor actually carried out. The asset
// type and check come from the finding, never from the caller.
type ExecutedFix struct {
	DecisionID  string
	FindingID   string
	ActionClass string
	Actor       string
}

var (
	ErrBadVerdict = errors.New("govern: invalid verdict")
	ErrNoTargets  = errors.New("govern: no targets")
	// ErrAlreadyResolved means a verdict was already recorded for a finding
	// against its current context fingerprint. Resolving it again would record
	// a second memory outcome for the same judgment, so it is refused.
	ErrAlreadyResolved = errors.New("govern: already resolved")
	// ErrNotPending means a target finding has no decision awaiting a governor.
	ErrNotPending = errors.New("govern: no pending decision for finding")
	// ErrTargetMismatch means the request does not describe the pending
	// decisions: mixed action classes, an action class that differs from the
	// queue's, or an email link whose decisions have since changed.
	ErrTargetMismatch = errors.New("govern: targets do not match the pending decisions")
	// ErrLinkCannotApprove means an email link tried to approve an action
	// class that needs a signed-in approver (see LinkCanApprove).
	ErrLinkCannotApprove = errors.New("govern: this action class cannot be approved from an email link")
	// ErrLinkCannotDeny means an email link tried to deny an urgent finding,
	// which takes a signed-in governor.
	ErrLinkCannotDeny = errors.New("govern: an urgent finding cannot be denied from an email link")
	// ErrSMTPNoTLS is returned when the SMTP server offers no STARTTLS and
	// plaintext was not explicitly allowed: approval emails carry bearer links.
	ErrSMTPNoTLS = errors.New("govern: SMTP server does not offer TLS; refusing to send approval links in clear text")
)
