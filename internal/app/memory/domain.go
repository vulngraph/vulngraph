// Package memory is the decaying-memory ledger that replaces a per-tenant neural
// model (see docs/adr/005). It records outcomes of proposed actions — a fix
// the executor ran is a success, a governor denial a failure; an approval
// alone records nothing — and computes a confidence for an (action class,
// asset type) key as an exponentially-decayed weighted rate of executed fixes
// versus denials: recent reality dominates and stale lessons fade. The result
// is interpretable and auditable — "parked rather than escalated because N of
// M similar proposals in the last D days were executed rather than denied".
// Confidence decides how urgently a human is asked, never whether one is (ADR
// 087).
package memory

import "time"

// Outcome is one recorded action result.
type Outcome struct {
	ActionClass string
	AssetType   string
	Environment string
	Success     bool
	DecidedBy   string
	OccurredAt  time.Time
	// DedupeKey names the decision this outcome is evidence of (for example
	// finding id + context fingerprint). Recording the same non-empty key twice
	// stores one row, so a retried job or a repeated verdict cannot add a
	// second sample for one judgment. Empty means always append.
	DedupeKey string
}

// Band is the routing decision derived from confidence.
type Band string

const (
	// BandHigh: enough recent evidence and a high success rate — parked for
	// approval like BandMedium; never executed without a human.
	BandHigh Band = "high"
	// BandMedium: act with human approval.
	BandMedium Band = "medium"
	// BandLow: low success rate — escalate.
	BandLow Band = "low"
	// BandInsufficient: not enough evidence — always escalate (safe harbor).
	BandInsufficient Band = "insufficient"
)

// Confidence is the computed assessment for an (action class, context).
type Confidence struct {
	Score       float64 // decayed weighted success rate, 0..1
	EffectiveN  float64 // sum of decay weights — the "amount" of evidence
	SampleCount int     // raw number of outcomes considered
	Band        Band
}
