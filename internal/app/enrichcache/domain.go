// Package enrichcache stores, per finding, an input fingerprint and the time it
// was last enriched. EnrichWorker skips re-enriching — and therefore
// re-deciding — a finding whose inputs are unchanged and which was enriched
// recently, so the periodic sweep stops re-walking the blast radius for every
// finding every cycle (the dominant ClickHouse load). Kept dependency-free (its
// own FingerprintInput, not finding.Finding) so it imports no other domain,
// mirroring reasoncache.
package enrichcache

import (
	"errors"
	"time"
)

// SweepProgress is durable enumeration state, not evidence of fresh scoring.
// A zero Before starts a new pass; the cursor uses millisecond enrichment time.
type SweepProgress struct {
	Cursor   string
	Before   time.Time
	Revision int64
}

var ErrSweepProgressConflict = errors.New("enrichcache: sweep progress changed")

// LogicVersion identifies the CURRENT enrichment logic — the scoring sources, the
// must-fix classifier, and the consistency gate. It does two jobs, and it must be
// one constant doing both or they can disagree:
//
//  1. It prefixes every input fingerprint (see Fingerprint), so bumping it makes
//     the change-gate recompute instead of short-circuiting.
//  2. It is compared against the last version a FULL corpus pass completed for
//     (LastFullPassVersion). A mismatch triggers one bulk re-enrichment of every
//     open finding, because (1) alone is not enough: invalidating the cache for a
//     finding that is never enqueued changes nothing, and findings on unchanged
//     assets are never enqueued (checks run only on changed assets).
//
// Bump this whenever enrichment SEMANTICS change — a classifier branch, a source's
// weighting, a threshold — not when refactoring.
// TestClassifyMustFixDecisionTableIsPinned (internal/app/enrich) fails when the
// must-fix classifier's behaviour changes without a bump.
//
// Deliberately a human-maintained constant rather than a hash over source names:
// checks.Fingerprint (internal/checks) hashes only sorted check IDs, so editing a
// check's predicate without renaming it never triggers its backfill — the same
// blind spot, one layer up. Logic changes are exactly what a name hash cannot see.
// v2 removes name-based principal suppression and recomputes existing scores.
const LogicVersion = "v2"

// Entry is one finding's last enrichment fingerprint and timestamp.
//
// InputFP is the FULL fingerprint (LogicVersion + context) — an exact match
// against a freshly-computed Fingerprint is what lets EnrichWorker skip
// re-enriching entirely. ContextFP and ScoreBand are the version-INDEPENDENT
// half, stored so a cache miss caused only by a LogicVersion bump (context
// unchanged) can be told apart from one caused by a real input change: see
// jobs.EnrichWorker.Work (the version-only re-score skip). ScoreBand is the band the finding carried
// at that enrichment, used to decide whether the version-only re-score
// actually moved anything.
//
// Graph is the graph context InputFP was built from, kept raw so a failed
// graph read on the next visit can carry the last measurement forward rather
// than hash a zero value that reads as a topology change (CarryForward).
type Entry struct {
	FindingID  string
	InputFP    string
	ContextFP  string
	ScoreBand  string
	EnrichedAt time.Time
	Graph      GraphContext
}

// GraphContext is the measured graph half of a FingerprintInput. Each field's
// zero value means "not measured": Exposed is "true"/"false" once read, the two
// buckets are "" until read.
type GraphContext struct {
	Exposed       string
	PrivescBucket string
	ReachBucket   string
}

// AlertState is the urgency a finding last alerted at (see AlertTransition).
type AlertState struct {
	FindingID    string
	ScoreBand    string
	MustFixClass string
	AlertedAt    time.Time
}

var ErrNotFound = errors.New("enrichcache: not found")
