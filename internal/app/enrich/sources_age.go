package enrich

import (
	"context"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// FindingAge is a demotion-only signal: a finding that has persisted for a long
// time without incident is lower urgency than a freshly-detected one. It reads
// only finding.FirstDetectedAt, so it costs nothing.
//
// It reads FirstDetectedAt and NEVER DetectedAt. DetectedAt is the most recent
// emission: every producer stamps `now` on re-observation, so it answers "how
// long since we last saw this", which for an age demotion is not merely
// imprecise but inverted — the longer a finding persists, the more often it is
// re-observed and the newer it looks.
// FirstDetectedAt is pinned by finding.Service.RecordObserved and read as a
// min across row versions, so no writer can move it forward.
// TestFindingAgeReadsFirstDetectedAtOnly guards the field choice.
//
// Guardrails: NEVER demotes a known-exploited (KEV)
// finding — a years-old KEV is more urgent, not less — and never touches internet-
// exposure findings, whose risk doesn't decay with age (a long-public bucket is
// still public). It never elevates and is never sufficient alone; it nudges
// longstanding, controlled, unreachable findings further down.
type FindingAge struct{ Now func() time.Time }

func (a FindingAge) Name() string { return sourceFindingAge }

func (a FindingAge) clock() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

const (
	ageDemoteWindow    = 90 * 24 * time.Hour
	ageDemoteOldWindow = 365 * 24 * time.Hour
)

func (a FindingAge) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	// A zero FirstDetectedAt is "we have never established when this started",
	// not "it started at the epoch". Contribute nothing — absence of evidence
	// never demotes.
	if f.KnownExploited || f.FirstDetectedAt.IsZero() || isExposure(f) {
		return Factor{}, false, nil
	}
	age := a.clock().Sub(f.FirstDetectedAt)
	switch {
	case age > ageDemoteOldWindow:
		return Factor{Source: sourceFindingAge, Points: -10, Detail: "present for over a year without escalation"}, true, nil
	case age > ageDemoteWindow:
		return Factor{Source: sourceFindingAge, Points: -5, Detail: "present for over 90 days"}, true, nil
	}
	return Factor{}, false, nil
}
