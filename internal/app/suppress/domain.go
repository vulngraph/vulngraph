// Package suppress owns finding suppressions: an operator acknowledges a finding
// and silences it, so it stops entering the decision pipeline and is flagged in
// the UI. Suppressions are mutable per-finding state in Postgres (the finding
// itself stays in ClickHouse); the enrich worker and the finding list consult
// this domain through service interfaces.
package suppress

import (
	"errors"
	"fmt"
	"time"
)

// Suppression records that a finding has been silenced, by whom, why, and until
// when. Every suppression expires: a permanent exception is never re-reviewed, so
// once ExpiresAt passes the suppression stops matching and the finding re-enters
// the pipeline. The row is kept so the finding can say its exception expired.
type Suppression struct {
	FindingID    string
	Reason       string
	SuppressedBy string
	SuppressedAt time.Time
	ExpiresAt    time.Time
	// LastReviewedAt is zero when nobody has reviewed the suppression since it
	// was created; ReviewedBy is empty in that case.
	LastReviewedAt time.Time
	ReviewedBy     string
}

// Expired reports whether the suppression has stopped matching at now.
func (s Suppression) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// State is one finding's suppression standing, as the finding-detail view needs
// it to render its Suppress/Unsuppress toggle truthfully. The zero value is "no
// suppression has ever covered this finding".
type State struct {
	Suppressed  bool        // an unexpired suppression covers the finding
	Expired     bool        // a suppression existed and has lapsed — the finding is back in the pipeline
	Suppression Suppression // the row behind either flag; zero when neither is set
}

const (
	// MaxExpiry caps how far out a suppression may expire, so every exception
	// is looked at again at least yearly.
	MaxExpiry = 365 * 24 * time.Hour
	// maxExpiryGrace absorbs a date picker's day granularity and the client's
	// timezone: "a year from today, end of day" lands up to a day past MaxExpiry.
	maxExpiryGrace = 24 * time.Hour
	// AgentMaxExpiry caps a suppression a caller that may be an agent sets or
	// renews: the MCP suppress_finding tool, and REST on an API key. Whatever
	// it silences comes back in front of a person within a month.
	AgentMaxExpiry = 30 * 24 * time.Hour
	// ExpiryNoticeWindow is how far ahead the expiry notice warns.
	ExpiryNoticeWindow = 14 * 24 * time.Hour
)

// ValidateExpiry checks a requested expiry against now: required, in the future,
// and no further out than MaxExpiry.
func ValidateExpiry(now, expiresAt time.Time) error {
	switch {
	case expiresAt.IsZero():
		return ErrMissingExpiry
	case !expiresAt.After(now):
		return ErrExpiryInPast
	case expiresAt.After(now.Add(MaxExpiry + maxExpiryGrace)):
		return ErrExpiryTooFar
	}
	return nil
}

// validateAgentExpiry is ValidateExpiry with the AgentMaxExpiry cap.
func validateAgentExpiry(now, expiresAt time.Time) error {
	if err := ValidateExpiry(now, expiresAt); err != nil {
		return err
	}
	if expiresAt.After(now.Add(AgentMaxExpiry + maxExpiryGrace)) {
		return ErrAgentExpiryTooFar
	}
	return nil
}

// AuditEvent is one row of the shared insert-only `audit_events` trail
// (ClickHouse, 7-year TTL).
//
// Suppression state itself is not a trail: Upsert overwrites the previous
// actor and reason, and Unsuppress is a hard DELETE. A finding suppressed by
// one person for one reason, re-suppressed by another for a different reason,
// then unsuppressed, would leave no evidence that any of it ever happened, so
// each of those transitions appends a row here.
type AuditEvent struct {
	TS         time.Time
	Actor      string
	Action     string // one of the AuditAction* values below
	TargetType string // always AuditTargetFinding
	TargetID   string // finding id
	Details    string // JSON: reason, and whether it came from a bulk operation
}

// Audit action + target values written to audit_events.
const (
	AuditActionSuppress   = "suppress.suppress"
	AuditActionUnsuppress = "suppress.unsuppress"
	AuditActionReview     = "suppress.review"
	// AuditActionCarry: a suppression copied to the finding that superseded
	// the suppressed one (Service.CarryForward).
	AuditActionCarry = "suppress.carry"
	// AuditActionRefused: an API-key request to suppress or review a finding
	// that only a person may silence (details: reason, operation).
	AuditActionRefused = "suppress.refused"
	AuditTargetFinding = "finding"
	// AuditActorUnknown is recorded when the caller supplied no actor.
	AuditActorUnknown = "unknown"
)

var (
	ErrNotFound      = errors.New("suppress: not found")
	ErrMissingReason = errors.New("suppress: reason is required")
	ErrMissingExpiry = errors.New("suppress: expires_at is required")
	ErrExpiryInPast  = errors.New("suppress: expires_at must be in the future")
	ErrExpiryTooFar  = errors.New("suppress: expires_at exceeds the maximum suppression lifetime")
	// ErrAgentExpiryTooFar: an API-key request asked for an expiry past
	// AgentMaxExpiry.
	ErrAgentExpiryTooFar = errors.New("suppress: an API key may suppress for at most 30 days")
	// ErrNeedsPerson: an API-key request to silence a finding that only a
	// person on a signed-in session may (FindingGate).
	ErrNeedsPerson = errors.New("suppress: this finding can only be suppressed from a signed-in session")
	// ErrUnknownFinding: the FindingGate found no such finding.
	ErrUnknownFinding = errors.New("suppress: finding not found")
)

// NeedsPersonError is ErrNeedsPerson for one finding, with the reason
// (enrich.AgentRefusal's wording).
type NeedsPersonError struct {
	FindingID string
	Reason    string
}

func (e *NeedsPersonError) Error() string {
	return fmt.Sprintf("%v: %s (%s)", ErrNeedsPerson, e.FindingID, e.Reason)
}

func (e *NeedsPersonError) Unwrap() error { return ErrNeedsPerson }
