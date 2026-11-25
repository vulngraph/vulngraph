// Package savedquery runs read-only Cypher queries on an optional cron schedule
// and, when alert_on_change is set, alerts via the notify domain if the hash of
// a complete (non-truncated) result set differs from the previous baseline.
package savedquery

import (
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("savedquery: not found")
	ErrEmptyCypher   = errors.New("savedquery: cypher is required")
	ErrWriteQuery    = errors.New("savedquery: query contains write operations — read-only Cypher only")
	ErrMissingName   = errors.New("savedquery: name is required")
	ErrGraphNotReady = errors.New("savedquery: graph not ready — run skipped")
	// ErrResultTruncated: the result hit the runner's row budget, so its hash is
	// not a measurement of the full result set and must not become the baseline.
	ErrResultTruncated = errors.New("savedquery: result truncated at the row budget — completeness unknown")
	// ErrMultiHopMayBeIncomplete: the graph engine that answered has a node
	// table above one engine node group (ladybug#1341), so a multi-hop or
	// variable-length match may have missed relationships. The run is recorded
	// and the baseline moves (single-hop matches are unaffected and it is the
	// only measurement there is), but its status says it may be incomplete.
	ErrMultiHopMayBeIncomplete = errors.New("savedquery: multi-hop results may be incomplete — a graph node table is above one engine node group (ladybug#1341)")
	// ErrAlertUndelivered: a change alert reached no channel. The baseline is
	// kept so the next scheduled run detects the same change and retries.
	ErrAlertUndelivered = errors.New("savedquery: change alert was not delivered")
	// ErrAlertNoRecipients: no enabled channel's routing accepts the alert
	// (none configured, none routing query_match, a chosen channel deleted or
	// disabled, min_score above the severity's score). A retry cannot change
	// that, so the baseline advances and the run records why nobody was told.
	ErrAlertNoRecipients = errors.New("savedquery: change alert matched no channel's routing")
	ErrInvalidSeverity   = errors.New("savedquery: alert_severity must be critical, high, medium, low or info")
	// ErrInvalidSchedule: the schedule is not a 5-field cron expression the
	// scheduler can fire. Accepting it would store a detection that never runs.
	ErrInvalidSchedule = errors.New("savedquery: invalid schedule")
)

// Alert severities a saved query may carry. DefaultAlertSeverity applies when a
// request leaves it empty.
const (
	SeverityCritical     = "critical"
	SeverityHigh         = "high"
	SeverityMedium       = "medium"
	SeverityLow          = "low"
	SeverityInfo         = "info"
	DefaultAlertSeverity = SeverityHigh
)

// ValidSeverity reports whether s is one of the alert severities above.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// SavedQuery is a named, optionally-scheduled Cypher detection.
// LastResultCount/LastResultHash are the change-detection baseline: only a
// complete scheduled run whose alert (if any) was delivered advances them.
type SavedQuery struct {
	ID              string
	Name            string
	Description     string
	Cypher          string
	CreatedBy       string
	Schedule        string   // cron expr; "" = manual only
	AlertChannelIDs []string // notify channel IDs to alert on change; empty = every query_match channel
	AlertOnChange   bool
	AlertSeverity   string // critical|high|medium|low|info; the change alert's severity
	Enabled         bool
	LastRunAt       *time.Time
	LastResultCount int
	LastResultHash  string
	// LastAttempt is the newest run in the history, whatever its outcome — the
	// detection's actual health. Nil when the query has never run. The baseline
	// above only moves on a good scheduled run, so it alone cannot show a query
	// whose runs all fail, or one that only ever ran manually.
	LastAttempt *Run
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Run is one execution of a saved query — history + change-detection record.
type Run struct {
	ID           string
	SavedQueryID string
	RanAt        time.Time
	NodeCount    int
	EdgeCount    int
	ResultHash   string
	Trigger      string // manual | schedule
	Error        string
}

// Run statuses, derived from a recorded Run's Error.
const (
	RunStatusOK         = "ok"
	RunStatusTruncated  = "truncated"
	RunStatusIncomplete = "incomplete"
	RunStatusFailed     = "failed"
)

// Status is ok for a run with no error, truncated for one that hit the row
// budget (its counts are partial), incomplete for one the graph engine flagged
// multi-hop-may-be-incomplete, and failed for anything else — including a
// change alert that was not delivered or matched no channel.
func (r Run) Status() string {
	switch r.Error {
	case "":
		return RunStatusOK
	case ErrResultTruncated.Error():
		return RunStatusTruncated
	case ErrMultiHopMayBeIncomplete.Error():
		return RunStatusIncomplete
	default:
		return RunStatusFailed
	}
}

// Audit actions written to audit_events for saved-query changes (target_type
// AuditTargetSavedQuery, target_id the query id). Details carry the query's
// definition (name, cypher, schedule, alerting); update has before/after.
const (
	AuditActionCreate     = "savedquery.create"
	AuditActionUpdate     = "savedquery.update"
	AuditActionDelete     = "savedquery.delete"
	AuditTargetSavedQuery = "saved_query"
)

// Trigger values recorded on a Run.
const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
)
