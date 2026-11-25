package scan

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/cronexpr"
)

// TemplateStrategy controls how templates are selected for a profile's scan runs.
type TemplateStrategy string

const (
	// StrategyAll uses the scanner's own default selection: nuclei picks
	// template tags by asset type and technology hints, medium+ severity. It
	// does not run every template.
	StrategyAll TemplateStrategy = "all"
	// StrategyTags runs only templates whose tags match ScanProfile.TemplateTags.
	// Tags on the scanner's exclusion list are dropped (nuclei: fuzzing,
	// intrusive, dos, windows, iis, sharepoint, lotus); a profile whose tags are
	// all excluded fails every run. The credential-attempt tags (default-login,
	// brute-force, bruteforce) are excluded too unless the profile names them.
	StrategyTags TemplateStrategy = "tags"
	// StrategyAIContextual is not available. No pod that executes profile runs
	// has an LLM tag selector, so CreateProfile and UpdateProfile reject it with
	// ErrStrategyUnavailable, and SelectTemplates fails every target of a
	// stored profile that still carries it.
	StrategyAIContextual TemplateStrategy = "ai_contextual"
)

// ScanFindingStatus is the lifecycle of a finding surfaced by a profile run.
type ScanFindingStatus string

const (
	// ScanFindingNew is set when the finding is seen for the first time.
	ScanFindingNew ScanFindingStatus = "new"
	// ScanFindingConfirmed is set when the finding has been triaged and accepted.
	ScanFindingConfirmed ScanFindingStatus = "confirmed"
	// ScanFindingResolved is set when the finding is no longer observed.
	ScanFindingResolved ScanFindingStatus = "resolved"
	// ScanFindingRegressed is set when a previously resolved finding reappears.
	ScanFindingRegressed ScanFindingStatus = "regressed"
)

// Audit actions written to audit_events for scan-profile changes (target_type
// AuditTargetScanProfile, target_id the profile id). Details carry the
// profile's definition; update has before/after.
const (
	AuditActionProfileCreate = "scan.profile_create"
	AuditActionProfileUpdate = "scan.profile_update"
	AuditActionProfileDelete = "scan.profile_delete"
)

// ScanProfile is a saved scan configuration that scopes which assets to scan,
// which scanner to use, how to pick templates, and optionally recurs on a
// schedule. Profiles drive repeated, context-aware scanning without manual
// target selection each run.
type ScanProfile struct {
	ID          string
	Name        string
	Description string
	// TargetQuery is a read-only Ladybug Cypher query that resolves the target set.
	// When empty, all internet-exposed assets are targeted (same as a global scan).
	// When set, the worker runs it as a Cypher query and maps returned Asset nodes
	// to scan targets. This makes a profile a declarative "Cypher → action" workflow:
	// define WHO to scan with graph logic, not a flat asset list.
	// Example: "MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id:'internet'})
	//           WHERE a.score >= 60 AND a.provider = 'gcp' RETURN a"
	TargetQuery      string
	ScannerType      string           // e.g. "nuclei"
	TemplateStrategy TemplateStrategy // how to pick templates for each run
	TemplateTags     []string         // used when TemplateStrategy == StrategyTags
	Schedule         string           // cron expression; "" means manual-only
	Enabled          bool
	// DriftEnabled triggers an automatic scan run whenever a connector sync
	// reports that a changed asset is externally reachable (public IP or
	// domain). Use this to detect configuration drift as soon as it happens
	// rather than waiting for the next scheduled run.
	//
	// Only takes effect on a profile with an EMPTY TargetQuery today
	// (jobs.ScanAssetWorker, the consumer, builds its scan target straight
	// from the drift-changed asset with no Cypher resolver to check that
	// asset against a scope) — a profile scoped by TargetQuery is silently
	// excluded from drift triggering rather than firing outside its intended
	// scope (internal/app/scan/profile_repo.go's listDriftProfilesQ). Scoped
	// drift-triggered scans are a real gap, not yet built.
	DriftEnabled bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// ScanProfileStatus is the aggregate view of a profile used by the UI: last
// execution state plus totals. It is always derived — never stored directly.
type ScanProfileStatus struct {
	ProfileID     string
	LastRunAt     *time.Time
	LastRunStatus *Status // nil when the profile has never been run
	TotalRuns     int
	OpenFindings  int
}

// ScanFinding is a single vulnerability or issue tied to a specific profile
// run and asset. It tracks lifecycle state across runs: new → confirmed,
// resolved, or regressed as subsequent runs confirm or clear the finding.
//
// AssetID holds the scanned target's host (scan.Target.Host), not a graph
// asset ID: a scan target carries no asset ID.
type ScanFinding struct {
	ID          string
	ScanRunID   string
	FindingID   string // foreign key into the findings domain
	AssetID     string // target host, see above
	CheckID     string // template/check that produced the finding, e.g. "CVE-2021-1234"
	Title       string
	Severity    string // info|low|medium|high|critical
	Status      ScanFindingStatus
	FirstSeenAt time.Time
	LastSeenAt  time.Time
	ResolvedAt  *time.Time // nil until status reaches ScanFindingResolved
}

// ProfileFilters narrows which profiles a repository query returns. Zero values
// mean "no filter" for that field.
type ProfileFilters struct {
	Enabled     *bool  // when non-nil, restrict to profiles with matching enabled flag
	ScannerType string // restrict to a specific scanner type; "" means any
	HasSchedule *bool  // when non-nil, true = scheduled profiles only, false = manual only
}

var ErrProfileNotFound = errors.New("scan: profile not found")

// ErrInvalidSchedule: a profile schedule is not a 5-field cron expression the
// schedule worker can fire. Accepting it would store a profile that never runs.
var ErrInvalidSchedule = errors.New("scan: invalid schedule")

// ErrStrategyUnavailable: a profile's template strategy cannot run on this
// deployment (StrategyAIContextual).
var ErrStrategyUnavailable = errors.New("scan: template strategy not available")

// ScheduleError reports why a non-empty profile schedule can never fire, or
// nil when it is empty (manual only) or valid. Validation runs at the API, not
// in the database, so a stored profile can still hold an invalid one; the API
// surfaces this error on it rather than letting the profile silently never
// run.
func ScheduleError(schedule string) error {
	if strings.TrimSpace(schedule) == "" {
		return nil
	}
	if err := cronexpr.Validate(schedule); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSchedule, err)
	}
	return nil
}
