// Package scan owns context-aware active scanning. Targets come from our own
// asset graph. By default these are internet-exposed assets (ListExternal). A
// scan profile can instead pick graph assets with an operator-written Cypher
// TargetQuery, which must end in LIMIT <= MaxTargets and is resolved on the
// worker by jobs.Deps.CypherResolver. Private and loopback addresses are
// refused unless SCAN_ALLOW_INTERNAL_TARGETS=true; link-local space and cloud
// metadata endpoints are refused always (AlwaysBlockedTargets). Results are
// recorded as findings sourced to the scanner that produced them. Scanners are pluggable connectors (the reference one is
// internal/scanner/nuclei); a multiScanner fans out to every enabled connector.
package scan

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Audit actions for a scan a person starts (audit_events). A scheduled
// profile run has no person behind it and writes no row.
const (
	// AuditActionStart: POST /api/scans, a full scan of the internet-facing
	// assets. The worker creates the run, so target_id is empty.
	AuditActionStart = "scan.start"
	// AuditActionProfileStart: POST /api/scan-profiles/{id}/trigger.
	// target_id is the profile id; details: run_id, name, scanner_type,
	// template_strategy, target_query.
	AuditActionProfileStart = "scan.profile_start"
	AuditTargetScan         = "scan"
	AuditTargetScanProfile  = "scan_profile"
)

// Status is the lifecycle of a scan run.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Run is one scan execution over the current external-facing asset set.
type Run struct {
	ID            string
	Status        Status
	TargetCount   int
	TargetURLs    []string // actual URLs/IPs that were scanned
	FindingCount  int
	TemplateTags  []string // nuclei template tags selected for this run
	TemplateCount int      // templates that produced at least one result
	ScannerName   string   // producing scanner, e.g. "nuclei"
	Error         string
	StartedAt     time.Time
	FinishedAt    *time.Time
}

// Target is one scannable endpoint derived from an owned asset. Web scanners
// use URL; network scanners use Host (+Port once discovered). We
// never scan arbitrary input — every Target traces back to an owned asset.
// AssetType and Tags carry context from the source asset so the scanner can
// select only relevant templates (e.g. gcs_bucket → storage/cloud templates).
type Target struct {
	URL       string            // e.g. "https://example.com"; empty for non-web targets
	Host      string            // hostname or IP
	Port      int               // 0 when not port-specific
	AssetType string            // e.g. "gce_instance", "gcs_bucket"
	Tags      map[string]string // asset metadata tags (service-name, product, etc.)
}

// Result is one match from one scanner — provider-neutral so the scan service
// never sees a scanner SDK's types. Scanner names the connector that produced
// the result (used for attribution and dedup across connectors).
type Result struct {
	Scanner    string // producing connector, e.g. "nuclei"
	TemplateID string // e.g. "tech-detect", "CVE-2021-1234"
	Name       string
	Severity   string // info|low|medium|high|critical
	MatchedURL string
	Host       string
	Port       int
	CVE        string  // e.g. "CVE-2021-1234" when the match maps to a CVE
	CVSS       float64 // 0 when the scanner reports no score
	Confidence string  // scanner-reported confidence, when available

	// Context carried onto the finding so the detail view explains what was found.
	// Sourced from the scanner's template/plugin metadata and the match itself.
	Description string // what the check detects (template description)
	Remediation string // how to fix it (template remediation)
	Reference   string // newline-joined reference links
	Evidence    string // matched/extracted values that triggered the result
}

// Capability is what a scanner can scan, as a bitmask so a connector can
// declare several and multiScanner can route each target to the connectors that
// fit it (web scanners want URLs, network scanners want hosts).
type Capability uint8

const (
	CapWeb     Capability = 1 << iota // HTTP(S) endpoints (URL targets) — nuclei
	CapNetwork                        // host/port/service discovery (Host targets)
)

// Has reports whether c includes want.
func (c Capability) Has(want Capability) bool { return c&want != 0 }

// relevantTo reports whether a target is meaningful for a capability set: web
// needs a URL, network needs a host.
func (t Target) relevantTo(caps Capability) bool {
	return (caps.Has(CapWeb) && t.URL != "") || (caps.Has(CapNetwork) && t.Host != "")
}

// ScanOutput is the full output of a scanner run: results plus metadata about
// which templates were selected and how many fired at least one match.
type ScanOutput struct {
	Results       []Result
	TemplateTags  []string // tags used to select templates (e.g. "exposure","misconfig")
	TemplateCount int      // distinct template IDs that produced at least one result
}

// Scanner is one pluggable scan connector. Vulngraph drives it over
// targets derived from owned assets and ingests provider-neutral Results.
// Capabilities declares what it scans so multiScanner routes targets to it.
// templateTags, when non-empty, selects which templates run (a scan profile's
// tags); nil lets the scanner choose. internal/scanner/nuclei is the reference
// implementation; tests use a fake.
type Scanner interface {
	Name() string
	Capabilities() Capability
	Scan(ctx context.Context, targets []Target, templateTags []string) (ScanOutput, error)
}

var ErrNotFound = errors.New("scan: not found")

// ErrUnknownScanner is returned by NewMultiScanner when the enabled set names a
// scanner that is not bundled. A misspelt name would otherwise select nothing.
var ErrUnknownScanner = errors.New("scan: unknown scanner")

// ErrNoScannerForTarget is returned by a multi-scanner Scan when a target fits
// no enabled scanner's capabilities. Nothing ran against it, so an empty result
// for it would read as a clean scan and resolve its confirmed findings.
var ErrNoScannerForTarget = errors.New("scan: no enabled scanner can scan the target")

// ErrNoEnqueuer is returned by TriggerProfileScan when the ProfileService was
// built without a ProfileJobEnqueuer. Pods that only EXECUTE profile runs (the
// scanner) legitimately pass nil, so a nil enqueuer is a configuration fact, not
// a bug — but triggering a run through such a service must fail loudly and, above
// all, BEFORE the scan_runs row exists: a nil enqueuer reached after
// CreateRunForProfile would panic into River's recover and leave a run stuck
// `running` with nothing alive to finish it.
var ErrNoEnqueuer = errors.New("scan: profile scan enqueuer is not configured")

// ErrUnboundedTargetQuery is returned when a profile's TargetQuery carries no
// LIMIT, or a LIMIT above MaxTargets.
//
// This is the chokepoint the bound has to be enforced at. Bounding the
// TargetPresets (presets.go) only covers queries a user accepted verbatim: the
// workflow builder composes its own Cypher from the WHO-section chips and never
// reads TargetPresets at all, so without this check the primary way profiles
// are created could save an unbounded query. An unbounded target query does
// not scan more assets — target resolution refuses a result that hit the node
// budget, because a truncated target LIST is unusable input to a scan's scope
// decision — so the profile fails EVERY run, and it fails at run time, hours
// after the person who could fix it walked away from the form. Rejecting at
// save time turns that into an immediate, actionable error.
var ErrUnboundedTargetQuery = errors.New("scan: target query must carry a LIMIT no greater than MaxTargets")

// targetQueryLimit matches a trailing LIMIT clause, case-insensitively. Cypher
// requires LIMIT last, so anchoring to the end is what makes this a bound on
// the RESULT rather than on some inner subclause.
var targetQueryLimit = regexp.MustCompile(`(?i)\blimit\s+(\d+)\s*;?\s*$`)

// ValidateTargetQuery enforces that a non-empty TargetQuery is bounded by a
// trailing LIMIT of at most MaxTargets. An empty query is valid and means "use
// the non-Cypher ListExternal path" — see ProfileService.ResolveTargets.
func ValidateTargetQuery(q string) error {
	trimmed := strings.TrimSpace(q)
	if trimmed == "" {
		return nil
	}
	m := targetQueryLimit.FindStringSubmatch(trimmed)
	if m == nil {
		return fmt.Errorf("%w: append \"LIMIT %d\"", ErrUnboundedTargetQuery, MaxTargets)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return fmt.Errorf("%w: unparseable LIMIT %q", ErrUnboundedTargetQuery, m[1])
	}
	if n == 0 {
		// LIMIT 0 is syntactically bounded but semantically empty: the resolver
		// returns no targets and the zero-target guard then fails the run — the
		// same deferred, run-time failure this save-time check exists to move
		// forward. Reject it here rather than at 03:00 in a scheduled sweep.
		return fmt.Errorf("%w: LIMIT 0 resolves no targets", ErrUnboundedTargetQuery)
	}
	if n > MaxTargets {
		return fmt.Errorf("%w: LIMIT %d exceeds the %d a single run can scan", ErrUnboundedTargetQuery, n, MaxTargets)
	}
	return nil
}

// ─── Template validation types ────────────────────────────────────────────────

// TemplateInfo is metadata extracted from a valid nuclei template.
type TemplateInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Author      string   `json:"author,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Protocols   []string `json:"protocols"`
}

// TemplateValidationError is one lint problem found in a template.
type TemplateValidationError struct {
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

// TemplateValidation is the result of linting a nuclei YAML template.
type TemplateValidation struct {
	Valid  bool                      `json:"valid"`
	Info   *TemplateInfo             `json:"info,omitempty"`
	Errors []TemplateValidationError `json:"errors,omitempty"`
}
