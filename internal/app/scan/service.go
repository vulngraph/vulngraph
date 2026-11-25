package scan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// MaxTargets bounds a single scan run so a large inventory can't launch an
// unbounded scan.
//
// Exported because it is the bound the TARGET QUERIES themselves must carry:
// every TargetPreset ends in `LIMIT MaxTargets` (presets.go), the workflow
// builder composes the same bound (frontend WorkflowBuilder.tsx), and
// ValidateTargetQuery rejects a profile whose query lacks it. A query without
// that LIMIT does not scan more assets — it exceeds the node budget, is
// reported Truncated, and the resolver refuses it, so the profile fails every
// run. A large inventory can easily have more assets with an
// ExposedToInternet edge than the 500-node budget.
const MaxTargets = 500

// AllowInternalTargetsEnv is the explicit opt-in for scanning private and
// loopback addresses. Link-local space and the cloud metadata endpoints
// (AlwaysBlockedTargets) stay refused even then. Unset (the default), the
// scanners refuse every internal address, so a user-supplied URL or a DNS record
// pointing inward cannot turn the scanner into an SSRF proxy against the
// cluster it runs in.
const AllowInternalTargetsEnv = "SCAN_ALLOW_INTERNAL_TARGETS"

// AllowInternalTargets reports whether AllowInternalTargetsEnv is exactly "true".
func AllowInternalTargets() bool {
	return os.Getenv(AllowInternalTargetsEnv) == "true"
}

// Repo persists scan runs. PGRepo implements it.
type Repo interface {
	CreateRun(ctx context.Context, targetCount int) (Run, error)
	FinishRun(ctx context.Context, id string, status Status, findingCount int, scanErr string, tags []string, templateCount int, targetURLs []string, scannerName string) error
	CancelRun(ctx context.Context, id string) error
	GetRun(ctx context.Context, id string) (Run, error)
	ListRuns(ctx context.Context, limit int) ([]Run, error)
	// FailStaleRuns fails every run stuck in 'running' since before cutoff,
	// returning the reaped run ids. Reconciles rows orphaned by a dead worker.
	FailStaleRuns(ctx context.Context, cutoff time.Time) ([]string, error)
}

// AssetReader is the slice of the asset service the scanner needs.
type AssetReader interface {
	ListExternal(ctx context.Context, limit int) ([]asset.Asset, error)
}

// AssetResolver resolves asset identity for import attribution. ByIDs does a
// batch lookup; ListByIP searches for an asset whose public IP matches the
// given address (best-effort — returns empty string when nothing matches).
type AssetResolver interface {
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
	List(ctx context.Context, f asset.Filter) ([]asset.Asset, error)
}

// FindingRecorder records the scan's findings and supports time-range lookup
// for per-scan finding queries.
//
// RecordObserved, not Record: a periodic re-scan of an already-known target
// re-detects the SAME finding (toFindings/toImportFindings both derive a
// stable, deterministic ID), built fresh with every enrichment field at Go
// zero. Record would clobber that finding's score/must_fix_class/enriched_at
// back to blank on every re-scan; RecordObserved carries the prior
// enrichment forward instead (internal/app/finding/service.go).
type FindingRecorder interface {
	RecordObserved(ctx context.Context, findings []finding.Finding) error
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// AuditRecorder writes the audit_events row of an action that has taken
// effect, and reports its own write failures (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

type Service struct {
	audit    AuditRecorder // nil: no audit rows (the worker and scanner pods, tests)
	repo     Repo
	assets   AssetReader
	resolver AssetResolver
	scanner  Scanner
	findings FindingRecorder
	// allowInternal is AllowInternalTargets() at construction: whether targets
	// on private space pass guardTargets. Metadata endpoints never do.
	allowInternal bool
}

func NewService(repo Repo, assets AssetReader, resolver AssetResolver, scanner Scanner, findings FindingRecorder) *Service {
	return &Service{repo: repo, assets: assets, resolver: resolver, scanner: scanner, findings: findings,
		allowInternal: AllowInternalTargets()}
}

// WithAudit records the scans a person starts in audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service {
	s.audit = a
	return s
}

// StartScan enqueues a full scan of the internet-facing assets on a person's
// request and records it. A failed enqueue writes no row.
func (s *Service) StartScan(ctx context.Context, t Triggerer) error {
	if err := t.EnqueueScan(ctx); err != nil {
		return fmt.Errorf("StartScan: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, AuditActionStart, AuditTargetScan, "", map[string]any{"scope": "internet_facing"})
	}
	return nil
}

// RunScan selects internet-facing assets, scans them, records the results as
// findings, and tracks the run. It returns the completed Run and the recorded
// findings, so the caller (the worker) can hand them to the enrichment pipeline.
func (s *Service) RunScan(ctx context.Context) (Run, []finding.Finding, error) {
	externals, err := s.assets.ListExternal(ctx, MaxTargets)
	if err != nil {
		return Run{}, nil, fmt.Errorf("RunScan: %w", err)
	}
	targets, byURL := targetsFor(externals)
	targets, refused := guardTargets(ctx, targets, s.allowInternal)
	if len(refused) > 0 {
		log.FromContext(ctx).Warn().Strs("refused", refused).
			Msg("scan: targets resolving to private or metadata addresses were not scanned")
	}

	// Collect the actual URLs so the scan detail UI can show "what was scanned".
	targetURLs := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.URL != "" {
			targetURLs = append(targetURLs, t.URL)
		} else if t.Host != "" {
			targetURLs = append(targetURLs, t.Host)
		}
	}

	run, err := s.repo.CreateRun(ctx, len(targets))
	if err != nil {
		return Run{}, nil, fmt.Errorf("RunScan: %w", err)
	}
	run.TargetURLs = targetURLs

	scanOut, scanErr := s.scanner.Scan(ctx, targets, nil)
	if scanErr != nil {
		s.finish(ctx, &run, StatusFailed, 0, scanErr.Error())
		return run, nil, fmt.Errorf("RunScan: %w", scanErr)
	}

	run.TemplateTags = scanOut.TemplateTags
	run.TemplateCount = scanOut.TemplateCount
	run.ScannerName = s.scanner.Name()

	findings := toFindings(scanOut.Results, byURL, time.Now())
	if err := s.findings.RecordObserved(ctx, findings); err != nil {
		s.finish(ctx, &run, StatusFailed, 0, err.Error())
		return run, nil, fmt.Errorf("RunScan: record findings: %w", err)
	}

	s.finish(ctx, &run, StatusCompleted, len(findings), "")
	return run, findings, nil
}

// ScanTargets runs the embedded scanner against a pre-resolved set of targets.
// templateTags (from ProfileService.SelectTemplates) selects the templates; a
// nil or empty slice means the scanner chooses by asset type. Used by the
// profile scan workers.
func (s *Service) ScanTargets(ctx context.Context, targets []Target, templateTags []string) (ScanOutput, error) {
	kept, refused := guardTargets(ctx, targets, s.allowInternal)
	if len(kept) == 0 && len(refused) > 0 {
		return ScanOutput{}, fmt.Errorf("ScanTargets: %w: %s", ErrTargetRefused, strings.Join(refused, " "))
	}
	if len(refused) > 0 {
		log.FromContext(ctx).Warn().Strs("refused", refused).
			Msg("scan: targets resolving to private or metadata addresses were not scanned")
	}
	out, err := s.scanner.Scan(ctx, kept, templateTags)
	if err != nil {
		return ScanOutput{}, fmt.Errorf("ScanTargets: %w", err)
	}
	return out, nil
}

// GetRunFindings returns the nuclei findings produced during the given scan run,
// identified by matching the run's time window and source="nuclei".
func (s *Service) GetRunFindings(ctx context.Context, id string) (Run, []finding.Finding, error) {
	run, err := s.repo.GetRun(ctx, id)
	if err != nil {
		return Run{}, nil, fmt.Errorf("GetRunFindings: %w", err)
	}
	// Use a tight time window: scan start → finish (or +1h for still-running).
	// A wider window (a day) would show every scan's findings under each run.
	before := run.StartedAt.Add(time.Hour)
	if run.FinishedAt != nil {
		before = *run.FinishedAt
	}
	findings, err := s.findings.List(ctx, finding.Filter{
		Source:         "nuclei",
		DetectedAfter:  run.StartedAt,
		DetectedBefore: before,
		Limit:          200,
	})
	if err != nil {
		return run, nil, fmt.Errorf("GetRunFindings: %w", err)
	}
	return run, findings, nil
}

func (s *Service) GetRun(ctx context.Context, id string) (Run, error) {
	r, err := s.repo.GetRun(ctx, id)
	if err != nil {
		return Run{}, fmt.Errorf("GetRun: %w", err)
	}
	return r, nil
}

func (s *Service) ListRuns(ctx context.Context, limit int) ([]Run, error) {
	r, err := s.repo.ListRuns(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	return r, nil
}

// CancelRun marks the scan_runs row cancelled if it is still running. It does
// not stop the running River job or nuclei: an in-flight scan runs to
// completion and FinishRun then records its real final status.
func (s *Service) CancelRun(ctx context.Context, id string) error {
	if err := s.repo.CancelRun(ctx, id); err != nil {
		return fmt.Errorf("CancelRun: %w", err)
	}
	return nil
}

// staleRunAge is how long a run may sit in 'running' before the reaper fails it.
// It must exceed the scan job's own timeout (4h, internal/jobs/scan.go) plus
// margin, so a legitimately long scan is never killed — only genuinely orphaned
// rows (worker died before FinishRun) are reaped.
const staleRunAge = 5 * time.Hour

// ReapStaleRuns fails runs orphaned in 'running' by a dead worker and returns
// the reaped ids. Called periodically by the scan reaper job.
func (s *Service) ReapStaleRuns(ctx context.Context) ([]string, error) {
	ids, err := s.repo.FailStaleRuns(ctx, time.Now().Add(-staleRunAge))
	if err != nil {
		return nil, fmt.Errorf("ReapStaleRuns: %w", err)
	}
	return ids, nil
}

func (s *Service) finish(ctx context.Context, run *Run, status Status, findingCount int, scanErr string) {
	run.Status, run.FindingCount, run.Error = status, findingCount, scanErr
	now := time.Now()
	run.FinishedAt = &now
	if err := s.repo.FinishRun(ctx, run.ID, status, findingCount, scanErr, run.TemplateTags, run.TemplateCount, run.TargetURLs, run.ScannerName); err != nil {
		run.Error = fmt.Sprintf("%s (finish: %v)", scanErr, err)
	}
}

// targetsFor builds scannable targets from external assets and a reverse map
// from URL back to the asset, so results can be attributed to the right
// resource. Host is carried alongside URL so network scanners can use it.
func targetsFor(assets []asset.Asset) (targets []Target, byURL map[string]asset.Asset) {
	byURL = make(map[string]asset.Asset, len(assets))
	for _, a := range assets {
		host := a.Domain
		if host == "" {
			host = a.PublicIP
		}
		if host == "" {
			continue
		}
		url := "https://" + host
		if _, dup := byURL[url]; dup {
			continue
		}
		byURL[url] = a
		targets = append(targets, Target{
			URL:       url,
			Host:      host,
			AssetType: a.Type,
			Tags:      a.Tags,
		})
	}
	return targets, byURL
}

// TargetsFromAssets is the exported form of targetsFor, for callers outside
// this package that resolve a target set some other way (e.g. cmd/graph's
// Cypher-target resolver, which maps TargetQuery result nodes back to assets
// via asset.Service.ByIDs and then needs the SAME Domain/PublicIP → Host/URL
// mapping RunScan uses, so a profile's Cypher-selected assets and the
// estate-wide scan attribute findings to targets identically).
func TargetsFromAssets(assets []asset.Asset) []Target {
	targets, _ := targetsFor(assets)
	return targets
}

// assetForURL returns the asset for a matched URL using an exact lookup first,
// then falling back to scheme+host only. Nuclei returns full paths like
// "https://host.example/admin/login" but byURL is keyed by "https://host.example".
func assetForURL(matchedURL string, byURL map[string]asset.Asset) asset.Asset {
	if a, ok := byURL[matchedURL]; ok {
		return a
	}
	// Strip path: find the third slash (scheme://host/).
	if i := strings.Index(matchedURL, "://"); i >= 0 {
		rest := matchedURL[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			base := matchedURL[:i+3+j]
			if a, ok := byURL[base]; ok {
				return a
			}
		}
	}
	return asset.Asset{}
}

// toFindings maps scanner results to findings, attributing each to the asset
// behind its matched URL when known and sourcing it to the producing scanner.
func toFindings(results []Result, byURL map[string]asset.Asset, now time.Time) []finding.Finding {
	out := make([]finding.Finding, 0, len(results))
	for _, r := range results {
		a := assetForURL(r.MatchedURL, byURL)
		source := r.Scanner
		if source == "" {
			source = "nuclei"
		}

		// Resource attribution: prefer the matched asset; otherwise fall back to the
		// scanned URL so the detail view always shows *what* was scanned, never
		// "Resource —" just because the URL isn't a known asset.
		resourceType, resourceID, resourceName := a.Type, a.ID, a.Name
		if resourceID == "" && r.MatchedURL != "" {
			resourceType, resourceID, resourceName = "endpoint", r.MatchedURL, r.MatchedURL
		}

		// Metadata carries the scanner-native context (matched URL, evidence,
		// references) that has no dedicated finding column. Stored in the findings
		// `tags` map and surfaced in the detail view's Detection section.
		meta := map[string]string{}
		if r.MatchedURL != "" {
			meta["matched_url"] = r.MatchedURL
		}
		if r.Evidence != "" {
			meta["evidence"] = r.Evidence
		}
		if r.Reference != "" {
			meta["references"] = r.Reference
		}
		// A template that maps to a CVE (via its classification block) carries it
		// here even when CheckID is a template slug — lets KEV/EPSS enrichment
		// join the finding to known-exploited / exploit-probability data.
		if r.CVE != "" {
			meta["cve"] = r.CVE
		}

		out = append(out, finding.Finding{
			ID:           dbutil.DeterministicID(source, r.TemplateID, r.MatchedURL),
			Source:       source,
			Type:         "vulnerability",
			Severity:     normalizeSeverity(r.Severity),
			Title:        r.Name,
			Description:  r.Description,
			Remediation:  r.Remediation,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			ResourceName: resourceName,
			Region:       a.Region,
			CheckID:      r.TemplateID,
			DetectedAt:   now,
			Metadata:     meta,
		})
	}
	return out
}

// ImportRequest carries findings from an external commercial scanner into the
// platform. Source must be one of the known scanner slugs; AssetID/AssetIP
// identify the target asset (AssetID takes precedence).
type ImportRequest struct {
	Source    string
	SourceRef string
	AssetID   string
	AssetIP   string
	Findings  []ImportFinding
}

// ImportFinding is one finding from an external scanner, before mapping to
// the internal Finding type.
type ImportFinding struct {
	CheckID     string
	Title       string
	Severity    string
	Description string
	Reference   string
	MatchedAt   string
}

// validImportSources are the accepted Source slugs for imported scans.
var validImportSources = map[string]bool{
	"openvas": true,
	"qualys":  true,
	"burp":    true,
	"custom":  true,
}

// ImportFindings creates a synthetic completed scan run attributed to an
// external scanner, records all supplied findings, and returns the created run.
// Asset attribution is best-effort: AssetID is preferred; AssetIP triggers a
// search; if neither resolves, findings are recorded without resource metadata.
func (s *Service) ImportFindings(ctx context.Context, req ImportRequest) (Run, error) {
	if !validImportSources[req.Source] {
		return Run{}, fmt.Errorf("ImportFindings: unsupported source %q", req.Source)
	}

	// Resolve the target asset for attribution.
	var a asset.Asset
	switch {
	case req.AssetID != "":
		assets, err := s.resolver.ByIDs(ctx, []string{req.AssetID})
		if err != nil {
			return Run{}, fmt.Errorf("ImportFindings: resolve asset: %w", err)
		}
		if len(assets) > 0 {
			a = assets[0]
		}
	case req.AssetIP != "":
		// List is a substring search — PublicIP match is best-effort.
		assets, err := s.resolver.List(ctx, asset.Filter{Search: req.AssetIP, Limit: 1})
		if err != nil {
			return Run{}, fmt.Errorf("ImportFindings: resolve asset by IP: %w", err)
		}
		for _, candidate := range assets {
			if candidate.PublicIP == req.AssetIP {
				a = candidate
				break
			}
		}
	}

	targetCount := 1
	if req.AssetID == "" && req.AssetIP == "" {
		targetCount = 0
	}

	run, err := s.repo.CreateRun(ctx, targetCount)
	if err != nil {
		return Run{}, fmt.Errorf("ImportFindings: %w", err)
	}

	now := time.Now()
	findings := toImportFindings(req, a, now)
	if err := s.findings.RecordObserved(ctx, findings); err != nil {
		s.finish(ctx, &run, StatusFailed, 0, err.Error())
		return run, fmt.Errorf("ImportFindings: record findings: %w", err)
	}

	run.ScannerName = req.Source
	run.TemplateTags = []string{}
	s.finish(ctx, &run, StatusCompleted, len(findings), "")
	return run, nil
}

// toImportFindings converts external ImportFindings to internal findings,
// attributing each to the resolved asset (if any).
func toImportFindings(req ImportRequest, a asset.Asset, now time.Time) []finding.Finding {
	out := make([]finding.Finding, 0, len(req.Findings))
	for _, f := range req.Findings {
		matchedAt := f.MatchedAt
		if matchedAt == "" {
			matchedAt = req.AssetIP
		}
		out = append(out, finding.Finding{
			ID:           dbutil.DeterministicID(req.Source, f.CheckID, matchedAt),
			Source:       req.Source,
			Type:         "vulnerability",
			Severity:     normalizeSeverity(f.Severity),
			Title:        f.Title,
			Description:  f.Description,
			ResourceType: a.Type,
			ResourceID:   a.ID,
			ResourceName: a.Name,
			Region:       a.Region,
			CheckID:      f.CheckID,
			Remediation:  f.Reference,
			DetectedAt:   now,
		})
	}
	return out
}

func normalizeSeverity(s string) finding.Severity {
	switch finding.Severity(s) {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityInfo:
		return finding.Severity(s)
	default:
		return finding.SeverityInfo
	}
}
