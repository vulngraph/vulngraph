package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ProfileRepo persists scan profiles and their per-asset findings; the
// Postgres implementation is in profile_repo.go.
type ProfileRepo interface {
	CreateProfile(ctx context.Context, name, description string, tags []string, enabled bool, targetQuery string, driftEnabled bool, schedule string, scannerType string, templateStrategy string) (ScanProfile, error)
	GetProfile(ctx context.Context, id string) (ScanProfile, error)
	ListProfiles(ctx context.Context) ([]ScanProfile, error)
	UpdateProfile(ctx context.Context, id, name, description string, tags []string, enabled bool, targetQuery string, driftEnabled bool, schedule string, scannerType string, templateStrategy string) (ScanProfile, error)
	DeleteProfile(ctx context.Context, id string) error

	// CreateRunForProfile creates a scan run linked to the given profile ID.
	// It is a variant of Repo.CreateRun that also sets the profile_id column.
	CreateRunForProfile(ctx context.Context, profileID string, targetCount int) (Run, error)

	// CreateRunForProfileAndEnqueue is CreateRunForProfile plus an atomic
	// follow-up job enqueue: it opens a Postgres transaction, inserts the run
	// row, calls enqueue with the open tx and the new run's ID, and commits
	// only if enqueue succeeds. Used by TriggerProfileScan, whose
	// run always has a follow-up ScanProfileJobArgs job; CreateRunForProfile
	// stays plain for callers (e.g. ScanAssetWorker) that execute the scan
	// synchronously and enqueue nothing.
	CreateRunForProfileAndEnqueue(ctx context.Context, profileID string, targetCount int, enqueue func(ctx context.Context, tx pgx.Tx, runID string) error) (Run, error)

	// GetScanFindingByAssetCheck returns the current open finding record for
	// the (assetID, checkID) pair, or ErrProfileNotFound when none exists.
	GetScanFindingByAssetCheck(ctx context.Context, assetID, checkID string) (ScanFinding, error)

	// BatchGetScanFindingsByAssetIDs returns the latest scan finding per
	// (asset_id, check_id) for all provided asset IDs in one query — replaces
	// the per-finding N+1 loop in ReconcileFindingLifecycle.
	BatchGetScanFindingsByAssetIDs(ctx context.Context, assetIDs []string) ([]ScanFinding, error)

	// UpsertScanFinding writes a new or updated ScanFinding row.
	UpsertScanFinding(ctx context.Context, f ScanFinding) error

	// ListOpenScanFindingsByRun returns confirmed findings from earlier runs of
	// the SAME profile as currentRunID (derived from the run) — the candidates
	// for auto-resolution after a clean re-scan. It never crosses profiles.
	ListOpenScanFindingsByRun(ctx context.Context, currentRunID string) ([]ScanFinding, error)

	// ListDriftEnabledProfiles returns all enabled profiles with drift
	// scanning on — see ListDriftEnabledProfileIDs below, the only caller.
	ListDriftEnabledProfiles(ctx context.Context) ([]ScanProfile, error)
}

// ProfileJobEnqueuer enqueues a profile-scoped scan job on an already-open
// Postgres transaction, via river.InsertTx. Implemented by internal/jobs so
// the service stays free of River types — pgx.Tx is the one Postgres type
// that has to cross this boundary for CreateRunForProfileAndEnqueue to
// enqueue on the same transaction as its row write. The services-no-storage
// depguard rule (.golangci.yml) matches only service.go and service_*.go, so
// it does not check this file's imports.
type ProfileJobEnqueuer interface {
	EnqueueProfileScan(ctx context.Context, tx pgx.Tx, profileID, runID string) error
}

// ExternalAssetLister fetches internet-exposed assets. *asset.Service satisfies this.
type ExternalAssetLister interface {
	ListExternal(ctx context.Context, limit int) ([]asset.Asset, error)
}

// ScannerRunner runs a single target. The ScannerRegistry returns one per name.
type ScannerRunner interface {
	Run(ctx context.Context, target Target, opts ScanOptions) ([]Result, error)
}

// ScanOptions carries per-run options forwarded to the scanner.
type ScanOptions struct {
	// Tags restricts the template set. Empty means "all templates".
	Tags []string
}

// ScannerRegistry resolves a named scanner connector.
type ScannerRegistry interface {
	Get(name string) (ScannerRunner, bool)
}

// ScanProfileJobArgs is the River job payload for a profile-scoped scan run.
// Kept in this file so the jobs package can reference it via a shared import
// without pulling in any River dependency into the scan package itself.
type ScanProfileJobArgs struct {
	ProfileID string `json:"profile_id"`
	RunID     string `json:"run_id"`
}

// ProfileService manages scan profiles and drives profile-scoped scan runs.
type ProfileService struct {
	audit    AuditRecorder // nil: no audit rows (the worker and scanner pods, tests)
	profiles ProfileRepo
	runs     Repo
	scanners ScannerRegistry
	assets   ExternalAssetLister
	enqueuer ProfileJobEnqueuer
}

// WithAudit records scan-profile creates, updates and deletes, and the
// profile scans a person starts, in audit_events: a profile decides what is
// actively probed and when.
func (s *ProfileService) WithAudit(a AuditRecorder) *ProfileService {
	s.audit = a
	return s
}

func (s *ProfileService) record(ctx context.Context, action, id string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetScanProfile, id, details)
	}
}

// profileAuditView is what an audit row keeps of a profile's definition.
func profileAuditView(p ScanProfile) map[string]any {
	return map[string]any{
		"name": p.Name, "target_query": p.TargetQuery, "scanner_type": p.ScannerType,
		"template_strategy": string(p.TemplateStrategy), "template_tags": p.TemplateTags,
		"schedule": p.Schedule, "enabled": p.Enabled, "drift_enabled": p.DriftEnabled,
	}
}

// NewProfileService constructs a ProfileService. scanners and enqueuer may
// be nil when those features are not configured; nil values cause the
// corresponding methods to return a clear error at call time. A nil enqueuer is
// the normal wiring on the scanner pod, which executes runs but never triggers
// them — TriggerProfileScan returns ErrNoEnqueuer there, before it writes a run.
func NewProfileService(
	profiles ProfileRepo,
	runs Repo,
	scanners ScannerRegistry,
	assets ExternalAssetLister,
	enqueuer ProfileJobEnqueuer,
) *ProfileService {
	return &ProfileService{
		profiles: profiles,
		runs:     runs,
		scanners: scanners,
		assets:   assets,
		enqueuer: enqueuer,
	}
}

// ── Profile CRUD (thin delegation to repo) ────────────────────────────────────

func (s *ProfileService) CreateProfile(ctx context.Context, name, description string, tags []string, enabled bool, targetQuery string, driftEnabled bool, schedule string, scannerType string, templateStrategy string) (ScanProfile, error) {
	if err := ValidateTargetQuery(targetQuery); err != nil {
		return ScanProfile{}, fmt.Errorf("CreateProfile: %w", err)
	}
	if err := ScheduleError(schedule); err != nil {
		return ScanProfile{}, fmt.Errorf("CreateProfile: %w", err)
	}
	if TemplateStrategy(templateStrategy) == StrategyAIContextual {
		return ScanProfile{}, fmt.Errorf("CreateProfile: %w: %s needs an LLM tag selector on the pods that run profiles, and none is wired", ErrStrategyUnavailable, StrategyAIContextual)
	}
	p, err := s.profiles.CreateProfile(ctx, name, description, tags, enabled, targetQuery, driftEnabled, schedule, scannerType, templateStrategy)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("CreateProfile: %w", err)
	}
	s.record(ctx, AuditActionProfileCreate, p.ID, profileAuditView(p))
	return p, nil
}

func (s *ProfileService) GetProfile(ctx context.Context, id string) (ScanProfile, error) {
	p, err := s.profiles.GetProfile(ctx, id)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("GetProfile: %w", err)
	}
	return p, nil
}

func (s *ProfileService) ListProfiles(ctx context.Context) ([]ScanProfile, error) {
	ps, err := s.profiles.ListProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListProfiles: %w", err)
	}
	return ps, nil
}

// ListDriftEnabledProfileIDs returns the IDs of enabled, drift-triggered scan
// profiles — the set jobs.Enqueuer.EnqueueDriftScans fans a scan out to for
// every externally-reachable asset a connector sync reports as changed.
// IDs only (not ScanProfile) so the caller-facing interface (jobs.driftProfileLister)
// stays satisfiable from outside this package without importing scan's types.
func (s *ProfileService) ListDriftEnabledProfileIDs(ctx context.Context) ([]string, error) {
	profiles, err := s.profiles.ListDriftEnabledProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListDriftEnabledProfileIDs: %w", err)
	}
	ids := make([]string, len(profiles))
	for i, p := range profiles {
		ids[i] = p.ID
	}
	return ids, nil
}

func (s *ProfileService) UpdateProfile(ctx context.Context, id, name, description string, tags []string, enabled bool, targetQuery string, driftEnabled bool, schedule string, scannerType string, templateStrategy string) (ScanProfile, error) {
	if err := ValidateTargetQuery(targetQuery); err != nil {
		return ScanProfile{}, fmt.Errorf("UpdateProfile: %w", err)
	}
	if err := ScheduleError(schedule); err != nil {
		return ScanProfile{}, fmt.Errorf("UpdateProfile: %w", err)
	}
	if TemplateStrategy(templateStrategy) == StrategyAIContextual {
		return ScanProfile{}, fmt.Errorf("UpdateProfile: %w: %s needs an LLM tag selector on the pods that run profiles, and none is wired", ErrStrategyUnavailable, StrategyAIContextual)
	}
	before, err := s.profiles.GetProfile(ctx, id)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("UpdateProfile: %w", err)
	}
	p, err := s.profiles.UpdateProfile(ctx, id, name, description, tags, enabled, targetQuery, driftEnabled, schedule, scannerType, templateStrategy)
	if err != nil {
		return ScanProfile{}, fmt.Errorf("UpdateProfile: %w", err)
	}
	s.record(ctx, AuditActionProfileUpdate, p.ID, map[string]any{"before": profileAuditView(before), "after": profileAuditView(p)})
	return p, nil
}

// DeleteProfile removes a profile; its audit row keeps the definition the
// delete destroyed.
func (s *ProfileService) DeleteProfile(ctx context.Context, id string) error {
	before, err := s.profiles.GetProfile(ctx, id)
	if err != nil {
		return fmt.Errorf("DeleteProfile: %w", err)
	}
	if err := s.profiles.DeleteProfile(ctx, id); err != nil {
		return fmt.Errorf("DeleteProfile: %w", err)
	}
	s.record(ctx, AuditActionProfileDelete, id, profileAuditView(before))
	return nil
}

// ── Trigger ───────────────────────────────────────────────────────────────────

// TriggerProfileScan loads the profile, creates a linked scan run, and enqueues
// a ScanProfileJobArgs River job on the SAME Postgres transaction as the run
// row, and returns the run ID. The actual scan executes
// asynchronously in the worker.
//
// The enqueuer is checked FIRST, before any row is written: a nil enqueuer
// (an unwired ProfileService) reached AFTER the run row committed would
// panic, River would recover it into a job error, and the run would stay
// stuck `running` with nothing alive to finish it. This guard is
// necessary but not sufficient — a CONFIGURED enqueuer whose actual call
// fails, or a crash between the two statements, could strand a run exactly
// the same way; CreateRunForProfileAndEnqueue's transaction is what closes
// that remaining gap.
//
// The schedule runner calls it; a person's trigger goes through
// StartProfileScan, which also writes the audit row.
func (s *ProfileService) TriggerProfileScan(ctx context.Context, profileID string) (string, error) {
	_, run, err := s.triggerProfileScan(ctx, profileID)
	if err != nil {
		return "", fmt.Errorf("TriggerProfileScan: %w", err)
	}
	return run.ID, nil
}

// StartProfileScan is TriggerProfileScan on a person's request: once the run
// is created and enqueued it records the start in audit_events. A refused or
// failed trigger writes no row.
func (s *ProfileService) StartProfileScan(ctx context.Context, profileID string) (string, error) {
	profile, run, err := s.triggerProfileScan(ctx, profileID)
	if err != nil {
		return "", fmt.Errorf("StartProfileScan: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, AuditActionProfileStart, AuditTargetScanProfile, profile.ID, map[string]any{
			"run_id":            run.ID,
			"name":              profile.Name,
			"scanner_type":      profile.ScannerType,
			"template_strategy": string(profile.TemplateStrategy),
			"target_query":      profile.TargetQuery,
		})
	}
	return run.ID, nil
}

func (s *ProfileService) triggerProfileScan(ctx context.Context, profileID string) (ScanProfile, Run, error) {
	if s.enqueuer == nil {
		return ScanProfile{}, Run{}, ErrNoEnqueuer
	}
	profile, err := s.profiles.GetProfile(ctx, profileID)
	if err != nil {
		return ScanProfile{}, Run{}, fmt.Errorf("get profile: %w", err)
	}
	run, err := s.profiles.CreateRunForProfileAndEnqueue(ctx, profile.ID, 0, func(ctx context.Context, tx pgx.Tx, runID string) error {
		return s.enqueuer.EnqueueProfileScan(ctx, tx, profile.ID, runID)
	})
	if err != nil {
		return ScanProfile{}, Run{}, fmt.Errorf("create run: %w", err)
	}
	return profile, run, nil
}

// ── Target resolution ─────────────────────────────────────────────────────────

// ResolveTargets returns the scan targets for a profile.
//
// When profile.TargetQuery is empty all internet-exposed assets are returned
// (the same set the standard RunScan uses).
//
// A non-empty profile.TargetQuery is resolved by the profile scan worker through
// jobs.Deps.CypherResolver (cmd/graph/cypher_target_resolver.go). This method
// returns an error for that case on purpose, so the service layer does not
// import explore.
func (s *ProfileService) ResolveTargets(ctx context.Context, profile ScanProfile) ([]Target, error) {
	if profile.TargetQuery != "" {
		return nil, fmt.Errorf("ResolveTargets: graph-query target resolution must be handled by the worker; profile %s has a non-empty TargetQuery", profile.ID)
	}

	externals, err := s.assets.ListExternal(ctx, MaxTargets)
	if err != nil {
		return nil, fmt.Errorf("ResolveTargets: %w", err)
	}
	targets, _ := targetsFor(externals)
	return targets, nil
}

// ── Template selection ────────────────────────────────────────────────────────

// SelectTemplates returns the template tags to pass to the scanner for one
// target under the profile's strategy. Returning nil means the scanner uses
// its default selection by asset type (StrategyAll).
func (s *ProfileService) SelectTemplates(ctx context.Context, profile ScanProfile, target Target) ([]string, error) {
	switch profile.TemplateStrategy {
	case StrategyAll:
		return nil, nil

	case StrategyTags:
		return profile.TemplateTags, nil

	case StrategyAIContextual:
		return nil, fmt.Errorf("SelectTemplates: %w: %s", ErrStrategyUnavailable, StrategyAIContextual)

	default:
		return nil, fmt.Errorf("SelectTemplates: unknown template strategy %q", profile.TemplateStrategy)
	}
}

// ── Finding lifecycle reconciliation ─────────────────────────────────────────

// ReconcileFindingLifecycle merges the fresh findings from a scan run into the
// persistent scan_findings table. completedTargets holds the AssetID keys of
// the targets whose scan actually finished; only their findings can be
// resolved, because absence from an errored target's (empty) result is not
// evidence the finding is gone.
//
// Rules:
//   - Finding with no existing record: created as ScanFindingNew.
//   - Finding with existing "resolved" record: status set to ScanFindingRegressed.
//   - Finding with existing "confirmed" record: last_seen_at bumped, no status change.
//   - Existing "confirmed" findings of a completed target absent from
//     newFindings: marked ScanFindingResolved. Confirmed findings of any other
//     target are left untouched.
func (s *ProfileService) ReconcileFindingLifecycle(ctx context.Context, scanRunID string, newFindings []ScanFinding, completedTargets []string) error {
	now := time.Now()

	// Track which (assetID, checkID) pairs are present in the new scan. One
	// template can match a host more than once (different URLs or ports); the
	// table holds one row per pair, so only the first result of a pair is kept.
	seen := make(map[string]struct{}, len(newFindings))
	unique := newFindings[:0:0]
	assetIDs := make([]string, 0, len(newFindings))
	for _, f := range newFindings {
		key := f.AssetID + "\x00" + f.CheckID
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, f)
		assetIDs = append(assetIDs, f.AssetID)
	}
	newFindings = unique

	// Pre-fetch all existing findings for these assets in one query — replaces
	// the per-finding GetScanFindingByAssetCheck N+1 loop below.
	priorBatch, err := s.profiles.BatchGetScanFindingsByAssetIDs(ctx, assetIDs)
	if err != nil {
		return fmt.Errorf("ReconcileFindingLifecycle: BatchGetScanFindingsByAssetIDs: %w", err)
	}
	existingByKey := make(map[string]ScanFinding, len(priorBatch))
	for _, f := range priorBatch {
		existingByKey[f.AssetID+"\x00"+f.CheckID] = f
	}

	// Process each incoming finding.
	for _, incoming := range newFindings {
		existing, ok := existingByKey[incoming.AssetID+"\x00"+incoming.CheckID]
		if !ok {
			// New finding — never seen before.
			incoming.ScanRunID = scanRunID
			incoming.Status = ScanFindingNew
			incoming.FirstSeenAt = now
			incoming.LastSeenAt = now
			if err := s.profiles.UpsertScanFinding(ctx, incoming); err != nil {
				return fmt.Errorf("ReconcileFindingLifecycle: upsert new finding: %w", err)
			}
			continue
		}

		switch existing.Status {
		case ScanFindingResolved:
			// Previously resolved and now reappearing.
			existing.Status = ScanFindingRegressed
			existing.ScanRunID = scanRunID
			existing.LastSeenAt = now
			existing.ResolvedAt = nil
		case ScanFindingConfirmed:
			// Still present — bump last seen.
			existing.LastSeenAt = now
		default:
			// new/regressed: keep status, update last seen.
			existing.LastSeenAt = now
		}

		if err := s.profiles.UpsertScanFinding(ctx, existing); err != nil {
			return fmt.Errorf("ReconcileFindingLifecycle: upsert existing finding: %w", err)
		}
	}

	// Auto-resolve confirmed findings that did not appear in this scan.
	// Only confirmed findings are auto-resolved; new/regressed findings wait
	// for explicit triage before they can be resolved.
	// Scoped to this run's own profile inside the repo query — a run of one
	// profile must never auto-resolve another profile's confirmed findings.
	prior, err := s.profiles.ListOpenScanFindingsByRun(ctx, scanRunID)
	if err != nil {
		return fmt.Errorf("ReconcileFindingLifecycle: ListOpenScanFindingsByRun: %w", err)
	}

	completed := make(map[string]struct{}, len(completedTargets))
	for _, t := range completedTargets {
		completed[t] = struct{}{}
	}
	for _, f := range prior {
		if _, ok := completed[f.AssetID]; !ok {
			continue // this run did not finish scanning the finding's target
		}
		key := f.AssetID + "\x00" + f.CheckID
		if _, present := seen[key]; present {
			continue // still in the new scan — already handled above
		}
		if f.Status != ScanFindingConfirmed {
			continue
		}
		f.Status = ScanFindingResolved
		f.ResolvedAt = &now
		f.LastSeenAt = now
		if err := s.profiles.UpsertScanFinding(ctx, f); err != nil {
			return fmt.Errorf("ReconcileFindingLifecycle: resolve finding %s: %w", f.ID, err)
		}
	}

	return nil
}

// ── Wrappers for worker-side drift execution ──────────────────────────────────
//
// ScanAssetWorker (in internal/jobs) creates its own run and finishes it;
// these thin wrappers expose the needed repo operations through ProfileService
// so the worker never imports repo types directly.

// CreateRunForProfile delegates to the profile repo so the worker can create
// a run that is correctly linked to a profile ID.
func (s *ProfileService) CreateRunForProfile(ctx context.Context, profileID string, targetCount int) (Run, error) {
	return s.profiles.CreateRunForProfile(ctx, profileID, targetCount)
}

// FinishRun marks a profile run as completed or failed. It uses sensible
// defaults for the extra repo params (empty tags/URLs, scanner = "nuclei").
func (s *ProfileService) FinishRun(ctx context.Context, runID string, status Status, findingCount int, errMsg string) error {
	return s.runs.FinishRun(ctx, runID, status, findingCount, errMsg, nil, 0, nil, "nuclei")
}
