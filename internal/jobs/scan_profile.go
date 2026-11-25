package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ScanProfileJobArgs triggers a single profile run identified by both profile
// and run IDs. The run record must already exist before the job is inserted so
// the UI can reflect "queued" state immediately.
type ScanProfileJobArgs struct {
	ProfileID string `json:"profile_id"`
	RunID     string `json:"run_id"`
}

func (ScanProfileJobArgs) Kind() string { return "scan_profile" }

// InsertOpts routes profile runs to queueScan with MaxAttempts=1 — these are
// execute-class jobs that either ran or errored; retries would re-fire nuclei over
// the same targets without any new signal.
//
// queueScan is the NUCLEI lane, and a profile run is a nuclei fan-out
// (scanProfileConcurrency = 10, up to 4h): it belongs on the pod that owns the
// nuclei budget, sharing that pod's one scan slot with the estate scan. A pod
// that consumes this queue without a real worker for the kind resolves every
// scan_profile to rescueOnlyWorker and discards it at MaxAttempts 1 — see
// Deps.ScanWorkerDisabled for which pod registers it.
func (ScanProfileJobArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: queueScan, MaxAttempts: 1}
}

// ScanAssetArgs triggers an immediate scan of a single asset under a specific
// profile. Used by drift scanning: when a connector sync reports that an
// internet-exposed asset changed, each drift-enabled profile enqueues one of
// these so the asset is scanned immediately rather than at the next scheduled run.
type ScanAssetArgs struct {
	ProfileID string `json:"profile_id"`
	AssetID   string `json:"asset_id"`
	// Trigger records why this scan was enqueued: "drift", "manual", or "schedule".
	Trigger string `json:"trigger"`
}

func (ScanAssetArgs) Kind() string { return "scan_asset" }

// InsertOpts routes drift scans to queueScan: a drift scan runs nuclei over one
// asset, so it belongs with the rest of the nuclei work on the pod that owns that
// budget, sharing its single scan slot.
func (ScanAssetArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       queueScan,
		MaxAttempts: 1,
		// Deduplicate: one PENDING drift scan per asset per profile is enough. If
		// the asset changes again before the scan runs, the existing job covers it.
		//
		// ByState is set explicitly because River's UniqueOptsByStateDefault
		// includes `completed`, and River keeps completed jobs for 24h — so the
		// default would have made a successful drift scan suppress every re-scan of
		// the same (profile, asset) pair for a further day. Drift means the asset
		// CHANGED AGAIN; suppressing that is the opposite of the intent. uniqueStates
		// is the in-flight set (and contains River's required states).
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// profileRunStore updates the run lifecycle stored in Postgres.
// *scan.ProfileService implements it.
//
// It deliberately has no StartRun: CreateRunForProfile already inserts the row
// with status 'running' and started_at = now(), so a StartRun would be a no-op
// write.
type profileRunStore interface {
	GetProfile(ctx context.Context, profileID string) (scan.ScanProfile, error)
	FinishRun(ctx context.Context, runID string, status scan.Status, findingCount int, errMsg string) error
}

// targetResolver turns a profile's target query into concrete scan targets.
// *scan.ProfileService implements it.
type targetResolver interface {
	ResolveTargets(ctx context.Context, profile scan.ScanProfile) ([]scan.Target, error)
}

// templateSelector picks templates appropriate for a profile and target.
// *scan.ProfileService implements it.
type templateSelector interface {
	SelectTemplates(ctx context.Context, profile scan.ScanProfile, target scan.Target) ([]string, error)
}

// lifecycleReconciler closes out stale findings after a profile run completes.
// *scan.ProfileService implements it.
type lifecycleReconciler interface {
	ReconcileFindingLifecycle(ctx context.Context, scanRunID string, newFindings []scan.ScanFinding, completedTargets []string) error
}

// cypherTargetResolver resolves a Ladybug Cypher query to a list of scan targets.
// Defined here (not in explore) to satisfy the domain layering — the worker pod
// injects an explore.CypherRunner-backed implementation at startup.
type cypherTargetResolver interface {
	// ResolveFromCypher runs the Cypher query and maps returned Asset nodes to
	// scan targets. Returns an empty slice (not an error) when the query matches
	// nothing — an empty target set is a valid profile state, not a failure.
	ResolveFromCypher(ctx context.Context, query string) ([]scan.Target, error)
}

// profileRunner is the union of all profile-service capabilities the worker
// needs. *scan.ProfileService satisfies it.
type profileRunner interface {
	profileRunStore
	targetResolver
	templateSelector
	lifecycleReconciler
}

// profileFindingRecorder records findings produced by a profile run.
// *finding.Service satisfies it. RecordObserved, not Record: a nuclei profile
// re-run re-detecting the same finding is an OBSERVATION, and must go through
// RecordObserved's carry-forward-enrichment protection
// (finding/service.go) — the same reasoning as every other producer's
// FindingStore.RecordObserved (internal/jobs/kev.go).
type profileFindingRecorder interface {
	RecordObserved(ctx context.Context, findings []finding.Finding) error
}

// profileScanner runs a scan over a subset of targets selected by a profile.
// *scan.Service satisfies it via its embedded Scanner.
type profileScanner interface {
	ScanTargets(ctx context.Context, targets []scan.Target, templateIDs []string) (scan.ScanOutput, error)
}

// ScanProfileWorker executes one profile run: resolves targets, fans out scans,
// records findings, then reconciles lifecycle state (resolved/regressed).
type ScanProfileWorker struct {
	river.WorkerDefaults[ScanProfileJobArgs]
	profiles profileRunner
	scanSvc  profileScanner
	finder   profileFindingRecorder
	// cypherResolver resolves TargetQuery Cypher to scan targets. Wired from
	// cmd/graph with either a local *graphstore.Service (all-in-one worker pod,
	// which holds the Ladybug primary) or an explore.LadybugRPCRepo dialed at
	// LADYBUG_RPC_URL (the split-topology scanner pod, which has no local graph).
	// When nil and a profile has a non-empty TargetQuery, Work returns an
	// explicit "not configured" error rather than silently scanning the wrong
	// (all-externals) target set.
	cypherResolver cypherTargetResolver
}

// Timeout gives profile runs up to 4 hours — the same ceiling as the global
// nuclei scan. A large profile can target hundreds of assets; 4h gives headroom.
func (ScanProfileWorker) Timeout(_ *river.Job[ScanProfileJobArgs]) time.Duration {
	return 4 * time.Hour
}

// scanProfileConcurrency is the maximum number of targets scanned in parallel
// within one profile run. Nuclei is CPU/network-heavy; 10 is a ceiling
// that keeps the scanner pod below saturation while still pipelining I/O waits.
const scanProfileConcurrency = 10

func (w *ScanProfileWorker) Work(ctx context.Context, job *river.Job[ScanProfileJobArgs]) error {
	logger := log.FromContext(ctx).With().
		Str("profile_id", job.Args.ProfileID).
		Str("run_id", job.Args.RunID).
		Logger()

	start := time.Now()

	profile, err := w.profiles.GetProfile(ctx, job.Args.ProfileID)
	if err != nil {
		return fmt.Errorf("Work: load profile: %w", err)
	}

	// Resolve targets: if the profile has a Cypher TargetQuery, run it via the
	// graph engine. A non-empty TargetQuery with no resolver configured is NOT
	// the same as "no query" — it must fail loudly and name the missing
	// dependency, not silently fall back to ResolveTargets's all-externals path
	// (which would scan a completely different, unintended target set) nor rely
	// on ResolveTargets's own generic error (which does not reflect this
	// worker's ability to resolve Cypher itself).
	var targets []scan.Target
	if profile.TargetQuery != "" {
		if w.cypherResolver == nil {
			err = fmt.Errorf("Work: profile %s has a non-empty TargetQuery but no cypherResolver is configured on this pod (set LADYBUG_RPC_URL, or run on a pod with local Ladybug graph access)", profile.ID)
		} else {
			targets, err = w.cypherResolver.ResolveFromCypher(ctx, profile.TargetQuery)
		}
	} else {
		targets, err = w.profiles.ResolveTargets(ctx, profile)
	}
	if err != nil {
		w.failRun(ctx, job.Args.RunID, err)
		return fmt.Errorf("Work: resolve targets: %w", err)
	}

	// A Cypher-driven profile that resolves to zero targets must not look like
	// a clean, complete run. A cold/rebuilding Ladybug or a broken Cypher
	// query answers with an empty result the same way a genuine zero-match
	// does, so this refuses to treat "zero targets" as success when a
	// TargetQuery was actually supplied. This does not apply to the
	// no-TargetQuery (all-externals) path: a genuinely empty external estate
	// is a normal state there.
	if profile.TargetQuery != "" && len(targets) == 0 {
		err = fmt.Errorf("Work: profile %s resolved zero targets from its TargetQuery — refusing to run (an empty result cannot be told apart from a cold or broken graph)", profile.ID)
		w.failRun(ctx, job.Args.RunID, err)
		return fmt.Errorf("Work: resolve targets: %w", err)
	}

	logger.Info().Int("targets", len(targets)).Msg("profile run starting")

	// Fan out per-target scans with a bounded semaphore so the scanner pod is
	// never saturated. Each goroutine selects its own template list, then scans.
	type result struct {
		target       string // scanTargetKey of a target whose scan completed
		findings     []finding.Finding
		scanFindings []scan.ScanFinding
		err          error
	}

	sem := make(chan struct{}, scanProfileConcurrency)
	results := make(chan result, len(targets))
	var wg sync.WaitGroup

	for _, t := range targets {
		t := t // capture loop var
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if p := recover(); p != nil {
					logger.Error().Interface("panic", p).Str("host", t.Host).Msg("scan_profile: target goroutine panicked")
					results <- result{err: fmt.Errorf("panic for target %s: %v", t.Host, p)}
				}
			}()

			sem <- struct{}{}
			defer func() { <-sem }()

			templateIDs, err := w.profiles.SelectTemplates(ctx, profile, t)
			if err != nil {
				results <- result{err: fmt.Errorf("SelectTemplates %s: %w", t.Host, err)}
				return
			}

			out, err := w.scanSvc.ScanTargets(ctx, []scan.Target{t}, templateIDs)
			if err != nil {
				results <- result{err: fmt.Errorf("ScanTargets %s: %w", t.Host, err)}
				return
			}

			now := time.Now()
			found := profileResultsToFindings(job.Args.RunID, out.Results, t, now)
			sf := profileResultsToScanFindings(job.Args.RunID, out.Results, t, now)
			results <- result{target: scanTargetKey(t), findings: found, scanFindings: sf}
		}()
	}

	// Close results once all goroutines finish so the drain loop below exits.
	//
	// Deferred recover, not cmd/graph's safego (that's package main; this is a
	// library package): if this goroutine panics before close(results), the drain
	// loop below blocks forever on a channel nobody will close, wedging a River
	// worker slot until the pod restarts. Recovering and still closing the channel
	// converts that hang into a normal, empty drain. resultsClosed lives outside
	// the goroutine so the recover can be its FIRST statement.
	resultsClosed := false
	go func() {
		defer func() {
			if p := recover(); p != nil {
				logger.Error().Interface("panic", p).Msg("scan_profile: results-closer goroutine panicked")
				if !resultsClosed {
					close(results) // the panic was in wg.Wait(); the channel is still open
				}
			}
		}()
		wg.Wait()
		resultsClosed = true
		close(results)
	}()

	var (
		allFindings     []finding.Finding
		allScanFindings []scan.ScanFinding
		completed       []string
		scanErrs        []error
	)
	for r := range results {
		if r.err != nil {
			scanErrs = append(scanErrs, r.err)
			continue
		}
		completed = append(completed, r.target)
		allFindings = append(allFindings, r.findings...)
		allScanFindings = append(allScanFindings, r.scanFindings...)
	}

	// Partial failures are logged but don't abort the run — we still record
	// whatever findings we gathered and reconcile lifecycle for the targets that
	// did succeed. An errored target returned no results, which says nothing
	// about its findings, so only completed targets may resolve any.
	for _, e := range scanErrs {
		logger.Warn().Err(e).Msg("profile run: target scan error")
	}

	if len(allFindings) > 0 {
		if err := w.finder.RecordObserved(ctx, allFindings); err != nil {
			w.failRun(ctx, job.Args.RunID, err)
			return fmt.Errorf("Work: record findings: %w", err)
		}
	}

	if len(completed) == 0 {
		logger.Warn().Int("errors", len(scanErrs)).Msg("profile run: no target completed, skipping lifecycle reconciliation")
	} else if err := w.profiles.ReconcileFindingLifecycle(ctx, job.Args.RunID, allScanFindings, completed); err != nil {
		// Reconciliation failure is non-fatal for the run itself — findings are
		// already recorded. Log and surface, but mark the run completed so the UI
		// doesn't hang on "running".
		logger.Warn().Err(err).Msg("profile run: lifecycle reconciliation failed")
	}

	// The status follows whether any target completed, not whether anything
	// was found: a completed target that found nothing still resolved its
	// confirmed findings above, so its run is not a failure. A mixed run is
	// completed with the errored count in its message.
	runStatus := scan.StatusCompleted
	runErrMsg := ""
	switch {
	case len(completed) == 0 && len(scanErrs) > 0:
		runStatus = scan.StatusFailed
		runErrMsg = fmt.Sprintf("all %d target(s) errored, nothing reconciled", len(scanErrs))
	case len(scanErrs) > 0:
		runErrMsg = fmt.Sprintf("%d of %d target(s) errored; only completed targets were reconciled", len(scanErrs), len(completed)+len(scanErrs))
	}

	if err := w.profiles.FinishRun(ctx, job.Args.RunID, runStatus, len(allFindings), runErrMsg); err != nil {
		return fmt.Errorf("Work: finish run: %w", err)
	}

	logger.Info().
		Int("targets", len(targets)).
		Int("findings", len(allFindings)).
		Int("errors", len(scanErrs)).
		Dur("elapsed", time.Since(start)).
		Str("status", string(runStatus)).
		Msg("profile run complete")

	return nil
}

// failRun attempts to mark the run as failed. The error from FinishRun is
// logged but not propagated — the caller's original error is what matters.
func (w *ScanProfileWorker) failRun(ctx context.Context, runID string, cause error) {
	if err := w.profiles.FinishRun(ctx, runID, scan.StatusFailed, 0, cause.Error()); err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("run_id", runID).Msg("scan_profile: could not mark run failed")
	}
}

// failRun marks a drift run failed and returns the stage error. A run that
// cannot be marked failed would sit as running forever, so that error is
// logged and joined onto the returned one rather than dropped.
func (w *ScanAssetWorker) failRun(ctx context.Context, runID, stage string, cause error) error {
	err := fmt.Errorf("ScanAssetWorker: %s: %w", stage, cause)
	if ferr := w.profiles.FinishRun(ctx, runID, scan.StatusFailed, 0, cause.Error()); ferr != nil {
		log.FromContext(ctx).Error().Err(ferr).Str("run_id", runID).Msg("drift scan: could not mark run failed")
		return errors.Join(err, fmt.Errorf("ScanAssetWorker: mark run failed: %w", ferr))
	}
	return err
}

// ── ScanAssetWorker ───────────────────────────────────────────────────────────
//
// ScanAssetWorker handles ScanAssetArgs jobs: drift-triggered single-asset scans.
// Unlike ScanProfileWorker (which resolves many targets from a query), this worker
// scans one pre-identified asset — the one that changed during a connector sync.

// assetDriftRunner is the profile-service capability set needed by ScanAssetWorker.
// It extends profileRunner with CreateRunForProfile (no run exists yet when the
// drift job is dequeued — we create it inline rather than pre-creating in the enqueueing path).
type assetDriftRunner interface {
	GetProfile(ctx context.Context, profileID string) (scan.ScanProfile, error)
	CreateRunForProfile(ctx context.Context, profileID string, targetCount int) (scan.Run, error)
	FinishRun(ctx context.Context, runID string, status scan.Status, findingCount int, errMsg string) error
	SelectTemplates(ctx context.Context, profile scan.ScanProfile, target scan.Target) ([]string, error)
	ReconcileFindingLifecycle(ctx context.Context, scanRunID string, newFindings []scan.ScanFinding, completedTargets []string) error
}

// singleAssetReader fetches one asset by ID. *asset.Service implements it.
type singleAssetReader interface {
	Get(ctx context.Context, id string) (asset.Asset, error)
}

// ScanAssetWorker processes single-asset drift-scan jobs (ScanAssetArgs).
type ScanAssetWorker struct {
	river.WorkerDefaults[ScanAssetArgs]
	profiles assetDriftRunner
	scanSvc  profileScanner
	finder   profileFindingRecorder
	assets   singleAssetReader
}

func (ScanAssetWorker) Timeout(_ *river.Job[ScanAssetArgs]) time.Duration {
	return 30 * time.Minute // single asset — much shorter ceiling than a full profile run
}

func (w *ScanAssetWorker) Work(ctx context.Context, job *river.Job[ScanAssetArgs]) error {
	logger := log.FromContext(ctx).With().
		Str("profile_id", job.Args.ProfileID).
		Str("asset_id", job.Args.AssetID).
		Str("trigger", job.Args.Trigger).
		Logger()

	profile, err := w.profiles.GetProfile(ctx, job.Args.ProfileID)
	if err != nil {
		return fmt.Errorf("ScanAssetWorker: load profile: %w", err)
	}

	a, err := w.assets.Get(ctx, job.Args.AssetID)
	if err != nil {
		return fmt.Errorf("ScanAssetWorker: load asset: %w", err)
	}

	// Build a single scan target from the asset. Mirrors targetsFor() in scan/service.go.
	host := a.Domain
	if host == "" {
		host = a.PublicIP
	}
	if host == "" {
		logger.Warn().Str("asset_id", job.Args.AssetID).Msg("drift scan: asset has no scannable host, skipping")
		return nil
	}
	target := scan.Target{
		URL:       "https://" + host,
		Host:      host,
		AssetType: a.Type,
		Tags:      a.Tags,
	}

	run, err := w.profiles.CreateRunForProfile(ctx, profile.ID, 1)
	if err != nil {
		return fmt.Errorf("ScanAssetWorker: create run: %w", err)
	}

	templateIDs, err := w.profiles.SelectTemplates(ctx, profile, target)
	if err != nil {
		return w.failRun(ctx, run.ID, "select templates", err)
	}

	out, err := w.scanSvc.ScanTargets(ctx, []scan.Target{target}, templateIDs)
	if err != nil {
		return w.failRun(ctx, run.ID, "scan", err)
	}

	now := time.Now()
	findings := profileResultsToFindings(run.ID, out.Results, target, now)
	scanFindings := profileResultsToScanFindings(run.ID, out.Results, target, now)

	if len(findings) > 0 {
		if err := w.finder.RecordObserved(ctx, findings); err != nil {
			return w.failRun(ctx, run.ID, "record findings", err)
		}
	}

	if err := w.profiles.ReconcileFindingLifecycle(ctx, run.ID, scanFindings, []string{scanTargetKey(target)}); err != nil {
		logger.Warn().Err(err).Msg("drift scan: lifecycle reconciliation failed (non-fatal)")
	}

	if err := w.profiles.FinishRun(ctx, run.ID, scan.StatusCompleted, len(findings), ""); err != nil {
		return fmt.Errorf("ScanAssetWorker: finish run: %w", err)
	}

	logger.Info().
		Int("findings", len(findings)).
		Str("host", host).
		Msg("drift scan complete")

	return nil
}

// profileResultsToFindings converts scanner results for a single target into
// finding.Finding values attributed to that target's profile run.
//
// Resource attribution mirrors toFindings (service.go): prefer the scanner's
// matched URL (the specific path/port nuclei hit), falling back to the
// target's own URL/Host when a template reports no per-match URL (e.g. a
// dial-failure retry event). Without that fallback feeding resource_id, a
// finding is untraceable to any asset and its deterministic ID collides with
// every other nuclei finding of the same source.
func profileResultsToFindings(runID string, results []scan.Result, target scan.Target, now time.Time) []finding.Finding {
	out := make([]finding.Finding, 0, len(results))
	for _, r := range results {
		source := r.Scanner
		if source == "" {
			source = "nuclei"
		}
		matchURL := r.MatchedURL
		if matchURL == "" {
			matchURL = target.URL
		}

		resourceType := target.AssetType
		resourceID := matchURL
		if resourceID == "" {
			resourceID = target.Host
		}
		if resourceType == "" && resourceID != "" {
			resourceType = "endpoint"
		}

		// Carry a classification CVE so KEV/EPSS enrichment can join a
		// template-slug finding to known-exploited / exploit-probability data.
		var meta map[string]string
		if r.CVE != "" {
			meta = map[string]string{"cve": r.CVE}
		}

		out = append(out, finding.Finding{
			ID:           dbutil.DeterministicID(source, r.TemplateID, resourceID),
			Source:       source,
			Type:         "vulnerability",
			Severity:     profileNormalizeSeverity(r.Severity),
			Title:        r.Name,
			CheckID:      r.TemplateID,
			ResourceType: resourceType,
			ResourceID:   resourceID,
			ResourceName: resourceID,
			DetectedAt:   now,
			Metadata:     meta,
		})
		_ = runID // runID carried by the job arg; reconcile uses it from Postgres
	}
	return out
}

// profileNormalizeSeverity maps a raw severity string from a scanner to the
// canonical finding.Severity enum, defaulting to info for unknown values.
func profileNormalizeSeverity(s string) finding.Severity {
	switch finding.Severity(s) {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium,
		finding.SeverityLow, finding.SeverityInfo:
		return finding.Severity(s)
	default:
		return finding.SeverityInfo
	}
}

// scanTargetKey is the scan_findings asset_id for a target. scan.Target
// carries no asset ID, so the host is the key: it is what identifies the
// target to both the profile and the drift worker.
func scanTargetKey(t scan.Target) string { return t.Host }

// profileResultsToScanFindings converts scanner results for one target into
// scan.ScanFinding values used by lifecycle reconciliation. The ID field is
// empty so the repo generates one on insert.
func profileResultsToScanFindings(runID string, results []scan.Result, target scan.Target, now time.Time) []scan.ScanFinding {
	out := make([]scan.ScanFinding, 0, len(results))
	for _, r := range results {
		sev := r.Severity
		if sev == "" {
			sev = "info"
		}
		out = append(out, scan.ScanFinding{
			ScanRunID:   runID,
			AssetID:     scanTargetKey(target),
			CheckID:     r.TemplateID,
			Title:       r.Name,
			Severity:    sev,
			FirstSeenAt: now,
			LastSeenAt:  now,
		})
	}
	return out
}
