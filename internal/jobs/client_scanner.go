package jobs

// This file holds the isolated scanner pod's worker-registration wiring
// (ScanDeps, newScanWorkerRegistry, registerScanWorkers — the scanner-pod
// counterparts of registerRealWorkers/newWorkerRegistry in client.go) and the
// insert-only clients used by callers that only need to enqueue jobs, not run
// them: InsertClient (the HTTP server's on-demand-sync client) and Enqueuer
// (connector.Syncer's River-backed implementation). NewScanClient itself
// stays in client.go: TestEveryQueueConsumingClientDisablesTheReindexer and
// TestEveryElectableClientConfiguresSoftStopTimeout parse client.go's source
// text expecting to find both electable river.NewClient(...) calls — NewClient
// and NewScanClient — in that one file. Kept apart from client.go to stay
// under CLAUDE.md's 800-line ceiling.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/obs"
)

// ScanDeps are the isolated scanner pod's dependencies. Concrete types rather
// than interfaces because the interfaces the workers take are unexported
// (kept next to their consumer), and cmd/graph has to be able to fill this in.
type ScanDeps struct {
	// Scans runs the estate-wide nuclei scan (ScanWorker).
	Scans *scan.Service
	// Profiles drives profile runs and drift scans. Nil disables both workers,
	// which on the scanner pod means nothing consumes their kinds at all.
	Profiles *scan.ProfileService
	// Assets resolves a single asset for a drift scan.
	Assets *asset.Service
	// Findings records what a profile or drift run produced.
	Findings *finding.Service
	// CypherResolver resolves a profile's Cypher TargetQuery to scan targets.
	// This pod has no local graph engine of its own (see cmd/graph/scanner.go),
	// so cmd/graph wires this from an explore.LadybugRPCRepo dialed at the worker
	// pod's LADYBUG_RPC_URL. Nil means a profile with a non-empty TargetQuery
	// fails its run with an explicit "not configured" error — see
	// ScanProfileWorker.Work.
	CypherResolver cypherTargetResolver
	// DiskScan runs the disk scan's volume jobs on this pod's own lane. Nil
	// leaves the lane unconsumed. This pod reads disks with the credentials a
	// plan sealed into the job and the narrow Postgres grants of
	// internal/migrate.scannerGrants — never the connectors themselves.
	DiskScan *DiskScanDeps
	// Metrics instruments every job with a span + run/duration metric via a
	// global River middleware, mirroring Deps.Metrics — nil disables job
	// instrumentation the same way.
	Metrics *obs.Metrics
}

// newScanWorkerRegistry registers the scanner pod's workers and returns the kinds
// it can NOT work, exactly as newWorkerRegistry does for the main worker — so the
// queue derivation and its guard test see the same decisions the binary makes.
func newScanWorkerRegistry(deps ScanDeps) (*river.Workers, map[string]bool) {
	workers := river.NewWorkers()
	registerScanWorkers(workers, deps)
	// The scanner's JobRescuer must know every job kind or it discards the main
	// worker's stuck jobs — see rescue.go. The rescue-only set it returns is also
	// what keeps this pod off every queue but queueScan.
	return workers, addRescueOnlyWorkers(workers)
}

// registerScanWorkers adds the scanner pod's real workers. Split out for the same
// reason registerRealWorkers is.
//
// Returns the *ScanProfileWorker it registered (nil if deps.Profiles is nil) —
// a test seam, see addNucleiFanoutWorkers.
func registerScanWorkers(workers *river.Workers, deps ScanDeps) *ScanProfileWorker {
	river.AddWorker(workers, &ScanWorker{scans: deps.Scans})
	// The scanner pod IS the nuclei budget: scanProfileConcurrency fans 10 targets
	// out per run for up to 4h. Registering these here is what lets the worker pod
	// keep SCAN_WORKER_DISABLED's promise that no nuclei runs on it.
	var profileWorker *ScanProfileWorker
	if deps.Profiles != nil {
		profileWorker = addNucleiFanoutWorkers(workers, nucleiFanout{
			profiles: deps.Profiles, drift: deps.Profiles, driftAssets: deps.Assets,
			scanSvc: deps.Scans, finder: deps.Findings, cypherResolver: deps.CypherResolver,
		})
	}
	addDiskScanVolumeWorker(workers, deps.DiskScan)
	return profileWorker
}

// InsertClient builds a River client that can only insert jobs (no queues, no
// workers) — used by the HTTP server to trigger an on-demand sync.
func InsertClient(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("InsertClient: %w", err)
	}
	return client, nil
}

// driftProfileLister provides the IDs of drift-enabled profiles for scan
// enqueueing. IDs only (not scan.ScanProfile) so it can be satisfied from
// outside this package without an import cycle (jobs → scan) — scan.ProfileService
// implements this directly (ListDriftEnabledProfileIDs). It must not return a
// jobs-local type: nothing outside this package could construct one, so the
// interface would compile with zero real implementations and leave the
// drift-scan enqueue path unwired.
type driftProfileLister interface {
	ListDriftEnabledProfileIDs(ctx context.Context) ([]string, error)
}

// Enqueuer wraps an insert-only River client to satisfy connector.Syncer,
// keeping the connector handler free of any River types.
type Enqueuer struct {
	client        *river.Client[pgx.Tx]
	driftProfiles driftProfileLister
}

func NewEnqueuer(client *river.Client[pgx.Tx]) *Enqueuer { return &Enqueuer{client: client} }

// WithDriftProfiles enables drift scan enqueueing on this Enqueuer.
func (e *Enqueuer) WithDriftProfiles(lister driftProfileLister) *Enqueuer {
	e.driftProfiles = lister
	return e
}

// EnqueueSync inserts an immediate sync for one connector.
func (e *Enqueuer) EnqueueSync(ctx context.Context, connectorID string) error {
	if _, err := e.client.Insert(ctx, SyncConnectorArgs{ConnectorID: connectorID}, nil); err != nil {
		return fmt.Errorf("EnqueueSync: %w", err)
	}
	return nil
}

// EnqueueOrgDiscovery inserts an immediate aws_org discovery. The job is a
// singleton, so a request while one is queued or running is a no-op.
func (e *Enqueuer) EnqueueOrgDiscovery(ctx context.Context) error {
	if _, err := e.client.Insert(ctx, DiscoverAWSOrgsArgs{}, nil); err != nil {
		return fmt.Errorf("EnqueueOrgDiscovery: %w", err)
	}
	return nil
}

// EnqueueScan inserts an immediate active scan.
func (e *Enqueuer) EnqueueScan(ctx context.Context) error {
	if _, err := e.client.Insert(ctx, ScanArgs{}, nil); err != nil {
		return fmt.Errorf("EnqueueScan: %w", err)
	}
	return nil
}

// EnqueueProfileScan inserts a scan job for one named scan profile on tx, so it
// commits atomically with the caller's scan_runs row write.
func (e *Enqueuer) EnqueueProfileScan(ctx context.Context, tx pgx.Tx, profileID, runID string) error {
	if _, err := e.client.InsertTx(ctx, tx, ScanProfileJobArgs{ProfileID: profileID, RunID: runID}, nil); err != nil {
		return fmt.Errorf("EnqueueProfileScan: %w", err)
	}
	return nil
}

// EnqueueDriftScans implements driftScanner. For each external asset ID that
// changed in a connector sync, it inserts one ScanAssetArgs job per drift-enabled
// profile. Duplicate jobs for the same (asset, profile) pair are deduplicated by
// River's UniqueOpts on ScanAssetArgs, so rapid successive changes don't pile up.
func (e *Enqueuer) EnqueueDriftScans(ctx context.Context, externalAssetIDs []string) error {
	if len(externalAssetIDs) == 0 {
		return nil
	}
	if e.driftProfiles == nil {
		return nil
	}
	profileIDs, err := e.driftProfiles.ListDriftEnabledProfileIDs(ctx)
	if err != nil {
		return fmt.Errorf("EnqueueDriftScans: list profiles: %w", err)
	}
	if len(profileIDs) == 0 {
		return nil
	}
	params := make([]river.InsertManyParams, 0, len(externalAssetIDs)*len(profileIDs))
	for _, assetID := range externalAssetIDs {
		for _, profileID := range profileIDs {
			params = append(params, river.InsertManyParams{
				Args: ScanAssetArgs{ProfileID: profileID, AssetID: assetID, Trigger: "drift"},
			})
		}
	}
	if _, err := e.client.InsertMany(ctx, params); err != nil {
		return fmt.Errorf("EnqueueDriftScans: insert: %w", err)
	}
	return nil
}
