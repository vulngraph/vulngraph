package main

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/scanner/nuclei"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// scanner runs the nuclei scan worker and, when DISK_SCAN_ENABLED, the disk scan
// volume worker. It owns queueScan and queueDiskScan and handles no
// other job types — isolating nuclei's CPU/memory spike from the main worker
// (connector syncs, enrichment, reasoning). Deploy as a separate pod with
// SCAN_INTERVAL set (e.g. 168h for weekly) and SCAN_WORKER_DISABLED=true on
// the main worker pod.
func scanner(ctx context.Context, getenv func(string) string) error {
	if err := waitForMigrations(ctx, migrateStatus(getenv), migrationWaitMinBackoff, migrationWaitMaxBackoff); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	pool, err := db.NewPool(ctx, pgDSN(getenv), int32(envInt(getenv, "PG_MAX_CONNS_SCANNER", db.MaxConnsScanner)))
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	defer pool.Close()

	ch, err := db.NewCH(ctx, chDSN(getenv), envInt(getenv, "CH_MAX_CONCURRENT", 0))
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	defer func() { _ = ch.Close() }()

	// Observability, off unless env-gated — same as worker/serve. In the split
	// topology this pod runs all nuclei execution once SCAN_WORKER_DISABLED is
	// set on the worker, so leaving metrics/tracing dark here would mean "did
	// nuclei run at all?" has no series behind it anywhere.
	shutdownTracing, err := obs.InitTracing(ctx, getenv, "scanner")
	if err != nil {
		return fmt.Errorf("scanner: tracing: %w", err)
	}
	defer func() { _ = shutdownTracing(context.Background()) }()
	metrics := obs.New()

	assetSvc := asset.NewService(asset.NewCHRepo(ch))
	findingSvc := finding.NewService(finding.NewCHRepo(ch)).
		// A resolve ends the finding's alert episode, so a regression re-alerts.
		// No scan job resolves findings, and graph_scanner has no grant on the
		// alert-state tables: a resolve added here logs the observer's refusal.
		WithResolveObserver(enrichcache.NewService(enrichcache.NewPGRepo(pool)))
	if err := nuclei.CheckEgressEnv(getenv); err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	nucleiScanner, err := bundledScanner(getenv)
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	scanSvc := scan.NewService(scan.NewPGRepo(pool), assetSvc, assetSvc, nucleiScanner, findingSvc)

	// This pod has no local Ladybug graph engine (unlike the worker, which holds
	// the primary — see worker.go's openGraphDB/graphDB) — the scanner's ONLY
	// path to Cypher target resolution is dialing the worker's internal RPC
	// endpoint, the same one the serve pod dials via LADYBUG_RPC_URL for its own
	// Cypher/Explore reads (see serve.go). Nil when LADYBUG_RPC_URL is unset: a
	// profile with a non-empty TargetQuery then fails its run with an explicit
	// "not configured" error (ScanProfileWorker.Work) instead of silently
	// scanning the wrong target set.
	var cypherResolver cypherProfileResolver
	if url := getenv("LADYBUG_RPC_URL"); url != "" {
		cypherResolver = &ladybugCypherTargetResolver{
			cypher: explore.NewLadybugRPCRepo(url, getenv("LADYBUG_RPC_SECRET")),
			assets: assetSvc,
		}
	}

	// Profile runs and drift scans EXECUTE nuclei, so they run here, on the pod that
	// owns the nuclei budget — not on the worker, which sets SCAN_WORKER_DISABLED
	// precisely to keep nuclei off itself. The enqueuer is nil because this pod only
	// executes profile runs; the worker's per-minute cron tick is what triggers them.
	profileSvc := scan.NewProfileService(
		scan.NewPGProfileRepo(pool),
		scan.NewPGRepo(pool),
		nil, // ScannerRegistry — nil; the workers call profileScanner (scanSvc) directly
		assetSvc,
		nil, // ProfileJobEnqueuer — nil; this pod executes profile runs, never triggers them
	)

	// The scanner is leader-electable, and only the leader enqueues periodics, so it
	// registers the SAME schedule the worker does — otherwise a scanner-as-leader
	// darkens every worker sweep. PeriodicConfigFromEnv is the SINGLE derivation both
	// pods use, pinned against the worker's deps→config derivation by
	// jobs.TestScannerSchedulesSameKindsAsWorker: a hand-written literal here is how
	// the two silently disagree, and a lane nothing consumes strands every job on it.
	periodic, err := jobs.PeriodicConfigFromEnv(getenv)
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	// Agentless VM disk reads: dark unless DISK_SCAN_ENABLED. This pod has no
	// grant on connectors and cannot decrypt them, so the scan runs on the
	// credentials each volume job carries sealed (internal/migrate/scanner.go).
	diskScan, err := scannerDiskScan(ctx, getenv, pool)
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}
	client, err := jobs.NewScanClient(pool, jobs.ScanDeps{
		Scans:          scanSvc,
		Profiles:       profileSvc,
		Assets:         assetSvc,
		Findings:       findingSvc,
		CypherResolver: cypherResolver,
		DiskScan:       diskScan,
		Metrics:        metrics,
	}, periodic)
	if err != nil {
		return fmt.Errorf("scanner: %w", err)
	}

	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("scanner: start: %w", err)
	}
	log.FromContext(ctx).Info().Msg("graph scanner started")

	// metrics listener — env-gated, pod-internal (like pprof / the ladybug RPC
	// port, never Ingress-reachable), same as worker.go/serve.go. Set
	// METRICS_PORT to expose Prometheus /metrics.
	if metricsPort := getenv("METRICS_PORT"); metricsPort != "" {
		safego(ctx, "metrics-listener", func() {
			if err := metrics.ListenAndServe(ctx, ":"+metricsPort); err != nil {
				log.FromContext(ctx).Error().Err(err).Msg("scanner: metrics listener exited")
			}
		})
	}

	<-ctx.Done()
	stopCtx, cancel := context.WithTimeout(context.Background(), jobs.ScannerStopTimeout)
	defer cancel()
	if err := client.Stop(stopCtx); err != nil {
		return fmt.Errorf("scanner: stop: %w", err)
	}
	return nil
}
