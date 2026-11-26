package main

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// scanner runs opt-in VM disk-volume jobs with isolated credentials.
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
	// topology this pod executes disk-volume reads and emits their metrics.
	shutdownTracing, err := obs.InitTracing(ctx, getenv, "scanner")
	if err != nil {
		return fmt.Errorf("scanner: tracing: %w", err)
	}
	defer func() { _ = shutdownTracing(context.Background()) }()
	metrics := obs.New()

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
	if diskScan == nil {
		return fmt.Errorf("scanner: DISK_SCAN_ENABLED must be true for the VM disk scanner")
	}
	client, err := jobs.NewScanClient(pool, jobs.ScanDeps{DiskScan: diskScan, Metrics: metrics}, periodic)
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
