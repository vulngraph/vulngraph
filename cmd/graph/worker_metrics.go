package main

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/migrate"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// registerMetricsSources wires the worker pod's live-state gauge sources.
//
// Kept out of worker() to stay under the 800-line file ceiling. It reads only
// already-constructed services, so it has no ordering constraint beyond "after
// graphDB is opened".
func registerMetricsSources(
	metrics *obs.Metrics,
	pool *pgxpool.Pool,
	graphDB *graphstore.Service,
	connectorSvc *connector.Service,
	assetSvc *asset.Service,
	findingSvc *finding.Service,
	getenv func(string) string,
) {
	// GraphStats, which the collector skips per-field).
	metrics.RegisterSources(obs.Sources{
		QueueDepth: func(ctx context.Context) []obs.QueueStat { return jobs.QueueDepths(ctx, pool) },
		Graph: func() obs.GraphStats {
			if graphDB == nil {
				return obs.GraphStats{}
			}
			var built int64
			if t := graphDB.LastBuiltAt(); !t.IsZero() {
				built = t.Unix()
			}
			reachOK, truncated := graphDB.EdgeSyncHealth()
			loaded, dropNotLoaded, dropEndpoint := graphDB.EdgeLoadStats()
			reachable, reachTotal := graphDB.ReachabilityStats()
			fid := graphDB.FidelityStats()
			tableRows, _ := graphDB.NodeTableRows()
			return obs.GraphStats{
				NodeTableRows: tableRows, NodeGroupRows: graphstore.LadybugNodeGroupRows,
				Nodes: graphDB.NodeCount(), NodeBudget: graphstore.NodeBudget,
				LastBuiltUnix: built,
				ReachComplete: &reachOK, TruncatedEdgeTypes: truncated,
				EdgeFetchComplete:                graphDB.EdgeFetchComplete(),
				AssetFetchComplete:               graphDB.AssetFetchComplete(),
				PublishRefusals:                  fid.Refusals,
				PublishDegradedAccepted:          fid.RepeatPublishes,
				PublishDegradedAcceptedStep:      fid.RepeatPublishesStep,
				PublishDegradedAcceptedColdStart: fid.RepeatPublishesColdStart,
				PublishDegradedAcceptedMonotonic: fid.RepeatPublishesMonotonic,
				LastRefusalUnix:                  fid.LastRefusalUnix,
				EdgesLoaded:                      loaded,
				EdgesDroppedNotLoaded:            dropNotLoaded,
				EdgesDroppedEndpointMiss:         dropEndpoint,
				IdentityZeroHop:                  graphDB.IdentityZeroHop(),
				ReachRateReachable:               reachable,
				ReachRateTotal:                   reachTotal,
				EdgeTypeParity:                   graphDB.EdgeTypeParity(),
			}
		},
		Connectors: func(ctx context.Context) []obs.ConnectorStat {
			cs, err := connectorSvc.List(ctx, true)
			if err != nil {
				return nil
			}
			now := time.Now()
			out := make([]obs.ConnectorStat, len(cs))
			for i, c := range cs {
				out[i] = obs.ConnectorStat{Name: c.Name, Stale: c.Stale(now, connector.DefaultStaleAfter), PartialStreak: c.PartialStreak}
			}
			return out
		},
		// Anchored to each provider's OWN high-water mark (never wall-clock — see
		// asset.ProviderStaleness) so a broken collector shows up as a rising
		// stale fraction instead of the whole provider looking newly deleted.
		// Without it, a large fraction of a provider's assets could go
		// un-recollected for days without any signal.
		AssetStaleness: func(ctx context.Context) []obs.AssetStalenessStat {
			stats, err := assetSvc.ProviderStaleness(ctx, int(assetStaleMargin/time.Second))
			if err != nil {
				return nil
			}
			out := make([]obs.AssetStalenessStat, len(stats))
			for i, s := range stats {
				out[i] = obs.AssetStalenessStat{Provider: s.Provider, Total: int64(s.Total), Stale: int64(s.Stale)}
			}
			return out
		},
		// Coverage-gap detection (absence, not just staleness): for the two
		// (provider, dimension) pairs the platform can derive honestly from
		// already-collected data — kubernetes clusters (distinct region) and aws
		// accounts (distinct account_id) — compare the dimension cardinality seen
		// in assets against the enabled connector count for that provider type.
		// A gap (seen > configured) means at least one live cluster/account has
		// no connector at all; ConnectorStat only describes connectors that
		// exist, so that gap is otherwise invisible by construction. Other
		// providers are deliberately not covered here — they have no equally
		// direct asset dimension to compare against without faking a signal.
		//
		// Enrich backlog depth. Findings the pipeline has never reached carry no
		// score and no band, so Summary excludes them from ByBand and every
		// score-sorted view buries them.
		Unenriched: func(ctx context.Context) []obs.UnenrichedStat {
			counts, err := findingSvc.UnenrichedCounts(ctx)
			if err != nil {
				return nil
			}
			out := make([]obs.UnenrichedStat, len(counts))
			for i, c := range counts {
				out[i] = obs.UnenrichedStat{Severity: string(c.Severity), N: int64(c.N)}
			}
			return out
		},
		// Prioritisation coverage per source. An enriched-but-unclassified finding
		// looks healthy everywhere else — it has a score, a band and a UI page — so a
		// whole source that can never reach must_fix would be indistinguishable from one
		// working perfectly. This is what makes that gap
		// visible without anyone running a query by hand.
		Unclassified: func(ctx context.Context) []obs.UnclassifiedStat {
			cov, err := findingSvc.MustFixCoverage(ctx)
			if err != nil {
				return nil
			}
			out := make([]obs.UnclassifiedStat, len(cov))
			for i, c := range cov {
				out[i] = obs.UnclassifiedStat{Source: c.Source, Blank: c.Blank, Classified: c.Classified}
			}
			return out
		},
		// Per-check junk rate: the standing scoreboard that replaces sampling
		// findings by hand. Reported for every check with any resolution history;
		// Measurable distinguishes "genuinely clean" from "not enough evidence yet".
		CheckQuality: func(ctx context.Context) []obs.CheckQualityStat {
			qs, dropped, err := findingSvc.CheckQuality(ctx)
			if err != nil {
				return nil
			}
			if dropped > 0 {
				// Never a silent truncation: a dropped check is one nobody can see the
				// junk rate for, which is the exact blindness this metric exists to end.
				log.FromContext(ctx).Warn().Int("dropped", dropped).Int("limit", finding.CheckQualityLimit).
					Msg("check-quality scoreboard truncated — checks beyond the limit report no junk rate")
			}
			out := make([]obs.CheckQualityStat, len(qs))
			for i, q := range qs {
				out[i] = obs.CheckQualityStat{
					CheckID: q.CheckID, Source: q.Source,
					Open: q.Open, Fixed: q.Fixed, ResourceGone: q.ResourceGone, Manual: q.Manual,
					JunkRate: q.JunkRate(), Measurable: q.Measurable(),
				}
			}
			return out
		},
		// Finding-age integrity: whether the immutable first-observation stamp is
		// actually surviving re-observation. Every producer re-stamps detected_at,
		// so without the first_detected_at pin this would be structurally 0 — which
		// is what lets it prove the pin is live rather than inert.
		FindingAge: func(ctx context.Context) []obs.FindingAgeStat {
			ai, err := findingSvc.AgeIntegrity(ctx)
			if err != nil {
				return nil
			}
			return []obs.FindingAgeStat{{
				Preserved:     ai.Preserved,
				Missing:       ai.Missing,
				OldestSeconds: ai.OldestSeconds,
			}}
		},
		// OSV scan-staleness: the "how stale is our actual package coverage?"
		// signal graph_feed_last_success_timestamp_seconds{feed="osv"} cannot
		// answer (that gauge stamps fresh even on a 0-new-packages refresh_osv
		// run). Combines ClickHouse (current package-inventory size) and
		// Postgres (osv_scanned_packages' oldest scan / row count) — the two
		// stores this signal actually lives in.
		OSVScanStaleness: func(ctx context.Context) []obs.OSVScanStalenessStat {
			total, err := assetSvc.CountPackages(ctx)
			if err != nil {
				return nil
			}
			scanned, oldest, err := jobs.OSVScanStaleness(ctx, pool)
			if err != nil {
				return nil
			}
			neverScanned := total - scanned
			if neverScanned < 0 {
				neverScanned = 0 // a package can be scanned under a purl no longer in the current inventory
			}
			var oldestUnix int64
			if !oldest.IsZero() {
				oldestUnix = oldest.Unix()
			}
			return []obs.OSVScanStalenessStat{{
				TotalPackages:   total,
				NeverScanned:    neverScanned,
				OldestScannedAt: oldestUnix,
			}}
		},
		// Image-scan coverage: how much of the container-image estate the
		// sweep has actually inventoried. Postgres-only (the sweep's own cursor),
		// so it costs a small aggregate rather than a ClickHouse full-table
		// read. It replaces using job status as a coverage proxy, which can
		// report the sweep dark while it is in fact covering every image.
		ImageScanCoverage: func(ctx context.Context) []obs.ImageScanCoverageStat {
			cov, err := jobs.ReadImageScanCoverage(ctx, pool)
			if err != nil {
				return nil
			}
			var oldestUnix int64
			if !cov.OldestScanned.IsZero() {
				oldestUnix = cov.OldestScanned.Unix()
			}
			return []obs.ImageScanCoverageStat{{
				TrackedDigests:  cov.TrackedDigests,
				NeverScanned:    cov.NeverScanned,
				CoveredRecent:   cov.CoveredRecent,
				OldestScannedAt: oldestUnix,
			}}
		},
		// Per-source production recency: the direct "did this source run?"
		// signal behind GraphFindingSourceDark. findingSvc.SourceActivity already
		// merges in every source ExpectedActivitySources names, including ones
		// with zero findings — see internal/app/finding/source_activity.go.
		SourceActivity: func(ctx context.Context) []obs.SourceActivityStat {
			stats, err := findingSvc.SourceActivity(ctx)
			if err != nil {
				return nil
			}
			out := make([]obs.SourceActivityStat, len(stats))
			for i, s := range stats {
				out[i] = obs.SourceActivityStat{Source: s.Source, LastActivityUnix: s.LastActivityUnix}
			}
			return out
		},
		ConnectorCoverage: func(ctx context.Context) []obs.ConnectorCoverageStat {
			dims, err := assetSvc.ProviderDimensionCounts(ctx)
			if err != nil {
				return nil
			}
			cs, err := connectorSvc.List(ctx, true)
			if err != nil {
				return nil
			}
			enabled := map[connector.Type]int{}
			for _, c := range cs {
				enabled[c.Type]++
			}
			var out []obs.ConnectorCoverageStat
			for _, d := range dims {
				switch asset.Provider(d.Provider) {
				case asset.ProviderKubernetes:
					out = append(out, obs.ConnectorCoverageStat{
						Provider: d.Provider, Dimension: "region",
						Seen: int64(d.Regions), Configured: int64(enabled[connector.TypeKubernetes]),
					})
				case asset.ProviderAWS:
					out = append(out, obs.ConnectorCoverageStat{
						Provider: d.Provider, Dimension: "account_id",
						Seen: int64(d.Accounts), Configured: int64(enabled[connector.TypeAWS]),
					})
				}
			}
			return out
		},
		// River queue-age: per queue, how old the oldest currently-available job
		// is. Mirrors QueueDepth's wiring (jobs owns the river_job query, this
		// function just plugs it into the collector).
		QueueOldestAvailable: func(ctx context.Context) []obs.QueueAgeStat {
			return jobs.QueueOldestAvailable(ctx, pool)
		},
		// Migration applied-vs-embedded version, per migration set.
		// migrate.Status erroring means this reading is UNKNOWN, not "caught up" —
		// emitting a zero/Pending-false stat on error would read as healthy and
		// make GraphMigrationPending unable to ever fire on the failure that
		// matters most (can't even tell). So on error the series is omitted
		// entirely this scrape, same convention as QueueOldestAvailable above and
		// every other best-effort source in this file.
		Migration: func(ctx context.Context) []obs.MigrationStat {
			statuses, err := migrate.Status(ctx, pgDSN(getenv), chDSN(getenv))
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("migrate.Status failed — migration metrics skipped this scrape")
				return nil
			}
			out := make([]obs.MigrationStat, len(statuses))
			for i, s := range statuses {
				out[i] = obs.MigrationStat{DB: s.DB, Applied: s.Applied, Target: s.Target, Pending: s.Pending}
			}
			return out
		},
	})
}
