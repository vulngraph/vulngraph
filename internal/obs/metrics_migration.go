package obs

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// MigrationStat is the scrape-time applied-vs-embedded migration version for
// one migration set (postgres, clickhouse, or river's own job tables) —
// obs's own, domain-knowledge-free mirror of internal/migrate.DBStatus. obs
// never imports internal/migrate directly (the same leaf-package rule that
// keeps every other Sources field a plain struct the caller fills in); the
// caller is expected to run internal/migrate.Status and map its result into
// this shape.
//
// This exists because migrate.Run applies as a Kubernetes init container: a
// short-lived process that exits before the main container starts and long
// before any /metrics scrape could observe it. Nothing else makes migration
// state observable, so a schema-version mismatch (e.g. a duplicate migration
// version stamped by two concurrent changes) could otherwise only be caught
// by a human running `kubectl get pods`. This metric is the signal for the
// cause: whether the database this pod is talking to actually holds the
// schema version the running binary expects.
type MigrationStat struct {
	DB      string // "postgres", "clickhouse", or "river"
	Applied int64  // highest version this database has recorded as applied
	Target  int64  // highest version embedded in the running binary
	Pending bool   // Applied < Target
}

var (
	descMigrationApplied = prometheus.NewDesc(namespace+"_migration_applied_version",
		"Highest migration version this database has actually applied, per migration set (db label: postgres, clickhouse, river). Read next to graph_migration_target_version; GraphMigrationPending alerts on the derived graph_migration_pending gauge instead of comparing these two at query time, so a dashboard reading this raw pair stays meaningful even if the alert's own comparison logic changes.", []string{"db"}, nil)
	descMigrationTarget = prometheus.NewDesc(namespace+"_migration_target_version",
		"Highest migration version embedded in the running binary, per migration set (db label). Changes only on deploy of a binary carrying new migration files.", []string{"db"}, nil)
	descMigrationPending = prometheus.NewDesc(namespace+"_migration_pending",
		"1 when a database's applied version is behind the running binary's embedded target (db label), 0 when caught up. migrate.Run is an init container that applies every pending migration before the main container starts, so on a healthy boot this main-container reading should never be 1 — GraphMigrationPending treats a sustained 1 as a schema-drift incident.", []string{"db"}, nil)
)

// describeMigration/collectMigration are called from liveCollector's
// Describe/Collect (metrics.go) — split out here for line count only, same
// reason as metrics_finding_age.go.
func (c *liveCollector) describeMigration(ch chan<- *prometheus.Desc) {
	ch <- descMigrationApplied
	ch <- descMigrationTarget
	ch <- descMigrationPending
}

func (c *liveCollector) collectMigration(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.s.Migration == nil {
		return
	}
	for _, s := range readSource(ctx, c, "migration", 0, c.s.Migration) {
		ch <- prometheus.MustNewConstMetric(descMigrationApplied, prometheus.GaugeValue, float64(s.Applied), s.DB)
		ch <- prometheus.MustNewConstMetric(descMigrationTarget, prometheus.GaugeValue, float64(s.Target), s.DB)
		pending := 0.0
		if s.Pending {
			pending = 1.0
		}
		ch <- prometheus.MustNewConstMetric(descMigrationPending, prometheus.GaugeValue, pending, s.DB)
	}
}
