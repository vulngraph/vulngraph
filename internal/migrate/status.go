package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/vulngraph/vulngraph/migrations"
)

// DBStatus is the applied-vs-embedded migration version for one of the three
// migration sets Run applies (postgres, clickhouse, river's own job tables).
//
// This is deliberately a passive READ of durable state (goose_db_version /
// river_migration), not something Run itself reports: Run executes as a
// short-lived Kubernetes init container that exits before any /metrics scrape
// could observe it. Status is meant to be called later, from a long-running
// serve/worker pod, which is the only way this state can reach a scrape.
//
// Pending (Applied < Target) means the running binary embeds a migration
// newer than what the database has actually applied. On a healthy boot, Run's
// init container already brought every database up to the binary's target
// before the main container was scheduled, so Pending observed from a
// long-running pod is not a normal transient wait state — there is no
// legitimate "still catching up" phase once the app is serving traffic.
type DBStatus struct {
	DB      string // "postgres", "clickhouse", or "river"
	Applied int64  // highest version this database has actually recorded as applied
	Target  int64  // highest version embedded in the running binary
	Pending bool   // Applied < Target
}

// Status reports the applied-vs-embedded version for all three migration
// sets Run applies, in the same order Run applies them. It opens its own
// short-lived connections (mirroring up()/river()'s style) and never writes.
func Status(ctx context.Context, pgDSN, chDSN string) ([]DBStatus, error) {
	pg, err := dbVersionStatus(ctx, "postgres", "pgx", pgDSN, goose.DialectPostgres, "postgres")
	if err != nil {
		return nil, fmt.Errorf("Status: postgres: %w", err)
	}
	rv, err := riverVersionStatus(ctx, pgDSN)
	if err != nil {
		return nil, fmt.Errorf("Status: river: %w", err)
	}
	ch, err := dbVersionStatus(ctx, "clickhouse", "clickhouse", chDSN, goose.DialectClickHouse, "clickhouse")
	if err != nil {
		return nil, fmt.Errorf("Status: clickhouse: %w", err)
	}
	return []DBStatus{pg, rv, ch}, nil
}

// dbVersionStatus reads one goose-managed database's applied-vs-embedded
// version via Provider.GetVersions, which deliberately does not take any
// SessionLocker/Locker — it is a read, so it cannot block on or be blocked by
// a concurrent Run holding the advisory lock (migrate.go's withAdvisoryLock).
func dbVersionStatus(ctx context.Context, name, driver, dsn string, dialect goose.Dialect, dir string) (DBStatus, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return DBStatus{}, fmt.Errorf("open %s: %w", driver, err)
	}
	defer func() { _ = db.Close() }()

	fsys, err := fs.Sub(migrations.FS, dir)
	if err != nil {
		return DBStatus{}, fmt.Errorf("sub fs %s: %w", dir, err)
	}

	provider, err := goose.NewProvider(dialect, db, fsys, migrations.ProviderOptions(dialect))
	if err != nil {
		return DBStatus{}, fmt.Errorf("provider %s: %w", dir, err)
	}

	current, target, err := provider.GetVersions(ctx)
	if err != nil {
		return DBStatus{}, fmt.Errorf("versions %s: %w", dir, err)
	}
	return DBStatus{DB: name, Applied: current, Target: target, Pending: current < target}, nil
}

// riverVersionStatus is the rivermigrate equivalent of dbVersionStatus:
// ExistingVersions is a read against river_migration and, like goose's
// GetVersions, does not acquire River's own advisory lock, so it cannot be
// blocked by a concurrent Run.
func riverVersionStatus(ctx context.Context, pgDSN string) (DBStatus, error) {
	pool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		return DBStatus{}, fmt.Errorf("river: pool: %w", err)
	}
	defer pool.Close()

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return DBStatus{}, fmt.Errorf("river: migrator: %w", err)
	}

	existing, err := migrator.ExistingVersions(ctx)
	if err != nil {
		return DBStatus{}, fmt.Errorf("river: existing versions: %w", err)
	}
	var applied int
	for _, v := range existing {
		if v.Version > applied {
			applied = v.Version
		}
	}
	var target int
	for _, v := range migrator.AllVersions() {
		if v.Version > target {
			target = v.Version
		}
	}
	return DBStatus{DB: "river", Applied: int64(applied), Target: int64(target), Pending: applied < target}, nil
}
