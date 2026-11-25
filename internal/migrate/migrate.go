// Package migrate applies the embedded goose migrations to Postgres and
// ClickHouse. It is the implementation behind `graph migrate`.
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
	"github.com/vulngraph/vulngraph/pkg/log"
)

// lockKey identifies the pg_advisory_lock that serialises migration runs. The
// value is arbitrary; what matters is that every boot uses the same one.
const lockKey int64 = 4823119705

// lockTimeout bounds how long a boot will WAIT for the advisory lock before
// giving up. It is set on the lock connection only, so it never shortens a
// migration statement (those run on separate connections opened in up()).
//
// Without it `SELECT pg_advisory_lock(…)` waits forever: this runs as an init
// container, which Kubernetes applies no timeout to, and a pod holding the
// lock that dies without closing its connection (e.g. a preempted node) would
// otherwise leave Postgres holding the lock until TCP keepalive reaps the
// session — on the order of hours. Thirty seconds is comfortably longer than
// any legitimate concurrent boot's migration run and short enough that the
// init container fails fast and lets Kubernetes' restart backoff retry.
const lockTimeout = "30s"

// Run applies all pending migrations: our Postgres schema, River's job tables
// (also Postgres), the scanner role's grants on those tables, then our
// ClickHouse schema. Every pod that boots calls this, so the whole run is serialised
// behind a Postgres advisory lock.
func Run(ctx context.Context, pgDSN, chDSN string) error {
	return withAdvisoryLock(ctx, pgDSN, func(ctx context.Context) error {
		if err := up(ctx, "pgx", pgDSN, goose.DialectPostgres, "postgres"); err != nil {
			return fmt.Errorf("Run: postgres: %w", err)
		}
		if err := river(ctx, pgDSN); err != nil {
			return fmt.Errorf("Run: river: %w", err)
		}
		if err := grantScanner(ctx, pgDSN); err != nil {
			return fmt.Errorf("Run: %w", err)
		}
		if err := up(ctx, "clickhouse", chDSN, goose.DialectClickHouse, "clickhouse"); err != nil {
			return fmt.Errorf("Run: clickhouse: %w", err)
		}
		return nil
	})
}

// withAdvisoryLock runs fn while holding a session-level advisory lock on a
// dedicated Postgres connection. Concurrent boots queue here instead of racing:
// goose checks the version table and applies in separate statements, so two
// unsynchronised runs can both read "not applied" and both apply — recording a
// migration twice, seconds apart, which survives only if that migration happens
// to be idempotent. The lock covers ClickHouse too, whose goose_db_version is
// exposed to the same race.
func withAdvisoryLock(ctx context.Context, pgDSN string, fn func(context.Context) error) error {
	db, err := sql.Open("pgx", pgDSN)
	if err != nil {
		return fmt.Errorf("withAdvisoryLock: open postgres: %w", err)
	}
	defer func() { _ = db.Close() }()

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("withAdvisoryLock: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// lock_timeout applies to advisory-lock waits, so this converts an unbounded
	// hang into a fast, retryable failure. Session-scoped: it dies with conn.
	if _, err := conn.ExecContext(ctx, "SET lock_timeout = '"+lockTimeout+"'"); err != nil {
		return fmt.Errorf("withAdvisoryLock: set lock_timeout: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockKey); err != nil {
		return fmt.Errorf("withAdvisoryLock: acquire (waited %s; another boot may hold it, "+
			"or a dead pod's session has not been reaped — retry): %w", lockTimeout, err)
	}
	defer func() {
		// Unlock on the caller's cancelled ctx would be dropped, leaving the lock
		// held until the connection dies and blocking the next boot for that long.
		unlockCtx := context.WithoutCancel(ctx)
		if _, err := conn.ExecContext(unlockCtx, "SELECT pg_advisory_unlock($1)", lockKey); err != nil {
			log.FromContext(ctx).Error().Err(err).Msg("migrate: releasing advisory lock")
		}
	}()

	return fn(ctx)
}

// river applies River's own job-table migrations.
func river(ctx context.Context, pgDSN string) error {
	pool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		return fmt.Errorf("river: pool: %w", err)
	}
	defer pool.Close()

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return fmt.Errorf("river: migrator: %w", err)
	}
	res, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	if err != nil {
		return fmt.Errorf("river: migrate: %w", err)
	}
	for _, v := range res.Versions {
		log.FromContext(ctx).Info().Str("database", "river").Int("version", v.Version).Msg("migration applied")
	}
	return nil
}

func up(ctx context.Context, driver, dsn string, dialect goose.Dialect, dir string) error {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return fmt.Errorf("up: open %s: %w", driver, err)
	}
	defer func() { _ = db.Close() }()

	fsys, err := fs.Sub(migrations.FS, dir)
	if err != nil {
		return fmt.Errorf("up: sub fs %s: %w", dir, err)
	}

	provider, err := goose.NewProvider(dialect, db, fsys)
	if err != nil {
		return fmt.Errorf("up: provider %s: %w", dir, err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("up: apply %s: %w", dir, err)
	}
	for _, r := range results {
		log.FromContext(ctx).Info().
			Str("database", dir).
			Str("migration", r.Source.Path).
			Dur("took", r.Duration).
			Msg("migration applied")
	}
	return nil
}
