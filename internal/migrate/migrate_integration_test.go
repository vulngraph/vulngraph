//go:build integration

package migrate

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Requires `docker compose up` (Postgres + ClickHouse from the repo root).
// Run with: go test -tags=integration ./internal/migrate/
const (
	pgDSN = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
	chDSN = "clickhouse://graph:graph@localhost:9000/graph"
)

func TestRun_AppliesAllMigrations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	require.NoError(t, Run(ctx, pgDSN, chDSN))

	// Re-running must be a no-op, not an error: goose tracks applied versions.
	require.NoError(t, Run(ctx, pgDSN, chDSN))

	pg, err := sql.Open("pgx", pgDSN)
	require.NoError(t, err)
	defer pg.Close()
	for _, table := range []string{"users", "sessions"} {
		var n int
		err := pg.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.tables WHERE table_name = $1`, table).Scan(&n)
		require.NoError(t, err)
		require.Equal(t, 1, n, "postgres table %s must exist", table)
	}

	ch, err := sql.Open("clickhouse", chDSN)
	require.NoError(t, err)
	defer ch.Close()
	for _, table := range []string{"assets", "graph_edges", "findings", "signals", "audit_events"} {
		var n uint64
		err := ch.QueryRowContext(ctx,
			`SELECT count() FROM system.tables WHERE database = 'graph' AND name = ?`, table).Scan(&n)
		require.NoError(t, err)
		require.Equal(t, uint64(1), n, "clickhouse table %s must exist", table)
	}

	// A migration must never be recorded twice: that is the signature of two
	// boots applying it concurrently.
	var dupes int
	err = pg.QueryRowContext(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM goose_db_version GROUP BY version_id HAVING count(*) > 1) d`).Scan(&dupes)
	require.NoError(t, err)
	require.Zero(t, dupes, "goose_db_version must have no duplicate version_id rows")
}

// The lock is what stops concurrent boots double-applying a migration, so assert
// the mutual exclusion directly rather than racing Run and hoping to lose.
func TestWithAdvisoryLock_SerialisesConcurrentRuns(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	var concurrent, peak atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := withAdvisoryLock(ctx, pgDSN, func(context.Context) error {
				n := concurrent.Add(1)
				for {
					old := peak.Load()
					if n <= old || peak.CompareAndSwap(old, n) {
						break
					}
				}
				time.Sleep(50 * time.Millisecond)
				concurrent.Add(-1)
				return nil
			})
			assert.NoError(t, err)
		}()
	}
	wg.Wait()

	require.Equal(t, int32(1), peak.Load(), "migrations must never run concurrently")
}

// The lock must be released even when the migration itself fails, or one bad
// boot wedges every later boot.
func TestWithAdvisoryLock_ReleasesOnError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	wantErr := errors.New("boom")
	require.ErrorIs(t, withAdvisoryLock(ctx, pgDSN, func(context.Context) error { return wantErr }), wantErr)

	ran := false
	require.NoError(t, withAdvisoryLock(ctx, pgDSN, func(context.Context) error { ran = true; return nil }))
	require.True(t, ran)
}

// A boot must FAIL rather than wait forever for the advisory lock.
//
// migrate is serve's init container: nothing above it applies a timeout, and
// serve is Recreate/1-replica, so an unbounded wait is serve down with no
// self-heal until the holder's TCP session is reaped (~2h on Linux defaults).
// This holds the lock on an independent connection and asserts the next boot
// gives up inside lockTimeout instead of hanging.
func TestWithAdvisoryLock_FailsFastWhenHeld(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	holder, err := sql.Open("pgx", pgDSN)
	require.NoError(t, err)
	defer holder.Close()

	conn, err := holder.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockKey)
	require.NoError(t, err)
	defer func() { _, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", lockKey) }()

	bound, err := time.ParseDuration(lockTimeout)
	require.NoError(t, err)

	ran := false
	start := time.Now()
	err = withAdvisoryLock(ctx, pgDSN, func(context.Context) error { ran = true; return nil })
	elapsed := time.Since(start)

	require.Error(t, err, "the lock is held: this boot must give up, not wait forever")
	require.ErrorContains(t, err, "acquire")
	require.False(t, ran, "fn must not run without the lock")
	require.Less(t, elapsed, bound*3, "gave up after %s, which is not a bounded wait", elapsed)
}

// Run grants the scanner role exactly scannerGrants: what the scanner process
// runs succeeds as it, and the tables that would make it a Vulngraph admin
// (users, API keys, sessions) or open connector credentials refuse it.
func TestRun_GrantsTheScannerRoleOnlyItsTables(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pg, err := sql.Open("pgx", pgDSN)
	require.NoError(t, err)
	defer pg.Close()
	_, err = pg.ExecContext(ctx, `DO $$ BEGIN CREATE ROLE `+ScannerRole+` NOLOGIN;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$`)
	require.NoError(t, err)
	require.NoError(t, Run(ctx, pgDSN, chDSN))

	conn, err := pg.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, "SET ROLE "+ScannerRole)
	require.NoError(t, err)
	defer func() { _, _ = conn.ExecContext(context.Background(), "RESET ROLE") }()

	for _, q := range []string{
		"SELECT max(version_id) FROM goose_db_version",
		"SELECT count(*) FROM river_migration",
		"SELECT count(*) FROM river_job",
		"SELECT count(*) FROM river_leader",
		"SELECT count(*) FROM river_queue",
		"SELECT count(*) FROM disk_scan_runs",
		"SELECT count(*) FROM disk_scan_volumes",
		"SELECT count(*) FROM disk_scan_connector_modes",
	} {
		_, err := conn.ExecContext(ctx, q)
		require.NoError(t, err, q)
	}
	for _, q := range []string{
		"INSERT INTO users DEFAULT VALUES",
		"UPDATE users SET role = 'admin'",
		"INSERT INTO api_keys DEFAULT VALUES",
		"SELECT count(*) FROM sessions",
		"SELECT count(*) FROM connectors",
		"SELECT count(*) FROM scan_profiles",
		"SELECT count(*) FROM scan_runs",
		"SELECT count(*) FROM scan_findings",
		"DELETE FROM disk_scan_runs",
		"CREATE TABLE scanner_probe (a int)",
	} {
		_, err := conn.ExecContext(ctx, q)
		require.ErrorContains(t, err, "permission denied", q)
	}
}

// Migrate's role owns every system catalog when it is the cluster's bootstrap
// superuser (graph in the root docker-compose.yml, postgres on many external
// servers), and PUBLIC reads most of them, as it does an extension's views.
// None of that is Vulngraph data, so Run grants the scanner role without
// naming any of it as an escape.
func TestRun_GrantsTheScannerRoleAsTheBootstrapSuperuser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	pg, err := sql.Open("pgx", pgDSN)
	require.NoError(t, err)
	defer pg.Close()
	_, err = pg.ExecContext(ctx, `DO $$ BEGIN CREATE ROLE `+ScannerRole+` NOLOGIN;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$`)
	require.NoError(t, err)

	var bootstrap bool
	require.NoError(t, pg.QueryRowContext(ctx,
		`SELECT current_user = (SELECT rolname FROM pg_roles WHERE oid = 10)`).Scan(&bootstrap))
	require.True(t, bootstrap, "the root docker-compose.yml's graph is the bootstrap superuser, which this test needs")
	var readable int
	require.NoError(t, pg.QueryRowContext(ctx, `SELECT count(*) FROM pg_class
		WHERE relnamespace = 'pg_catalog'::regnamespace AND relowner = 10
			AND has_table_privilege($1::name, oid, 'SELECT')`, ScannerRole).Scan(&readable))
	require.Positive(t, readable, "the scanner role reads catalogs migrate's role owns, through PUBLIC")

	var installed bool
	require.NoError(t, pg.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements')`).Scan(&installed))
	if !installed {
		_, err = pg.ExecContext(ctx, "CREATE EXTENSION pg_stat_statements SCHEMA public")
		require.NoError(t, err)
		defer func() { _, _ = pg.ExecContext(context.Background(), "DROP EXTENSION pg_stat_statements") }()
	}

	require.NoError(t, Run(ctx, pgDSN, chDSN))
}

// A scanner role that holds more than its own grants is not confined, and
// REVOKE ... FROM it does not take those rights away: CREATE where graph's
// queries resolve names (as PUBLIC can in public before Postgres 15), a role
// with table privileges, a privilege on graph's tables through PUBLIC, or a
// role attribute that reaches past grants. Run refuses each, naming it, and
// grants again once it is revoked.
func TestRun_RefusesAScannerRoleThatIsNotConfined(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	pg, err := sql.Open("pgx", pgDSN)
	require.NoError(t, err)
	defer pg.Close()
	_, err = pg.ExecContext(ctx, `DO $$ BEGIN CREATE ROLE `+ScannerRole+` NOLOGIN;
		EXCEPTION WHEN duplicate_object THEN NULL; END $$`)
	require.NoError(t, err)
	require.NoError(t, Run(ctx, pgDSN, chDSN))

	for _, tc := range []struct{ grant, revoke, refusal string }{
		{"GRANT CREATE ON SCHEMA public TO " + ScannerRole, "REVOKE CREATE ON SCHEMA public FROM " + ScannerRole,
			"CREATE on schema public"},
		{"GRANT pg_read_all_data TO " + ScannerRole, "REVOKE pg_read_all_data FROM " + ScannerRole,
			"membership in pg_read_all_data"},
		{"GRANT pg_write_all_data TO " + ScannerRole, "REVOKE pg_write_all_data FROM " + ScannerRole,
			"membership in pg_write_all_data"},
		{"GRANT SELECT ON users TO PUBLIC", "REVOKE SELECT ON users FROM PUBLIC",
			"SELECT on users through PUBLIC or a role"},
		{"GRANT UPDATE (role) ON users TO PUBLIC", "REVOKE UPDATE (role) ON users FROM PUBLIC",
			"UPDATE on users through PUBLIC or a role"},
		{"ALTER ROLE " + ScannerRole + " CREATEROLE", "ALTER ROLE " + ScannerRole + " NOCREATEROLE", "CREATEROLE"},
	} {
		_, err = pg.ExecContext(ctx, tc.grant)
		require.NoError(t, err, tc.grant)
		err = Run(ctx, pgDSN, chDSN)
		_, revokeErr := pg.ExecContext(context.Background(), tc.revoke)
		require.NoError(t, revokeErr, tc.revoke)
		require.ErrorContains(t, err, ScannerRole+" holds ", tc.grant)
		require.ErrorContains(t, err, tc.refusal, tc.grant)
		require.NoError(t, Run(ctx, pgDSN, chDSN), tc.revoke)
	}
}
