//go:build integration

package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/migrations"
)

// A separate schema gives each transition test an empty version ledger without
// dropping or rewinding the shared integration database used by other packages.
func isolatedMigrationDB(t *testing.T) (context.Context, *sql.DB, *goose.Provider, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	baseDSN := os.Getenv("TEST_DATABASE_URL")
	if baseDSN == "" {
		baseDSN = pgDSN
	}
	admin, err := sql.Open("pgx", baseDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("migration_hardening_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := admin.ExecContext(cleanup, "DROP SCHEMA "+quoted+" CASCADE")
		require.NoError(t, err)
	})
	u, err := url.Parse(baseDSN)
	require.NoError(t, err)
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	dsn := u.String()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	fsys, err := fs.Sub(migrations.FS, "postgres")
	require.NoError(t, err)
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys, migrations.ProviderOptions(goose.DialectPostgres))
	require.NoError(t, err)
	return ctx, db, provider, dsn
}

func TestHardeningMigrationsFreshInstall(t *testing.T) {
	ctx, db, provider, dsn := isolatedMigrationDB(t)
	// This is the production order: app schema before River exists, then River.
	require.NoError(t, up(ctx, "pgx", dsn, goose.DialectPostgres, "postgres"))
	var riverTable sql.NullString
	require.NoError(t, db.QueryRowContext(ctx, "SELECT to_regclass('river_job')::text").Scan(&riverTable))
	require.False(t, riverTable.Valid)
	require.NoError(t, river(ctx, dsn))
	require.NoError(t, up(ctx, "pgx", dsn, goose.DialectPostgres, "postgres"))
	require.NoError(t, river(ctx, dsn))
	pending, err := provider.HasPending(ctx)
	require.NoError(t, err)
	require.False(t, pending)
	var version int64
	var since time.Time
	require.NoError(t, db.QueryRowContext(ctx, "INSERT INTO users(email,password_hash,role) VALUES ('fresh@example.com','test','admin') RETURNING authority_version,admin_since").Scan(&version, &since))
	require.EqualValues(t, 1, version)
	require.False(t, since.IsZero())
}

func TestHardeningMigrationsUpgrade(t *testing.T) {
	// Include an interrupted/old River installation without the pending enum
	// label: app migrations execute before River gets to upgrade its own schema.
	for _, legacyRiver := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy_river_%v", legacyRiver), func(t *testing.T) {
			ctx, db, provider, dsn := isolatedMigrationDB(t)
			_, err := provider.UpTo(ctx, 6)
			require.NoError(t, err)
			pool, err := pgxpool.New(ctx, dsn)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			rm, err := rivermigrate.New(riverpgxv5.New(pool), nil)
			require.NoError(t, err)
			var opts *rivermigrate.MigrateOpts
			if legacyRiver {
				opts = &rivermigrate.MigrateOpts{TargetVersion: 2}
			}
			_, err = rm.Migrate(ctx, rivermigrate.DirectionUp, opts)
			require.NoError(t, err)
			for _, statement := range []string{
				"INSERT INTO users(email,password_hash,role,created_at) VALUES ('admin@example.com','test','admin',now()-interval '1 year'),('viewer@example.com','test','viewer',now()-interval '1 year')",
				"INSERT INTO users(email,password_hash,role,disabled_at) VALUES ('disabled@example.com','test','admin',now())",
				"INSERT INTO scan_profiles(name,schedule,enabled,drift_enabled) VALUES ('old profile','0 * * * *',true,true)",
				"INSERT INTO scan_runs(status) VALUES ('running'),('completed')",
			} {
				_, err = db.ExecContext(ctx, statement)
				require.NoError(t, err)
			}
			states := []string{"available", "scheduled", "retryable", "running"}
			if !legacyRiver {
				states = append(states, "pending")
			}
			for _, kind := range []string{"scan", "scan_profile", "scan_asset", "run_scheduled_profiles"} {
				for _, state := range states {
					_, err = db.ExecContext(ctx, "INSERT INTO river_job(kind,state,max_attempts,args) VALUES ($1,$2,3,'{}')", kind, state)
					require.NoError(t, err)
				}
			}
			_, err = db.ExecContext(ctx, "INSERT INTO river_job(kind,state,max_attempts,args) VALUES ('refresh_vm_vuln','available',3,'{}')")
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, "INSERT INTO river_job(kind,state,max_attempts,args,finalized_at) VALUES ('scan','completed',3,'{}',now())")
			require.NoError(t, err)
			var before time.Time
			require.NoError(t, db.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&before))
			results, err := provider.UpTo(ctx, 8)
			require.NoError(t, err)
			require.Len(t, results, 2)
			require.EqualValues(t, 7, results[0].Source.Version)
			require.EqualValues(t, 8, results[1].Source.Version)
			var n int
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM scan_profiles WHERE enabled OR drift_enabled OR schedule <> ''").Scan(&n))
			require.Zero(t, n)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM scan_runs WHERE status = 'cancelled' AND finished_at IS NOT NULL").Scan(&n))
			require.Equal(t, 1, n)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM scan_runs WHERE status = 'completed'").Scan(&n))
			require.Equal(t, 1, n)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM river_job WHERE state = 'cancelled' AND finalized_at IS NOT NULL").Scan(&n))
			require.Equal(t, len(states)*4, n)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM river_job WHERE kind = 'refresh_vm_vuln' AND state = 'available'").Scan(&n))
			require.Equal(t, 1, n)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM river_job WHERE kind = 'scan' AND state = 'completed'").Scan(&n))
			require.Equal(t, 1, n)
			var since time.Time
			var authority int64
			require.NoError(t, db.QueryRowContext(ctx, "SELECT authority_version,admin_since FROM users WHERE email='admin@example.com'").Scan(&authority, &since))
			require.EqualValues(t, 1, authority)
			require.False(t, since.Before(before))
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE email <> 'admin@example.com' AND admin_since IS NULL").Scan(&n))
			require.Equal(t, 2, n)
			// Ordinary profile edits cannot reset tenure or bump authority.
			_, err = db.ExecContext(ctx, "UPDATE users SET updated_at=now() WHERE email='admin@example.com'")
			require.NoError(t, err)
			var unchanged time.Time
			require.NoError(t, db.QueryRowContext(ctx, "SELECT authority_version,admin_since FROM users WHERE email='admin@example.com'").Scan(&authority, &unchanged))
			require.EqualValues(t, 1, authority)
			require.True(t, since.Equal(unchanged))
			_, err = db.ExecContext(ctx, "UPDATE users SET role='viewer' WHERE email='admin@example.com'")
			require.NoError(t, err)
			var revoked sql.NullTime
			require.NoError(t, db.QueryRowContext(ctx, "SELECT authority_version,admin_since FROM users WHERE email='admin@example.com'").Scan(&authority, &revoked))
			require.EqualValues(t, 2, authority)
			require.False(t, revoked.Valid)
			_, err = db.ExecContext(ctx, "UPDATE users SET role='admin' WHERE email='admin@example.com'")
			require.NoError(t, err)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT authority_version,admin_since FROM users WHERE email='admin@example.com'").Scan(&authority, &unchanged))
			require.EqualValues(t, 3, authority)
			require.True(t, unchanged.After(since))
			// Re-running is a no-op; it must not restart administrator tenure.
			results, err = provider.UpTo(ctx, 8)
			require.NoError(t, err)
			require.Empty(t, results)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT admin_since FROM users WHERE email='admin@example.com'").Scan(&since))
			require.True(t, since.Equal(unchanged))
			// River can finish upgrading after our migration changed its queued jobs.
			require.NoError(t, river(ctx, dsn))
			_, err = provider.DownTo(ctx, 6)
			require.NoError(t, err)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='users' AND column_name = 'authority_version'").Scan(&n))
			require.Zero(t, n)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM scan_profiles WHERE enabled OR drift_enabled OR schedule <> ''").Scan(&n))
			require.Zero(t, n, "rollback must not reactivate scanning")
			_, err = provider.UpTo(ctx, 8)
			require.NoError(t, err)
		})
	}
}
