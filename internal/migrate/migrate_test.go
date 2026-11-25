package migrate

import (
	"database/sql"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/migrations"
)

// goose rejects duplicate or unparseable versions when the provider is built, so
// constructing one catches a misnumbered migration without touching a database.
func TestEmbeddedMigrationsAreWellFormed(t *testing.T) {
	for _, tc := range []struct {
		dir     string
		dialect goose.Dialect
	}{
		{"postgres", goose.DialectPostgres},
		{"clickhouse", goose.DialectClickHouse},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			fsys, err := fs.Sub(migrations.FS, tc.dir)
			require.NoError(t, err)

			db, err := sql.Open("pgx", "postgres://unused")
			require.NoError(t, err)
			t.Cleanup(func() { _ = db.Close() })

			provider, err := goose.NewProvider(tc.dialect, db, fsys)
			require.NoError(t, err)

			sources := provider.ListSources()
			require.NotEmpty(t, sources)

			for i, s := range sources {
				require.Equalf(t, int64(i+1), s.Version,
					"%s: migrations are numbered contiguously from 00001 (docs/migrations.md); take the next number",
					s.Path)

				body, err := fs.ReadFile(fsys, strings.TrimPrefix(s.Path, "/"))
				require.NoError(t, err)
				require.Contains(t, string(body), "-- +goose Up", s.Path)
			}
		})
	}
}

// The advisory lock must never be waited on without a bound.
//
// migrate runs as an init container, which Kubernetes applies no timeout to.
// A blocking `SELECT pg_advisory_lock(…)` would leave a pod that died holding
// the lock stuck until TCP keepalive reaps the dead session, with the app
// down and no self-heal. A bounded wait fails the init container fast and
// lets Kubernetes' restart backoff be the retry loop.
//
// Asserted against the source because withAdvisoryLock opens its own connection
// from a DSN and cannot be faked; the behavioural proof is in
// migrate_integration_test.go (build tag `integration`).
func TestAdvisoryLockWaitIsBounded(t *testing.T) {
	src, err := os.ReadFile("migrate.go")
	require.NoError(t, err)
	body := string(src)

	start := strings.Index(body, "func withAdvisoryLock(")
	require.Positive(t, start)
	end := strings.Index(body[start+1:], "\nfunc ")
	require.Positive(t, end)
	fn := body[start : start+1+end]

	setAt := strings.Index(fn, "SET lock_timeout")
	acquireAt := strings.Index(fn, "pg_advisory_lock(")
	require.Positive(t, setAt, "withAdvisoryLock must bound how long it waits for the lock")
	require.Positive(t, acquireAt)
	require.Less(t, setAt, acquireAt, "lock_timeout has to be set BEFORE the wait it bounds")

	d, err := time.ParseDuration(lockTimeout)
	require.NoError(t, err, "lockTimeout must be a duration Postgres and Go both parse")
	require.Positive(t, d)
	require.LessOrEqual(t, d, 2*time.Minute,
		"the point is to fail fast enough that Kubernetes retries; a long wait is barely better than none")
}

// idx_dst_id is the only thing standing between the incoming-edge path and a
// full scan of graph_edges: dst_id is key position 3 of ORDER BY
// (src_id, edge_type, dst_id), so the primary key prunes nothing for a
// dst_id-only lookup. GRANULARITY 4 would set a floor of four granules
// (32,768 rows) per matched entry to return typically one row, and a 1%
// false-positive rate would add most of that back, so it is GRANULARITY 1 at
// 0.001, matching findings.idx_id and assets.idx_id.
func TestGraphEdgesDstIndexIsShapedForPointLookups(t *testing.T) {
	body, err := fs.ReadFile(migrations.FS, "clickhouse/00001_init.sql")
	require.NoError(t, err)

	require.Contains(t, string(body), "INDEX idx_dst_id dst_id TYPE bloom_filter(0.001) GRANULARITY 1",
		"graph_edges.idx_dst_id must stay shaped for point lookups")
}
