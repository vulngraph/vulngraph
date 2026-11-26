package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/migrations"
)

// Exercise Goose's actual SQL parser and batching, including Down sections and
// StatementBegin/End blocks. The recorder never executes SQL: dialect semantics
// and real schema transitions are covered by the integration tests.
func TestGooseParsesEmbeddedSQLInBothDirections(t *testing.T) {
	for _, tc := range []struct {
		dir     string
		dialect goose.Dialect
	}{
		{"postgres", goose.DialectPostgres}, {"clickhouse", goose.DialectClickHouse},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			rec := &sqlRecorder{}
			db := sql.OpenDB(recordConnector{rec})
			t.Cleanup(func() { _ = db.Close() })
			fsys, err := fs.Sub(migrations.FS, tc.dir)
			require.NoError(t, err)
			provider, err := goose.NewProvider(tc.dialect, db, fsys, goose.WithDisableVersioning(true))
			require.NoError(t, err)
			sources := provider.ListSources()
			require.NotEmpty(t, sources)
			for _, source := range sources {
				for _, up := range []bool{true, false} {
					rec.statements = nil
					commits := rec.commits
					result, err := provider.ApplyVersion(context.Background(), source.Version, up)
					require.NoError(t, err, "%s up=%v", source.Path, up)
					require.Equal(t, source.Version, result.Source.Version)
					if tc.dir == "postgres" && (source.Version == 7 || source.Version == 8) {
						require.Equal(t, commits+1, rec.commits, "security migrations must be transactional")
						if up {
							marker := "DO $$"
							end := "END $$;"
							if source.Version == 8 {
								marker = "CREATE FUNCTION track_user_authority()"
							}
							blocks := 0
							for _, statement := range rec.statements {
								if strings.Contains(statement, marker) {
									blocks++
									require.Contains(t, statement, end, "Goose must not split the PL/pgSQL block")
								}
							}
							require.Equal(t, 1, blocks)
						}
					}
				}
			}
			t.Logf("Goose parsed %d %s migrations in both directions", len(sources), tc.dir)
		})
	}
}

type sqlRecorder struct {
	statements []string
	commits    int
}
type recordConnector struct{ rec *sqlRecorder }

func (c recordConnector) Connect(context.Context) (driver.Conn, error) { return recordConn(c), nil }
func (c recordConnector) Driver() driver.Driver                        { return recordDriver(c) }

type recordDriver struct{ rec *sqlRecorder }

func (d recordDriver) Open(string) (driver.Conn, error) { return recordConn(d), nil }

type recordConn struct{ rec *sqlRecorder }

func (recordConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("SQL recorder does not support prepared statements")
}
func (recordConn) Close() error                { return nil }
func (c recordConn) Begin() (driver.Tx, error) { return recordTx(c), nil }
func (c recordConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.rec.statements = append(c.rec.statements, query)
	return driver.RowsAffected(1), nil
}

type recordTx struct{ rec *sqlRecorder }

func (t recordTx) Commit() error { t.rec.commits++; return nil }
func (recordTx) Rollback() error { return nil }
