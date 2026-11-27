//go:build integration

package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func versionTestDB(t *testing.T) (context.Context, *sql.DB, *goose.Provider) {
	t.Helper()
	raw := os.Getenv("TEST_CLICKHOUSE_URL")
	if raw == "" {
		t.Skip("requires isolated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	admin, err := sql.Open("clickhouse", raw)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	name := "versions_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	require.NoError(t, exec(ctx, admin, "CREATE DATABASE "+ident(name)+" ENGINE=Atomic"))
	t.Cleanup(func() { require.NoError(t, exec(context.Background(), admin, "DROP DATABASE "+ident(name)+" SYNC")) })
	u, err := url.Parse(raw)
	require.NoError(t, err)
	u.Path = "/" + name
	db, err := sql.Open("clickhouse", u.String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	p, err := goose.NewProvider(goose.DialectClickHouse, db, os.DirFS("."), goose.WithGoMigrations(PreciseVersions()))
	require.NoError(t, err)
	_, err = p.UpTo(ctx, 2)
	require.NoError(t, err)
	return ctx, db, p
}

func seedVersions(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	for _, c := range versionColumns {
		require.NoError(t, exec(ctx, db, "SYSTEM STOP MERGES "+ident(c.table)))
	}
	for _, query := range []string{
		`INSERT INTO assets(id,type,name,metadata,tags,discovered_at,last_seen,synced_at) SELECT toString(number),'ec2_instance','old','{"state":"old"}',map('env','old'),now()-100,now(),now()-2 FROM numbers(1000)`,
		`INSERT INTO assets(id,type,name,metadata,tags,discovered_at,last_seen,synced_at) SELECT toString(number),'ec2_instance','latest','{"state":"latest"}',map('env','production'),now()-100,now(),now()-1 FROM numbers(1000)`,
		`INSERT INTO graph_edges(src_id,dst_id,edge_type,properties,synced_at) SELECT toString(number),concat('target-',toString(number)),'runs_on','{"port":443}',now() FROM numbers(1000)`,
		`INSERT INTO findings(id,source,title,tags,detected_at,first_detected_at,synced_at) VALUES('finding','cspm','retained',map('env','prod'),now(),now()-10000,now())`,
		`INSERT INTO signals(id,factors,created_at,synced_at) VALUES('signal','[{"factor":"public"}]',now(),now())`,
		`INSERT INTO beliefs(finding_id,provenance,claim,evidence,created_at) VALUES('finding','adjudicator','retained','[{"fact":"public"}]',now())`,
		`INSERT INTO phishing_candidates(id,domain,detected_at) VALUES('candidate','example.invalid',now())`,
		`ALTER TABLE assets MODIFY COMMENT 'custom comment with \'quote\' and unicode λ'`,
	} {
		require.NoError(t, exec(ctx, db, query))
	}
}

func assertVersions(t *testing.T, ctx context.Context, db *sql.DB, typ string) {
	t.Helper()
	for _, c := range versionColumns {
		var got string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT type FROM system.columns WHERE database=currentDatabase() AND table=? AND name=?`, c.table, c.column).Scan(&got))
		require.Equal(t, typ, got, c.table)
	}
}

func TestPreciseVersionsUpgradeRollbackReplay(t *testing.T) {
	ctx, db, p := versionTestDB(t)
	seedVersions(t, ctx, db)
	before := map[string][3]uint64{}
	for _, c := range versionColumns {
		cols, _, err := copyColumns(ctx, db, c.table, copyMarker{Column: c.column, Target: "DateTime"})
		require.NoError(t, err)
		before[c.table], err = copyDigest(ctx, db, c.table, cols)
		require.NoError(t, err)
	}
	for range 2 {
		_, err := p.Up(ctx)
		require.NoError(t, err)
		assertVersions(t, ctx, db, "DateTime64(9)")
		current, target, err := p.GetVersions(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 3, current)
		require.Equal(t, current, target)
		for _, c := range versionColumns {
			_, cols, err := copyColumns(ctx, db, c.table, copyMarker{Column: c.column, Target: "DateTime"})
			require.NoError(t, err)
			got, err := copyDigest(ctx, db, c.table, cols)
			require.NoError(t, err)
			require.Equal(t, before[c.table], got, c.table)
		}
		var n uint64
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count() FROM system.data_skipping_indices WHERE database=currentDatabase() AND table='graph_edges' AND name='idx_edge_type'`).Scan(&n))
		require.EqualValues(t, 1, n)
		info, err := table(ctx, db, "assets")
		require.NoError(t, err)
		require.Equal(t, "custom comment with 'quote' and unicode λ", info.comment)
		_, err = p.Up(ctx)
		require.NoError(t, err)
		_, err = p.DownTo(ctx, 2)
		require.NoError(t, err)
		assertVersions(t, ctx, db, "DateTime")
	}
	_, err := p.Up(ctx)
	require.NoError(t, err)
	// Rollback uses the latest current data, never an obsolete upgrade backup.
	require.NoError(t, exec(ctx, db, `INSERT INTO assets(id,type,name,metadata,last_seen,synced_at) VALUES('0','ec2_instance','after upgrade','{"changed":true}',now(),now64(9))`))
	_, err = p.DownTo(ctx, 2)
	require.NoError(t, err)
	var name, metadata string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT name,metadata FROM assets FINAL WHERE id='0'`).Scan(&name, &metadata))
	require.Equal(t, "after upgrade", name)
	require.Equal(t, `{"changed":true}`, metadata)
}

func TestPreciseVersionsResumesEveryCopyBoundary(t *testing.T) {
	for _, stage := range []string{"marked", "renamed", "detached", "created", "partial", "published", "comment-restored"} {
		t.Run(stage, func(t *testing.T) {
			ctx, db, _ := versionTestDB(t)
			seedVersions(t, ctx, db)
			info, err := table(ctx, db, "assets")
			require.NoError(t, err)
			m := copyMarker{"assets", "synced_at", "DateTime64(9)", info.uuid, uuid.NewString(), info.comment}
			source, dest := "_vg_m3_assets_source", "_vg_m3_assets_copy"
			require.NoError(t, exec(ctx, db, "ALTER TABLE assets MODIFY COMMENT "+literal(markerComment(m))))
			if stage != "marked" {
				require.NoError(t, exec(ctx, db, "RENAME TABLE assets TO "+source))
			}
			if stage == "detached" {
				require.NoError(t, exec(ctx, db, "DETACH TABLE "+source+" PERMANENTLY SYNC"))
			}
			if stage == "created" || stage == "partial" || stage == "published" || stage == "comment-restored" {
				ddl, err := copyDDL(info.ddl, dest, m)
				require.NoError(t, err)
				require.NoError(t, exec(ctx, db, ddl))
				if stage != "created" {
					cols, projection, err := copyColumns(ctx, db, source, m)
					require.NoError(t, err)
					q := "INSERT INTO " + dest + " (" + cols + ") SELECT " + projection + " FROM " + source + " FINAL"
					if stage == "partial" {
						q += " LIMIT 10"
					}
					require.NoError(t, exec(ctx, db, q))
				}
				if stage == "published" || stage == "comment-restored" {
					require.NoError(t, exec(ctx, db, "RENAME TABLE "+dest+" TO assets"))
				}
				if stage == "comment-restored" {
					require.NoError(t, exec(ctx, db, "ALTER TABLE assets MODIFY COMMENT "+literal(m.Comment)))
				}
			}
			require.NoError(t, rebuildVersion(ctx, db, "assets", "synced_at", "DateTime64(9)"))
			var n uint64
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count() FROM assets FINAL WHERE name='latest' AND metadata='{"state":"latest"}' AND tags['env']='production'`).Scan(&n))
			require.EqualValues(t, 1000, n)
			current, err := table(ctx, db, "assets")
			require.NoError(t, err)
			require.Equal(t, m.CopyUUID, current.uuid)
			require.Equal(t, m.Comment, current.comment)
			require.NoError(t, rebuildVersion(ctx, db, "assets", "synced_at", "DateTime64(9)"))
			require.NoError(t, db.QueryRowContext(ctx, `SELECT count() FROM system.tables WHERE database=currentDatabase() AND startsWith(name,'_vg_m3_')`).Scan(&n))
			require.Zero(t, n)
		})
	}
}

func TestPreciseVersionsRejectsUnownedIntermediateTables(t *testing.T) {
	for _, name := range []string{"_vg_m3_assets_source", "_vg_m3_assets_copy"} {
		t.Run(name, func(t *testing.T) {
			ctx, db, p := versionTestDB(t)
			require.NoError(t, exec(ctx, db, "CREATE TABLE "+name+" AS assets"))
			info, err := table(ctx, db, "assets")
			require.NoError(t, err)
			_, err = p.Up(ctx)
			require.Error(t, err)
			current, err := table(ctx, db, "assets")
			require.NoError(t, err)
			require.Equal(t, info.uuid, current.uuid)
			_, err = table(ctx, db, name)
			require.NoError(t, err)
			version, err := p.GetDBVersion(ctx)
			require.NoError(t, err)
			require.EqualValues(t, 2, version)
		})
	}
}

func TestPreciseVersionsDrainsInflightInsert(t *testing.T) {
	ctx, db, _ := versionTestDB(t)
	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("insert panic: %v", r)
			}
		}()
		done <- exec(ctx, db, `INSERT INTO assets(id,type,name,last_seen,synced_at) SELECT 'inflight','ec2_instance',if(sleep(2)=0,'retained','unexpected'),now(),now()`)
	}()
	require.Eventually(t, func() bool {
		var n uint64
		err := db.QueryRowContext(ctx, `SELECT count() FROM system.processes WHERE current_database=currentDatabase() AND startsWith(query,'INSERT INTO assets')`).Scan(&n)
		return err == nil && n == 1
	}, time.Second, 10*time.Millisecond)
	require.NoError(t, rebuildVersion(ctx, db, "assets", "synced_at", "DateTime64(9)"))
	require.NoError(t, <-done)
	var name string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT name FROM assets FINAL WHERE id='inflight'`).Scan(&name))
	require.Equal(t, "retained", name)
}

func TestPreciseVersionsUsesDocumentedMigratorGrants(t *testing.T) {
	ctx, db, _ := versionTestDB(t)
	var database string
	require.NoError(t, db.QueryRowContext(ctx, "SELECT currentDatabase()").Scan(&database))
	user := "migrate_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := uuid.NewString()
	_, err := db.ExecContext(ctx, "CREATE USER "+ident(user)+" IDENTIFIED BY "+literal(password))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), "DROP USER "+ident(user))
		require.NoError(t, err)
	})
	require.NoError(t, exec(ctx, db, "GRANT ALL ON "+ident(database)+".* TO "+ident(user)))
	for _, metadata := range []string{"system.detached_tables", "system.mutations"} {
		require.NoError(t, exec(ctx, db, "GRANT SELECT ON "+metadata+" TO "+ident(user)))
	}
	u, err := url.Parse(os.Getenv("TEST_CLICKHOUSE_URL"))
	require.NoError(t, err)
	u.Path, u.User = "/"+database, url.UserPassword(user, password)
	restricted, err := sql.Open("clickhouse", u.String())
	require.NoError(t, err)
	defer restricted.Close()
	p, err := goose.NewProvider(goose.DialectClickHouse, restricted, os.DirFS("."), goose.WithGoMigrations(PreciseVersions()))
	require.NoError(t, err)
	_, err = p.Up(ctx)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 2)
	require.NoError(t, err)
}

func TestPreciseVersionsRejectsDependentViewBeforeRenaming(t *testing.T) {
	ctx, db, p := versionTestDB(t)
	require.NoError(t, exec(ctx, db, `CREATE MATERIALIZED VIEW asset_watch ENGINE=Memory AS SELECT id FROM assets`))
	before, err := table(ctx, db, "assets")
	require.NoError(t, err)
	_, err = p.Up(ctx)
	require.ErrorContains(t, err, "dependent views")
	after, err := table(ctx, db, "assets")
	require.NoError(t, err)
	require.Equal(t, before.uuid, after.uuid)
	require.Equal(t, before.comment, after.comment)
}

func TestPreciseVersionsRejectsPendingMutation(t *testing.T) {
	ctx, db, p := versionTestDB(t)
	require.NoError(t, exec(ctx, db, `INSERT INTO assets(id,type,name,last_seen,synced_at) VALUES('pending','ec2_instance','old',now(),now())`))
	require.NoError(t, exec(ctx, db, "SYSTEM STOP MERGES assets"))
	require.NoError(t, exec(ctx, db, `ALTER TABLE assets UPDATE name='new' WHERE id='pending' SETTINGS mutations_sync=0`))
	_, err := p.Up(ctx)
	require.ErrorContains(t, err, "pending mutations")
	require.NoError(t, exec(ctx, db, "SYSTEM START MERGES assets"))
	_, err = table(ctx, db, "assets")
	require.NoError(t, err)
}

func TestPreciseVersionsRetainsRowsAwaitingTTL(t *testing.T) {
	ctx, db, p := versionTestDB(t)
	require.NoError(t, exec(ctx, db, "SYSTEM STOP MERGES graph_edges"))
	require.NoError(t, exec(ctx, db, `INSERT INTO graph_edges(src_id,dst_id,edge_type,properties,synced_at) VALUES('expired','target','runs_on','{}',now()-INTERVAL 31 DAY)`))
	_, err := p.Up(ctx)
	require.NoError(t, err, "rows awaiting normal TTL cleanup must not prevent upgrading")
}
