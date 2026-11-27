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

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/migrations"
)

func TestDeletionConfirmationMigrationUpgradeRollbackReplay(t *testing.T) {
	ctx, db, provider, _ := isolatedMigrationDB(t)
	_, err := provider.UpTo(ctx, 9)
	require.NoError(t, err)
	var id string
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO connectors(type,name,config_enc) VALUES('aws','fixture','') RETURNING id`).Scan(&id))
	_, err = db.ExecContext(ctx, `INSERT INTO connector_asset_hashes(connector_id,asset_id,hash) VALUES($1,'gone','h')`, id)
	require.NoError(t, err)
	for range 2 {
		_, err = provider.UpTo(ctx, 10)
		require.NoError(t, err)
		var observed sql.NullTime
		require.NoError(t, db.QueryRowContext(ctx, `SELECT deletion_observed_at FROM connectors WHERE id=$1`, id).Scan(&observed))
		require.False(t, observed.Valid, "old connectors cannot inherit confirmed absence")
		_, err = db.ExecContext(ctx, `INSERT INTO connector_deletion_candidates VALUES($1,'gone',now(),now())`, id)
		require.NoError(t, err)
		_, err = provider.UpTo(ctx, 10)
		require.NoError(t, err)
		var n int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM connector_deletion_candidates`).Scan(&n))
		require.Equal(t, 1, n)
		_, err = provider.DownTo(ctx, 9)
		require.NoError(t, err)
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM connector_asset_hashes`).Scan(&n))
		require.Equal(t, 1, n)
	}
	_, err = provider.UpTo(ctx, 10)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO connector_deletion_candidates VALUES($1,'gone',now(),now())`, id)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `DELETE FROM connector_asset_hashes WHERE connector_id=$1`, id)
	require.NoError(t, err)
	var n int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM connector_deletion_candidates`).Scan(&n))
	require.Zero(t, n)
}

func TestEdgeTypeIndexMigrationExistingDataRollbackReplay(t *testing.T) {
	raw := os.Getenv("TEST_CLICKHOUSE_URL")
	if raw == "" {
		t.Skip("requires isolated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := sql.Open("clickhouse", raw)
	require.NoError(t, err)
	defer admin.Close()
	name := fmt.Sprintf("migration_index_%d", time.Now().UnixNano())
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	defer func() { _, e := admin.ExecContext(context.Background(), "DROP DATABASE "+name); require.NoError(t, e) }()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	u.Path = "/" + name
	database, err := sql.Open("clickhouse", u.String())
	require.NoError(t, err)
	defer database.Close()
	files, err := fs.Sub(migrations.FS, "clickhouse")
	require.NoError(t, err)
	provider, err := goose.NewProvider(goose.DialectClickHouse, database, files, migrations.ProviderOptions(goose.DialectClickHouse))
	require.NoError(t, err)
	_, err = provider.UpTo(ctx, 1)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO graph_edges(src_id,src_type,dst_id,dst_type,edge_type,properties,synced_at)
 SELECT toString(number),'container_image',concat('pkg:',toString(number)), 'package','runs_package','{}',now() FROM numbers(100000)`)
	require.NoError(t, err)
	for range 2 {
		_, err = provider.UpTo(ctx, 2)
		require.NoError(t, err)
		var n uint64
		require.NoError(t, database.QueryRowContext(ctx, `SELECT count() FROM graph_edges WHERE edge_type='runs_package'`).Scan(&n))
		require.EqualValues(t, 100000, n)
		require.NoError(t, database.QueryRowContext(ctx, `SELECT count() FROM system.data_skipping_indices WHERE database=currentDatabase() AND table='graph_edges' AND name='idx_edge_type'`).Scan(&n))
		require.EqualValues(t, 1, n)
		_, err = provider.UpTo(ctx, 2)
		require.NoError(t, err)
		_, err = provider.DownTo(ctx, 1)
		require.NoError(t, err)
		require.NoError(t, database.QueryRowContext(ctx, `SELECT count() FROM graph_edges`).Scan(&n))
		require.EqualValues(t, 100000, n)
	}
	_, err = provider.UpTo(ctx, 2)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `DELETE FROM graph_edges WHERE src_id='1' SETTINGS mutations_sync=1`)
	require.NoError(t, err)
	var n uint64
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count() FROM graph_edges WHERE edge_type='runs_package'`).Scan(&n))
	require.EqualValues(t, 99999, n)
}
