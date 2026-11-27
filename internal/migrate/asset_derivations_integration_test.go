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

func TestAssetDerivationsMigrationUpgradeRollbackReplay(t *testing.T) {
	raw := os.Getenv("TEST_CLICKHOUSE_URL")
	if raw == "" {
		t.Skip("requires isolated ClickHouse")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	admin, err := sql.Open("clickhouse", raw)
	require.NoError(t, err)
	defer admin.Close()
	name := fmt.Sprintf("migration_derivations_%d", time.Now().UnixNano())
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+name)
	require.NoError(t, err)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_, e := admin.ExecContext(cleanup, "DROP DATABASE "+name)
		require.NoError(t, e)
	}()
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
	_, err = provider.UpTo(ctx, 4)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO assets (id,type,name,risk_score,last_seen,synced_at) VALUES ('legacy','ec2_instance','current',80,now64(9),now64(9))")
	require.NoError(t, err)
	for range 2 {
		_, err = provider.UpTo(ctx, 5)
		require.NoError(t, err)
		_, err = provider.UpTo(ctx, 5)
		require.NoError(t, err)
		var score uint8
		require.NoError(t, database.QueryRowContext(ctx, "SELECT risk_score FROM asset_current_with_derivations WHERE id='legacy'").Scan(&score))
		require.Equal(t, uint8(80), score, "migration cannot invent provenance for legacy risk")
		_, err = provider.DownTo(ctx, 4)
		require.NoError(t, err)
		var remaining uint64
		require.NoError(t, database.QueryRowContext(ctx, `SELECT count() FROM system.tables WHERE database=currentDatabase()
 AND name IN ('asset_finding_risk','asset_risk_publications','asset_annotations','asset_current_with_derivations','asset_versions_with_derivations')`).Scan(&remaining))
		require.Zero(t, remaining)
		require.NoError(t, database.QueryRowContext(ctx, "SELECT risk_score FROM assets WHERE id='legacy'").Scan(&score))
		require.Equal(t, uint8(80), score, "rollback must preserve the original observation")
	}
}
