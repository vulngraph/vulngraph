//go:build integration

package migrate

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRetirementMigration_UpgradeRollbackReplay(t *testing.T) {
	ctx, db, provider, _ := isolatedMigrationDB(t)
	_, err := provider.UpTo(ctx, 8)
	require.NoError(t, err)
	at := time.Now().UTC().Truncate(time.Second)
	_, err = db.ExecContext(ctx, "INSERT INTO asset_deletions(asset_id,connector_id,deleted_at) VALUES ('gone','former-connector',$1)", at)
	require.NoError(t, err)
	results, err := provider.UpTo(ctx, 9)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.EqualValues(t, 9, results[0].Source.Version)
	var retired sql.NullTime
	var proof time.Time
	require.NoError(t, db.QueryRowContext(ctx, "SELECT deleted_at,retired_at FROM asset_deletions WHERE asset_id='gone'").Scan(&proof, &retired))
	require.True(t, proof.Equal(at))
	require.False(t, retired.Valid, "existing proofs must be queued for retirement")
	results, err = provider.UpTo(ctx, 9)
	require.NoError(t, err)
	require.Empty(t, results)
	_, err = provider.DownTo(ctx, 8)
	require.NoError(t, err)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT deleted_at FROM asset_deletions WHERE asset_id='gone'").Scan(&proof))
	require.True(t, proof.Equal(at), "rollback preserves the deletion proof")
	_, err = provider.UpTo(ctx, 9)
	require.NoError(t, err)
	require.NoError(t, db.QueryRowContext(ctx, "SELECT retired_at FROM asset_deletions WHERE asset_id='gone'").Scan(&retired))
	require.False(t, retired.Valid)
}
