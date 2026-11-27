//go:build integration

package clickhouse

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPreciseObservationsUpgradeRollbackReplay(t *testing.T) {
	ctx, db, p := versionTestDB(t)
	_, err := p.UpTo(ctx, 3)
	require.NoError(t, err)
	old := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	precise := old.Add(123456789 * time.Nanosecond)
	_, err = db.ExecContext(ctx, `INSERT INTO assets(id,type,name,metadata,last_seen,synced_at) SELECT toString(number),'ec2_instance','retained','{"key":"value"}',parseDateTimeBestEffort(`+literal(old.Format(time.RFC3339))+`),now64(9) FROM numbers(1000)`)
	require.NoError(t, err)
	// A crash after the first DDL leaves the safe TTL conversion in place.
	require.NoError(t, exec(ctx, db, "ALTER TABLE assets MODIFY TTL toDateTime(last_seen)+INTERVAL 180 DAY SETTINGS materialize_ttl_after_modify=0"))
	for range 2 {
		_, err = p.Up(ctx)
		require.NoError(t, err)
		var typ string
		require.NoError(t, db.QueryRowContext(ctx, "SELECT type FROM system.columns WHERE database=currentDatabase() AND table='assets' AND name='last_seen'").Scan(&typ))
		require.Equal(t, "DateTime64(9)", typ)
		var n uint64
		require.NoError(t, db.QueryRowContext(ctx, `SELECT count() FROM assets WHERE name='retained' AND metadata='{"key":"value"}' AND last_seen=parseDateTimeBestEffort(`+literal(old.Format(time.RFC3339))+`)`).Scan(&n))
		require.EqualValues(t, 1000, n)
		_, err = db.ExecContext(ctx, `INSERT INTO assets(id,type,name,last_seen,synced_at) VALUES('precise','ec2_instance','new',parseDateTime64BestEffort(`+literal(precise.Format(time.RFC3339Nano))+`,9),now64(9))`)
		require.NoError(t, err)
		var stored time.Time
		require.NoError(t, db.QueryRowContext(ctx, "SELECT last_seen FROM assets FINAL WHERE id='precise'").Scan(&stored))
		require.True(t, stored.Equal(precise), "fractional observations must survive storage")
		_, err = p.Up(ctx)
		require.NoError(t, err)
		_, err = p.DownTo(ctx, 3)
		require.NoError(t, err)
		require.NoError(t, db.QueryRowContext(ctx, "SELECT last_seen FROM assets FINAL WHERE id='precise'").Scan(&stored))
		require.True(t, stored.Equal(old))
	}
}
