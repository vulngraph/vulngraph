//go:build integration

package connector

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_ConnectorLifecycle(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)

	name := "it-" + time.Now().Format("150405.000000")
	cfg := map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}

	created, err := svc.Create(ctx, TypeAWS, name, cfg, "schedule")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		require.NoError(t, err)
	})
	require.Equal(t, SyncPending, created.SyncStatus)

	// Round-trips through real AES-GCM + Postgres bytea.
	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, cfg, got.Config)
	require.Equal(t, "schedule", got.EventSource)

	// Duplicate (type, name) is rejected by the unique index.
	_, err = svc.Create(ctx, TypeAWS, name, cfg, "")
	require.ErrorIs(t, err, ErrNameTaken)

	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), true, false))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, SyncOK, got.SyncStatus)
	require.NotNil(t, got.LastSyncedAt)
	require.EqualValues(t, 1, got.SyncStreak, "a clean no-op sync must persist and advance the streak")

	list, err := svc.List(ctx, true)
	require.NoError(t, err)
	require.NotEmpty(t, list)
	for _, c := range list {
		require.Nil(t, c.Config, "List must not decrypt credentials")
	}

	require.NoError(t, svc.Delete(ctx, created.ID))
	_, err = svc.Get(ctx, created.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

// TestPGRepo_SyncStreak_TransitionsAcrossRealPostgres is the regression guard
// for the adaptive sync backoff's persistence: a clean no-op sync must
// increment sync_streak, and ANYTHING else (a real diff, a partial
// collection, an outright failure) must reset it to 0 — round-tripped
// through the actual SQL (the CASE expression in SetConnectorSyncResult), not
// a fake.
func TestPGRepo_SyncStreak_TransitionsAcrossRealPostgres(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)

	name := "it-streak-" + time.Now().Format("150405.000000")
	created, err := svc.Create(ctx, TypeAWS,
		name, map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		require.NoError(t, err)
	})
	require.Zero(t, created.SyncStreak, "a brand-new connector starts at streak 0")

	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), true, false))
	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, got.SyncStreak)

	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), true, false))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, got.SyncStreak, "consecutive clean syncs keep incrementing")

	// A non-clean sync (a real diff, a partial collection, or a failure) must
	// reset the streak, not merely fail to advance it.
	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), false, false))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Zero(t, got.SyncStreak, "a non-clean sync resets the streak to 0")

	// Rebuild the streak, then confirm an outright failure also resets it.
	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), true, false))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.EqualValues(t, 1, got.SyncStreak)

	require.NoError(t, svc.RecordSync(ctx, created.ID, errors.New("boom"), time.Now(), false, false))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Zero(t, got.SyncStreak, "a hard failure resets the streak")
}

// TestPGRepo_PartialStreak_TransitionsAcrossRealPostgres round-trips
// PartialStreak through the real SQL (the CASE expression added alongside
// sync_streak's) — the persistence half of the fix for a connector that ran
// Partial every sync for weeks while LastSuccessAt kept advancing and
// SyncStatus stayed "ok", reading as fully healthy the whole time.
func TestPGRepo_PartialStreak_TransitionsAcrossRealPostgres(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)

	name := "it-partial-" + time.Now().Format("150405.000000")
	created, err := svc.Create(ctx, TypeAWS,
		name, map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		require.NoError(t, err)
	})
	require.Zero(t, created.PartialStreak, "a brand-new connector starts at streak 0")

	// A Partial sync with runErr == nil: status stays SyncOK, LastSuccessAt
	// still advances — PartialStreak is the only signal that moves.
	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), false, true))
	got, err := svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, SyncOK, got.SyncStatus)
	require.NotNil(t, got.LastSyncedAt)
	require.EqualValues(t, 1, got.PartialStreak)

	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), false, true))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.EqualValues(t, 2, got.PartialStreak, "consecutive Partial syncs keep incrementing")

	require.NoError(t, svc.RecordSync(ctx, created.ID, nil, time.Now(), true, false))
	got, err = svc.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Zero(t, got.PartialStreak, "a non-Partial sync resets the streak, even though it's unrelated to cleanNoOp/SyncStreak")
}

// TestPGRepo_EveryValidTypeCanActuallyBeCreated guards against drift between
// Type.Valid() and the Postgres connectors_type_check constraint: if a type is
// valid at the app layer but the constraint was never migrated to match, every
// create attempt fails with a generic 500 that no coverage tool ever
// surfaced (nothing measures a connector that can't exist). Iterating every
// Type domain.go declares valid — not a hardcoded list here — means a future
// new type added to domain.go without its companion migration fails THIS
// test immediately, in CI, instead of silently bricking a feature in a deployment.
func TestPGRepo_EveryValidTypeCanActuallyBeCreated(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)

	for typ, keys := range requiredKeys {
		typ, keys := typ, keys
		t.Run(string(typ), func(t *testing.T) {
			require.True(t, typ.Valid(), "requiredKeys carries a type domain.go itself doesn't consider valid")
			cfg := map[string]string{}
			for _, k := range keys {
				cfg[k] = "test-value"
			}
			for _, group := range oneOfKeys[typ] {
				if len(group) > 0 {
					cfg[group[0]] = "test-value"
				}
			}
			if typ == TypeAWSOrg { // values are validated, not only present
				cfg = orgConfig(nil)
			}
			name := "it-" + string(typ) + "-" + time.Now().Format("150405.000000")
			created, err := svc.Create(ctx, typ, name, cfg, "")
			require.NoError(t, err, "%s is Valid() but Postgres rejected creating it — connectors_type_check is missing a migration", typ)
			t.Cleanup(func() {
				_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
				require.NoError(t, err)
			})
		})
	}
}

// CollectingAsset reads the sync's per-asset record: enabled connectors with a
// row for the asset, and nothing for a disabled one.
func TestPGRepo_CollectingAsset(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)
	suffix := time.Now().Format("150405.000000")
	asset := "arn:aws:ec2:eu-west-1:1:security-group/sg-it-" + suffix

	var ids []string
	for _, name := range []string{"own-a-", "own-b-"} {
		c, err := svc.Create(ctx, TypeAWS, name+suffix, map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}, "")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", c.ID)
			require.NoError(t, err)
		})
		ids = append(ids, c.ID)
	}

	require.NoError(t, svc.UpsertAssetHashEntries(ctx, ids[0], []AssetHashEntry{{AssetID: asset, Hash: "h"}}))
	got, err := svc.ConnectorsCollecting(ctx, asset)
	require.NoError(t, err)
	require.Equal(t, []string{ids[0]}, got)

	require.NoError(t, svc.UpsertAssetHashEntries(ctx, ids[1], []AssetHashEntry{{AssetID: asset, Hash: "h"}}))
	got, err = svc.ConnectorsCollecting(ctx, asset)
	require.NoError(t, err)
	require.ElementsMatch(t, ids, got)

	_, err = pool.Exec(ctx, "UPDATE connectors SET enabled = false WHERE id = $1", ids[1])
	require.NoError(t, err)
	got, err = svc.ConnectorsCollecting(ctx, asset)
	require.NoError(t, err)
	require.Equal(t, []string{ids[0]}, got, "a disabled connector does not own anything")
}

// SetConnectorMode returns the mode it replaced, which the audit row's before
// value is taken from, and an unknown or malformed id is ErrNotFound.
func TestPGRepo_SetModeReturnsThePreviousMode(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	repo := NewPGRepo(pool)
	created, err := NewService(repo, cipher).Create(ctx, TypeAWS, "it-mode-"+time.Now().Format("150405.000000"),
		map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		require.NoError(t, err)
	})

	prev, err := repo.SetMode(ctx, created.ID, ModeReadWrite)
	require.NoError(t, err)
	require.Equal(t, ModeReadOnly, prev)
	prev, err = repo.SetMode(ctx, created.ID, ModeReadWrite)
	require.NoError(t, err)
	require.Equal(t, ModeReadWrite, prev)

	_, err = repo.SetMode(ctx, "00000000-0000-0000-0000-000000000000", ModeReadWrite)
	require.ErrorIs(t, err, ErrNotFound)
	_, err = repo.SetMode(ctx, "not-a-uuid", ModeReadWrite)
	require.ErrorIs(t, err, ErrNotFound)
}

// A sweep that could not read an asset's public IP keeps the stored address,
// so drift (curr_public_ip vs prev_public_ip) never reports a lost exposure
// for it; the next readable sweep records a real change as usual.
func TestPGRepo_UnreadPublicIPKeepsTheStoredAddress(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)
	suffix := time.Now().Format("150405.000000")
	c, err := svc.Create(ctx, TypeAWS, "pubip-"+suffix, map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", c.ID)
		require.NoError(t, err)
	})
	id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-" + suffix
	ips := func() (curr, prev string) {
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT curr_public_ip, prev_public_ip FROM connector_asset_hashes WHERE connector_id = $1 AND asset_id = $2",
			c.ID, id).Scan(&curr, &prev))
		return curr, prev
	}

	require.NoError(t, svc.UpsertAssetHashEntries(ctx, c.ID, []AssetHashEntry{{AssetID: id, Hash: "h1", PubIP: "20.1.2.3"}}))
	require.NoError(t, svc.UpsertAssetHashEntries(ctx, c.ID, []AssetHashEntry{{AssetID: id, Hash: "h2", PubIPUnread: true}}))
	curr, prev := ips()
	require.Equal(t, "20.1.2.3", curr, "an unread IP must not overwrite the stored one")
	require.Equal(t, curr, prev, "no IP change is recorded for an unread sweep")

	require.NoError(t, svc.UpsertAssetHashEntries(ctx, c.ID, []AssetHashEntry{{AssetID: id, Hash: "h3"}}))
	curr, prev = ips()
	require.Equal(t, "", curr, "a read sweep with no IP is a real loss of the address")
	require.Equal(t, "20.1.2.3", prev)
}

func TestPGRepo_DiskScanMode(t *testing.T) {
	ctx := context.Background()
	dsn := os.Getenv("CONNECTOR_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
	}
	pool, err := db.NewPool(ctx, dsn, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	svc := NewService(NewPGRepo(pool), cipher)

	cfg := map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1", ConfigDiskScanRoleARN: "arn:aws:iam::1:role/disk"}
	c, err := svc.Create(ctx, TypeAWS, "it-disk-"+time.Now().Format("150405.000000"), cfg, "")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", c.ID) })
	require.Equal(t, diskscan.DiskScanModeOff, c.DiskScanMode, "the column default is off")

	admin := DiskScanActor{ID: "it-admin", Admin: true}
	require.NoError(t, svc.SetDiskScanMode(ctx, c.ID, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, admin))
	got, err := svc.Get(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, diskscan.DiskScanModeCreateSnapshots, got.DiskScanMode)
	require.Equal(t, "it-admin", got.DiskScanEnabledBy)
	require.NotNil(t, got.DiskScanEnabledAt)

	enabled, err := svc.DiskScanEnabled(ctx)
	require.NoError(t, err)
	var found bool
	for _, s := range enabled {
		found = found || s.ConnectorID == c.ID
	}
	require.True(t, found)

	require.NoError(t, svc.SetDiskScanMode(ctx, c.ID, diskscan.DiskScanModeOff, "", admin))
	got, err = svc.Get(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, diskscan.DiskScanModeOff, got.DiskScanMode)
	require.Empty(t, got.DiskScanEnabledBy)

	err = svc.SetDiskScanMode(ctx, "00000000-0000-0000-0000-000000000000", diskscan.DiskScanModeOff, "", admin)
	require.ErrorIs(t, err, ErrNotFound)
}
