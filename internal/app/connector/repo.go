package connector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// storedConnector is a connector as persisted: config is still ciphertext. The
// service decrypts it into a domain Connector.
type storedConnector struct {
	Connector        // Config is nil at this layer
	ConfigCiphertext []byte
}

// PGRepo implements Repo on Postgres. It deals only in ciphertext; encryption
// is the service's job.
type PGRepo struct {
	q    *sqlcgen.Queries
	pool *pgxpool.Pool
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool), pool: pool} }

const (
	uniqueViolation           = "23505"
	invalidTextRepresentation = "22P02" // e.g. a non-UUID id — the row can't exist
)

// Create inserts the row and seals its config in one transaction.
//
// The two steps exist because the ciphertext is bound to the connector's id
// (AAD) and Postgres assigns that id — so the row must exist before its config
// can be sealed. Wrapping both in a transaction means the intermediate state
// (a row with an empty config_enc) is never visible and never committed: either
// there is a connector with an openable config, or there is no connector.
func (r *PGRepo) Create(ctx context.Context, c Connector, encrypt func(id string) ([]byte, error)) (storedConnector, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return storedConnector{}, fmt.Errorf("Create: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	q := r.q.WithTx(tx)
	// An empty ciphertext, not nil: config_enc is NOT NULL, so a nil here fails
	// the insert outright (SQLSTATE 23502). It is a placeholder that cannot
	// escape — the UPDATE below runs in the same transaction, so no committed row
	// ever carries it, and a failure between the two rolls the insert back with
	// it. The two steps exist because the AAD binds the ciphertext to the row id,
	// and the id is assigned by the insert.
	row, err := q.CreateConnector(ctx, sqlcgen.CreateConnectorParams{
		Type:        string(c.Type),
		Name:        c.Name,
		ConfigEnc:   []byte{},
		Enabled:     c.Enabled,
		EventSource: c.EventSource,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return storedConnector{}, ErrNameTaken
		}
		return storedConnector{}, fmt.Errorf("Create: %w", err)
	}

	enc, err := encrypt(row.ID)
	if err != nil {
		return storedConnector{}, fmt.Errorf("Create: encrypt config: %w", err)
	}
	if err := q.UpdateConnectorConfig(ctx, sqlcgen.UpdateConnectorConfigParams{ID: row.ID, ConfigEnc: enc}); err != nil {
		return storedConnector{}, fmt.Errorf("Create: seal config: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return storedConnector{}, fmt.Errorf("Create: commit: %w", err)
	}

	row.ConfigEnc = enc
	return toStored(row), nil
}

// UpdateConfig replaces a connector's sealed config in place.
func (r *PGRepo) UpdateConfig(ctx context.Context, id string, configEnc []byte) error {
	err := r.q.UpdateConnectorConfig(ctx, sqlcgen.UpdateConnectorConfigParams{ID: id, ConfigEnc: configEnc})
	if err != nil {
		return fmt.Errorf("UpdateConfig: %w", err)
	}
	return nil
}

// ResealConfig swaps a connector's sealed config only while it still equals
// old, so a write that landed after the caller read old is never overwritten.
func (r *PGRepo) ResealConfig(ctx context.Context, id string, old, sealed []byte) (bool, error) {
	n, err := r.q.ResealConnectorConfig(ctx, sqlcgen.ResealConnectorConfigParams{ID: id, OldConfigEnc: old, NewConfigEnc: sealed})
	if err != nil {
		return false, fmt.Errorf("ResealConfig: %w", err)
	}
	return n == 1, nil
}

func (r *PGRepo) Get(ctx context.Context, id string) (storedConnector, error) {
	row, err := r.q.GetConnector(ctx, id)
	if err != nil {
		// A non-UUID id (e.g. a bad path param) makes Postgres reject the query
		// with 22P02; such an id can't match any row, so treat it as not-found
		// rather than letting it surface as a 500.
		var pgErr *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
			return storedConnector{}, ErrNotFound
		}
		return storedConnector{}, fmt.Errorf("Get: %w", err)
	}
	return toStored(row), nil
}

func (r *PGRepo) List(ctx context.Context, enabledOnly bool) ([]storedConnector, error) {
	var (
		rows []sqlcgen.Connector
		err  error
	)
	if enabledOnly {
		rows, err = r.q.ListEnabledConnectors(ctx)
	} else {
		rows, err = r.q.ListConnectors(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	out := make([]storedConnector, len(rows))
	for i, row := range rows {
		out[i] = toStored(row)
	}
	return out, nil
}

func (r *PGRepo) Delete(ctx context.Context, id string) error {
	n, err := r.q.DeleteConnector(ctx, id)
	if err != nil {
		return fmt.Errorf("Delete: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetSyncResult stores a sync's outcome. cleanNoOp — a clean, complete,
// non-backfill sync whose fingerprint matched — advances sync_streak;
// anything else (a real change, a partial collection, a pending backfill, or
// an outright failure) resets it to 0. See Connector.SyncStreak.
//
// partial advances partial_streak independently — see Connector.PartialStreak.
func (r *PGRepo) SetSyncResult(ctx context.Context, id string, status SyncStatus, syncErr string, at time.Time, cleanNoOp, partial bool) error {
	params := sqlcgen.SetConnectorSyncResultParams{
		ID:           id,
		SyncStatus:   string(status),
		SyncError:    syncErr,
		LastSyncedAt: pgtype.Timestamptz{Time: at, Valid: true},
		CleanNoOp:    cleanNoOp,
		Partial:      partial,
	}
	// Advance last_success_at only on success; on failure it stays NULL here and
	// the query's COALESCE preserves the prior success timestamp.
	if status == SyncOK {
		params.LastSuccessAt = pgtype.Timestamptz{Time: at, Valid: true}
	}
	if err := r.q.SetConnectorSyncResult(ctx, params); err != nil {
		return fmt.Errorf("SetSyncResult: %w", err)
	}
	return nil
}

// SetMode stores mode and returns the mode it replaced. An id that matches no
// row, or is not a UUID, is ErrNotFound.
func (r *PGRepo) SetMode(ctx context.Context, id string, mode Mode) (Mode, error) {
	if !mode.Valid() {
		return "", fmt.Errorf("SetMode: %w: %q", ErrInvalidType, mode)
	}
	prev, err := r.q.SetConnectorMode(ctx, sqlcgen.SetConnectorModeParams{ID: id, Mode: string(mode)})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("SetMode: %w", err)
	}
	return Mode(prev), nil
}

// diskScanOff is the column value for diskscan.DiskScanModeOff, which is the
// empty string in the domain.
const diskScanOff = "off"

// diskScanModeFromColumn maps a stored mode to the domain value. An
// unrecognised value reads as off: unknown must never read as enabled.
func diskScanModeFromColumn(v string) diskscan.DiskScanMode {
	m := diskscan.DiskScanMode(v)
	if m == diskscan.DiskScanModeExistingSnapshots || m == diskscan.DiskScanModeCreateSnapshots {
		return m
	}
	return diskscan.DiskScanModeOff
}

// SetDiskScan stores the disk-scan mode with who enabled it and when, and
// returns the mode it replaced. An id that matches no row, or is not a UUID,
// is ErrNotFound.
func (r *PGRepo) SetDiskScan(ctx context.Context, id string, mode diskscan.DiskScanMode, by string, at time.Time) (diskscan.DiskScanMode, error) {
	if !mode.Valid() {
		return "", fmt.Errorf("SetDiskScan: %w: %q", ErrDiskScanInvalidMode, mode)
	}
	params := sqlcgen.SetConnectorDiskScanParams{ID: id, Mode: diskScanOff}
	if mode.Enabled() {
		params.Mode = string(mode)
		params.EnabledBy = by
		params.EnabledAt = pgtype.Timestamptz{Time: at, Valid: true}
	}
	prev, err := r.q.SetConnectorDiskScan(ctx, params)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("SetDiskScan: %w", err)
	}
	return diskScanModeFromColumn(prev), nil
}

func (r *PGRepo) SetSyncFingerprint(ctx context.Context, id, fingerprint string) error {
	err := r.q.SetConnectorSyncFingerprint(ctx, sqlcgen.SetConnectorSyncFingerprintParams{
		ID:              id,
		SyncFingerprint: fingerprint,
	})
	if err != nil {
		return fmt.Errorf("SetSyncFingerprint: %w", err)
	}
	return nil
}

func (r *PGRepo) GetAssetHashes(ctx context.Context, connectorID string) (map[string]StoredAssetHash, error) {
	rows, err := r.q.GetConnectorAssetHashes(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("GetAssetHashes: %w", err)
	}
	out := make(map[string]StoredAssetHash, len(rows))
	for _, row := range rows {
		out[row.AssetID] = StoredAssetHash{Hash: row.Hash, AssetType: row.AssetType, Region: row.Region}
	}
	return out, nil
}

// CollectingAsset lists the enabled connectors with a stored hash for assetID.
func (r *PGRepo) CollectingAsset(ctx context.Context, assetID string) ([]string, error) {
	ids, err := r.q.ListConnectorsCollectingAsset(ctx, assetID)
	if err != nil {
		return nil, fmt.Errorf("CollectingAsset: %w", err)
	}
	return ids, nil
}

// upsertAssetHashEntry is the per-asset SQL for the richer change-tracking upsert.
// On insert: records first_seen_at=now(), curr values, change_count=0.
// On conflict (same connector+asset): if hash changed, rotates curr→prev, bumps
// change_count, and updates last_changed_at; otherwise just refreshes curr values.
// An unread public IP ($8) keeps the stored address, so drift never reports
// the loss of an exposure the collector simply could not see.
const upsertAssetHashEntry = `
INSERT INTO connector_asset_hashes
    (connector_id, asset_id, hash, first_seen_at, last_changed_at, curr_public_ip, curr_name, prev_public_ip, prev_name, change_count, asset_type, region)
VALUES ($1, $2, $3, now(), now(), $4, $5, '', '', 0, $6, $7)
ON CONFLICT (connector_id, asset_id) DO UPDATE SET
    hash            = $3,
    curr_public_ip  = CASE WHEN $8::boolean THEN connector_asset_hashes.curr_public_ip ELSE $4 END,
    curr_name       = $5,
    asset_type      = $6,
    region          = $7,
    last_changed_at = CASE WHEN connector_asset_hashes.hash != $3 THEN now()                              ELSE connector_asset_hashes.last_changed_at END,
    prev_public_ip  = CASE WHEN connector_asset_hashes.hash != $3 THEN connector_asset_hashes.curr_public_ip ELSE connector_asset_hashes.prev_public_ip  END,
    prev_name       = CASE WHEN connector_asset_hashes.hash != $3 THEN connector_asset_hashes.curr_name      ELSE connector_asset_hashes.prev_name        END,
    change_count    = CASE WHEN connector_asset_hashes.hash != $3 THEN connector_asset_hashes.change_count + 1 ELSE connector_asset_hashes.change_count   END
`

func (r *PGRepo) UpsertAssetHashEntries(ctx context.Context, connectorID string, entries []AssetHashEntry) error {
	if len(entries) == 0 {
		return nil
	}
	// Deduplicate by asset_id: a sweep can surface the same asset twice (two
	// discovery paths for one resource); keep the last occurrence.
	seen := make(map[string]int, len(entries))
	order := make([]int, 0, len(entries))
	for i, e := range entries {
		if _, exists := seen[e.AssetID]; !exists {
			order = append(order, i)
		}
		seen[e.AssetID] = i
	}

	batch := &pgx.Batch{}
	for _, origIdx := range order {
		e := entries[seen[entries[origIdx].AssetID]]
		batch.Queue(upsertAssetHashEntry, connectorID, e.AssetID, e.Hash, e.PubIP, e.AssetName, e.AssetType, e.Region, e.PubIPUnread)
	}
	br := r.pool.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()
	for range order {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("UpsertAssetHashEntries exec: %w", err)
		}
	}
	return nil
}

func (r *PGRepo) DeleteAssetHashes(ctx context.Context, connectorID string, ids []string) error {
	err := r.q.DeleteConnectorAssetHashes(ctx, sqlcgen.DeleteConnectorAssetHashesParams{
		ConnectorID: connectorID,
		Column2:     ids,
	})
	if err != nil {
		return fmt.Errorf("DeleteAssetHashes: %w", err)
	}
	return nil
}

// RecordAssetDeletions upserts the proven deletions.
func (r *PGRepo) RecordAssetDeletions(ctx context.Context, connectorID string, ids []string, at time.Time) error {
	if err := r.q.RecordAssetDeletions(ctx, sqlcgen.RecordAssetDeletionsParams{
		AssetIds: ids, ConnectorID: connectorID, DeletedAt: at,
	}); err != nil {
		return fmt.Errorf("RecordAssetDeletions: %w", err)
	}
	return nil
}

// PruneAssetDeletions drops deletion records older than cutoff.
func (r *PGRepo) PruneAssetDeletions(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := r.q.PruneAssetDeletions(ctx, cutoff)
	if err != nil {
		return 0, fmt.Errorf("PruneAssetDeletions: %w", err)
	}
	return n, nil
}

// AssetDeletions returns the recorded deletion time of each id that has one.
func (r *PGRepo) AssetDeletions(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out := make(map[string]time.Time)
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.q.GetAssetDeletions(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("AssetDeletions: %w", err)
	}
	for _, row := range rows {
		out[row.AssetID] = row.DeletedAt
	}
	return out, nil
}

// RecordProvenCapability persists a proven capability claim. Idempotent: the
// underlying query is ON CONFLICT DO NOTHING, so recording an already-proven
// capability again is a no-op rather than resetting first_proven_at (proof is
// monotonic).
func (r *PGRepo) RecordProvenCapability(ctx context.Context, connectorID string, capability ProvenCapability, at time.Time) error {
	err := r.q.RecordProvenCapability(ctx, sqlcgen.RecordProvenCapabilityParams{
		ConnectorID:   connectorID,
		Capability:    string(capability),
		FirstProvenAt: at,
	})
	if err != nil {
		return fmt.Errorf("RecordProvenCapability: %w", err)
	}
	return nil
}

// ListProvenCapabilities returns every capability ever proven for a
// connector, oldest proofs included — proof is monotonic, so there is no
// "as of" filtering to do here.
func (r *PGRepo) ListProvenCapabilities(ctx context.Context, connectorID string) ([]ProvenCapability, error) {
	rows, err := r.q.ListProvenCapabilities(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("ListProvenCapabilities: %w", err)
	}
	out := make([]ProvenCapability, len(rows))
	for i, c := range rows {
		out[i] = ProvenCapability(c)
	}
	return out, nil
}

// SetEnabled enables or disables a connector. Discovery uses it on org
// children; disabling never deletes the child or its collected data.
func (r *PGRepo) SetEnabled(ctx context.Context, id string, enabled bool) error {
	if err := r.q.SetConnectorEnabled(ctx, sqlcgen.SetConnectorEnabledParams{ID: id, Enabled: enabled}); err != nil {
		return fmt.Errorf("SetEnabled: %w", err)
	}
	return nil
}

// DeleteOrg deletes an aws_org connector and disables its children in one
// transaction, so no child is left enabled without an org to resolve its
// credential from. The children and their data are kept.
func (r *PGRepo) DeleteOrg(ctx context.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("DeleteOrg: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit
	q := r.q.WithTx(tx)
	if err := q.DisableAWSOrgChildren(ctx, id); err != nil {
		return fmt.Errorf("DeleteOrg: disable children: %w", err)
	}
	n, err := q.DeleteConnector(ctx, id)
	if err != nil {
		return fmt.Errorf("DeleteOrg: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("DeleteOrg: commit: %w", err)
	}
	return nil
}

// ListOrgAccounts returns an org connector's discovered accounts with each
// child's health.
func (r *PGRepo) ListOrgAccounts(ctx context.Context, orgID string) ([]OrgAccount, error) {
	rows, err := r.q.ListAWSOrgAccounts(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListOrgAccounts: %w", err)
	}
	out := make([]OrgAccount, len(rows))
	for i, row := range rows {
		a := OrgAccount{
			OrgConnectorID: row.OrgConnectorID, AccountID: row.AccountID, Name: row.Name, Email: row.Email,
			AWSState: row.AwsState, OUPath: row.OuPath, Status: OrgAccountStatus(row.Status),
			StatusDetail: row.StatusDetail, ChildConnectorID: row.ChildConnectorID,
			FirstSeenAt: row.FirstSeenAt, LastSeenAt: row.LastSeenAt, StatusChangedAt: row.StatusChangedAt,
		}
		if row.ChildEnabled.Valid {
			h := &ChildHealth{
				Enabled: row.ChildEnabled.Bool, SyncStatus: SyncStatus(row.ChildSyncStatus.String),
				SyncError: row.ChildSyncError.String, CreatedAt: row.ChildCreatedAt.Time,
			}
			if row.ChildLastSuccessAt.Valid {
				t := row.ChildLastSuccessAt.Time
				h.LastSuccessAt = &t
			}
			a.Child = h
		}
		out[i] = a
	}
	return out, nil
}

// UpsertOrgAccount writes one discovered account's row; at stamps
// first_seen_at on insert and status_changed_at when the status moves.
func (r *PGRepo) UpsertOrgAccount(ctx context.Context, a OrgAccount, at time.Time) error {
	err := r.q.UpsertAWSOrgAccount(ctx, sqlcgen.UpsertAWSOrgAccountParams{
		OrgConnectorID: a.OrgConnectorID, AccountID: a.AccountID, Name: a.Name, Email: a.Email,
		AwsState: a.AWSState, OuPath: a.OUPath, Status: string(a.Status), StatusDetail: a.StatusDetail,
		ChildConnectorID: a.ChildConnectorID, SeenAt: at, LastSeenAt: a.LastSeenAt,
	})
	if err != nil {
		return fmt.Errorf("UpsertOrgAccount: %w", err)
	}
	return nil
}

func toStored(row sqlcgen.Connector) storedConnector {
	mode := ModeReadOnly
	if row.Mode == string(ModeReadWrite) {
		mode = ModeReadWrite
	}
	c := Connector{
		ID:              row.ID,
		Type:            Type(row.Type),
		Name:            row.Name,
		Enabled:         row.Enabled,
		EventSource:     row.EventSource,
		SyncStatus:      SyncStatus(row.SyncStatus),
		SyncError:       row.SyncError,
		SyncFingerprint: row.SyncFingerprint,
		SyncStreak:      row.SyncStreak,
		PartialStreak:   row.PartialStreak,
		Mode:            mode,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,

		DiskScanMode:      diskScanModeFromColumn(row.DiskScanMode),
		DiskScanEnabledBy: row.DiskScanEnabledBy,
	}
	if row.DiskScanEnabledAt.Valid {
		t := row.DiskScanEnabledAt.Time
		c.DiskScanEnabledAt = &t
	}
	if row.LastSyncedAt.Valid {
		t := row.LastSyncedAt.Time
		c.LastSyncedAt = &t
	}
	if row.LastSuccessAt.Valid {
		t := row.LastSuccessAt.Time
		c.LastSuccessAt = &t
	}
	return storedConnector{Connector: c, ConfigCiphertext: row.ConfigEnc}
}
