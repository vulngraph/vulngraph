package diskscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

// invalidTextRepresentation is Postgres's error for a non-UUID id: such an id
// cannot match a row.
const invalidTextRepresentation = "22P02"

// PGRepo implements Repository on Postgres.
type PGRepo struct {
	q    *sqlcgen.Queries
	pool *pgxpool.Pool
}

var _ Repository = (*PGRepo)(nil)

func NewPGRepo(pool *pgxpool.Pool) *PGRepo {
	return &PGRepo{q: sqlcgen.New(pool), pool: pool}
}

func notFound(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidTextRepresentation)
}

func tsOrNull(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: !t.IsZero()}
}

func timeOrZero(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

// count32 narrows a stored count; the columns are int32 and a Go int count
// above that cannot occur, so clamping only guards the conversion.
func count32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n) //nolint:gosec // clamped above
}

func runFromRow(r sqlcgen.DiskScanRun) DiskScanRun {
	return DiskScanRun{
		ID: r.ID, ConnectorID: r.ConnectorID, Status: RunStatus(r.Status),
		StartedAt: r.StartedAt, FinishedAt: timeOrZero(r.FinishedAt),
		Counts: RunCounts{Volumes: int(r.Volumes), Scanned: int(r.Scanned), Gaps: int(r.Gaps), NotEnabled: int(r.NotEnabled)},
		Err:    r.Err,
	}
}

func (r *PGRepo) InsertRun(ctx context.Context, run DiskScanRun) (DiskScanRun, error) {
	row, err := r.q.InsertDiskScanRun(ctx, sqlcgen.InsertDiskScanRunParams{
		ConnectorID: run.ConnectorID, Status: string(run.Status), StartedAt: run.StartedAt,
		FinishedAt: tsOrNull(run.FinishedAt), Err: run.Err,
	})
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("InsertRun: %w", err)
	}
	return runFromRow(row), nil
}

func (r *PGRepo) GetRun(ctx context.Context, id string) (DiskScanRun, error) {
	row, err := r.q.GetDiskScanRun(ctx, id)
	if err != nil {
		if notFound(err) {
			return DiskScanRun{}, ErrNotFound
		}
		return DiskScanRun{}, fmt.Errorf("GetRun: %w", err)
	}
	return runFromRow(row), nil
}

func (r *PGRepo) ListRuns(ctx context.Context, connectorID string, limit int) ([]DiskScanRun, error) {
	rows, err := r.q.ListDiskScanRuns(ctx, sqlcgen.ListDiskScanRunsParams{ConnectorID: connectorID, MaxRows: count32(limit)})
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	out := make([]DiskScanRun, len(rows))
	for i, row := range rows {
		out[i] = runFromRow(row)
	}
	return out, nil
}

func (r *PGRepo) FinishRun(ctx context.Context, run DiskScanRun) error {
	n, err := r.q.FinishDiskScanRun(ctx, sqlcgen.FinishDiskScanRunParams{
		ID: run.ID, Status: string(run.Status), FinishedAt: tsOrNull(run.FinishedAt),
		Volumes: count32(run.Counts.Volumes), Scanned: count32(run.Counts.Scanned),
		Gaps: count32(run.Counts.Gaps), NotEnabled: count32(run.Counts.NotEnabled), Err: run.Err,
	})
	if err != nil {
		return fmt.Errorf("FinishRun: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *PGRepo) CountVolumes(ctx context.Context, runID string) (RunCounts, error) {
	row, err := r.q.CountDiskScanVolumes(ctx, runID)
	if err != nil {
		return RunCounts{}, fmt.Errorf("CountVolumes: %w", err)
	}
	return RunCounts{Scanned: int(row.Scanned), Gaps: int(row.Gaps), NotEnabled: int(row.NotEnabled)}, nil
}

func (r *PGRepo) UpsertVolume(ctx context.Context, boot bool, res VolumeResult) error {
	err := r.q.UpsertDiskScanVolume(ctx, sqlcgen.UpsertDiskScanVolumeParams{
		RunID: res.RunID, AssetID: res.AssetID, VolumeRef: res.VolumeRef, Boot: boot,
		SnapshotID: res.SnapshotID, SnapshotSource: string(res.SnapshotSource), Encrypted: res.Encrypted,
		InventoryKnown: res.InventoryKnown, CveMatchableKnown: res.CVEMatchableKnown, Gap: res.Gap,
		PackageCount: count32(res.PackageCount), ObservedAt: res.ObservedAt,
	})
	if err != nil {
		return fmt.Errorf("UpsertVolume: %w", err)
	}
	return nil
}

func (r *PGRepo) LatestVolumes(ctx context.Context, assetIDs []string) ([]VolumeResult, error) {
	rows, err := r.q.LatestDiskScanVolumes(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("LatestVolumes: %w", err)
	}
	out := make([]VolumeResult, len(rows))
	for i, row := range rows {
		out[i] = VolumeResult{
			RunID: row.RunID, AssetID: row.AssetID, VolumeRef: row.VolumeRef, SnapshotID: row.SnapshotID,
			SnapshotSource: SnapshotSource(row.SnapshotSource), Encrypted: row.Encrypted,
			InventoryKnown: row.InventoryKnown, CVEMatchableKnown: row.CveMatchableKnown, Gap: row.Gap,
			PackageCount: int(row.PackageCount), ObservedAt: row.ObservedAt,
		}
	}
	return out, nil
}

func (r *PGRepo) ListVolumes(ctx context.Context, runID string) ([]VolumeResult, error) {
	rows, err := r.q.ListDiskScanVolumes(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("ListVolumes: %w", err)
	}
	out := make([]VolumeResult, len(rows))
	for i, row := range rows {
		out[i] = VolumeResult{
			RunID: row.RunID, AssetID: row.AssetID, VolumeRef: row.VolumeRef, SnapshotID: row.SnapshotID,
			SnapshotSource: SnapshotSource(row.SnapshotSource), Encrypted: row.Encrypted,
			InventoryKnown: row.InventoryKnown, CVEMatchableKnown: row.CveMatchableKnown, Gap: row.Gap,
			PackageCount: int(row.PackageCount), ObservedAt: row.ObservedAt,
		}
	}
	return out, nil
}

func intentFromRow(s sqlcgen.DiskScanSnapshot) SnapshotIntent {
	return SnapshotIntent{
		ID: s.ID, RunID: s.RunID, ConnectorID: s.ConnectorID, Provider: s.Provider, Region: s.Region,
		VolumeRef: s.VolumeRef, SnapshotID: s.SnapshotID, CreatedAt: s.CreatedAt, DeleteAfter: s.DeleteAfter,
		DeletedAt: timeOrZero(s.DeletedAt),
	}
}

// InsertIntent is a no-op when the (run, volume) row already exists.
func (r *PGRepo) InsertIntent(ctx context.Context, in SnapshotIntent) error {
	_, err := r.q.InsertDiskScanSnapshotIntent(ctx, sqlcgen.InsertDiskScanSnapshotIntentParams{
		RunID: in.RunID, ConnectorID: in.ConnectorID, Provider: in.Provider, Region: in.Region,
		VolumeRef: in.VolumeRef, CreatedAt: in.CreatedAt, DeleteAfter: in.DeleteAfter,
	})
	if err != nil {
		return fmt.Errorf("InsertIntent: %w", err)
	}
	return nil
}

func (r *PGRepo) GetIntent(ctx context.Context, runID, volumeRef string) (SnapshotIntent, error) {
	row, err := r.q.GetDiskScanSnapshotIntent(ctx, sqlcgen.GetDiskScanSnapshotIntentParams{RunID: runID, VolumeRef: volumeRef})
	if err != nil {
		if notFound(err) {
			return SnapshotIntent{}, ErrNotFound
		}
		return SnapshotIntent{}, fmt.Errorf("GetIntent: %w", err)
	}
	return intentFromRow(row), nil
}

func (r *PGRepo) AttachSnapshot(ctx context.Context, intentID, snapshotID string) error {
	n, err := r.q.AttachDiskScanSnapshot(ctx, sqlcgen.AttachDiskScanSnapshotParams{ID: intentID, SnapshotID: snapshotID})
	if err != nil {
		if notFound(err) {
			return ErrNotFound
		}
		return fmt.Errorf("AttachSnapshot: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkDeleted is idempotent: an intent already marked, or unknown, is not an error.
func (r *PGRepo) MarkDeleted(ctx context.Context, intentID string, at time.Time) error {
	_, err := r.q.MarkDiskScanSnapshotDeleted(ctx, sqlcgen.MarkDiskScanSnapshotDeletedParams{ID: intentID, DeletedAt: tsOrNull(at)})
	if err != nil && !notFound(err) {
		return fmt.Errorf("MarkDeleted: %w", err)
	}
	return nil
}

func (r *PGRepo) MarkDeletedBySnapshot(ctx context.Context, provider, snapshotID string, at time.Time) error {
	_, err := r.q.MarkDiskScanSnapshotDeletedByRef(ctx, sqlcgen.MarkDiskScanSnapshotDeletedByRefParams{
		Provider: provider, SnapshotID: snapshotID, DeletedAt: tsOrNull(at),
	})
	if err != nil {
		return fmt.Errorf("MarkDeletedBySnapshot: %w", err)
	}
	return nil
}

func (r *PGRepo) ListOrphans(ctx context.Context, now time.Time, limit int) ([]SnapshotIntent, error) {
	rows, err := r.q.ListDiskScanOrphans(ctx, sqlcgen.ListDiskScanOrphansParams{DeleteAfter: now, Limit: count32(limit)})
	if err != nil {
		return nil, fmt.Errorf("ListOrphans: %w", err)
	}
	out := make([]SnapshotIntent, len(rows))
	for i, row := range rows {
		out[i] = intentFromRow(row)
	}
	return out, nil
}

func (r *PGRepo) GetCache(ctx context.Context, provider, snapshotID string, now time.Time) (CacheEntry, bool, error) {
	row, err := r.q.GetDiskScanCache(ctx, sqlcgen.GetDiskScanCacheParams{Provider: provider, SnapshotID: snapshotID, ExpiresAt: tsOrNull(now)})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return CacheEntry{}, false, nil
		}
		return CacheEntry{}, false, fmt.Errorf("GetCache: %w", err)
	}
	var extents []engine.Extent
	if err := json.Unmarshal(row.Extents, &extents); err != nil {
		return CacheEntry{}, false, fmt.Errorf("GetCache: extents: %w", err)
	}
	return CacheEntry{
		Provider: row.Provider, SnapshotID: row.SnapshotID, Digest: row.Digest, Extents: extents,
		Result: VolumeResult{
			SnapshotID: row.SnapshotID, Encrypted: row.Encrypted, InventoryKnown: row.InventoryKnown,
			CVEMatchableKnown: row.CveMatchableKnown, Gap: row.Gap, PackageCount: int(row.PackageCount),
		},
		CachedAt: row.CachedAt, ExpiresAt: timeOrZero(row.ExpiresAt),
	}, true, nil
}

func (r *PGRepo) PutCache(ctx context.Context, e CacheEntry) error {
	extents := e.Extents
	if extents == nil {
		extents = []engine.Extent{}
	}
	raw, err := json.Marshal(extents)
	if err != nil {
		return fmt.Errorf("PutCache: extents: %w", err)
	}
	err = r.q.PutDiskScanCache(ctx, sqlcgen.PutDiskScanCacheParams{
		Provider: e.Provider, SnapshotID: e.SnapshotID, Digest: e.Digest, Extents: raw,
		Encrypted: e.Result.Encrypted, InventoryKnown: e.Result.InventoryKnown,
		CveMatchableKnown: e.Result.CVEMatchableKnown, Gap: e.Result.Gap,
		PackageCount: count32(e.Result.PackageCount), CachedAt: e.CachedAt, ExpiresAt: tsOrNull(e.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("PutCache: %w", err)
	}
	return nil
}
