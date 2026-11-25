package pkginv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// PGRepo implements Repo on Postgres.
type PGRepo struct {
	q *sqlcgen.Queries
}

func NewPGRepo(pool *pgxpool.Pool) *PGRepo { return &PGRepo{q: sqlcgen.New(pool)} }

func (r *PGRepo) Get(ctx context.Context, source, assetID string) (InventoryRecord, bool, error) {
	row, err := r.q.GetPackageInventory(ctx, sqlcgen.GetPackageInventoryParams{Source: source, AssetID: assetID})
	if errors.Is(err, pgx.ErrNoRows) {
		return InventoryRecord{}, false, nil
	}
	if err != nil {
		return InventoryRecord{}, false, fmt.Errorf("Get: %w", err)
	}
	rec, err := fromRow(row)
	if err != nil {
		return InventoryRecord{}, false, fmt.Errorf("Get: %w", err)
	}
	return rec, true, nil
}

func (r *PGRepo) Upsert(ctx context.Context, rec InventoryRecord) error {
	covered, err := json.Marshal(append([]Covered{}, rec.Covered...))
	if err != nil {
		return fmt.Errorf("Upsert: covered: %w", err)
	}
	n, err := r.q.UpsertPackageInventory(ctx, sqlcgen.UpsertPackageInventoryParams{
		Source: rec.Source, AssetID: rec.AssetID, ApiKeyID: rec.APIKeyID,
		ScannerName: rec.Scanner.Name, ScannerVersion: rec.Scanner.Version,
		OsID: rec.OS.ID, OsVersionID: rec.OS.VersionID, OsName: rec.OS.Name,
		Ecosystem: rec.Ecosystem, ObservedAt: rec.ObservedAt, ReceivedAt: rec.ReceivedAt,
		Complete: rec.Complete, PackageCount: int32(rec.PackageCount), Covered: covered,
		InventoryKnown: rec.InventoryKnown, CveMatchableKnown: rec.CVEMatchableKnown, Gap: rec.Gap,
	})
	if err != nil {
		return fmt.Errorf("Upsert: %w", err)
	}
	if n == 0 {
		return ErrStale
	}
	return nil
}

func (r *PGRepo) ListForAssets(ctx context.Context, assetIDs []string) ([]InventoryRecord, error) {
	rows, err := r.q.ListPackageInventoriesForAssets(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("ListForAssets: %w", err)
	}
	out := make([]InventoryRecord, 0, len(rows))
	for _, row := range rows {
		rec, err := fromRow(row)
		if err != nil {
			return nil, fmt.Errorf("ListForAssets: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func fromRow(row sqlcgen.PackageInventory) (InventoryRecord, error) {
	var covered []Covered
	if err := json.Unmarshal(row.Covered, &covered); err != nil {
		return InventoryRecord{}, fmt.Errorf("covered: %w", err)
	}
	return InventoryRecord{
		Source: row.Source, AssetID: row.AssetID, APIKeyID: row.ApiKeyID,
		Scanner:    Scanner{Name: row.ScannerName, Version: row.ScannerVersion},
		OS:         OS{ID: row.OsID, VersionID: row.OsVersionID, Name: row.OsName},
		Ecosystem:  row.Ecosystem,
		ObservedAt: row.ObservedAt.UTC(), ReceivedAt: row.ReceivedAt.UTC(), Complete: row.Complete,
		PackageCount: int(row.PackageCount), Covered: covered,
		InventoryKnown: row.InventoryKnown, CVEMatchableKnown: row.CveMatchableKnown, Gap: row.Gap,
	}, nil
}
