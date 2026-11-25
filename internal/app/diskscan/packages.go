package diskscan

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// PackageSet is the package list one disk scan read from one volume: the
// latest per (asset, volume). It is applied only together with the result
// whose SnapshotID it carries, so a list never outlives the verdict it came with.
type PackageSet struct {
	AssetID    string
	VolumeRef  string
	RunID      string
	SnapshotID string
	Ecosystem  string
	Packages   []pkginventory.InstalledPackage
	ObservedAt time.Time
}

// packageStore is the optional repo capability behind RecordPackages.
type packageStore interface {
	PutPackages(ctx context.Context, set PackageSet) error
	ListPackages(ctx context.Context, assetIDs []string) ([]PackageSet, error)
}

// RecordPackages stores a volume's package list. It refuses a list with no
// packages: a disk whose inventory is unknown has a gap, not an empty list.
func (s *Service) RecordPackages(ctx context.Context, set PackageSet) error {
	if set.AssetID == "" || set.VolumeRef == "" || set.RunID == "" || set.SnapshotID == "" || set.Ecosystem == "" {
		return fmt.Errorf("RecordPackages: asset, volume, run, snapshot and ecosystem are required: %w", ErrInvalid)
	}
	if len(set.Packages) == 0 {
		return fmt.Errorf("RecordPackages: an empty list is not an inventory: %w", ErrInvalid)
	}
	store, ok := s.repo.(packageStore)
	if !ok {
		return fmt.Errorf("RecordPackages: repository stores no packages: %w", ErrInvalid)
	}
	if set.ObservedAt.IsZero() {
		set.ObservedAt = s.utcNow()
	}
	if err := store.PutPackages(ctx, set); err != nil {
		return fmt.Errorf("RecordPackages: %w", err)
	}
	return nil
}

// Packages returns the stored package lists of the assets' volumes.
func (s *Service) Packages(ctx context.Context, assetIDs []string) ([]PackageSet, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}
	store, ok := s.repo.(packageStore)
	if !ok {
		return nil, fmt.Errorf("Packages: repository stores no packages: %w", ErrInvalid)
	}
	sets, err := store.ListPackages(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("Packages: %w", err)
	}
	return sets, nil
}

func (r *PGRepo) PutPackages(ctx context.Context, set PackageSet) error {
	raw, err := json.Marshal(set.Packages)
	if err != nil {
		return fmt.Errorf("PutPackages: marshal: %w", err)
	}
	err = r.q.UpsertDiskScanPackages(ctx, sqlcgen.UpsertDiskScanPackagesParams{
		AssetID: set.AssetID, VolumeRef: set.VolumeRef, RunID: set.RunID, SnapshotID: set.SnapshotID,
		Ecosystem: set.Ecosystem, Packages: raw, ObservedAt: set.ObservedAt,
	})
	if err != nil {
		return fmt.Errorf("PutPackages: %w", err)
	}
	return nil
}

func (r *PGRepo) ListPackages(ctx context.Context, assetIDs []string) ([]PackageSet, error) {
	rows, err := r.q.ListDiskScanPackages(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("ListPackages: %w", err)
	}
	out := make([]PackageSet, 0, len(rows))
	for _, row := range rows {
		var pkgs []pkginventory.InstalledPackage
		if err := json.Unmarshal(row.Packages, &pkgs); err != nil {
			return nil, fmt.Errorf("ListPackages: %s: %w", row.AssetID, err)
		}
		out = append(out, PackageSet{
			AssetID: row.AssetID, VolumeRef: row.VolumeRef, RunID: row.RunID, SnapshotID: row.SnapshotID,
			Ecosystem: row.Ecosystem, Packages: pkgs, ObservedAt: row.ObservedAt,
		})
	}
	return out, nil
}
