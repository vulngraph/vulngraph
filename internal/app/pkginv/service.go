package pkginv

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// Repo stores one claim per (source, asset).
type Repo interface {
	// Get returns the stored claim; found is false when the source has none.
	Get(ctx context.Context, source, assetID string) (rec InventoryRecord, found bool, err error)
	// Upsert replaces the source's claim for the asset, and returns ErrStale
	// when the stored claim is newer.
	Upsert(ctx context.Context, rec InventoryRecord) error
	ListForAssets(ctx context.Context, assetIDs []string) ([]InventoryRecord, error)
}

// Assets is the slice of the asset service a submission needs. It never
// creates an asset: Ingest receives package assets and runs_package edges only.
type Assets interface {
	Get(ctx context.Context, id string) (asset.Asset, error)
	LiveIDs(ctx context.Context, ids []string) ([]string, error)
	Ingest(ctx context.Context, assets []asset.Asset, edges []asset.Edge) error
}

// Deletions answers "which of these assets did a complete sweep prove deleted,
// and when". *connector.Service implements it.
type Deletions interface {
	AssetDeletions(ctx context.Context, ids []string) (map[string]time.Time, error)
}

// Tombstones answers "which of these assets is believed gone, and since when".
// The forget domain's store implements it.
type Tombstones interface {
	Tombstones(ctx context.Context, ids []string) (map[string]time.Time, error)
}

// Auditor writes the audit row for a submission. *audit.Service implements it.
type Auditor interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// Limiter is a per-key token bucket. *auth.KeyedLimiter implements it.
type Limiter interface {
	Allow(key string) (bool, time.Duration)
}

// Service validates, judges and records submissions.
type Service struct {
	repo      Repo
	assets    Assets
	deletions Deletions
	forgotten Tombstones
	audit     Auditor
	limiter   Limiter
	advisory  func() distro.Sources
	now       func() time.Time
}

// NewService wires a Service. deletions and forgotten are both required: an
// asset either one says is gone cannot be written to. advisory reports the
// advisory sources the deployment has switched on.
func NewService(repo Repo, assets Assets, deletions Deletions, forgotten Tombstones, audit Auditor, limiter Limiter, advisory func() distro.Sources) *Service {
	return &Service{repo: repo, assets: assets, deletions: deletions, forgotten: forgotten,
		audit: audit, limiter: limiter, advisory: advisory, now: time.Now}
}

// vmTypes are the asset types that run an OS with a package list.
var vmTypes = []string{"ec2_instance", "gce_instance", "azure_vm"}

// Submit validates one inventory and records it against the named asset. The
// path asset (pathAssetID) wins over any asset_id in the body; with neither,
// cloud_resource_id names the asset. Every outcome, accepted or rejected, is
// audited.
func (s *Service) Submit(ctx context.Context, p Principal, pathAssetID string, req Request) (InventoryRecord, error) {
	target := firstNonEmpty(pathAssetID, req.AssetID, req.CloudResourceID)
	rec, err := s.submit(ctx, p, pathAssetID, req)
	s.record(ctx, p, target, req, rec, err)
	if err != nil {
		return InventoryRecord{}, err
	}
	return rec, nil
}

func (s *Service) submit(ctx context.Context, p Principal, pathAssetID string, req Request) (InventoryRecord, error) {
	if !p.MaySubmit() {
		return InventoryRecord{}, ErrForbidden
	}
	limitKey := p.KeyID + ":" + firstNonEmpty(pathAssetID, req.AssetID, req.CloudResourceID)
	if ok, _ := s.limiter.Allow(limitKey); !ok {
		return InventoryRecord{}, ErrRateLimited
	}
	now := s.now()
	sub, err := Validate(req, now)
	if err != nil {
		return InventoryRecord{}, err
	}
	a, err := s.resolve(ctx, firstNonEmpty(pathAssetID, sub.AssetID, sub.CloudResourceID))
	if err != nil {
		return InventoryRecord{}, err
	}
	source := SourceKey(p.KeyID, sub.Scanner.Name)
	if prev, found, err := s.repo.Get(ctx, source, a.ID); err != nil {
		return InventoryRecord{}, fmt.Errorf("Submit: %w", err)
	} else if found && sub.ObservedAt.Before(prev.ObservedAt) {
		return InventoryRecord{}, ErrStale
	}
	v := Evaluate(sub, now, s.advisory())
	if len(v.Packages) > 0 {
		pkgAssets, edges := pkginventory.InventoryGraph(a.ID, a.Type, v.Packages, now)
		if err := s.assets.Ingest(ctx, pkgAssets, edges); err != nil {
			return InventoryRecord{}, fmt.Errorf("Submit: %w", err)
		}
	}
	rec := InventoryRecord{
		Source: source, AssetID: a.ID, APIKeyID: p.KeyID,
		Scanner: sub.Scanner, OS: sub.OS, Ecosystem: v.Ecosystem,
		ObservedAt: sub.ObservedAt, ReceivedAt: now.UTC(), Complete: sub.Complete,
		PackageCount: len(sub.Packages), Covered: sub.Covered,
		InventoryKnown: v.InventoryKnown, CVEMatchableKnown: v.CVEMatchableKnown, Gap: v.Gap,
	}
	if err := s.repo.Upsert(ctx, rec); err != nil {
		return InventoryRecord{}, fmt.Errorf("Submit: %w", err)
	}
	return rec, nil
}

// resolve finds the one existing, live, undeleted VM the identifier names. The
// identifier is matched exactly against asset ids, so it can name at most one.
func (s *Service) resolve(ctx context.Context, id string) (asset.Asset, error) {
	if id == "" {
		return asset.Asset{}, invalid("asset_id or cloud_resource_id is required")
	}
	a, err := s.assets.Get(ctx, id)
	if errors.Is(err, asset.ErrNotFound) {
		return asset.Asset{}, ErrAssetNotFound
	}
	if err != nil {
		return asset.Asset{}, fmt.Errorf("resolve: %w", err)
	}
	if !slices.Contains(vmTypes, a.Type) {
		return asset.Asset{}, ErrAssetNotFound
	}
	live, err := s.assets.LiveIDs(ctx, []string{a.ID})
	if err != nil {
		return asset.Asset{}, fmt.Errorf("resolve: %w", err)
	}
	if !slices.Contains(live, a.ID) {
		return asset.Asset{}, ErrAssetNotFound
	}
	deleted, err := s.deletions.AssetDeletions(ctx, []string{a.ID})
	if err != nil {
		return asset.Asset{}, fmt.Errorf("resolve: %w", err)
	}
	forgotten, err := s.forgotten.Tombstones(ctx, []string{a.ID})
	if err != nil {
		return asset.Asset{}, fmt.Errorf("resolve: %w", err)
	}
	for _, gone := range []map[string]time.Time{deleted, forgotten} {
		if at, ok := gone[a.ID]; ok && !at.Before(a.LastSeen) {
			return asset.Asset{}, ErrAssetNotFound
		}
	}
	return a, nil
}

// Latest returns, per asset, the inventory the sync overlay should apply: the
// freshest known claim across sources, else the freshest claim of any kind. A
// claim that was known when received but has aged past FreshFor is returned as
// a stale gap, so a source that stops reporting never reads as clean. Assets
// with no claim are absent from the map.
func (s *Service) Latest(ctx context.Context, assetIDs []string) (map[string]InventoryRecord, error) {
	if len(assetIDs) == 0 {
		return map[string]InventoryRecord{}, nil
	}
	recs, err := s.repo.ListForAssets(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("Latest: %w", err)
	}
	now := s.now()
	byAsset := make(map[string][]InventoryRecord)
	for _, r := range recs {
		if r.InventoryKnown && now.Sub(r.ObservedAt) > FreshFor {
			r.InventoryKnown, r.CVEMatchableKnown, r.Gap = false, false, GapStale
		}
		byAsset[r.AssetID] = append(byAsset[r.AssetID], r)
	}
	out := make(map[string]InventoryRecord, len(byAsset))
	for id, rs := range byAsset {
		if best, ok := Freshest(rs); ok {
			out[id] = best
		}
	}
	return out, nil
}

func (s *Service) record(ctx context.Context, p Principal, target string, req Request, rec InventoryRecord, err error) {
	outcome, reason := OutcomeAccepted, ""
	if err != nil {
		outcome, reason = OutcomeRejected, rejectReason(err)
	}
	scanner := req.Scanner.Name
	if !reScannerName.MatchString(scanner) {
		scanner = ""
	}
	if !reResourceID.MatchString(target) {
		target = ""
	}
	d := map[string]any{
		"scanner":       scanner,
		"package_count": len(req.Packages),
		"complete":      req.Complete,
		"outcome":       outcome,
	}
	if p.KeyID != "" {
		d["inventory_key_id"] = p.KeyID
	}
	if reason != "" {
		d["reason"] = reason
	}
	if err == nil {
		d["inventory_known"] = rec.InventoryKnown
		d["gap"] = rec.Gap
	}
	if target == "" {
		target = "unknown"
	}
	s.audit.Record(ctx, AuditActionSubmit, AuditTargetAsset, target, d)
}

// rejectReason is the stable code audited for a refusal; it never carries
// submitted text.
func rejectReason(err error) string {
	switch {
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	case errors.Is(err, ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrAssetNotFound):
		return "asset_not_found"
	case errors.Is(err, ErrStale):
		return "stale"
	default:
		return "error"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
