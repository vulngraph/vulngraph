package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Repo is the asset/edge storage the service needs. CHRepo implements it.
type Repo interface {
	LineageSources(context.Context, []string, string, int) ([]Edge, bool, error)
	LineageTargets(context.Context, []string, string, int) ([]Edge, bool, error)
	AnyConfirmedExposure(context.Context, []string) (bool, error)
	UpsertAssets(ctx context.Context, assets []Asset) error
	UpsertEdges(ctx context.Context, edges []Edge) error
	GetAsset(ctx context.Context, id string) (Asset, error)
	FindByExactName(ctx context.Context, name string, limit int) ([]Asset, error)
	FindPackageVersions(ctx context.Context, name string, limit int) ([]Asset, error)
	EdgesFrom(ctx context.Context, srcIDs []string) ([]Edge, error)
	EdgesTo(ctx context.Context, dstIDs []string) ([]Edge, error)
	EdgesForAttack(ctx context.Context, ids []string) ([]Edge, error)
	EdgesInto(ctx context.Context, dstID, edgeType string) ([]Edge, error)
	EdgesIntoTypes(ctx context.Context, dstID string, edgeTypes []string) ([]Edge, error)
	EdgesOut(ctx context.Context, srcID, edgeType string) ([]Edge, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]Edge, error)
	ListExternal(ctx context.Context, limit int) ([]Asset, error)
	List(ctx context.Context, f Filter) ([]Asset, error)
	ListByType(ctx context.Context, assetType string, limit int) ([]Asset, error)
	LivePackageIDs(ctx context.Context) (map[string]bool, error)
	PackageCoordsAfter(ctx context.Context, after string) ([]PackageCoord, string, error)
	PackageRunners(ctx context.Context, packageIDs []string) ([]PackageRunner, error)
	CountPackages(ctx context.Context) (int64, error)
	ByIDs(ctx context.Context, ids []string) ([]Asset, error)
	AccountsByIDs(ctx context.Context, ids []string) (map[string]string, error)
	ExistingIDs(ctx context.Context, ids []string) ([]string, error)
	LiveIDs(ctx context.Context, ids []string) ([]string, error)
	VerifyExpiredEphemeral(ctx context.Context, ids []string) (map[string]bool, error)
	ProviderHighWater(ctx context.Context, provider string) (time.Time, error)
	TypeHighWater(ctx context.Context, assetType string) (time.Time, error)
	TableStats(ctx context.Context, table string) (TableStats, error)
	OptimizeTable(ctx context.Context, table string) error
	ProviderStaleness(ctx context.Context, marginSeconds int) ([]ProviderStaleness, error)
	ProviderDimensionCounts(ctx context.Context) ([]ProviderDimensions, error)
	Summary(ctx context.Context) (Summary, error)
	IsExposedEdge(ctx context.Context, assetID string) (bool, error)
	AllEdgesForSync(ctx context.Context, proj SyncProjection) (EdgeSyncResult, error)
	ListAllForSync(ctx context.Context, proj SyncProjection) (AssetSyncResult, error)
	WriteChangeLog(ctx context.Context, connectorID string, changes []FieldChange) error
	ChangeLog(ctx context.Context, assetID string, limit int) ([]FieldChange, error)
	PurgeAccount(ctx context.Context, provider, accountID string) (int, error)
	AssetIDsByAccount(ctx context.Context, provider, accountID string) ([]string, error)
	PurgeEdgesForAssets(ctx context.Context, ids []string) (int, error)
	RetireAssets(ctx context.Context, deletions map[string]time.Time) ([]string, error)
	PackageRiskByRunner(ctx context.Context) (map[string]uint8, error)
	UpsertImageBases(ctx context.Context, bases []ImageBase) error
	ImageBases(ctx context.Context) ([]ImageBase, error)
}

// Blast-radius traversal budgets.
const (
	defaultMaxDepth = 3
	maxNodeBudget   = 500
)

type Service struct {
	repo           Repo
	deletionProofs DeletionProofs
}

type DeletionProofs interface {
	AssetDeletions(context.Context, []string) (map[string]time.Time, error)
}

func (s *Service) WithDeletionProofs(proofs DeletionProofs) *Service {
	s.deletionProofs = proofs
	return s
}

func NewService(repo Repo) *Service { return &Service{repo: repo} }

// WriteChangeLog records per-field asset changes (drift timeline source).
func (s *Service) WriteChangeLog(ctx context.Context, connectorID string, changes []FieldChange) error {
	return s.repo.WriteChangeLog(ctx, connectorID, changes)
}

// ChangeLog returns an asset's field-change history, newest first.
func (s *Service) ChangeLog(ctx context.Context, assetID string, limit int) ([]FieldChange, error) {
	return s.repo.ChangeLog(ctx, assetID, limit)
}

// Ingest stores a batch of assets and their edges.
func (s *Service) Ingest(ctx context.Context, assets []Asset, edges []Edge) error {
	s.pinFirstDiscoveredAt(ctx, assets)
	if err := s.repo.UpsertAssets(ctx, assets); err != nil {
		return fmt.Errorf("Ingest: %w", err)
	}
	if err := s.repo.UpsertEdges(ctx, edges); err != nil {
		return fmt.Errorf("Ingest: %w", err)
	}
	return nil
}

// IngestEdges stores computed edges (correlate output).
func (s *Service) IngestEdges(ctx context.Context, edges []Edge) error {
	if err := s.repo.UpsertEdges(ctx, edges); err != nil {
		return fmt.Errorf("IngestEdges: %w", err)
	}
	return nil
}

// IngestAssets upserts a batch of assets (correlate output, e.g. a rule
// annotating an existing asset's metadata rather than emitting an edge).
func (s *Service) IngestAssets(ctx context.Context, assets []Asset) error {
	s.pinFirstDiscoveredAt(ctx, assets)
	if err := s.repo.UpsertAssets(ctx, assets); err != nil {
		return fmt.Errorf("IngestAssets: %w", err)
	}
	return nil
}

// pinFirstDiscoveredAtChunkSize bounds each ByIDs lookup pinFirstDiscoveredAt
// issues. ClickHouse's IN clause is query-string-interpolated by the driver,
// so a full connector-sync Ingest call must chunk its ids rather than pass an
// unbounded batch into one IN list and risk max_query_size.
const pinFirstDiscoveredAtChunkSize = 500

// pinFirstDiscoveredAt carries an asset's FirstDiscoveredAt forward across
// re-collection, mirroring finding.Service.pinFirstDetectedAt's earliest()
// pattern. Every collector stamps DiscoveredAt with the sweep's clock on
// every observation, so without this pin FirstDiscoveredAt would silently
// mean "last collected" for every re-observed asset. Mutates assets in
// place.
//
// A ByIDs failure on one chunk is LOGGED, not silent, and that chunk's assets
// fall through to the repo's firstDiscoveredAt() floor (DiscoveredAt) —
// best-effort, but visibly so: a silent skip here would reintroduce the
// "last collected, not first discovered" bug this column exists to fix,
// invisibly, on every affected asset for the rest of its history.
func (s *Service) pinFirstDiscoveredAt(ctx context.Context, assets []Asset) {
	if len(assets) == 0 {
		return
	}
	for start := 0; start < len(assets); start += pinFirstDiscoveredAtChunkSize {
		end := min(start+pinFirstDiscoveredAtChunkSize, len(assets))
		chunk := assets[start:end]

		ids := make([]string, len(chunk))
		for i, a := range chunk {
			ids[i] = a.ID
		}
		existing, err := s.repo.ByIDs(ctx, ids)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Int("chunk_size", len(chunk)).
				Msg("asset: FirstDiscoveredAt carry-forward lookup failed — assets fall back to DiscoveredAt")
			continue
		}
		byID := make(map[string]Asset, len(existing))
		for _, a := range existing {
			byID[a.ID] = a
		}
		for i, a := range chunk {
			prev, ok := byID[a.ID]
			if !ok {
				continue
			}
			chunk[i].FirstDiscoveredAt = earliest(prev.FirstDiscoveredAt, prev.DiscoveredAt, a.FirstDiscoveredAt, a.DiscoveredAt)
		}
	}
}

// earliest returns the oldest non-zero timestamp, or the zero time if every
// candidate is zero. Zero is "unknown", not "the epoch" — a plain min would
// let one unset field pin an asset's first observation to 1970. Mirrors
// finding.earliest exactly (kept as a package-local twin rather than shared,
// same as the two packages' domain.go/repo.go pairs — a small pure function,
// not infrastructure, so duplicating it doesn't reach into either package's
// repo).
func earliest(ts ...time.Time) time.Time {
	var out time.Time
	for _, t := range ts {
		if t.IsZero() || t.Year() < 2000 {
			continue // zero, or a driver-decoded DateTime(0)
		}
		if out.IsZero() || t.Before(out) {
			out = t
		}
	}
	return out
}

// Get returns a single asset by ID.
func (s *Service) Get(ctx context.Context, id string) (Asset, error) {
	a, err := s.repo.GetAsset(ctx, id)
	if err != nil {
		return Asset{}, fmt.Errorf("Get: %w", err)
	}
	return a, nil
}

// resolveCandidates bounds FindByExactName's result: the same name can
// legitimately exist on more than one asset (the same IAM role name reused
// across accounts is the live case ResolveID exists for), so ResolveID checks
// a small window of exact-name matches rather than assuming there is only one.
// FindByExactName is an equality lookup (WHERE name = ?), not a wildcard scan
// — ResolveID still requires an exact match itself, in Go, below.
const resolveCandidates = 25

// ResolveID maps a resource identifier to its canonical asset ID. An exact ID hit
// wins; otherwise the only accepted fallback is an asset whose Name equals the
// identifier exactly. Needed because not every finding source keys findings by
// the asset ID — aws_guardduty's iam_user findings carry the role/user NAME while
// the asset ID is the ARN (the same mismatch danglingJoinSpecs documents), so a
// caller that seeds a graph walk with finding.ResourceID walks from a node that
// does not exist.
//
// The exact-name requirement is load-bearing, not defensive: a role name is a
// substring of that workload's instance-profile ARN, task-definition ARN and log
// group, so accepting a partial match would seed the walk from an unrelated node
// and size a remediation against the wrong asset's reach — a confidently wrong
// blast radius, which is worse than the visibly wrong zero it replaces.
// Returns ErrNotFound when nothing matches exactly.
func (s *Service) ResolveID(ctx context.Context, identifier string) (string, error) {
	if identifier == "" {
		return "", fmt.Errorf("ResolveID: %w", ErrNotFound)
	}
	if a, err := s.repo.GetAsset(ctx, identifier); err == nil {
		return a.ID, nil
	}
	matches, err := s.repo.FindByExactName(ctx, identifier, resolveCandidates)
	if err != nil {
		return "", fmt.Errorf("ResolveID: %w", err)
	}
	for _, a := range matches {
		if a.Name == identifier || a.ID == identifier {
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("ResolveID %q: %w", identifier, ErrNotFound)
}

// EdgesFrom returns outgoing edges for a batch of source asset IDs.
func (s *Service) EdgesFrom(ctx context.Context, ids []string) ([]Edge, error) {
	return s.repo.EdgesFrom(ctx, ids)
}

// EdgesInto returns all edges of edgeType pointing at dstID.
func (s *Service) EdgesInto(ctx context.Context, dstID, edgeType string) ([]Edge, error) {
	return s.repo.EdgesInto(ctx, dstID, edgeType)
}

// EdgesIntoTypes returns inbound edges of any of edgeTypes pointing at dstID in one query.
func (s *Service) EdgesIntoTypes(ctx context.Context, dstID string, edgeTypes []string) ([]Edge, error) {
	return s.repo.EdgesIntoTypes(ctx, dstID, edgeTypes)
}

// EdgesOut returns outgoing edges from srcID filtered to edgeType.
// Uses a typed CH query (WHERE src_id = ? AND edge_type = ?) so high-connectivity
// assets don't over-fetch all edge types just to find one.
func (s *Service) EdgesOut(ctx context.Context, srcID, edgeType string) ([]Edge, error) {
	return s.repo.EdgesOut(ctx, srcID, edgeType)
}

// EdgesOutBatch returns outgoing edges for all srcIDs filtered to edgeType in one query.
func (s *Service) EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]Edge, error) {
	return s.repo.EdgesOutBatch(ctx, srcIDs, edgeType)
}

// EdgesTo returns the fresh incoming edges, of every type, for a batch of
// destination IDs.
func (s *Service) EdgesTo(ctx context.Context, dstIDs []string) ([]Edge, error) {
	edges, err := s.repo.EdgesTo(ctx, dstIDs)
	if err != nil {
		return nil, fmt.Errorf("EdgesTo: %w", err)
	}
	return edges, nil
}

// RecordImageBases stores the base identity the image-vuln sweep read off
// scanned container images.
func (s *Service) RecordImageBases(ctx context.Context, bases []ImageBase) error {
	if err := s.repo.UpsertImageBases(ctx, bases); err != nil {
		return fmt.Errorf("RecordImageBases: %w", err)
	}
	return nil
}

// ImageBases returns every recorded container image base identity.
func (s *Service) ImageBases(ctx context.Context) ([]ImageBase, error) {
	out, err := s.repo.ImageBases(ctx)
	if err != nil {
		return nil, fmt.Errorf("ImageBases: %w", err)
	}
	return out, nil
}

// ListExternal returns internet-facing assets (public IP or domain).
func (s *Service) ListExternal(ctx context.Context, limit int) ([]Asset, error) {
	out, err := s.repo.ListExternal(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("ListExternal: %w", err)
	}
	return out, nil
}

// ListExternalIDs returns the IDs of the limit most-recently-seen internet-facing
// assets. The caller (jobs.invalidateExposedFindings) owns what limit means for
// its own memory budget — this method doesn't hardcode a second, smaller
// ceiling on top of it. limit is still subject to CHRepo.ListExternal's own
// outer ceiling (clampExternalLimit/defaultExternalLimit).
func (s *Service) ListExternalIDs(ctx context.Context, limit int) ([]string, error) {
	assets, err := s.repo.ListExternal(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("ListExternalIDs: %w", err)
	}
	ids := make([]string, len(assets))
	for i, a := range assets {
		ids[i] = a.ID
	}
	return ids, nil
}

// ListAll returns ALL assets — used by the Ladybug bulk sync.
// Calls ListAllForSync to bypass the assetPageLimit=100 pagination cap in List().
//
// proj narrows what each asset carries (Metadata keys, whether Tags are retained); the
// zero value means everything. See asset.SyncProjection for the cost.
func (s *Service) ListAll(ctx context.Context, proj SyncProjection) (AssetSyncResult, error) {
	out, err := s.repo.ListAllForSync(ctx, proj)
	if err != nil {
		return AssetSyncResult{}, fmt.Errorf("ListAll: %w", err)
	}
	return out, nil
}

// AllEdges returns the full edge set plus truncation accounting — used by the
// Ladybug bulk sync to decide whether internet_hops may assert ReachNone.
func (s *Service) AllEdges(ctx context.Context, proj SyncProjection) (EdgeSyncResult, error) {
	out, err := s.repo.AllEdgesForSync(ctx, proj)
	if err != nil {
		return EdgeSyncResult{}, fmt.Errorf("AllEdges: %w", err)
	}
	return out, nil
}

// IsExposedEdge reports whether assetID has an exposed_to_internet edge.
func (s *Service) IsExposedEdge(ctx context.Context, assetID string) (bool, error) {
	ok, err := s.repo.IsExposedEdge(ctx, assetID)
	if err != nil {
		return false, fmt.Errorf("IsExposedEdge: %w", err)
	}
	return ok, nil
}

// ListByType returns every asset of one type, newest first.
func (s *Service) ListByType(ctx context.Context, assetType string, limit int) ([]Asset, error) {
	out, err := s.repo.ListByType(ctx, assetType, limit)
	if err != nil {
		return nil, fmt.Errorf("ListByType: %w", err)
	}
	return out, nil
}

// PackageRunners returns the departure evidence for packageIDs: every runner
// with an edge into them inside the edge TTL (see PackageRunner).
func (s *Service) PackageRunners(ctx context.Context, packageIDs []string) ([]PackageRunner, error) {
	out, err := s.repo.PackageRunners(ctx, packageIDs)
	if err != nil {
		return nil, fmt.Errorf("PackageRunners: %w", err)
	}
	return out, nil
}

// PackageScan describes one completed pass over the live package inventory.
type PackageScan struct {
	// ListedAt was captured before the live set was read: a package observed
	// after it may be missing from the pass, so absence from the pass says
	// nothing about such a package.
	ListedAt time.Time
	// LiveIDs is every package id that had a fresh edge when the set was read
	// — the pass's inventory, handed back so a caller judging departures
	// does not build a second copy of it.
	LiveIDs map[string]bool
}

// ScanLivePackages walks every LIVE package once, handing fn one page of
// coordinates at a time. The live-id set is read ONCE, up front, against one
// freshness cutoff, and the package rows are walked by keyset — so a package
// is neither skipped nor dropped because the window moved or the inventory
// grew while the pass ran. Any read error, or an error from fn, aborts the
// pass: a caller must not reconcile on a partial walk.
func (s *Service) ScanLivePackages(ctx context.Context, fn func([]PackageCoord) error) (PackageScan, error) {
	scan := PackageScan{ListedAt: time.Now()}
	live, err := s.repo.LivePackageIDs(ctx)
	if err != nil {
		return PackageScan{}, fmt.Errorf("ScanLivePackages: %w", err)
	}
	scan.LiveIDs = live
	if len(live) == 0 {
		return scan, nil
	}
	for after := ""; ; {
		page, next, err := s.repo.PackageCoordsAfter(ctx, after)
		if err != nil {
			return PackageScan{}, fmt.Errorf("ScanLivePackages: %w", err)
		}
		if next == "" {
			return scan, nil
		}
		kept := page[:0]
		for _, c := range page {
			if live[c.ID] {
				kept = append(kept, c)
			}
		}
		if len(kept) > 0 {
			if err := fn(kept); err != nil {
				return PackageScan{}, fmt.Errorf("ScanLivePackages: %w", err)
			}
		}
		after = next
	}
}

// CountPackages returns the current count of live package assets — the denominator
// the OSV scan-staleness observability gauge (internal/obs/metrics.go) needs
// to compute how much of the inventory has never been checked against OSV.
func (s *Service) CountPackages(ctx context.Context) (int64, error) {
	n, err := s.repo.CountPackages(ctx)
	if err != nil {
		return 0, fmt.Errorf("CountPackages: %w", err)
	}
	return n, nil
}

// List returns assets matching a filter.
func (s *Service) List(ctx context.Context, f Filter) ([]Asset, error) {
	out, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("List: %w", err)
	}
	return out, nil
}

// ByIDs returns the current rows for the given asset IDs.
func (s *Service) ByIDs(ctx context.Context, ids []string) ([]Asset, error) {
	out, err := s.repo.ByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("ByIDs: %w", err)
	}
	return out, nil
}

// ExistingIDs returns the subset of ids that currently have an asset row — the
// dangling-finding sweep uses it to distinguish a finding whose
// resource still exists from one whose resource is gone.
func (s *Service) ExistingIDs(ctx context.Context, ids []string) ([]string, error) {
	out, err := s.repo.ExistingIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("ExistingIDs: %w", err)
	}
	return out, nil
}

// ProviderHighWater returns when the given provider last collected anything.
func (s *Service) ProviderHighWater(ctx context.Context, provider string) (time.Time, error) {
	out, err := s.repo.ProviderHighWater(ctx, provider)
	if err != nil {
		return time.Time{}, fmt.Errorf("ProviderHighWater: %w", err)
	}
	return out, nil
}

// ProviderStaleness reports, per provider, total assets and how many have not
// had a last_seen within marginSeconds of that provider's own high-water mark
// — the obs Sources feed for graph_asset_stale/graph_asset_total.
func (s *Service) ProviderStaleness(ctx context.Context, marginSeconds int) ([]ProviderStaleness, error) {
	out, err := s.repo.ProviderStaleness(ctx, marginSeconds)
	if err != nil {
		return nil, fmt.Errorf("ProviderStaleness: %w", err)
	}
	return out, nil
}

// ProviderDimensionCounts returns, per provider, the distinct region/account_id
// values seen — the obs Sources feed for graph_connector_coverage_seen.
func (s *Service) ProviderDimensionCounts(ctx context.Context) ([]ProviderDimensions, error) {
	out, err := s.repo.ProviderDimensionCounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("ProviderDimensionCounts: %w", err)
	}
	return out, nil
}

// Summary returns aggregate counts.
func (s *Service) Summary(ctx context.Context) (Summary, error) {
	out, err := s.repo.Summary(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("Summary: %w", err)
	}
	return out, nil
}

// Direction selects which way a blast-radius traversal walks the graph:
//   - DirOut  ("what can this asset reach?") follows outgoing edges — the default.
//   - DirIn   ("who can reach this asset?")  follows incoming edges.
//   - DirBoth walks both, for the full neighbourhood.
//   - DirAttack follows each edge type the way an attacker moves along it
//     (graphschema.AttackDirection) — the blast-radius default, matching the
//     Ladybug walk so the ClickHouse fallback reports the same reach.
type Direction string

const (
	DirOut    Direction = "out"
	DirIn     Direction = "in"
	DirBoth   Direction = "both"
	DirAttack Direction = "attack"
)

// ParseDirection maps a query-string value to a Direction (default: out).
func ParseDirection(s string) Direction {
	switch s {
	case "in":
		return DirIn
	case "both":
		return DirBoth
	case "attack":
		return DirAttack
	default:
		return DirOut
	}
}

// BlastRadius performs a bounded BFS from seedID following each edge the way an
// attacker moves along it ("if this asset is compromised, what can be reached?").
// It is the default used by enrichment, the responder, and MCP, and the
// ClickHouse fallback for the Ladybug blast walk; callers needing a plain
// structural direction use BlastRadiusDir.
func (s *Service) BlastRadius(ctx context.Context, seedID string, maxDepth int) (BlastRadius, error) {
	return s.BlastRadiusDir(ctx, seedID, maxDepth, DirAttack)
}

// hopEdges fetches one frontier hop's edges in the requested direction(s).
func (s *Service) hopEdges(ctx context.Context, frontier []string, dir Direction) ([]Edge, error) {
	if dir == DirAttack {
		return s.repo.EdgesForAttack(ctx, frontier)
	}
	var edges []Edge
	if dir == DirOut || dir == DirBoth {
		out, err := s.repo.EdgesFrom(ctx, frontier)
		if err != nil {
			return nil, err
		}
		edges = append(edges, out...)
	}
	if dir == DirIn || dir == DirBoth {
		in, err := s.repo.EdgesTo(ctx, frontier)
		if err != nil {
			return nil, err
		}
		edges = append(edges, in...)
	}
	return edges, nil
}

// attackFollowsOut / attackFollowsIn report whether an attacker-direction walk
// follows an edge type src→dst / dst→src.
func attackFollowsOut(edgeType string) bool {
	return graphschema.AttackDirection(edgeType) != graphschema.DirReverse
}

func attackFollowsIn(edgeType string) bool {
	d := graphschema.AttackDirection(edgeType)
	return d == graphschema.DirReverse || d == graphschema.DirBoth
}

type endpoint struct{ id, typ string }

// farEndpoints returns the not-yet-seen endpoints of e that lie on the far side
// of the current frontier, given the traversal direction. For DirOut the far
// side is the destination; for DirIn it's the source; for DirBoth it's whichever
// endpoint isn't in the frontier.
func farEndpoints(e Edge, frontier []string, dir Direction, seen map[string]bool) []endpoint {
	inFrontier := func(id string) bool {
		for _, f := range frontier {
			if f == id {
				return true
			}
		}
		return false
	}
	var out []endpoint
	consider := func(id, typ string) {
		if id != "" && !seen[id] {
			out = append(out, endpoint{id, typ})
		}
	}
	switch dir {
	case DirAttack:
		// An edge may have been fetched from either side; advance along every
		// side the attacker direction allows.
		if inFrontier(e.SrcID) && attackFollowsOut(e.EdgeType) {
			consider(e.DstID, e.DstType)
		}
		if inFrontier(e.DstID) && attackFollowsIn(e.EdgeType) {
			consider(e.SrcID, e.SrcType)
		}
	case DirIn:
		consider(e.SrcID, e.SrcType)
	case DirBoth:
		// Walk to whichever endpoint advances away from the frontier.
		if inFrontier(e.SrcID) {
			consider(e.DstID, e.DstType)
		} else {
			consider(e.SrcID, e.SrcType)
		}
	default: // DirOut
		consider(e.DstID, e.DstType)
	}
	return out
}

// PurgeAccount hard-deletes every asset for one provider+account — see
// CHRepo.PurgeAccount for why this exists as a separate, explicit action
// rather than a staleness sweep, and why it is never called automatically.
func (s *Service) PurgeAccount(ctx context.Context, provider, accountID string) (int, error) {
	n, err := s.repo.PurgeAccount(ctx, provider, accountID)
	if err != nil {
		return 0, fmt.Errorf("PurgeAccount: %w", err)
	}
	return n, nil
}

// AssetIDsByAccount returns every asset ID for one provider+account. The
// caller resolving findings before a purge needs the actual IDs, not a count.
func (s *Service) AssetIDsByAccount(ctx context.Context, provider, accountID string) ([]string, error) {
	ids, err := s.repo.AssetIDsByAccount(ctx, provider, accountID)
	if err != nil {
		return nil, fmt.Errorf("AssetIDsByAccount: %w", err)
	}
	return ids, nil
}

// AssetMetadata returns one asset's metadata, or nil (and no error) when the
// asset does not exist — the purge path asks it which shared assets a
// connector's account points at.
func (s *Service) AssetMetadata(ctx context.Context, id string) (map[string]string, error) {
	a, err := s.repo.GetAsset(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("AssetMetadata: %w", err)
	}
	return a.Metadata, nil
}

// PurgeEdgesForAssets hard-deletes every graph_edges row touching any of the
// given asset IDs — see CHRepo.PurgeEdgesForAssets for why PurgeAccount alone
// leaves a purged account's topology dangling in the graph.
func (s *Service) PurgeEdgesForAssets(ctx context.Context, ids []string) (int, error) {
	n, err := s.repo.PurgeEdgesForAssets(ctx, ids)
	if err != nil {
		return 0, fmt.Errorf("PurgeEdgesForAssets: %w", err)
	}
	return n, nil
}
