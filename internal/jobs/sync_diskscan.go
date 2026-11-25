// VM package-inventory overlay for the sync worker.
//
// The collectors stamp every VM with the inventory they could read (SSM,
// OS Config) or none. Sources that live outside a collector — the agentless
// disk scan, and later a customer's own agent — are applied here, right after
// collection, because a collector rewrites asset metadata on every sweep and
// would otherwise erase what they stamped. The same rule as everywhere: an
// inventory is only believed when its source says it is known, and a source
// that cannot say leaves the collector's own stamp, which reads as unknown.
package jobs

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// InventoryRecord is one source's newest word on one VM.
type InventoryRecord struct {
	// Source is the asset.PackageInventory* value the stamp carries.
	Source string
	// Known is true only when the source positively read a package list. A
	// record that is not Known carries Gap and no packages.
	Known bool
	// CVEKnown is whether the source vouches that its packages can support a CVE
	// verdict; the overlay still applies the advisory-source check on top.
	CVEKnown bool
	Gap      string
	// ObservedAt is when the inventory was captured. The newest known capture wins.
	ObservedAt time.Time
	Ecosystem  string
	Packages   []pkginventory.InstalledPackage
	// Stamp, when set, writes the VM's known-ness keys itself and the record
	// carries no packages: its source wrote the package edges on its own (the
	// bring-your-own-agent ingest). Unset, the overlay stamps from the fields
	// above and emits the package assets and edges.
	Stamp func(meta map[string]string)
}

func (r InventoryRecord) usable() bool {
	return r.Known && r.Ecosystem != "" && (len(r.Packages) > 0 || r.Stamp != nil)
}

// InventorySource is the seam for an inventory that does not come from a
// collector. Latest returns, per VM id, its newest record; a VM the source has
// never seen is absent. connectorID is the connector being synced, so a source
// can hide what it holds for a connector that has since opted out.
//
// The bring-your-own-agent reader joins here by adding one InventorySource to
// Deps.InventorySources; nothing else in the sync path changes.
type InventorySource interface {
	Latest(ctx context.Context, connectorID string, vmIDs []string) (map[string]InventoryRecord, error)
}

// vmInventoryTypes are the asset types the overlay stamps.
var vmInventoryTypes = map[string]bool{"ec2_instance": true, "azure_vm": true}

// inventoryOverlay applies InventorySources to a sweep's VMs.
type inventoryOverlay struct {
	sources  []InventorySource
	advisory distro.Sources
	now      func() time.Time
}

func newInventoryOverlay(sources []InventorySource, advisory distro.Sources) *inventoryOverlay {
	if len(sources) == 0 {
		return nil
	}
	return &inventoryOverlay{sources: sources, advisory: advisory, now: time.Now}
}

// apply stamps res's VMs in place and appends the package assets and edges of
// any inventory it adopts. A source that errors is skipped: its VMs keep the
// collector's stamp.
func (o *inventoryOverlay) apply(ctx context.Context, c connector.Connector, res *collect.Result) {
	if o == nil {
		return
	}
	var vmIdx []int
	var ids []string
	for i, a := range res.Assets {
		if vmInventoryTypes[a.Type] {
			vmIdx = append(vmIdx, i)
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	recs := make([]map[string]InventoryRecord, 0, len(o.sources))
	for _, src := range o.sources {
		got, err := src.Latest(ctx, c.ID, ids)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("connector_id", c.ID).
				Msg("inventory overlay: a source is unavailable; its VMs keep the collector's stamp")
			continue
		}
		recs = append(recs, got)
	}
	now := o.now()
	known := make(map[string]bool, len(res.Assets))
	for _, a := range res.Assets {
		known[a.ID] = true
	}
	var newAssets []asset.Asset
	var newEdges []asset.Edge
	var displaced []string
	for _, i := range vmIdx {
		vm := &res.Assets[i]
		cands := make([]InventoryRecord, 0, len(recs))
		for _, m := range recs {
			if r, ok := m[vm.ID]; ok {
				cands = append(cands, r)
			}
		}
		stampDiskScan(vm, cands)
		best, ok := o.pick(vm.Metadata, cands)
		if !ok {
			stampGap(vm, cands)
			continue
		}
		if asset.PackageInventoryKnown(vm.Metadata) {
			displaced = append(displaced, vm.ID)
		}
		if best.Stamp != nil {
			best.Stamp(vm.Metadata)
			continue
		}
		o.stamp(vm, best, now)
		pkgAssets, pkgEdges := pkginventory.InventoryGraph(vm.ID, vm.Type, best.Packages, now)
		for _, pa := range pkgAssets {
			if !known[pa.ID] {
				known[pa.ID] = true
				newAssets = append(newAssets, pa)
			}
		}
		newEdges = append(newEdges, pkgEdges...)
	}
	if len(displaced) > 0 {
		res.Edges = slices.DeleteFunc(res.Edges, func(e asset.Edge) bool {
			return e.EdgeType == "runs_package" && slices.Contains(displaced, e.SrcID)
		})
	}
	res.Assets = append(res.Assets, newAssets...)
	res.Edges = append(res.Edges, newEdges...)
}

// pick returns the newest known record that beats what the collector stamped:
// a VM with no inventory takes any known record, one that has one takes only a
// strictly newer capture.
func (o *inventoryOverlay) pick(meta map[string]string, cands []InventoryRecord) (InventoryRecord, bool) {
	var best InventoryRecord
	found := false
	for _, r := range cands {
		if r.usable() && (!found || r.ObservedAt.After(best.ObservedAt)) {
			best, found = r, true
		}
	}
	if !found {
		return InventoryRecord{}, false
	}
	if asset.PackageInventoryKnown(meta) && !best.ObservedAt.UTC().Truncate(24*time.Hour).After(observedOn(meta)) {
		return InventoryRecord{}, false
	}
	return best, true
}

func observedOn(meta map[string]string) time.Time {
	t, err := time.Parse(time.DateOnly, meta[asset.MetaPackageInventoryObservedOn])
	if err != nil {
		return time.Time{}
	}
	return t
}

// stamp writes the known-ness keys for an adopted inventory, replacing the
// collector's none-and-reason with the source's own.
func (o *inventoryOverlay) stamp(vm *asset.Asset, r InventoryRecord, now time.Time) {
	m := vm.Metadata
	delete(m, asset.MetaPackageInventoryGap)
	delete(m, asset.MetaPackageCVEGap)
	m[asset.MetaPackageInventory] = r.Source
	m[asset.MetaPackageInventoryObservedOn] = r.ObservedAt.UTC().Format(time.DateOnly)
	m[asset.MetaPackageEcosystem] = r.Ecosystem
	cveGap := pkginventory.CVEGap(r.Ecosystem, pkginventory.HasSourceNames(r.Packages), o.advisory, now)
	matchable := r.CVEKnown && cveGap == ""
	m[asset.MetaPackageCVEMatchable] = fmt.Sprintf("%t", matchable)
	if cveGap != "" {
		m[asset.MetaPackageCVEGap] = cveGap
	}
}

// stampGap lets a source's own gap explain a VM that has no known inventory
// from any source, instead of the collector's generic reason. A VM that has
// one keeps it.
func stampGap(vm *asset.Asset, cands []InventoryRecord) {
	if asset.PackageInventoryKnown(vm.Metadata) {
		return
	}
	for _, r := range cands {
		if r.Stamp != nil && !r.Known {
			r.Stamp(vm.Metadata)
			return
		}
	}
}

// stampDiskScan records the disk scan's own state on the VM, whichever
// inventory ends up believed: scanned, not enabled, or none (enabled, but no
// readable disk). Only a disk record sets it.
func stampDiskScan(vm *asset.Asset, cands []InventoryRecord) {
	for _, r := range cands {
		if r.Source != asset.PackageInventoryDisk {
			continue
		}
		if vm.Metadata == nil {
			vm.Metadata = map[string]string{}
		}
		switch {
		case r.Known:
			vm.Metadata[asset.MetaDiskScan] = asset.DiskScanScanned
			delete(vm.Metadata, asset.MetaDiskScanGap)
		case r.Gap == diskscan.GapNotEnabled:
			vm.Metadata[asset.MetaDiskScan] = asset.DiskScanNotEnabled
			vm.Metadata[asset.MetaDiskScanGap] = r.Gap
		default:
			vm.Metadata[asset.MetaDiskScan] = asset.DiskScanNone
			if r.Gap != "" {
				vm.Metadata[asset.MetaDiskScanGap] = r.Gap
			}
		}
		return
	}
}

// diskInventorySource adapts the disk scan's results to an InventorySource.
type diskInventorySource struct {
	svc        diskInventoryReader
	staleAfter time.Duration
	now        func() time.Time
}

// diskInventoryReader is the slice of *diskscan.Service the overlay reads.
type diskInventoryReader interface {
	EnabledConnectors(ctx context.Context) ([]diskscan.ConnectorSettings, error)
	Latest(ctx context.Context, assetIDs []string) (map[string]diskscan.VolumeResult, error)
	Packages(ctx context.Context, assetIDs []string) ([]diskscan.PackageSet, error)
}

func newDiskInventorySource(svc diskInventoryReader, staleAfter time.Duration) *diskInventorySource {
	return &diskInventorySource{svc: svc, staleAfter: staleAfter, now: time.Now}
}

// Latest returns the disk scan's word on each VM. A connector that is not
// enabled gets not_enabled for every VM, and its stored results are not read:
// turning the feature off hides what it found. A result older than staleAfter
// is the stale gap, and a known result without its own package list is a read
// error, never an empty inventory.
func (s *diskInventorySource) Latest(ctx context.Context, connectorID string, vmIDs []string) (map[string]InventoryRecord, error) {
	enabled, err := s.svc.EnabledConnectors(ctx)
	if err != nil {
		return nil, fmt.Errorf("Latest: %w", err)
	}
	on := slices.ContainsFunc(enabled, func(c diskscan.ConnectorSettings) bool { return c.ConnectorID == connectorID })
	out := make(map[string]InventoryRecord, len(vmIDs))
	if !on {
		for _, id := range vmIDs {
			out[id] = InventoryRecord{Source: asset.PackageInventoryDisk, Gap: diskscan.GapNotEnabled}
		}
		return out, nil
	}
	results, err := s.svc.Latest(ctx, vmIDs)
	if err != nil {
		return nil, fmt.Errorf("Latest: %w", err)
	}
	sets, err := s.svc.Packages(ctx, vmIDs)
	if err != nil {
		return nil, fmt.Errorf("Latest: %w", err)
	}
	now := s.now()
	for _, id := range vmIDs {
		res, ok := results[id]
		if !ok {
			out[id] = InventoryRecord{Source: asset.PackageInventoryDisk}
			continue
		}
		out[id] = s.record(res, sets, now)
	}
	return out, nil
}

func (s *diskInventorySource) record(res diskscan.VolumeResult, sets []diskscan.PackageSet, now time.Time) InventoryRecord {
	rec := InventoryRecord{Source: asset.PackageInventoryDisk, ObservedAt: res.ObservedAt, Gap: res.Gap}
	if !res.InventoryKnown {
		return rec
	}
	rec.Gap = diskscan.GapReadError
	if now.Sub(res.ObservedAt) > s.staleAfter {
		rec.Gap = diskscan.GapStale
		return rec
	}
	for _, set := range sets {
		if set.AssetID == res.AssetID && set.VolumeRef == res.VolumeRef && set.SnapshotID == res.SnapshotID && len(set.Packages) > 0 {
			rec.Known, rec.CVEKnown, rec.Gap = true, res.CVEMatchableKnown, ""
			rec.Ecosystem, rec.Packages = set.Ecosystem, set.Packages
			return rec
		}
	}
	return rec
}

// byoaReader is the slice of *pkginv.Service the overlay reads.
type byoaReader interface {
	Latest(ctx context.Context, assetIDs []string) (map[string]pkginv.InventoryRecord, error)
}

// byoaInventorySource adapts customer-agent inventories to an InventorySource.
// Staleness is the reader's: an inventory past its freshness window comes back
// as a byoa_stale gap, which never beats a known one.
type byoaInventorySource struct{ svc byoaReader }

// NewBYOAInventorySource returns the source for a pkginv reader.
func NewBYOAInventorySource(svc byoaReader) InventorySource { return byoaInventorySource{svc: svc} }

func (s byoaInventorySource) Latest(ctx context.Context, _ string, vmIDs []string) (map[string]InventoryRecord, error) {
	got, err := s.svc.Latest(ctx, vmIDs)
	if err != nil {
		return nil, fmt.Errorf("Latest: %w", err)
	}
	out := make(map[string]InventoryRecord, len(got))
	for id, r := range got {
		out[id] = InventoryRecord{
			Source: asset.PackageInventoryBYOA, Known: r.InventoryKnown, CVEKnown: r.CVEMatchableKnown, Gap: r.Gap,
			ObservedAt: r.ObservedAt, Ecosystem: r.Ecosystem, Stamp: r.Stamp,
		}
	}
	return out, nil
}
