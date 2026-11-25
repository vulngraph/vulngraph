package jobs

import (
	"slices"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// addDiskScanWorkers registers the disk scan's workers on the worker pod: plan
// and sweep always (they need the connectors, which this pod can decrypt), and
// the volume worker only when this pod also runs the heavy scans, which is the
// all-in-one topology — in the split one the scanner pod runs it.
func addDiskScanWorkers(workers *river.Workers, d *DiskScanDeps, assets *asset.Service, runsVolumes bool) {
	if d == nil {
		return
	}
	lim := d.limits()
	river.AddWorker(workers, &DiskScanPlanWorker{
		svc: d.Service, assets: assets, clouds: d.Clouds, inserts: riverDiskInserter{}, limits: lim,
	})
	river.AddWorker(workers, &DiskScanSweepWorker{svc: d.Service, clouds: d.Clouds, limits: lim})
	if runsVolumes {
		addDiskScanVolumeWorker(workers, d)
	}
}

// addDiskScanVolumeWorker registers the volume worker, the only disk scan
// worker the scanner pod runs.
func addDiskScanVolumeWorker(workers *river.Workers, d *DiskScanDeps) {
	if d == nil {
		return
	}
	river.AddWorker(workers, &DiskScanVolumeWorker{
		svc: d.Service, clouds: d.Clouds, advisory: d.Advisory, limits: d.limits(),
	})
}

// inventoryOverlay builds the sync worker's overlay from the sources the pod
// was wired with, the disk scan's among them.
func (deps Deps) inventoryOverlay() *inventoryOverlay {
	sources := slices.Clone(deps.InventorySources)
	if deps.DiskScan != nil && deps.DiskScan.Service != nil {
		sources = append(sources, newDiskInventorySource(deps.DiskScan.Service, deps.DiskScan.limits().ResultStaleAfter))
	}
	return newInventoryOverlay(sources, deps.InventoryAdvisory)
}
