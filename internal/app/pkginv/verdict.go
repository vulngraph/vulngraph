package pkginv

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// Verdict is the server's reading of a submission: how far to believe it and,
// when it is believed, the packages to put in the graph.
type Verdict struct {
	Ecosystem         string
	InventoryKnown    bool
	CVEMatchableKnown bool
	Gap               string
	// Packages is set only when the inventory is known: a gap emits no edges,
	// the same rule the SSM path follows.
	Packages []pkginventory.InstalledPackage
}

// Evaluate decides known-ness. Nothing the agent states, bar the package list
// itself, can raise it: complete=true is a claim, believed only while the
// capture is fresh and the OS resolves to an advisory source that is switched
// on. Every other case is a gap, never a clean-looking empty list.
func Evaluate(s Submission, now time.Time, advisory distro.Sources) Verdict {
	v := Verdict{Ecosystem: pkginventory.InventoryEcosystem(s.OS.ID, s.OS.VersionID)}
	pkgs := make([]pkginventory.InstalledPackage, 0, len(s.Packages))
	for _, p := range s.Packages {
		eco := p.Ecosystem
		if eco == "" {
			eco = v.Ecosystem
		}
		ip, ok := pkginventory.InventoryPackage(eco, p.Name, p.Version, p.Release, p.Epoch, "byoa")
		if !ok {
			continue
		}
		ip.SourceName, ip.SourceVersion = p.SourceName, p.SourceVersion
		pkgs = append(pkgs, ip)
	}
	switch {
	case !s.Complete:
		v.Gap = GapIncomplete
	case now.Sub(s.ObservedAt) > FreshFor:
		v.Gap = GapStale
	case v.Ecosystem == "":
		v.Gap = asset.CVEGapUnknownRelease
	default:
		v.Gap = pkginventory.CVEGap(v.Ecosystem, pkginventory.HasSourceNames(pkgs), advisory, now)
	}
	if v.Gap != "" {
		return v
	}
	v.InventoryKnown, v.CVEMatchableKnown, v.Packages = true, true, pkgs
	return v
}

// Stamp writes the inventory's known-ness onto a VM's metadata, following the
// keys the SSM path writes (asset.MetaPackageInventory...). A gap writes only
// none and the reason: an ecosystem on a VM with no usable inventory would read
// as coverage. The scanner and version are stamped either way so the UI can say
// who reported it.
func (r InventoryRecord) Stamp(meta map[string]string) {
	if meta == nil {
		return
	}
	meta[asset.MetaPackageInventoryScanner] = r.Scanner.Name
	meta[asset.MetaPackageInventoryScannerVersion] = r.Scanner.Version
	if !r.InventoryKnown {
		meta[asset.MetaPackageInventory] = asset.PackageInventoryNone
		meta[asset.MetaPackageInventoryGap] = r.Gap
		return
	}
	meta[asset.MetaPackageInventory] = asset.PackageInventoryBYOA
	meta[asset.MetaPackageInventoryObservedOn] = r.ObservedAt.UTC().Format(time.DateOnly)
	meta[asset.MetaPackageEcosystem] = r.Ecosystem
	meta[asset.MetaPackageCVEMatchable] = boolString(r.CVEMatchableKnown)
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// Freshest picks, among one asset's records, the one the overlay should apply:
// the newest known inventory, else the newest record of any kind so a gap is
// still visible. Ties break on source for a stable result.
func Freshest(recs []InventoryRecord) (InventoryRecord, bool) {
	var best InventoryRecord
	found := false
	for _, r := range recs {
		if !found || better(r, best) {
			best, found = r, true
		}
	}
	return best, found
}

func better(a, b InventoryRecord) bool {
	if a.InventoryKnown != b.InventoryKnown {
		return a.InventoryKnown
	}
	if !a.ObservedAt.Equal(b.ObservedAt) {
		return a.ObservedAt.After(b.ObservedAt)
	}
	return a.Source < b.Source
}
