package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

type staticSource map[string]InventoryRecord

func (s staticSource) Latest(context.Context, string, []string) (map[string]InventoryRecord, error) {
	return s, nil
}

type failingSource struct{}

func (failingSource) Latest(context.Context, string, []string) (map[string]InventoryRecord, error) {
	return nil, errors.New("down")
}

var overlayNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func overlayFor(sources ...InventorySource) *inventoryOverlay {
	o := newInventoryOverlay(sources, distro.Sources{distro.SourceOSV: true})
	o.now = func() time.Time { return overlayNow }
	return o
}

func debPkgs() []pkginventory.InstalledPackage {
	return []pkginventory.InstalledPackage{{Ecosystem: "Debian:12", Name: "libssl3", Version: "3.0", SourceName: "openssl"}}
}

func diskRec(age time.Duration) InventoryRecord {
	return InventoryRecord{Source: asset.PackageInventoryDisk, Known: true, CVEKnown: true, ObservedAt: overlayNow.Add(-age),
		Ecosystem: "Debian:12", Packages: debPkgs()}
}

func byoaRec(age time.Duration, known bool, gap string) InventoryRecord {
	rec := pkginv.InventoryRecord{
		Source: "byoa", Scanner: pkginv.Scanner{Name: "trivy", Version: "1"}, Ecosystem: "Debian:12",
		ObservedAt: overlayNow.Add(-age), InventoryKnown: known, CVEMatchableKnown: known, Gap: gap,
	}
	return InventoryRecord{Source: asset.PackageInventoryBYOA, Known: known, CVEKnown: known, Gap: gap,
		ObservedAt: rec.ObservedAt, Ecosystem: rec.Ecosystem, Stamp: rec.Stamp}
}

func ssmVM(observedOn string) asset.Asset {
	return asset.Asset{ID: "vm", Type: "ec2_instance", Metadata: map[string]string{
		asset.MetaPackageInventory: asset.PackageInventorySSM, asset.MetaPackageInventoryObservedOn: observedOn,
		asset.MetaPackageEcosystem: "Debian:12", asset.MetaPackageCVEMatchable: "true",
	}}
}

func noneVM() asset.Asset {
	return asset.Asset{ID: "vm", Type: "ec2_instance", Metadata: map[string]string{
		asset.MetaPackageInventory: asset.PackageInventoryNone, asset.MetaPackageInventoryGap: "not_managed",
	}}
}

func apply(o *inventoryOverlay, vm asset.Asset, edges ...asset.Edge) collect.Result {
	res := collect.Result{Assets: []asset.Asset{vm}, Edges: edges}
	o.apply(context.Background(), connector.Connector{ID: "c1"}, &res)
	return res
}

func ssmEdge() asset.Edge {
	return asset.Edge{SrcID: "vm", SrcType: "ec2_instance", DstID: "pkg:old", DstType: "package", EdgeType: "runs_package"}
}

func TestOverlay_DiskFillsAVMWithNoInventory(t *testing.T) {
	res := apply(overlayFor(staticSource{"vm": diskRec(time.Hour)}), noneVM())
	m := res.Assets[0].Metadata
	require.Equal(t, asset.PackageInventoryDisk, m[asset.MetaPackageInventory])
	require.NotContains(t, m, asset.MetaPackageInventoryGap, "the collector's reason is replaced")
	require.Equal(t, "2026-11-25", m[asset.MetaPackageInventoryObservedOn])
	require.Equal(t, "Debian:12", m[asset.MetaPackageEcosystem])
	require.Equal(t, "true", m[asset.MetaPackageCVEMatchable])
	require.Equal(t, asset.DiskScanScanned, m[asset.MetaDiskScan])
	require.True(t, asset.PackageInventoryKnown(m))
	require.Len(t, res.Edges, 1, "runs_package edge emitted")
	require.Equal(t, "runs_package", res.Edges[0].EdgeType)
	require.Len(t, res.Assets, 2, "the package asset is emitted")
}

func TestOverlay_CVEMatchableNeedsTheAdvisorySourceAndTheSourcesWord(t *testing.T) {
	o := newInventoryOverlay([]InventorySource{staticSource{"vm": diskRec(time.Hour)}}, nil)
	o.now = func() time.Time { return overlayNow }
	m := apply(o, noneVM()).Assets[0].Metadata
	require.Equal(t, "false", m[asset.MetaPackageCVEMatchable], "no advisory source switched on")
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, m[asset.MetaPackageCVEGap])

	r := diskRec(time.Hour)
	r.CVEKnown = false
	m = apply(overlayFor(staticSource{"vm": r}), noneVM()).Assets[0].Metadata
	require.Equal(t, "false", m[asset.MetaPackageCVEMatchable], "the scanner did not vouch for it")
}

func TestOverlay_Precedence(t *testing.T) {
	today, week := overlayNow.Format(time.DateOnly), overlayNow.Add(-7*24*time.Hour).Format(time.DateOnly)
	for _, tc := range []struct {
		name   string
		vm     asset.Asset
		recs   []InventorySource
		want   string
		wantOn string
	}{
		{"fresher disk beats older ssm", ssmVM(week), []InventorySource{staticSource{"vm": diskRec(time.Hour)}}, asset.PackageInventoryDisk, today},
		{"same-day disk does not displace ssm", ssmVM(today), []InventorySource{staticSource{"vm": diskRec(time.Hour)}}, asset.PackageInventorySSM, today},
		{"older disk never beats ssm", ssmVM(today), []InventorySource{staticSource{"vm": diskRec(72 * time.Hour)}}, asset.PackageInventorySSM, today},
		{"fresher byoa beats older ssm", ssmVM(week), []InventorySource{staticSource{"vm": byoaRec(time.Hour, true, "")}}, asset.PackageInventoryBYOA, today},
		{"older byoa never beats a newer disk", noneVM(),
			[]InventorySource{staticSource{"vm": diskRec(time.Hour)}, staticSource{"vm": byoaRec(48*time.Hour, true, "")}}, asset.PackageInventoryDisk, today},
		{"newer byoa beats older disk", noneVM(),
			[]InventorySource{staticSource{"vm": diskRec(48 * time.Hour)}, staticSource{"vm": byoaRec(time.Hour, true, "")}}, asset.PackageInventoryBYOA, today},
		{"a stale byoa never beats a fresh known one", noneVM(),
			[]InventorySource{staticSource{"vm": diskRec(48 * time.Hour)}, staticSource{"vm": byoaRec(time.Hour, false, pkginv.GapStale)}}, asset.PackageInventoryDisk,
			overlayNow.Add(-48 * time.Hour).Format(time.DateOnly)},
		{"a stale byoa never beats ssm", ssmVM(week), []InventorySource{staticSource{"vm": byoaRec(time.Hour, false, pkginv.GapStale)}}, asset.PackageInventorySSM, week},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := apply(overlayFor(tc.recs...), tc.vm).Assets[0].Metadata
			require.Equal(t, tc.want, m[asset.MetaPackageInventory])
			require.Equal(t, tc.wantOn, m[asset.MetaPackageInventoryObservedOn])
		})
	}
}

func TestOverlay_AdoptedInventoryReplacesTheSSMEdges(t *testing.T) {
	res := apply(overlayFor(staticSource{"vm": diskRec(time.Hour)}), ssmVM("2026-11-01"), ssmEdge())
	for _, e := range res.Edges {
		require.NotEqual(t, "pkg:old", e.DstID, "the displaced inventory's edges are dropped")
	}
	require.NotEmpty(t, res.Edges)

	res = apply(overlayFor(staticSource{"vm": diskRec(72 * time.Hour)}), ssmVM(overlayNow.Format(time.DateOnly)), ssmEdge())
	require.Equal(t, "pkg:old", res.Edges[0].DstID, "an inventory that stays believed keeps its edges")
}

func TestOverlay_BYOAWritesItsOwnStampAndNoGraph(t *testing.T) {
	res := apply(overlayFor(staticSource{"vm": byoaRec(time.Hour, true, "")}), noneVM())
	m := res.Assets[0].Metadata
	require.Equal(t, asset.PackageInventoryBYOA, m[asset.MetaPackageInventory])
	require.Equal(t, "trivy", m[asset.MetaPackageInventoryScanner])
	require.Len(t, res.Assets, 1)
	require.Empty(t, res.Edges, "BYOA wrote its edges when it was submitted")
	require.True(t, asset.PackageInventoryKnown(m))
}

func TestOverlay_BYOAGapExplainsAVMNobodyKnows(t *testing.T) {
	m := apply(overlayFor(staticSource{"vm": byoaRec(time.Hour, false, pkginv.GapStale)}), noneVM()).Assets[0].Metadata
	require.Equal(t, asset.PackageInventoryNone, m[asset.MetaPackageInventory])
	require.Equal(t, pkginv.GapStale, m[asset.MetaPackageInventoryGap])
}

func TestOverlay_DiskGapIsStampedButNeverMakesInventoryKnown(t *testing.T) {
	for gap, want := range map[string]string{
		diskscan.GapNotEnabled: asset.DiskScanNotEnabled, diskscan.GapUnsupportedFS: asset.DiskScanNone, "": asset.DiskScanNone,
	} {
		rec := InventoryRecord{Source: asset.PackageInventoryDisk, Gap: gap}
		m := apply(overlayFor(staticSource{"vm": rec}), noneVM()).Assets[0].Metadata
		require.Equal(t, want, m[asset.MetaDiskScan], gap)
		require.Equal(t, asset.PackageInventoryNone, m[asset.MetaPackageInventory])
		require.False(t, asset.PackageInventoryKnown(m))
	}
}

func TestOverlay_ASourceThatErrorsLeavesTheCollectorsStamp(t *testing.T) {
	m := apply(overlayFor(failingSource{}, staticSource{"vm": diskRec(time.Hour)}), noneVM()).Assets[0].Metadata
	require.Equal(t, asset.PackageInventoryDisk, m[asset.MetaPackageInventory], "the other source still applies")
	m = apply(overlayFor(failingSource{}), noneVM()).Assets[0].Metadata
	require.Equal(t, asset.PackageInventoryNone, m[asset.MetaPackageInventory])
	require.NotContains(t, m, asset.MetaDiskScan)
}

func TestOverlay_OnlyVMsAndNoSourcesIsANoOp(t *testing.T) {
	require.Nil(t, newInventoryOverlay(nil, nil))
	var o *inventoryOverlay
	res := collect.Result{Assets: []asset.Asset{{ID: "b", Type: "s3_bucket"}}}
	o.apply(context.Background(), connector.Connector{}, &res)
	overlayFor(staticSource{"b": diskRec(0)}).apply(context.Background(), connector.Connector{}, &res)
	require.Nil(t, res.Assets[0].Metadata)
}

// ---- the disk source ----

type fakeDiskReader struct {
	enabled []diskscan.ConnectorSettings
	latest  map[string]diskscan.VolumeResult
	sets    []diskscan.PackageSet
	reads   int
}

func (f *fakeDiskReader) EnabledConnectors(context.Context) ([]diskscan.ConnectorSettings, error) {
	return f.enabled, nil
}

func (f *fakeDiskReader) Latest(context.Context, []string) (map[string]diskscan.VolumeResult, error) {
	f.reads++
	return f.latest, nil
}

func (f *fakeDiskReader) Packages(context.Context, []string) ([]diskscan.PackageSet, error) {
	return f.sets, nil
}

func diskSource(r *fakeDiskReader) *diskInventorySource {
	s := newDiskInventorySource(r, 7*24*time.Hour)
	s.now = func() time.Time { return overlayNow }
	return s
}

func goodResult(age time.Duration) (map[string]diskscan.VolumeResult, []diskscan.PackageSet) {
	return map[string]diskscan.VolumeResult{"vm": {AssetID: "vm", VolumeRef: "v", SnapshotID: "s", InventoryKnown: true, CVEMatchableKnown: true, ObservedAt: overlayNow.Add(-age)}},
		[]diskscan.PackageSet{{AssetID: "vm", VolumeRef: "v", SnapshotID: "s", Ecosystem: "Debian:12", Packages: debPkgs()}}
}

func TestDiskSource_HidesResultsOfAConnectorThatIsNoLongerEnabled(t *testing.T) {
	latest, sets := goodResult(time.Hour)
	r := &fakeDiskReader{latest: latest, sets: sets, enabled: []diskscan.ConnectorSettings{{ConnectorID: "other"}}}
	got, err := diskSource(r).Latest(context.Background(), "c1", []string{"vm"})
	require.NoError(t, err)
	require.False(t, got["vm"].Known)
	require.Equal(t, diskscan.GapNotEnabled, got["vm"].Gap)
	require.Zero(t, r.reads, "a disabled connector's stored results are not even read")
}

func TestDiskSource_ResultsOlderThanAWeekAreStale(t *testing.T) {
	latest, sets := goodResult(8 * 24 * time.Hour)
	r := &fakeDiskReader{latest: latest, sets: sets, enabled: []diskscan.ConnectorSettings{{ConnectorID: "c1"}}}
	got, _ := diskSource(r).Latest(context.Background(), "c1", []string{"vm"})
	require.False(t, got["vm"].Known)
	require.Equal(t, diskscan.GapStale, got["vm"].Gap)
	require.Empty(t, got["vm"].Packages)
}

func TestDiskSource_AKnownResultNeedsItsOwnPackages(t *testing.T) {
	latest, sets := goodResult(time.Hour)
	sets[0].SnapshotID = "another-snapshot"
	r := &fakeDiskReader{latest: latest, sets: sets, enabled: []diskscan.ConnectorSettings{{ConnectorID: "c1"}}}
	got, _ := diskSource(r).Latest(context.Background(), "c1", []string{"vm"})
	require.False(t, got["vm"].Known, "never an empty inventory")
	require.Equal(t, diskscan.GapReadError, got["vm"].Gap)
}

func TestDiskSource_FreshKnownResultAndUnscannedVM(t *testing.T) {
	latest, sets := goodResult(time.Hour)
	r := &fakeDiskReader{latest: latest, sets: sets, enabled: []diskscan.ConnectorSettings{{ConnectorID: "c1"}}}
	got, _ := diskSource(r).Latest(context.Background(), "c1", []string{"vm", "unscanned"})
	require.True(t, got["vm"].Known)
	require.True(t, got["vm"].CVEKnown)
	require.Equal(t, "Debian:12", got["vm"].Ecosystem)
	require.False(t, got["unscanned"].Known)
	require.Empty(t, got["unscanned"].Gap)
}
