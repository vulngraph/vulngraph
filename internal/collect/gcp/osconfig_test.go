package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	osconfig "google.golang.org/api/osconfig/v1"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

type fakeOSConfig struct {
	byZone map[string][]gceInventory
	errs   map[string]error
	calls  int
}

func (f *fakeOSConfig) ListInventories(_ context.Context, _, zone string) ([]gceInventory, error) {
	f.calls++
	if err := f.errs[zone]; err != nil {
		return nil, err
	}
	return f.byZone[zone], nil
}

// The stamp must land on the assets Collect actually returns, every instance
// must say whether its inventory is known, and one zone's failure must not fail
// the sweep. (Partial is not asserted: without credentials the other families
// already flag it; the inventory path never writes it at all.)
func TestCollect_OSConfigInventoryStampsEveryInstance(t *testing.T) {
	now := time.Now()
	fake := &fakeCompute{instances: []gceInstance{
		{Name: "web", NumericID: 101, Zone: "europe-west4-a", Network: "default"},
		{Name: "rhel", NumericID: 102, Zone: "europe-west4-a", Network: "default"},
		{Name: "bare", NumericID: 103, Zone: "europe-west4-a", Network: "default"},
		{Name: "db", NumericID: 201, Zone: "europe-west4-b", Network: "default"},
	}}
	osc := &fakeOSConfig{
		byZone: map[string][]gceInventory{"europe-west4-a": {
			{InstanceID: "101", ShortName: "debian", Version: "12", UpdateTime: now.Add(-time.Hour),
				Packages: []gcePackage{{Name: "openssl", Version: "3.0.11-1~deb12u2"}}},
			{InstanceID: "102", ShortName: "rhel", Version: "9.2", UpdateTime: now.Add(-time.Hour),
				Packages: []gcePackage{{Name: "openssl-libs", Version: "1:3.0.7-24.el9"}}},
		}},
		errs: map[string]error{"europe-west4-b": &googleapi.Error{Code: http.StatusForbidden, Message: "osconfig.inventories.list denied"}},
	}
	c := withFake(fake)
	c.newOSConfig = func(context.Context) (osConfigAPI, error) { return osc, nil }
	c.advisory = distro.Sources{distro.SourceOSV: true}

	res, err := c.Collect(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, 2, osc.calls, "one call per zone, not per instance")

	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	web := byID["proj-1/europe-west4-a/web"].Metadata
	require.Equal(t, asset.PackageInventoryOSConfig, web[asset.MetaPackageInventory])
	require.Equal(t, "Debian:12", web[asset.MetaPackageEcosystem])
	require.False(t, asset.PackageCVEClaimable(web), "OS Config lists binary names; OSV keys Debian by source package")
	require.Equal(t, asset.CVEGapNoSourceNames, web[asset.MetaPackageCVEGap])

	rhel := byID["proj-1/europe-west4-a/rhel"].Metadata
	require.True(t, asset.PackageInventoryKnown(rhel))
	require.True(t, asset.PackageCVEClaimable(rhel), "OSV keys Red Hat by binary name, which OS Config reports")

	bare := byID["proj-1/europe-west4-a/bare"].Metadata
	require.Equal(t, asset.PackageInventoryNone, bare[asset.MetaPackageInventory])
	require.Equal(t, gapNotOSConfigManaged, bare[asset.MetaPackageInventoryGap])

	db := byID["proj-1/europe-west4-b/db"].Metadata
	require.Equal(t, asset.PackageInventoryNone, db[asset.MetaPackageInventory])
	require.Equal(t, gapOSConfigDenied, db[asset.MetaPackageInventoryGap])

	pkg, ok := byID["pkg:deb/debian/openssl@3.0.11-1~deb12u2"]
	require.True(t, ok, "the package node uses the disk/image scanners' purl")
	require.Equal(t, "Debian:12", pkg.Metadata["ecosystem"])
	rpm, ok := byID["pkg:rpm/redhat/openssl-libs@1:3.0.7-24.el9"]
	require.True(t, ok)
	require.Equal(t, "Red Hat:9", rpm.Metadata["ecosystem"], "the OSV client translates it to Red Hat's CPE streams")

	var runs []asset.Edge
	for _, e := range res.Edges {
		if e.EdgeType == "runs_package" {
			runs = append(runs, e)
		}
	}
	require.Len(t, runs, 2)

	// INTEL_OSV_DISABLED / OFFLINE_MODE: nothing matches the RHEL host's
	// packages any more, so it is no longer claimable as clean.
	c.advisory = distro.Sources{distro.SourceOSV: false}
	osc.calls = 0
	res, err = c.Collect(context.Background(), nil)
	require.NoError(t, err)
	var stamped bool
	for _, a := range res.Assets {
		if a.ID == "proj-1/europe-west4-a/rhel" {
			stamped = true
			require.True(t, asset.PackageInventoryKnown(a.Metadata))
			require.False(t, asset.PackageCVEClaimable(a.Metadata))
			require.Equal(t, asset.CVEGapAdvisorySourceDisabled, a.Metadata[asset.MetaPackageCVEGap])
		}
	}
	require.True(t, stamped)
}

func TestGCEInventoryVerdict(t *testing.T) {
	now := time.Now()
	fresh := gceInventory{InstanceID: "1", ShortName: "ubuntu", Version: "22.04", UpdateTime: now,
		Packages: []gcePackage{{Name: "bash", Version: "5.1-6ubuntu1"}}}
	stale := fresh
	stale.UpdateTime = now.Add(-30 * 24 * time.Hour)
	cos := fresh
	cos.ShortName = "cos"
	empty := fresh
	empty.Packages = nil
	huge := fresh
	huge.Packages, huge.OverCap = nil, true

	for _, tt := range []struct {
		name string
		z    *zoneInventory
		gap  string
	}{
		{"fresh", &zoneInventory{byInstance: map[string]gceInventory{"1": fresh}}, ""},
		{"stale", &zoneInventory{byInstance: map[string]gceInventory{"1": stale}}, gapStaleInventory},
		{"container-optimized os", &zoneInventory{byInstance: map[string]gceInventory{"1": cos}}, gapUnsupportedPlatform},
		{"no packages reported", &zoneInventory{byInstance: map[string]gceInventory{"1": empty}}, gapNotOSConfigManaged},
		{"over the package cap", &zoneInventory{byInstance: map[string]gceInventory{"1": huge}}, gapOverPackageCap},
		{"absent", &zoneInventory{byInstance: map[string]gceInventory{}}, gapNotOSConfigManaged},
		{"zone failed", &zoneInventory{gap: gapOSConfigDisabled}, gapOSConfigDisabled},
		{"zone never read", nil, gapOSConfigUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, _, _, gap := gceInventoryVerdict(tt.z, "1", now)
			require.Equal(t, tt.gap, gap)
			if gap == "" {
				require.Len(t, pkgs, 1)
			} else {
				require.Empty(t, pkgs)
			}
		})
	}
}

func TestToNeutralInventory_InstalledOnly(t *testing.T) {
	inv := &osconfig.Inventory{
		Name:       "projects/123/locations/europe-west4-a/instances/5001/inventory",
		OsInfo:     &osconfig.InventoryOsInfo{ShortName: "debian", Version: "12"},
		UpdateTime: "2026-10-07T10:00:00Z",
		Items: map[string]osconfig.InventoryItem{
			"a": {InstalledPackage: &osconfig.InventorySoftwarePackage{AptPackage: &osconfig.InventoryVersionedPackage{PackageName: "openssl", Version: "3.0.11-1~deb12u2"}}},
			"b": {AvailablePackage: &osconfig.InventorySoftwarePackage{AptPackage: &osconfig.InventoryVersionedPackage{PackageName: "openssl", Version: "3.0.13-1~deb12u1"}}},
		},
	}
	g := toNeutralInventory(inv)
	require.Equal(t, "5001", g.InstanceID)
	require.Equal(t, "debian", g.ShortName)
	require.False(t, g.UpdateTime.IsZero())
	require.Equal(t, []gcePackage{{Name: "openssl", Version: "3.0.11-1~deb12u2"}}, g.Packages,
		"an available update is not installed software")
	require.Equal(t, 1, g.PendingUpdates, "but it is a pending update")
}

// os_updates_pending comes from a fresh inventory on any platform, and is
// absent without one.
func TestStampPendingUpdates(t *testing.T) {
	now := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	z := &zoneInventory{byInstance: map[string]gceInventory{
		"1": {UpdateTime: now.Add(-time.Hour), PendingUpdates: 3, ShortName: "windows"},
		"2": {UpdateTime: now.Add(-30 * 24 * time.Hour), PendingUpdates: 3},
	}}
	md := map[string]string{}
	stampPendingUpdates(md, z, "1", now)
	require.Equal(t, "3", md["os_updates_pending"])
	for _, tc := range []struct {
		z  *zoneInventory
		id string
	}{{z, "2"}, {z, "9"}, {&zoneInventory{gap: gapOSConfigDenied}, "1"}, {nil, "1"}} {
		md := map[string]string{}
		stampPendingUpdates(md, tc.z, tc.id, now)
		require.NotContains(t, md, "os_updates_pending")
	}
}

func TestOSConfigGap(t *testing.T) {
	require.Equal(t, gapOSConfigDenied, osconfigGap(context.Background(), &googleapi.Error{Code: http.StatusForbidden}))
	require.Equal(t, gapOSConfigUnavailable, osconfigGap(context.Background(), errors.New("connection reset")))
	require.Equal(t, gapOSConfigDisabled, osconfigGap(context.Background(), &googleapi.Error{
		Code: http.StatusForbidden, Message: "OS Config API has not been used in project 123 before or it is disabled",
	}))
}

func TestToNeutral_InstanceGroupFromCreatedBy(t *testing.T) {
	v := "projects/123/zones/europe-west4-a/instanceGroupManagers/web-mig"
	g := toNeutral(&compute.Instance{Name: "web-abcd", Metadata: &compute.Metadata{Items: []*compute.MetadataItems{{Key: "created-by", Value: &v}}}})
	require.Equal(t, "web-mig", g.InstanceGroup)
	require.Equal(t, "web-mig", gceMetadata(g, nil, false)["instance_group"])
}

// An over-cap host's list is dropped at conversion, not carried through the
// zone's whole listing only to be discarded by the verdict.
func TestToNeutralInventory_OverCapDropsList(t *testing.T) {
	items := map[string]osconfig.InventoryItem{}
	for i := range osconfigMaxPackages + 1 {
		items[fmt.Sprintf("p%d", i)] = osconfig.InventoryItem{InstalledPackage: &osconfig.InventorySoftwarePackage{
			AptPackage: &osconfig.InventoryVersionedPackage{PackageName: fmt.Sprintf("p%d", i), Version: "1"},
		}}
	}
	g := toNeutralInventory(&osconfig.Inventory{Name: "projects/1/locations/z/instances/9/inventory", Items: items})
	require.True(t, g.OverCap)
	require.Nil(t, g.Packages)
}
