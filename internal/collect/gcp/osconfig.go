package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/googleapi"
	osconfig "google.golang.org/api/osconfig/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// GCE software inventory from VM Manager / OS Config: the installed packages the
// OS Config agent reports, read with osconfig.inventories.list (read-only). One
// call per ZONE returns every instance's inventory there (instances/-), so unlike
// AWS SSM there is no per-instance cost to bound and no cache.
//
// Like the AWS reader it never flags the sweep Partial: it enumerates nothing
// deletion reconciliation acts on, and VM Manager is off in most projects. Every
// instance is stamped with package_inventory known-ness instead.

const (
	osconfigSource = "osconfig"
	// osconfigZoneTimeout bounds one zone's listing (all of its pages).
	osconfigZoneTimeout = 2 * time.Minute
	// osconfigMaxPackages mirrors the AWS cap: a list longer than this is
	// recorded as none, never truncated into a partial verdict.
	osconfigMaxPackages = 10000
	// osconfigCaptureMaxAge: an agent that stopped reporting leaves its last
	// inventory in place. A week-old one is not today's package list.
	osconfigCaptureMaxAge = 7 * 24 * time.Hour
	// osconfigPageSize bounds one FULL-view page. A FULL inventory carries every
	// installed AND available package, so the API default page (unbounded by
	// us) could hold hundreds of hosts' full lists in one response.
	osconfigPageSize = 25
)

const (
	gapNotOSConfigManaged  = "not_osconfig_managed"
	gapOSConfigDisabled    = "osconfig_api_disabled"
	gapOSConfigDenied      = "osconfig_access_denied"
	gapOSConfigUnavailable = "osconfig_unavailable"
	gapUnsupportedPlatform = "unsupported_platform"
	gapStaleInventory      = "stale_inventory"
	gapOverPackageCap      = "over_package_cap"
)

// gceInventory is a provider-neutral view of one instance's OS Config inventory.
type gceInventory struct {
	InstanceID string // numeric — the {instance_id} segment of the resource name
	ShortName  string // os-release style ID: debian, ubuntu, rhel, rocky, sles, windows, cos
	Version    string
	UpdateTime time.Time
	Packages   []gcePackage // INSTALLED packages only
	// PendingUpdates counts the AVAILABLE_PACKAGE items: updates the OS
	// package manager (apt, yum, zypper, Windows Update, googet) offers but
	// has not installed (CIS GCP 4.12).
	PendingUpdates int
	// OverCap is set, and Packages dropped, when the host reports more than
	// osconfigMaxPackages: the verdict is none either way, so the list is not
	// held for the rest of the zone's listing.
	OverCap bool
}

type gcePackage struct{ Name, Version string }

// osConfigAPI is the slice of OS Config the collector needs.
type osConfigAPI interface {
	ListInventories(ctx context.Context, projectID, zone string) ([]gceInventory, error)
}

func defaultOSConfig(ctx context.Context) (osConfigAPI, error) {
	svc, err := osconfig.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("defaultOSConfig: %w", err)
	}
	return &realOSConfig{svc: svc}, nil
}

type realOSConfig struct{ svc *osconfig.Service }

func (r *realOSConfig) ListInventories(ctx context.Context, projectID, zone string) ([]gceInventory, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s/instances/-", projectID, zone)
	var out []gceInventory
	// Each page is reduced to the neutral view (installed packages only) as it
	// arrives, so only one raw page is ever held.
	err := r.svc.Projects.Locations.Instances.Inventories.List(parent).View("FULL").PageSize(osconfigPageSize).
		Pages(ctx, func(page *osconfig.ListInventoriesResponse) error {
			for _, inv := range page.Inventories {
				if inv != nil {
					out = append(out, toNeutralInventory(inv))
				}
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("ListInventories %s: %w", zone, err)
	}
	return out, nil
}

// toNeutralInventory keeps installed apt/yum/zypper packages. Available
// (pending-update) packages are not installed software; COS, googet and Windows
// entries carry no OSV package identity.
func toNeutralInventory(inv *osconfig.Inventory) gceInventory {
	g := gceInventory{InstanceID: path.Base(path.Dir(inv.Name))}
	if inv.OsInfo != nil {
		g.ShortName, g.Version = inv.OsInfo.ShortName, inv.OsInfo.Version
	}
	if t, err := time.Parse(time.RFC3339, inv.UpdateTime); err == nil {
		g.UpdateTime = t
	}
	for _, item := range inv.Items {
		if item.AvailablePackage != nil {
			g.PendingUpdates++
		}
		sp := item.InstalledPackage
		if sp == nil {
			continue
		}
		for _, vp := range []*osconfig.InventoryVersionedPackage{sp.AptPackage, sp.YumPackage, sp.ZypperPackage} {
			if vp != nil {
				g.Packages = append(g.Packages, gcePackage{Name: vp.PackageName, Version: vp.Version})
			}
		}
	}
	if len(g.Packages) > osconfigMaxPackages {
		g.Packages, g.OverCap = nil, true
		return g
	}
	sort.Slice(g.Packages, func(i, j int) bool { return g.Packages[i].Name < g.Packages[j].Name })
	return g
}

// inventoryInstances stamps the sweep's instances with OS Config inventory. A
// nil newOSConfig (a test Collector built without New) stamps nothing: the key
// stays absent, which reads as unknown.
func (c *Collector) inventoryInstances(ctx context.Context, projectID string, instances []asset.Asset, now time.Time) ([]asset.Asset, []asset.Edge) {
	if c.newOSConfig == nil || len(instances) == 0 {
		return nil, nil
	}
	client, err := c.newOSConfig(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("gcp os config client unavailable — instances stamped package_inventory=none")
		for _, inst := range instances {
			stampOSConfigInventory(inst.Metadata, gapOSConfigUnavailable, "", "", "")
		}
		return nil, nil
	}
	return collectOSConfigInventory(ctx, client, projectID, instances, c.advisory, now)
}

// zoneInventory is one zone's listing outcome.
type zoneInventory struct {
	byInstance map[string]gceInventory
	gap        string // set when the zone's listing failed
}

// collectOSConfigInventory reads the inventory of every zone holding an
// instance, stamps each instance asset with its known-ness, and returns the
// package assets + runs_package edges. instances are the sweep's gce_instance
// assets; their Metadata maps are mutated in place.
func collectOSConfigInventory(ctx context.Context, client osConfigAPI, projectID string, instances []asset.Asset, advisory distro.Sources, now time.Time) ([]asset.Asset, []asset.Edge) {
	zones := map[string]*zoneInventory{}
	for _, inst := range instances {
		if _, ok := zones[inst.Region]; !ok && inst.Region != "" {
			zones[inst.Region] = nil
		}
	}
	logger := log.FromContext(ctx)
	for zone := range zones {
		zctx, cancel := context.WithTimeout(ctx, osconfigZoneTimeout)
		list, err := client.ListInventories(zctx, projectID, zone)
		cancel()
		if err != nil {
			gap := osconfigGap(ctx, err)
			logger.Warn().Err(err).Str("zone", zone).Str("gap", gap).
				Msg("gcp os config inventory unavailable — zone's instances stamped package_inventory=none (no software inventory, not a clean one)")
			zones[zone] = &zoneInventory{gap: gap}
			continue
		}
		z := &zoneInventory{byInstance: make(map[string]gceInventory, len(list))}
		for _, inv := range list {
			z.byInstance[inv.InstanceID] = inv
		}
		zones[zone] = z
	}

	seen := map[string]bool{}
	var (
		assets []asset.Asset
		edges  []asset.Edge
	)
	for _, inst := range instances {
		stampPendingUpdates(inst.Metadata, zones[inst.Region], inst.Metadata["gcp_instance_id"], now)
		pkgs, eco, observedOn, gap := gceInventoryVerdict(zones[inst.Region], inst.Metadata["gcp_instance_id"], now)
		// OS Config reports binary package names only, never the source package.
		stampOSConfigInventory(inst.Metadata, gap, eco, pkginventory.CVEGap(eco, false, advisory, now), observedOn)
		if gap != "" {
			continue
		}
		pkgAssets, pkgEdges := pkginventory.InventoryGraph(inst.ID, inst.Type, pkgs, now)
		for _, a := range pkgAssets {
			if !seen[a.ID] {
				seen[a.ID] = true
				assets = append(assets, a)
			}
		}
		edges = append(edges, pkgEdges...)
	}
	return assets, edges
}

// stampPendingUpdates records os_updates_pending from a fresh inventory, on
// every platform the agent reports (Windows and COS included, which the
// package CVE match cannot grade). No inventory, or a stale one, leaves the
// key absent.
func stampPendingUpdates(meta map[string]string, z *zoneInventory, numericID string, now time.Time) {
	if z == nil || z.gap != "" || numericID == "" || meta == nil {
		return
	}
	inv, ok := z.byInstance[numericID]
	if !ok || inv.UpdateTime.IsZero() || now.Sub(inv.UpdateTime) > osconfigCaptureMaxAge {
		return
	}
	meta["os_updates_pending"] = strconv.Itoa(inv.PendingUpdates)
}

func gceInventoryVerdict(z *zoneInventory, numericID string, now time.Time) (pkgs []pkginventory.InstalledPackage, eco, observedOn, gap string) {
	switch {
	case z == nil:
		return nil, "", "", gapOSConfigUnavailable
	case z.gap != "":
		return nil, "", "", z.gap
	}
	inv, ok := z.byInstance[numericID]
	if !ok || numericID == "" {
		return nil, "", "", gapNotOSConfigManaged
	}
	eco = pkginventory.InventoryEcosystem(inv.ShortName, inv.Version)
	switch {
	case eco == "":
		return nil, "", "", gapUnsupportedPlatform
	case inv.OverCap:
		return nil, "", "", gapOverPackageCap
	case inv.UpdateTime.IsZero() || len(inv.Packages) == 0:
		return nil, "", "", gapNotOSConfigManaged
	case now.Sub(inv.UpdateTime) > osconfigCaptureMaxAge:
		return nil, "", "", gapStaleInventory
	case len(inv.Packages) > osconfigMaxPackages:
		return nil, "", "", gapOverPackageCap
	}
	for _, p := range inv.Packages {
		if ip, ok := pkginventory.InventoryPackage(eco, p.Name, p.Version, "", "", osconfigSource); ok {
			pkgs = append(pkgs, ip)
		}
	}
	return pkgs, eco, inv.UpdateTime.UTC().Format(time.DateOnly), ""
}

func stampOSConfigInventory(meta map[string]string, gap, eco, cveGap, observedOn string) {
	if meta == nil {
		return
	}
	if gap != "" {
		meta[asset.MetaPackageInventory] = asset.PackageInventoryNone
		meta[asset.MetaPackageInventoryGap] = gap
		return
	}
	meta[asset.MetaPackageInventory] = asset.PackageInventoryOSConfig
	meta[asset.MetaPackageInventoryObservedOn] = observedOn
	meta[asset.MetaPackageEcosystem] = eco
	meta[asset.MetaPackageCVEMatchable] = boolStr(cveGap == "")
	if cveGap != "" {
		meta[asset.MetaPackageCVEGap] = cveGap
	}
}

// osconfigGap names why a zone's listing failed.
func osconfigGap(ctx context.Context, err error) string {
	if serviceDisabledErr(ctx, err) {
		return gapOSConfigDisabled
	}
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && (apiErr.Code == http.StatusForbidden || apiErr.Code == http.StatusUnauthorized) {
		return gapOSConfigDenied
	}
	if strings.Contains(strings.ToLower(err.Error()), "permission") {
		return gapOSConfigDenied
	}
	return gapOSConfigUnavailable
}
