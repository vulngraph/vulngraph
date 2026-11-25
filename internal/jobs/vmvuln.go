package jobs

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// VM CVE fleet findings: one finding per (advisory × package version × fleet),
// where a fleet is the unit a VM is remediated at — its autoscaling group /
// managed instance group, else its AMI, else the instance itself. A vulnerable
// openssl baked into one AMI behind a 300-instance ASG is ONE finding with
// affected_instances=300, not 300 findings, and its remediation names the image
// to rebuild.
//
// It is DERIVED from the supply_chain finding the OSV refresh already records per
// (advisory × purl) — the same advisory match, severity and KEV catalog — joined
// to the runs_package edges the VM inventory collectors write. The package-level
// finding stays the estate-wide root cause (it also covers images and repos); a
// fleet finding is the same advisory placed on a host, which is what lets the
// general must-fix classifier weigh the host's own reachability, KEV and blast
// radius (a package node has no blast radius of its own, so the package path is
// capped at "elevated").
//
// One finding per remediation unit: when nothing but inventoried VMs runs the
// package and these fleet findings cover every one of them, they are canonical
// and the package finding is classified routine, pointing at them
// (enrich.SupplyChainExposure.FleetCanonical). It is NOT resolved: it is the
// record these findings derive from, and resolving it would end them too. An
// image or repo also running the package keeps the package finding's own
// evaluation for that side. Each pass re-enriches the package findings it
// grouped so that verdict follows the fleet findings promptly.
//
// Only VMs whose inventory is KNOWN (asset.PackageInventoryKnown) contribute, and
// a fleet with any live member whose inventory is NOT known is never resolved by
// absence: "no inventory" must never read as "patched".

const (
	vmVulnSource = "vm_vuln"
	// listVMLimit is asset.ListByType's ceiling. A listing that reaches it may be
	// truncated, and a truncated run must not resolve anything.
	listVMLimit = 20000
	// vmLiveWindow: a VM not re-collected inside the graph-edge freshness window
	// is gone (terminated instances drop out of collection, their rows linger).
	vmLiveWindow = 48 * time.Hour
	// vmEdgeBatch bounds one runs_package read: ~100 hosts × ~1k packages.
	vmEdgeBatch = 100
	// vmPurlBatch bounds one supply-chain finding lookup.
	vmPurlBatch = 200
	// maxAffectedIDs caps the instance ids listed as evidence on one finding;
	// affected_instances always carries the full count.
	maxAffectedIDs = 50
	// vmVulnRecordBatch bounds one RecordObserved write.
	vmVulnRecordBatch = 500
	// vmVulnPageLimit pages the open-fleet-findings read at List's max.
	vmVulnPageLimit = 200
)

// RefreshVMVulnArgs regroups supply-chain CVEs on VM-installed packages into
// fleet findings. Its producer is the OSV refresh, which enqueues it at the end
// of every run (enqueueVMVuln): the fleet findings are a projection of the
// supply-chain findings that refresh just reconciled.
type RefreshVMVulnArgs struct{}

func (RefreshVMVulnArgs) Kind() string { return "refresh_vm_vuln" }

// InsertOpts: the enrich lane, like the OSV refresh it derives from — a bounded
// ClickHouse join that records findings and enqueues their enrichment.
func (RefreshVMVulnArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, 3)
}

// enqueueVMVuln queues the fleet regroup. Best-effort: a missed insert waits for
// the next OSV refresh, and the unique-by-state singleton absorbs duplicates.
func enqueueVMVuln(ctx context.Context) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return // no client (unit test)
	}
	if _, err := client.Insert(ctx, RefreshVMVulnArgs{}, nil); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("osv: could not enqueue vm fleet regroup")
	}
}

// VMInventoryStore is the slice of the asset service the fleet job reads.
type VMInventoryStore interface {
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
}

// vmVulnFindingStore is the slice of the finding service the fleet job needs.
type vmVulnFindingStore interface {
	ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	RecordObserved(ctx context.Context, findings []finding.Finding) error
	Resolve(ctx context.Context, findings []finding.Finding, reason finding.ResolutionReason) error
}

// VMVulnWorker builds and reconciles the fleet findings.
type VMVulnWorker struct {
	river.WorkerDefaults[RefreshVMVulnArgs]
	assets   VMInventoryStore
	findings vmVulnFindingStore
	// deletions is the sync's record of proven deletions — the evidence a
	// fleet that left collection is gone, not merely uncollected. nil
	// leaves only the absence fallback.
	deletions DeletionRecords
}

func (VMVulnWorker) Timeout(_ *river.Job[RefreshVMVulnArgs]) time.Duration {
	return 30 * time.Minute
}

// vmFleet is one remediation unit: the VMs sharing a fleet key.
type vmFleet struct {
	kind, id string
}

func (f vmFleet) key() string { return f.kind + ":" + f.id }

// fleetOf is the root-cause grouping key for one VM. The ASG / MIG is the unit
// that gets a new launch template; the AMI is the image that gets rebuilt; only a
// hand-built host is its own fleet. Account-scoped: two accounts on one public
// AMI are two owners.
func fleetOf(vm asset.Asset) vmFleet {
	if asg := vm.Tags["aws:autoscaling:groupName"]; asg != "" {
		return vmFleet{"asg", vm.AccountID + "/" + vm.Region + "/" + asg}
	}
	if mig := vm.Metadata["instance_group"]; mig != "" {
		return vmFleet{"instance_group", vm.AccountID + "/" + mig}
	}
	if ami := vm.Metadata["image_id"]; ami != "" {
		return vmFleet{"ami", vm.AccountID + "/" + ami}
	}
	return vmFleet{"instance", vm.ID}
}

// fleetGroup accumulates one (advisory × purl × fleet) finding.
type fleetGroup struct {
	pkg     finding.Finding // the package-level supply_chain finding
	purl    string
	fleet   vmFleet
	members map[string]asset.Asset
}

// vmVulnRun is one pass's working state.
type vmVulnRun struct {
	live          []asset.Asset
	known         []asset.Asset
	unknownFleets map[string]bool
	liveFleets    map[string]bool
	// goneFleets are fleets with no live member whose every listed member is
	// gone (assetGone: a sync-recorded deletion, or unseen past the absence
	// fallback). A fleet that merely went quiet — its collector's credential
	// expired, its account stopped syncing — is in neither set, and its
	// findings stay open until the fallback.
	goneFleets map[string]bool
	// listedFleets is every fleet key any listed VM (live or not) maps to. A
	// fleet finding whose key no VM maps to any more — a member's key changed
	// (an ASG tag or image_id appeared), or every member aged out of the
	// listing — has nothing left to judge it, and resolves only by aging out.
	listedFleets map[string]bool
	complete     bool
}

// fleetPackages records, per (fleet, purl identity) a reconcile asked about,
// the purls the fleet's inventoried members run now — so an open fleet
// finding the pass did not reproduce can tell an upgrade from a removal.
type fleetPackages map[string]map[string]bool

func fleetPurlKey(fleet, purl string) string {
	key, _ := purlParts(purl)
	return fleet + "\x00" + key
}

func (s fleetPackages) note(want map[string]bool, fleet, purl string) {
	k := fleetPurlKey(fleet, purl)
	if !want[k] {
		return
	}
	if s[k] == nil {
		s[k] = map[string]bool{}
	}
	s[k][purl] = true
}

func (w *VMVulnWorker) Work(ctx context.Context, _ *river.Job[RefreshVMVulnArgs]) error {
	run, err := w.loadVMs(ctx)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	// The open fleet findings, read once: their current resource keeps a
	// fleet's finding on the same member pass to pass, and the reconcile
	// judges the ones this pass does not reproduce. A failed read records
	// without stickiness and skips the reconcile.
	logger := log.FromContext(ctx)
	open, openErr := w.openFleetFindings(ctx)
	if openErr != nil {
		logger.Warn().Err(openErr).Msg("vm_vuln: open fleet findings unreadable — representatives not pinned, reconcile skipped")
	}
	want := map[string]bool{}
	for _, f := range open {
		want[fleetPurlKey(f.Metadata["fleet_kind"]+":"+f.Metadata["fleet_id"], f.Metadata["purl"])] = true
	}
	groups, exposed, seen, err := w.group(ctx, run.known, want)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	now := time.Now()
	found := make([]finding.Finding, 0, len(groups))
	for _, g := range groups {
		found = append(found, fleetFinding(g, exposed, open[fleetFindingID(g)].ResourceID, now))
	}
	for start := 0; start < len(found); start += vmVulnRecordBatch {
		if err := w.findings.RecordObserved(ctx, found[start:min(start+vmVulnRecordBatch, len(found))]); err != nil {
			return fmt.Errorf("Work: record: %w", err)
		}
	}
	if len(found) > 0 {
		enqueueEnrich(ctx, found)
		enqueueEnrich(ctx, groupedPackageFindings(groups))
		// KEV is an enrichment output keyed on the CVE: kick it so a new fleet
		// finding carries known_exploited before the daily periodic.
		if client, cerr := river.ClientFromContextSafely[pgx.Tx](ctx); cerr == nil {
			if _, err := client.Insert(ctx, RefreshKEVArgs{}, nil); err != nil {
				logger.Warn().Err(err).Msg("vm_vuln: could not enqueue kev refresh")
			}
		}
	}
	resolved := 0
	if openErr == nil {
		if resolved, err = w.reconcile(ctx, run, open, seen, found); err != nil {
			logger.Warn().Err(err).Msg("vm_vuln: reconcile skipped")
		}
	}
	logger.Info().
		Int("live_vms", len(run.live)).Int("inventoried_vms", len(run.known)).
		Int("fleets_unknown", len(run.unknownFleets)).
		Int("findings", len(found)).Int("resolved", resolved).Bool("complete", run.complete).
		Msg("vm_vuln fleet findings refreshed")
	return nil
}

// loadVMs reads every live VM and splits them by inventory known-ness.
func (w *VMVulnWorker) loadVMs(ctx context.Context) (vmVulnRun, error) {
	run := vmVulnRun{unknownFleets: map[string]bool{}, liveFleets: map[string]bool{}, goneFleets: map[string]bool{}, listedFleets: map[string]bool{}, complete: true}
	now := time.Now()
	cutoff := now.Add(-vmLiveWindow)
	var all []asset.Asset
	for _, typ := range graphschema.VMAssetTypes {
		vms, err := w.assets.ListByType(ctx, typ, listVMLimit)
		if err != nil {
			return vmVulnRun{}, fmt.Errorf("loadVMs: %s: %w", typ, err)
		}
		if len(vms) >= listVMLimit {
			run.complete = false
		}
		all = append(all, vms...)
	}
	var stale []string
	for _, vm := range all {
		run.listedFleets[fleetOf(vm).key()] = true
		if vm.LastSeen.Before(cutoff) {
			stale = append(stale, vm.ID)
		}
	}
	deleted, _ := assetDeletions(ctx, w.deletions, stale)
	quiet := map[string]bool{} // fleets with a non-live member not proven gone
	for _, vm := range all {
		if vm.LastSeen.Before(cutoff) {
			fleet := fleetOf(vm).key()
			if assetGone(vm, deleted[vm.ID], now) {
				run.goneFleets[fleet] = true
			} else {
				quiet[fleet] = true
			}
			continue
		}
		run.live = append(run.live, vm)
		fleet := fleetOf(vm).key()
		run.liveFleets[fleet] = true
		if asset.PackageInventoryKnown(vm.Metadata) {
			run.known = append(run.known, vm)
		} else {
			run.unknownFleets[fleet] = true
		}
	}
	for fleet := range run.goneFleets {
		if run.liveFleets[fleet] || quiet[fleet] {
			delete(run.goneFleets, fleet)
		}
	}
	return run, nil
}

// group joins the known VMs' packages to the open supply-chain findings on them.
// It also returns which of those VMs are directly internet-exposed, so a fleet's
// finding can sit on an exposed member.
func (w *VMVulnWorker) group(ctx context.Context, vms []asset.Asset, want map[string]bool) (map[string]*fleetGroup, map[string]bool, fleetPackages, error) {
	groups := map[string]*fleetGroup{}
	seen := fleetPackages{}
	exposed := map[string]bool{}
	vulnByPurl := map[string][]finding.Finding{}
	looked := map[string]bool{}
	byID := make(map[string]asset.Asset, len(vms))
	for _, vm := range vms {
		byID[vm.ID] = vm
	}
	for start := 0; start < len(vms); start += vmEdgeBatch {
		batch := vms[start:min(start+vmEdgeBatch, len(vms))]
		ids := make([]string, len(batch))
		for i, vm := range batch {
			ids[i] = vm.ID
		}
		runs, err := w.assets.EdgesOutBatch(ctx, ids, "runs_package")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("group: runs_package: %w", err)
		}
		exp, err := w.assets.EdgesOutBatch(ctx, ids, "exposed_to_internet")
		if err != nil {
			return nil, nil, nil, fmt.Errorf("group: exposed_to_internet: %w", err)
		}
		for _, e := range exp {
			exposed[e.SrcID] = true
		}
		var fresh []string
		for _, e := range runs {
			if !looked[e.DstID] {
				looked[e.DstID] = true
				fresh = append(fresh, e.DstID)
			}
		}
		if err := w.lookupVulns(ctx, fresh, vulnByPurl); err != nil {
			return nil, nil, nil, fmt.Errorf("group: %w", err)
		}
		for _, e := range runs {
			vm, ok := byID[e.SrcID]
			if !ok {
				continue
			}
			seen.note(want, fleetOf(vm).key(), e.DstID)
			for _, pf := range vulnByPurl[e.DstID] {
				fleet := fleetOf(vm)
				key := pf.CheckID + "\x00" + e.DstID + "\x00" + fleet.key()
				g := groups[key]
				if g == nil {
					g = &fleetGroup{pkg: pf, purl: e.DstID, fleet: fleet, members: map[string]asset.Asset{}}
					groups[key] = g
				}
				g.members[vm.ID] = vm
			}
		}
	}
	return groups, exposed, seen, nil
}

// lookupVulns fills vulnByPurl with the OPEN supply_chain package findings on
// purls. A purl with none stays absent.
func (w *VMVulnWorker) lookupVulns(ctx context.Context, purls []string, vulnByPurl map[string][]finding.Finding) error {
	return openPackageFindings(ctx, w.findings, purls, vmPurlBatch, vulnByPurl)
}

// openPackageFindings fills vulnByPurl with the OPEN supply_chain package
// findings on purls, batch purls per read. A purl with none stays absent.
func openPackageFindings(ctx context.Context, store interface {
	ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}, purls []string, batch int, vulnByPurl map[string][]finding.Finding) error {
	for start := 0; start < len(purls); start += batch {
		rows, err := store.ByResourceIDs(ctx, purls[start:min(start+batch, len(purls))])
		if err != nil {
			return fmt.Errorf("openPackageFindings: %w", err)
		}
		for _, f := range rows {
			// Resolved(), not ResolvedAt.IsZero(): ClickHouse returns an open
			// finding's resolved_at as the epoch, which is not Go's zero time.
			if f.Source == "supply_chain" && f.ResourceType == "package" && !f.Resolved() && f.CheckID != "" {
				vulnByPurl[f.ResourceID] = append(vulnByPurl[f.ResourceID], f)
			}
		}
	}
	return nil
}

// fleetFindingID is the fleet finding's identity: advisory × purl × fleet,
// never the member it sits on.
func fleetFindingID(g *fleetGroup) string {
	return dbutil.DeterministicID("vm-fleet", g.pkg.CheckID, g.purl, g.fleet.key())
}

// representativeOf picks the member a fleet finding sits on. It must be a real
// VM — enrich scores and classifies the finding with that host's own
// reachability, blast radius and liveness; there is no fleet asset to score —
// and an exposed one when the fleet has any, so must-fix sees the exposure.
// Among the eligible, the previous representative (prev) is kept while it
// stays eligible: a member swap on every pass churns the finding's resource
// for nothing. ids is sorted; the lowest eligible id breaks a fresh tie.
func representativeOf(ids []string, exposed map[string]bool, prev string) string {
	eligible := ids
	var exposedIDs []string
	for _, id := range ids {
		if exposed[id] {
			exposedIDs = append(exposedIDs, id)
		}
	}
	if len(exposedIDs) > 0 {
		eligible = exposedIDs
	}
	for _, id := range eligible {
		if id == prev {
			return prev
		}
	}
	return eligible[0]
}

// fleetFinding shapes one group, on representativeOf's member. The exposed
// members are listed (exposed_instance_ids, capped) so a consumer that needs
// the fleet's exposure does not depend on which member carries the finding.
func fleetFinding(g *fleetGroup, exposed map[string]bool, prevRep string, now time.Time) finding.Finding {
	ids := make([]string, 0, len(g.members))
	exposedCount := 0
	for id := range g.members {
		ids = append(ids, id)
		if exposed[id] {
			exposedCount++
		}
	}
	sort.Strings(ids)
	rep := g.members[representativeOf(ids, exposed, prevRep)]
	listed := ids[:min(len(ids), maxAffectedIDs)]
	var exposedIDs []string
	for _, id := range ids {
		if exposed[id] && len(exposedIDs) < maxAffectedIDs {
			exposedIDs = append(exposedIDs, id)
		}
	}

	name := g.pkg.ResourceName
	_, version := purlParts(g.purl)
	hosts := "instance"
	if len(ids) != 1 {
		hosts = "instances"
	}
	meta := map[string]string{
		"package":                  name,
		"version":                  version,
		"purl":                     g.purl,
		"package_finding_id":       g.pkg.ID,
		"fleet_kind":               g.fleet.kind,
		"fleet_id":                 g.fleet.id,
		"affected_instances":       strconv.Itoa(len(ids)),
		"affected_instance_ids":    strings.Join(listed, ","),
		"exposed_instances":        strconv.Itoa(exposedCount),
		"exposed_instance_ids":     strings.Join(exposedIDs, ","),
		"package_ecosystem":        rep.Metadata[asset.MetaPackageEcosystem],
		asset.MetaPackageInventory: rep.Metadata[asset.MetaPackageInventory],
	}
	if cve := g.pkg.Metadata["cve"]; cve != "" {
		meta["cve"] = cve // a MAL-* advisory's CVE alias, for KEV/EPSS matching
	}
	return finding.Finding{
		ID:           fleetFindingID(g),
		Source:       vmVulnSource,
		Type:         "vulnerable_package",
		Severity:     g.pkg.Severity,
		Title:        fmt.Sprintf("%s in %s %s on %d %s (%s %s)", g.pkg.CheckID, name, version, len(ids), hosts, g.fleet.kind, g.fleet.id),
		Description:  fmt.Sprintf("%s\n\nInstalled on %d %s of %s %s (%d directly internet-exposed), per their OS package inventory.", g.pkg.Title, len(ids), hosts, g.fleet.kind, g.fleet.id, exposedCount),
		ResourceType: rep.Type,
		ResourceID:   rep.ID,
		ResourceName: rep.Name,
		Region:       rep.Region,
		CheckID:      g.pkg.CheckID,
		Remediation:  fleetRemediation(g.fleet, g.pkg.Remediation),
		DetectedAt:   now,
		Metadata:     meta,
	}
}

// groupedPackageFindings returns each package finding the groups derive from,
// once, in id order. Re-enriching them lets the package finding defer to (or
// stop deferring to) its fleet findings without waiting for the drift sweep.
func groupedPackageFindings(groups map[string]*fleetGroup) []finding.Finding {
	byID := map[string]finding.Finding{}
	for _, g := range groups {
		byID[g.pkg.ID] = g.pkg
	}
	out := make([]finding.Finding, 0, len(byID))
	for _, f := range byID {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func fleetRemediation(fleet vmFleet, pkgRemediation string) string {
	switch fleet.kind {
	case "asg", "instance_group":
		return pkgRemediation + " Bake the fix into the group's launch template / instance template image and roll the group; patching running members alone is undone by the next scale-out."
	case "ami":
		return pkgRemediation + " Rebuild the AMI with the fix and relaunch its instances (or patch them in place until they are replaced)."
	}
	return pkgRemediation
}
