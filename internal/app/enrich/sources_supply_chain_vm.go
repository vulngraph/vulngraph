package enrich

import (
	"context"
	"fmt"
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// maxSupplyChainVMs caps the VM lineage fan-out like maxSupplyChainImages caps
// the image one: a base-OS package (openssl, glibc) is installed on every host in
// the estate, and one exposed host is all "runs on an exposed VM" needs. Beyond
// the cap the walk is a sample, never exhaustive.
const maxSupplyChainVMs = 200

// splitVMSources partitions a package's runs_package edges by what runs it. A
// source with no src_type stays on the image side, which is what every
// runs_package edge was before VMs had an inventory.
func splitVMSources(edges []asset.Edge) (vm, other []asset.Edge) {
	for _, e := range edges {
		if graphschema.IsVMType(e.SrcType) {
			vm = append(vm, e)
		} else {
			other = append(other, e)
		}
	}
	return vm, other
}

// vmDeployExposure is the VM lineage: package ← runs_package ← ec2_instance /
// gce_instance → exposed_to_internet. A VM is itself the running workload, so
// there is no runs_image hop: an inventoried VM is deployed by definition, and
// exposed when it carries its own exposed_to_internet edge.
//
// The runs_package edges exist only for VMs whose inventory was KNOWN when they
// were stamped (the collectors emit none for package_inventory=none), so a VM
// whose agent has since gone dark falls out of this lineage when its edges leave
// the freshness window — an absent lineage, which callers already read as "no
// signal", never as a containment claim.
//
// The exposure read is typed: each VM also carries one runs_package edge per
// installed package, which an untyped outbound read would drag along.
func (s SupplyChainExposure) vmDeployExposure(ctx context.Context, vmEdges []asset.Edge) (deployExposure, error) {
	vmIDs := uniqueSrcIDs(vmEdges)
	if len(vmIDs) == 0 {
		return deployExposure{}, nil
	}
	truncated := len(vmIDs) > maxSupplyChainVMs
	if truncated {
		vmIDs = vmIDs[:maxSupplyChainVMs]
	}
	exposed, unknown, err := s.workloadExposure(ctx, vmIDs)
	if err != nil {
		return deployExposure{lineage: true, deployed: true}, err
	}
	return deployExposure{lineage: true, deployed: true, exposed: exposed, truncated: truncated || unknown}, nil
}

// One finding per vulnerable VM package. The VM fleet job (jobs/vmvuln.go)
// derives one vm_vuln finding per (advisory × package × fleet) from the open
// package finding, placed on a real member host so the general classifier weighs
// that host's own reachability, KEV and blast radius. When the package runs ONLY
// on inventoried VMs, those fleet findings are the canonical record: the package
// finding stays open (it is what they derive from, and the estate-wide audit
// trail of the advisory) but stops scoring and classifying the same hosts a
// second time. When an image or a dependent repo also runs it, the package
// finding keeps its full evaluation for that side.
const (
	vmVulnSource = "vm_vuln"
	// fleetListPageLimit pages the fleet-finding read at List's max.
	fleetListPageLimit = 200
	// maxFleetListPages bounds that read. Stopping early only under-counts
	// coverage, which keeps the package finding's own evaluation.
	maxFleetListPages = 10
)

// FleetFindingLister lists findings by source and check. finding.Service
// satisfies it.
type FleetFindingLister interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// FleetCanonical reports whether the package finding f is carried entirely by
// its per-fleet vm_vuln findings: nothing but inventoried VMs runs the package
// (no image, no dependent repo) and the open fleet findings derived from f
// cover at least as many instances as run it. instances is that coverage.
//
// Every doubt answers false, so the package finding keeps its own evaluation:
// no lister wired, any image or repo lineage, no VM runner, or fewer covered
// instances than runners (a VM the fleet job did not group — outside its live
// window, or its listing was truncated).
func (s SupplyChainExposure) FleetCanonical(ctx context.Context, f finding.Finding) (canonical bool, instances int, err error) {
	if s.Fleets == nil || !isSupplyChainPackage(f) {
		return false, 0, nil
	}
	r, err := s.runnersOf(ctx, f.ResourceID)
	if err != nil {
		return false, 0, fmt.Errorf("FleetCanonical: %w", err)
	}
	return s.fleetCovers(ctx, f, r)
}

// packageRunners is everything that runs or depends on a package: dependent
// repos (depends_on) and runs_package sources split into VMs and images.
type packageRunners struct {
	repos, vms, images []string
}

func (s SupplyChainExposure) runnersOf(ctx context.Context, packageID string) (packageRunners, error) {
	deps, err := s.Graph.EdgesInto(ctx, packageID, "depends_on")
	if err != nil {
		return packageRunners{}, fmt.Errorf("depends_on: %w", err)
	}
	runs, err := s.Graph.EdgesInto(ctx, packageID, "runs_package")
	if err != nil {
		return packageRunners{}, fmt.Errorf("runs_package: %w", err)
	}
	vmEdges, imgEdges := splitVMSources(runs)
	return packageRunners{repos: uniqueSrcIDs(deps), vms: uniqueSrcIDs(vmEdges), images: uniqueSrcIDs(imgEdges)}, nil
}

// fleetCovers is FleetCanonical over already-read runners: only VMs run the
// package, and its open fleet findings cover at least as many instances.
func (s SupplyChainExposure) fleetCovers(ctx context.Context, f finding.Finding, r packageRunners) (bool, int, error) {
	ok, cov, err := s.fleetCoverage(ctx, f, r)
	return ok, cov.instances, err
}

// fleetCoverage is what the open fleet findings derived from f cover: how many
// instances, and the lowest band any of them currently holds.
func (s SupplyChainExposure) fleetCoverage(ctx context.Context, f finding.Finding, r packageRunners) (bool, fleetCover, error) {
	if len(r.repos) > 0 || len(r.images) > 0 || len(r.vms) == 0 {
		return false, fleetCover{}, nil
	}
	cov, err := s.fleetInstances(ctx, f)
	if err != nil {
		return false, fleetCover{}, err
	}
	return cov.instances >= len(r.vms), cov, nil
}

type fleetCover struct {
	instances int
	minBand   Band
}

// fleetInstances sums affected_instances over the open fleet findings derived
// from f (their package_finding_id). A VM belongs to one fleet, so the sum is a
// distinct-host count.
func (s SupplyChainExposure) fleetInstances(ctx context.Context, f finding.Finding) (fleetCover, error) {
	var cov fleetCover
	seen := false
	cursor := ""
	for range maxFleetListPages {
		page, err := s.Fleets.List(ctx, finding.Filter{Source: vmVulnSource, CheckID: f.CheckID, Limit: fleetListPageLimit, Cursor: cursor})
		if err != nil {
			return fleetCover{}, fmt.Errorf("fleetInstances: %w", err)
		}
		for _, ff := range page {
			if ff.Metadata["package_finding_id"] != f.ID {
				continue
			}
			if n, err := strconv.Atoi(ff.Metadata["affected_instances"]); err == nil && n > 0 {
				cov.instances += n
			}
			if b := Band(ff.ScoreBand); !seen || bandRank(b) < bandRank(cov.minBand) {
				cov.minBand, seen = b, true
			}
		}
		if len(page) < fleetListPageLimit {
			break
		}
		cursor = finding.EncodeCursor(page[len(page)-1], false)
	}
	return cov, nil
}

func fleetCanonicalDetail(instances int) string {
	return fmt.Sprintf("runs only on inventoried VMs — urgency is carried by its per-fleet vm_vuln findings (%d instances), which weigh each host's own reachability", instances)
}
