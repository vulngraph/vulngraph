package enrich

import (
	"context"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// maxSupplyChainRepos caps how many dependent repos a single package's
// traversal considers. A heavily-depended-on package (golang.org/x/net has
// hundreds of live dependents) would otherwise turn one finding's enrich into
// an unbounded fan-out of edge/Ladybug lookups. Beyond the cap the traversal is a
// best-effort sample, not exhaustive — the same truncate-the-slice pattern
// used for every other bounded graph read in this codebase (graphstore's
// maxQueryItems, asset.Service's maxNodeBudget), not a new mechanism.
const maxSupplyChainRepos = 200

// maxSupplyChainImages caps the container-image lineage fan-out the same way
// maxSupplyChainRepos caps the repo fan-out: a widely-used base-image package
// (glibc, openssl) is referenced by many images, each run by many pods. Beyond
// the cap the traversal is a best-effort sample — enough to establish "runs on
// an exposed pod", never an exhaustive walk.
const maxSupplyChainImages = 200

// maxSupplyChainWorkloads caps reposDeployExposure's second hop
// (workloads → exposed_to_internet) the same way imageDeployExposure caps its
// podIDs before the equivalent hop. maxSupplyChainRepos bounds the FIRST hop's
// input, not the workload count it fans out to — one repo's deploys_to can
// point at many CI/CD environments/regions, so a capped repo set can still
// produce a much larger workload list. Unbounded, that list feeds a ClickHouse
// CHIn (values interpolated into the query text, not true bind parameters),
// which can exceed max_query_size.
const maxSupplyChainWorkloads = 200

// LineageProvider walks the supply-chain → cloud edges: package ← repo (depends_on)
// and repo → workload (deploys_to) → exposed_to_internet. Satisfied by asset.Service.
//
// The outbound hops are typed (EdgesOutBatch), never an untyped "every edge out
// of these ids" read: a VM carries one runs_package edge per installed package
// (~1k each), so an untyped read of 200 VMs to find one exposed_to_internet edge
// pulled ~200k rows per package finding.
type LineageProvider interface {
	EdgesInto(ctx context.Context, dstID, edgeType string) ([]asset.Edge, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
}

// deployExposure is what one lineage walk established. truncated reports that a
// fan-out cap cut the walk short, so a negative exposed is a SAMPLE, not a
// measurement: the unvisited remainder may be exposed. Nothing may demote a
// finding to contained on a truncated walk.
type deployExposure struct {
	lineage, deployed, exposed, truncated bool
}

// LadybugDeployGraph queries Ladybug for workloads deployed from repos and their
// internet-exposure status via the pre-computed Exposed node signal. Replaces
// steps 2+3 of the SupplyChainExposure CH traversal with a single Ladybug call.
// Optional — nil falls back to the CH lineage path (EdgesOutBatch).
type LadybugDeployGraph interface {
	// DeployedExposure returns whether any workload deployed from repoIDs exists
	// and whether any such workload is internet-exposed (Ladybug Exposed signal).
	DeployedExposure(ctx context.Context, repoIDs []string) (anyDeployed, anyExposed bool, err error)
}

// SupplyChainExposure scores a vulnerable-dependency finding by whether the
// package actually runs on something internet-exposed — the question a flat SCA
// tool can't answer. It walks two reachability lineages and floors a
// confirmed internet-exposed path into the reasoning pipeline:
//
//	repo:  package ← depends_on ← repo → deploys_to → workload → exposed_to_internet
//	image: package ← runs_package ← container_image ← runs_image ← workload → exposed_to_internet
//
// Ladybug (optional): when set, steps 2+3 (repos → workloads → exposure) use Ladybug
// node signals instead of CH edge queries, eliminating 2 of 3 sequential CH hops.
//
// A confirmed malicious package (isMaliciousPackage) is deliberately exempt
// from this exposure-based scoring — see CriticalFloor (sources_critical_floor.go)
// and assessSupplyChainMustFix (mustfix.go) for where its urgency/score come
// from instead. Do not add a MAL-* branch here too.
type SupplyChainExposure struct {
	Graph   LineageProvider    // CH: depends_on edges into the package (always CH)
	Ladybug LadybugDeployGraph // optional Ladybug: deploys_to + Exposed signal (nil = CH path)
	// Fleets lists the per-fleet vm_vuln findings and the base-image root-cause
	// findings (optional; nil = a package finding always speaks for its runners
	// too). See FleetCanonical and AlertCarrier.
	Fleets FleetFindingLister
	Reach  ReachProvider
}

func (SupplyChainExposure) Name() string { return "supply_chain_exposure" }

func (s SupplyChainExposure) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if !isSupplyChainPackage(f) {
		return Factor{}, false, nil
	}
	canonical, instances, err := s.FleetCanonical(ctx, f)
	if err != nil {
		return Factor{}, false, err
	}
	if canonical {
		// The fleets carry this package's urgency on the hosts themselves, each
		// with its own reachability and KEV floor, so one KEV CVE on ten fleets
		// pages ten times, not eleven. The package copy is capped below page even
		// over a page floor (Factor.RootCause) — it stays visible and linked.
		return Factor{Source: s.Name(), RootCause: true, Detail: fleetCanonicalDetail(instances)}, true, nil
	}
	de, err := s.packageDeployExposure(ctx, f.ResourceID)
	if err != nil {
		return Factor{}, false, err
	}
	if !de.lineage || !de.deployed {
		return Factor{}, false, nil // no dependent repo, or shipped but never deployed
	}
	if de.exposed {
		return Factor{
			Source: s.Name(),
			Points: 20,
			Floor:  ThresholdPipeline,
			Detail: "vulnerable package runs on an internet-exposed workload",
		}, true, nil
	}
	return Factor{
		Source: s.Name(),
		Points: 10,
		Detail: "vulnerable package runs on a deployed workload",
	}, true, nil
}

// PackageDeployExposure implements enrich.SupplyChainReachProvider (mustfix.go):
// the must-fix classifier's package-purl reachability lookup, reusing the exact
// traversal Evaluate scores with — so scoring and must-fix classification can
// never disagree about what "reachable" means for a supply-chain finding.
func (s SupplyChainExposure) PackageDeployExposure(ctx context.Context, packageID string) (anyDeployed, anyExposed, truncated bool, err error) {
	de, err := s.packageDeployExposure(ctx, packageID)
	return de.deployed, de.exposed, de.truncated, err
}

// RepoDeployExposure implements enrich.SupplyChainReachProvider (mustfix.go) for
// a finding whose resource is the REPOSITORY itself rather than a package purl —
// a GitHub code-scanning (SAST) alert. It runs steps 2+3 of the repo lineage
// (repo → deploys_to → workload → exposed_to_internet), skipping step 1's
// depends_on hop because the repo is already the traversal's starting point.
//
// Reusing repoDeployExposure's own steps 2+3 rather than a second traversal is
// deliberate: "deployed" and "internet-exposed" must mean the same thing for a
// vulnerable dependency and for vulnerable first-party code in the same repo.
func (s SupplyChainExposure) RepoDeployExposure(ctx context.Context, repoID string) (anyDeployed, anyExposed, truncated bool, err error) {
	if repoID == "" {
		return false, false, false, nil
	}
	de, err := s.reposDeployExposure(ctx, []string{repoID})
	return de.deployed, de.exposed, de.truncated, err
}

// packageDeployExposure walks EVERY lineage a package can reach a running,
// internet-facing workload through, and OR-combines them:
//
//	repo:  package ← depends_on ← repo → deploys_to → workload → exposed_to_internet
//	image: package ← runs_package ← container_image ← runs_image ← workload → exposed_to_internet
//	vm:    package ← runs_package ← ec2_instance/gce_instance → exposed_to_internet
//
// The image path is what lets an image-vuln finding (internal/scanner/imagevuln)
// reach must_fix: those findings key on the same package purl / CVE
// as the SBOM feed, but their package is linked to a container_image, not a
// repo, so the repo path alone always reported "no lineage" for them.
//
// lineage reports whether ANY lineage links the package to anything at all
// (false → callers must not read deployed/exposed as negative evidence);
// deployed whether any (capped) dependent repo/image/VM is actually run;
// exposed whether any such deployment is internet-facing; truncated whether a
// cap cut any walk short (see deployExposure).
func (s SupplyChainExposure) packageDeployExposure(ctx context.Context, packageID string) (deployExposure, error) {
	repo, err := s.repoDeployExposure(ctx, packageID)
	if err != nil {
		return deployExposure{}, err
	}
	// A confirmed internet-exposed repo deployment is the strongest signal —
	// skip the image walk (nothing stronger to find).
	if repo.exposed {
		return repo, nil
	}

	// One runs_package read serves both runtime lineages: a VM source is a host
	// whose exposure is its own, an image source is reached through its pods.
	runEdges, err := s.Graph.EdgesInto(ctx, packageID, "runs_package")
	if err != nil {
		return deployExposure{}, err
	}
	vmEdges, imgEdges := splitVMSources(runEdges)

	img, err := s.imageDeployExposure(ctx, imgEdges)
	if err != nil {
		return deployExposure{}, err
	}
	if img.exposed {
		return img, nil
	}
	vm, err := s.vmDeployExposure(ctx, vmEdges)
	if err != nil {
		return deployExposure{}, err
	}
	return deployExposure{
		lineage:   repo.lineage || img.lineage || vm.lineage,
		deployed:  repo.deployed || img.deployed || vm.deployed,
		exposed:   vm.exposed,
		truncated: repo.truncated || img.truncated || vm.truncated,
	}, nil
}

// repoDeployExposure is the SBOM lineage: package ← depends_on ← repo →
// deploys_to → workload → exposed_to_internet.
func (s SupplyChainExposure) repoDeployExposure(ctx context.Context, packageID string) (deployExposure, error) {
	// Step 1: package ← repo (depends_on edges always from CH — not in Ladybug).
	depEdges, err := s.Graph.EdgesInto(ctx, packageID, "depends_on")
	if err != nil {
		return deployExposure{}, err
	}
	repoIDs := uniqueSrcIDs(depEdges)
	if len(repoIDs) == 0 {
		return deployExposure{}, nil // package not linked to any repo — no lineage signal
	}
	truncated := len(repoIDs) > maxSupplyChainRepos
	if truncated {
		repoIDs = repoIDs[:maxSupplyChainRepos]
	}

	// Steps 2+3: repos → workloads → internet.
	de, err := s.reposDeployExposure(ctx, repoIDs)
	de.lineage = true
	de.truncated = de.truncated || truncated
	return de, err
}

// reposDeployExposure is steps 2+3 of the repo lineage on their own: repos →
// deploys_to → workload → exposed_to_internet. Shared by repoDeployExposure
// (which reaches these repos through a package's depends_on edges) and
// RepoDeployExposure (whose finding names the repo directly).
func (s SupplyChainExposure) reposDeployExposure(ctx context.Context, repoIDs []string) (deployExposure, error) {
	// Ladybug path: single Neighbors call returning nodes with Exposed signal.
	if s.Ladybug != nil {
		wDeployed, wExposed, kErr := s.Ladybug.DeployedExposure(ctx, repoIDs)
		if kErr == nil && wExposed {
			return deployExposure{lineage: true, deployed: wDeployed, exposed: wExposed}, nil
		}
		// Ladybug error → fall through to CH path below.
	}

	// CH fallback: steps 2+3 as typed reads.
	repoOut, err := s.Graph.EdgesOutBatch(ctx, repoIDs, "deploys_to")
	if err != nil {
		return deployExposure{}, err
	}
	workloadIDs := dstIDsOfType(repoOut, "deploys_to")
	if len(workloadIDs) == 0 {
		return deployExposure{lineage: true}, nil // shipped but no deployed workload found
	}
	truncated := len(workloadIDs) > maxSupplyChainWorkloads
	if truncated {
		workloadIDs = workloadIDs[:maxSupplyChainWorkloads]
	}

	exposed, unknown, err := s.workloadExposure(ctx, workloadIDs)
	if err != nil {
		return deployExposure{lineage: true, deployed: true}, err
	}
	return deployExposure{lineage: true, deployed: true, exposed: exposed, truncated: truncated || unknown}, nil
}

// imageDeployExposure is the container-image lineage: package ← runs_package ←
// container_image ← runs_image ← workload (k8s_pod, ecs_service, cloudrun_service)
// → exposed_to_internet. Membership comes from inventory; workload exposure
// also consults the resident internet-hops map for LB/ingress paths. Every hop
// is bounded, and missing reach evidence remains unknown. imgEdges are the
// package's non-VM runs_package edges (step 1, read once by the caller).
func (s SupplyChainExposure) imageDeployExposure(ctx context.Context, imgEdges []asset.Edge) (deployExposure, error) {
	imageIDs := uniqueSrcIDs(imgEdges)
	if len(imageIDs) == 0 {
		return deployExposure{}, nil // package not linked to any image — no image lineage
	}
	truncated := len(imageIDs) > maxSupplyChainImages
	if truncated {
		imageIDs = imageIDs[:maxSupplyChainImages]
	}

	// Step 2: image ← workload (runs_image edges from the kubernetes, ECS and
	// Cloud Run collectors). Stopping at the pod cap with images or edges still
	// unvisited marks the walk truncated — conservatively, since an unvisited
	// pod may be a duplicate, but never the other way round.
	seen := map[string]struct{}{}
	var podIDs []string
	for _, img := range imageIDs {
		if len(podIDs) >= maxSupplyChainImages {
			truncated = true
			break
		}
		podEdges, pErr := s.Graph.EdgesInto(ctx, img, "runs_image")
		if pErr != nil {
			return deployExposure{lineage: true}, pErr
		}
		for _, e := range podEdges {
			if _, ok := seen[e.SrcID]; ok || e.SrcID == "" {
				continue
			}
			if len(podIDs) >= maxSupplyChainImages {
				truncated = true
				break
			}
			seen[e.SrcID] = struct{}{}
			podIDs = append(podIDs, e.SrcID)
		}
	}
	if len(podIDs) == 0 {
		return deployExposure{lineage: true}, nil // image exists but no live pod runs it
	}

	// Step 3: pod → internet.
	exposed, unknown, err := s.workloadExposure(ctx, podIDs)
	if err != nil {
		return deployExposure{lineage: true, deployed: true}, err
	}
	return deployExposure{lineage: true, deployed: true, exposed: exposed, truncated: truncated || unknown}, nil
}

// isSupplyChainPackage reports whether a finding's resource is a bare package
// purl from SBOM/dependency scanning — never itself an asset.Asset row, so the
// normal seed-based reachability path (assessMustFix's asset.Service.Get) can
// never resolve for it (this is the live gap this file exists to close).
func isSupplyChainPackage(f finding.Finding) bool {
	return f.Source == "supply_chain" && f.ResourceType == "package"
}

// isMaliciousPackage reports whether a supply-chain finding is a confirmed
// OpenSSF Malicious Packages advisory (MAL-<year>-<n>) rather than an ordinary
// vulnerability — the published artefact IS hostile (credential-stealing
// install hooks, hijacked releases), not merely exploitable if reached.
// Mirrors osv.IsMalicious's prefix check; duplicated rather than imported
// because internal/intel/osv is an HTTP client package with nothing else
// worth pulling into enrich's pure scoring/classification logic. Gated on
// isSupplyChainPackage so an unrelated CheckID that happens to start with
// "MAL-" from some other source can never match. Used by both
// assessSupplyChainMustFix (mustfix.go) and CriticalFloor
// (sources_critical_floor.go) — deployment/reachability and score ceilings
// must never apply to this class; see both call sites for why.
func isMaliciousPackage(f finding.Finding) bool {
	return isSupplyChainPackage(f) && strings.HasPrefix(f.CheckID, "MAL-")
}

func uniqueSrcIDs(edges []asset.Edge) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, e := range edges {
		if _, ok := seen[e.SrcID]; ok || e.SrcID == "" {
			continue
		}
		seen[e.SrcID] = struct{}{}
		out = append(out, e.SrcID)
	}
	return out
}

func dstIDsOfType(edges []asset.Edge, edgeType string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, e := range edges {
		if e.EdgeType != edgeType || e.DstID == "" {
			continue
		}
		if _, ok := seen[e.DstID]; ok {
			continue
		}
		seen[e.DstID] = struct{}{}
		out = append(out, e.DstID)
	}
	return out
}
