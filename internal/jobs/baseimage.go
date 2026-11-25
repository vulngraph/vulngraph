package jobs

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Base-image root cause (ADR 088). The image-vuln sweep records each scanned
// image's base identity (image_bases); this job joins it to what is RUNNING and
// produces two kinds of finding, both source "base_image":
//
//   - container-image-os-end-of-life on every running image whose base OS
//     release is past its end of standard support (internal/checks);
//   - base-image-root-cause, one per base (the base image the image names, else
//     its base OS release) that carries base-layer CVEs or is end-of-life: how
//     many running images and workloads are built on it, how many of their CVEs
//     come from the base layer versus the application layer, how many are KEV,
//     and which replacement bases to rebuild on.
//
// The root-cause finding is a projection, like vm_vuln's fleet findings: the
// per-(CVE × package) supply_chain findings stay the unit of record and are not
// duplicated. It sits on a real member image (an exposed one when there is
// one) so enrich classifies it with that image's own reachability.
//
// Its own source, not "cspm": the sync-time lifecycle reconcile resolves an
// unemitted cspm finding on a re-collected resource unless the registry check
// says it could not evaluate it, and this check is not in that registry.

const (
	// baseImageBatch bounds one edge read over image ids.
	baseImageBatch = 100
	// baseImageWorkloadBatch bounds one exposure read over workload ids.
	baseImageWorkloadBatch = 200
	// baseImagePurlBatch bounds one supply-chain finding lookup. Packages are
	// heavily shared across images on one base, so the distinct set is small
	// next to images × packages; ByResourceIDs' cost is per call, not per id.
	baseImagePurlBatch = 1000
	// baseImageRecordBatch bounds one RecordObserved write.
	baseImageRecordBatch = 500
	// baseImagePageLimit pages the open-findings read at List's max.
	baseImagePageLimit = 200
)

// RefreshBaseImagesArgs rebuilds the base-image findings. Producers: the
// image-vuln sweep (new identities, new runs_package edges) and the OSV refresh
// (new package findings), each at the end of a run, like refresh_vm_vuln.
type RefreshBaseImagesArgs struct{}

func (RefreshBaseImagesArgs) Kind() string { return "refresh_base_images" }

// InsertOpts: the enrich lane, like refresh_vm_vuln — a bounded ClickHouse join
// that records findings and enqueues their enrichment.
func (RefreshBaseImagesArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, 3)
}

// enqueueBaseImages queues the regroup. Best-effort: a missed insert waits for
// the next producer run, and the unique-by-state singleton absorbs duplicates.
func enqueueBaseImages(ctx context.Context) {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return // no client (unit test)
	}
	if _, err := client.Insert(ctx, RefreshBaseImagesArgs{}, nil); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("could not enqueue base-image regroup")
	}
}

// BaseImageInventory is the slice of the asset service the job reads.
type BaseImageInventory interface {
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
	EdgesTo(ctx context.Context, dstIDs []string) ([]asset.Edge, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
	ImageBases(ctx context.Context) ([]asset.ImageBase, error)
}

// BaseImageCoverageObserver publishes identification coverage. *obs.Metrics
// satisfies it; nil publishes nothing.
type BaseImageCoverageObserver interface {
	ObserveBaseImageCoverage(counts map[string]int)
}

// BaseImageWorker builds and reconciles the base-image findings.
type BaseImageWorker struct {
	river.WorkerDefaults[RefreshBaseImagesArgs]
	assets    BaseImageInventory
	findings  vmVulnFindingStore
	catalogue imagevuln.Catalogue
	metrics   BaseImageCoverageObserver
	// deletions: see VMVulnWorker.deletions.
	deletions DeletionRecords
}

func (BaseImageWorker) Timeout(_ *river.Job[RefreshBaseImagesArgs]) time.Duration {
	return 30 * time.Minute
}

// runningImage is one live container image some workload runs.
type runningImage struct {
	img       asset.Asset
	base      asset.ImageBase
	scanned   bool // the sweep recorded an identity for it
	workloads []string
	exposed   []string          // the workloads running it that are directly internet-exposed
	purls     []string          // its runs_package destinations
	repos     map[string]string // owning repo id → file declaring the image
}

// identity is the image's coverage state (obs.BaseIdentity*).
func (r *runningImage) identity() string {
	if !r.scanned {
		return obs.BaseIdentityUnscanned
	}
	switch r.base.BaseImageSource {
	case imagevuln.BaseSourceAnnotation:
		return obs.BaseIdentityAnnotation
	case imagevuln.BaseSourceOSRelease:
		return obs.BaseIdentityOSRelease
	}
	return obs.BaseIdentityUnknown
}

// baseImageRun is one pass's working state.
type baseImageRun struct {
	running  []*runningImage
	byID     map[string]*runningImage
	complete bool // the image listing was not truncated
	// listed is every listed image row, live or not, by id: a retired
	// member's repository is how its rebuild is recognised.
	listed map[string]asset.Asset
	// deleted holds the non-live images that are gone (assetGone: a
	// sync-recorded deletion, or unseen past the absence fallback). An image
	// that merely stopped being collected — its cluster's connector down — is
	// not in it, and its findings stay open until the fallback.
	deleted map[string]bool
	// groupMembers is every listed image, live or not, by base group key —
	// the full membership a retired group is judged on (a finding's
	// affected_image_ids is capped at maxListedImages).
	groupMembers map[string][]string
}

func (w *BaseImageWorker) Work(ctx context.Context, _ *river.Job[RefreshBaseImagesArgs]) error {
	run, err := w.load(ctx)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	vulns, err := w.vulns(ctx, run.running)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	logger := log.FromContext(ctx)
	// The open findings, read once: a root-cause finding keeps the member it
	// sits on, and the reconcile judges the ones not reproduced. A failed read
	// records without pinning and skips the reconcile.
	open, openErr := w.openBaseFindings(ctx)
	if openErr != nil {
		logger.Warn().Err(openErr).Msg("base_image: open findings unreadable — representatives not pinned, reconcile skipped")
	}
	now := time.Now()
	groups := groupByBase(run.running, vulns)
	found := eolFindings(run.running, now)
	for _, g := range groups {
		if f, ok := g.finding(w.catalogue, open[baseGroupFindingID(g.key)].ResourceID, now); ok {
			found = append(found, f)
		}
	}
	for start := 0; start < len(found); start += baseImageRecordBatch {
		if err := w.findings.RecordObserved(ctx, found[start:min(start+baseImageRecordBatch, len(found))]); err != nil {
			return fmt.Errorf("Work: record: %w", err)
		}
	}
	if len(found) > 0 {
		enqueueEnrich(ctx, found)
	}

	resolved := 0
	if openErr == nil {
		if resolved, err = w.reconcile(ctx, run, groups, open, found); err != nil {
			logger.Warn().Err(err).Msg("base_image: reconcile skipped")
		}
	}
	counts := map[string]int{}
	for _, r := range run.running {
		counts[r.identity()]++
	}
	if w.metrics != nil {
		w.metrics.ObserveBaseImageCoverage(counts)
	}
	identified := counts[obs.BaseIdentityAnnotation] + counts[obs.BaseIdentityOSRelease]
	logger.Info().
		Int("running_images", len(run.running)).
		Str("identified", fmt.Sprintf("%d/%d", identified, len(run.running))).
		Int("unknown", counts[obs.BaseIdentityUnknown]).Int("unscanned", counts[obs.BaseIdentityUnscanned]).
		Int("bases", len(groups)).Int("findings", len(found)).Int("resolved", resolved).
		Bool("complete", run.complete).
		Msg("base_image findings refreshed")
	return nil
}

// load reads the live container images, keeps the ones a workload runs, and
// attaches each one's identity, workloads, exposure, packages and owners.
// Every read failure fails the run: an image whose exposure or packages could
// not be read would otherwise look unexposed or clean.
func (w *BaseImageWorker) load(ctx context.Context) (baseImageRun, error) {
	images, err := w.assets.ListByType(ctx, "container_image", listImageLimit)
	if err != nil {
		return baseImageRun{}, fmt.Errorf("load: list images: %w", err)
	}
	bases, err := w.assets.ImageBases(ctx)
	if err != nil {
		return baseImageRun{}, fmt.Errorf("load: %w", err)
	}
	baseByID := make(map[string]asset.ImageBase, len(bases))
	for _, b := range bases {
		baseByID[b.ImageID] = b
	}

	run := baseImageRun{byID: map[string]*runningImage{}, complete: len(images) < listImageLimit,
		listed: map[string]asset.Asset{}, deleted: map[string]bool{}, groupMembers: map[string][]string{}}
	now := time.Now()
	cutoff := now.Add(-vmLiveWindow)
	var stale []string
	for _, img := range images {
		run.listed[img.ID] = img
		if key, ok := groupKeyOf(baseByID[img.ID]); ok {
			run.groupMembers[key] = append(run.groupMembers[key], img.ID)
		}
		if img.LastSeen.Before(cutoff) {
			stale = append(stale, img.ID)
		}
	}
	deletedAt, _ := assetDeletions(ctx, w.deletions, stale)
	var live []*runningImage
	for _, img := range images {
		if img.LastSeen.Before(cutoff) {
			run.deleted[img.ID] = assetGone(img, deletedAt[img.ID], now)
			continue
		}
		b, scanned := baseByID[img.ID]
		live = append(live, &runningImage{img: img, base: b, scanned: scanned, repos: map[string]string{}})
	}
	for start := 0; start < len(live); start += baseImageBatch {
		if err := w.attachEdges(ctx, live[start:min(start+baseImageBatch, len(live))]); err != nil {
			return baseImageRun{}, fmt.Errorf("load: %w", err)
		}
	}
	for _, r := range live {
		if len(r.workloads) > 0 {
			run.running = append(run.running, r)
			run.byID[r.img.ID] = r
		}
	}
	if err := w.attachExposure(ctx, run.running); err != nil {
		return baseImageRun{}, fmt.Errorf("load: %w", err)
	}
	return run, nil
}

// attachEdges reads one batch's runs_image (workloads), runs_package (purls)
// and defined_in (owning repos) edges. Every reader applies edge freshness.
func (w *BaseImageWorker) attachEdges(ctx context.Context, batch []*runningImage) error {
	byID := make(map[string]*runningImage, len(batch))
	ids := make([]string, len(batch))
	for i, r := range batch {
		byID[r.img.ID] = r
		ids[i] = r.img.ID
	}
	in, err := w.assets.EdgesTo(ctx, ids)
	if err != nil {
		return fmt.Errorf("attachEdges: runs_image: %w", err)
	}
	for _, e := range in {
		if r := byID[e.DstID]; r != nil && e.EdgeType == "runs_image" && e.SrcID != "" {
			r.workloads = append(r.workloads, e.SrcID)
		}
	}
	pkgs, err := w.assets.EdgesOutBatch(ctx, ids, "runs_package")
	if err != nil {
		return fmt.Errorf("attachEdges: runs_package: %w", err)
	}
	for _, e := range pkgs {
		if r := byID[e.SrcID]; r != nil {
			r.purls = append(r.purls, e.DstID)
		}
	}
	owners, err := w.assets.EdgesOutBatch(ctx, ids, "defined_in")
	if err != nil {
		return fmt.Errorf("attachEdges: defined_in: %w", err)
	}
	for _, e := range owners {
		if r := byID[e.SrcID]; r != nil {
			r.repos[e.DstID] = e.Properties["path"]
		}
	}
	return nil
}

// attachExposure marks an image exposed when a workload running it has a
// direct exposed_to_internet edge — the same rule the supply-chain image
// lineage uses (enrich.SupplyChainExposure.imageDeployExposure). A workload
// fronted by a load balancer or ingress is reached by enrich's internet-hops
// BFS on the finding itself, not here.
func (w *BaseImageWorker) attachExposure(ctx context.Context, running []*runningImage) error {
	seen := map[string]bool{}
	var workloads []string
	for _, r := range running {
		for _, wl := range r.workloads {
			if !seen[wl] {
				seen[wl] = true
				workloads = append(workloads, wl)
			}
		}
	}
	exposed := map[string]bool{}
	for start := 0; start < len(workloads); start += baseImageWorkloadBatch {
		edges, err := w.assets.EdgesOutBatch(ctx, workloads[start:min(start+baseImageWorkloadBatch, len(workloads))], "exposed_to_internet")
		if err != nil {
			return fmt.Errorf("attachExposure: %w", err)
		}
		for _, e := range edges {
			exposed[e.SrcID] = true
		}
	}
	for _, r := range running {
		for _, wl := range r.workloads {
			if exposed[wl] {
				r.exposed = append(r.exposed, wl)
			}
		}
	}
	return nil
}

// vulns reads the open supply-chain findings on the packages of every running
// image with an identified base — the only images a group can hold.
func (w *BaseImageWorker) vulns(ctx context.Context, running []*runningImage) (map[string][]finding.Finding, error) {
	seen := map[string]bool{}
	var purls []string
	for _, r := range running {
		if _, ok := groupKeyOf(r.base); !ok || !r.scanned {
			continue
		}
		for _, p := range r.purls {
			if !seen[p] {
				seen[p] = true
				purls = append(purls, p)
			}
		}
	}
	sort.Strings(purls)
	out := map[string][]finding.Finding{}
	if err := openPackageFindings(ctx, w.findings, purls, baseImagePurlBatch, out); err != nil {
		return nil, fmt.Errorf("vulns: %w", err)
	}
	return out, nil
}

// eolFindings evaluates the container-image end-of-life check on every running
// image with a known base OS, on a copy of its asset carrying the identity.
func eolFindings(running []*runningImage, now time.Time) []finding.Finding {
	var out []finding.Finding
	imageChecks := checks.ContainerImageChecks().All()
	for _, r := range running {
		if !r.scanned || r.base.BaseOS == "" {
			continue
		}
		a := withBaseMetadata(r)
		for _, c := range imageChecks {
			if f, ok := c.Evaluate(a, now); ok {
				f.Source = baseImageSource
				out = append(out, f)
			}
		}
	}
	return out
}

// withBaseMetadata is a copy of the image asset carrying its base identity and
// workload exposure, the keys the container-image checks read.
func withBaseMetadata(r *runningImage) asset.Asset {
	a := r.img
	a.Metadata = make(map[string]string, len(r.img.Metadata)+5)
	for k, v := range r.img.Metadata {
		a.Metadata[k] = v
	}
	a.Metadata[asset.MetaBaseImageSource] = r.base.BaseImageSource
	a.Metadata[asset.MetaWorkloadExposed] = strconv.FormatBool(len(r.exposed) > 0)
	if r.base.BaseOS != "" {
		a.Metadata[asset.MetaBaseOS] = r.base.BaseOS
	}
	if r.base.BaseImage != "" {
		a.Metadata[asset.MetaBaseImage] = r.base.BaseImage
	}
	if r.base.BaseImageDigest != "" {
		a.Metadata[asset.MetaBaseImageDigest] = r.base.BaseImageDigest
	}
	return a
}
