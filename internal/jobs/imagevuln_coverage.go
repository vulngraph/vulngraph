package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// imageEdgeStore reads which images are running and their last-known package
// edges, and re-stamps those edges. *asset.Service satisfies it.
type imageEdgeStore interface {
	EdgesTo(ctx context.Context, dstIDs []string) ([]asset.Edge, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
	IngestEdges(ctx context.Context, edges []asset.Edge) error
}

// imageEdgeBatch bounds one image-id IN list on the edge reads.
const imageEdgeBatch = 100

// coverUnscanned keeps a running image that this sweep did not scan from
// reading as gone or clean.
//
// Package liveness is a fresh runs_package edge, and only a successful scan
// writes one. An image whose scan fails — and then backs off for 2^n hours —
// or that the sweep never reached (the per-sweep cap, the deadline) would see
// its edges age past graph_edges freshness, and the OSV reconcile would then
// resolve every CVE on its packages as resource_gone while the image still
// runs. So for every RUNNING image among failed and unscanned (a fresh
// runs_image edge into it — container_image rows are never deleted, and a
// stopped image's packages should age out), the last-known runs_package
// edges are re-stamped as they stand, and a failed one gets a scan-failure
// finding saying why.
//
// unscanned also carries images whose scan succeeded but was incomplete
// (scan_incomplete): that scan wrote edges for what it read, but the packages
// of the layers it lost — usually the base — exist only as the edges of an
// earlier complete scan, and must not age out because a later walk fell short.
//
// Best-effort per batch, on a detached context like recordAttempts: it runs at
// the sweep's own deadline, and losing it costs a day of freshness, not data.
func (w *ImageVulnWorker) coverUnscanned(ctx context.Context, failed []imageFailure, unscanned []scanTarget) {
	if w.edges == nil || (len(failed) == 0 && len(unscanned) == 0) {
		return
	}
	ctx = context.WithoutCancel(ctx)
	logger := log.FromContext(ctx)

	refs := map[string]string{}           // image asset id → ref
	digests := map[string]string{}        // image asset id → digest
	failures := map[string]imageFailure{} // image asset id → the failure a finding reports
	var ids []string
	add := func(digest, ref string) {
		id := collect.ImageAssetID(digest)
		if _, dup := refs[id]; !dup {
			ids = append(ids, id)
		}
		refs[id], digests[id] = ref, digest
	}
	for _, f := range failed {
		add(f.digest, f.ref)
		if !f.interrupted {
			failures[collect.ImageAssetID(f.digest)] = f
		}
	}
	for _, t := range unscanned {
		add(t.digest, t.ref)
	}

	var (
		restamped int
		findings  []finding.Finding
		now       = time.Now()
	)
	for start := 0; start < len(ids); start += imageEdgeBatch {
		batch := ids[start:min(start+imageEdgeBatch, len(ids))]
		running, err := w.runningImages(ctx, batch)
		if err != nil {
			logger.Error().Err(err).Int("images", len(batch)).
				Msg("imagevuln: could not read which unscanned images are running; their package edges were not re-stamped")
			continue
		}
		n, err := w.restampPackageEdges(ctx, running)
		if err != nil {
			logger.Error().Err(err).Int("images", len(running)).
				Msg("imagevuln: could not re-stamp unscanned running images' package edges")
		}
		restamped += n
		for _, id := range running {
			if f, ok := failures[id]; ok {
				findings = append(findings, imagevuln.ScanFailedFinding(digests[id], refs[id], f.reason, f.noManifests, now))
			}
		}
	}
	if len(findings) > 0 {
		if err := w.findings.RecordObserved(ctx, findings); err != nil {
			logger.Error().Err(err).Int("findings", len(findings)).Msg("imagevuln: could not record scan-failure findings")
		} else {
			enqueueEnrich(ctx, findings)
		}
	}
	logger.Info().Int("failed", len(failed)).Int("unscanned", len(unscanned)).
		Int("edges_restamped", restamped).Int("scan_failed_findings", len(findings)).
		Msg("imagevuln: kept unscanned running images' last-known packages live")
}

// runningImages returns the image asset ids in ids that a workload runs now.
func (w *ImageVulnWorker) runningImages(ctx context.Context, ids []string) ([]string, error) {
	in, err := w.edges.EdgesTo(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("runningImages: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range in {
		if e.EdgeType == "runs_image" && !seen[e.DstID] {
			seen[e.DstID] = true
			out = append(out, e.DstID)
		}
	}
	return out, nil
}

// restampPackageEdges re-writes the images' fresh runs_package edges unchanged,
// returning how many. Only edges still inside the freshness window are read, so
// this keeps the last scan's view alive; it never resurrects one already gone.
func (w *ImageVulnWorker) restampPackageEdges(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	edges, err := w.edges.EdgesOutBatch(ctx, ids, "runs_package")
	if err != nil {
		return 0, fmt.Errorf("restampPackageEdges: %w", err)
	}
	if len(edges) == 0 {
		return 0, nil
	}
	if err := w.edges.IngestEdges(ctx, edges); err != nil {
		return 0, fmt.Errorf("restampPackageEdges: %w", err)
	}
	return len(edges), nil
}

// resolveCoverage closes the image's scan-failure finding now that a scan
// succeeded, its OS coverage finding when the scan matched its OS packages in
// full (never after a partial walk: that is a gap of its own), and its
// language-coverage finding when no language package was missed by a walk
// that read every layer. The digest is the same immutable image, so what
// changes between scans is the scanner (it learns to read a package database)
// or the deployment (a feed switched back on); every digest is rescanned inside
// imageRescanAfter, so a finding an older scan opened closes within a day of
// the change.
func (w *ImageVulnWorker) resolveCoverage(ctx context.Context, digest string, res imagevuln.Result) error {
	ids := []string{imagevuln.ScanFailedFindingID(digest)}
	if res.OSCVEGap == "" {
		ids = append(ids, imagevuln.OSCoverageFindingID(digest))
	}
	// A walk cut short never reached the lost layers' language packages either,
	// so its empty language gap is not a reading.
	if res.LanguageGap == "" && res.OSCVEGap != asset.CVEGapScanIncomplete {
		ids = append(ids, imagevuln.LanguageCoverageFindingID(digest))
	}
	found, err := w.findings.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("resolveCoverage: %w", err)
	}
	var open []finding.Finding
	for _, f := range found {
		if !f.Resolved() {
			open = append(open, f)
		}
	}
	if err := w.findings.Resolve(ctx, open, finding.ReasonFixed); err != nil {
		return fmt.Errorf("resolveCoverage: %w", err)
	}
	return nil
}
