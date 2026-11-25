package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

// scriptedImageScanner fails the digests in errs and returns results otherwise.
type scriptedImageScanner struct {
	mu      sync.Mutex
	errs    map[string]error
	results map[string]imagevuln.Result
}

func (s *scriptedImageScanner) ScanImage(_ context.Context, digest, _ string) (imagevuln.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.errs[digest]; err != nil {
		return imagevuln.Result{}, err
	}
	return s.results[digest], nil
}

// fakeImageEdges serves runs_image edges INTO images (which are running) and
// their last-known runs_package edges, and records what is re-stamped.
type fakeImageEdges struct {
	mu        sync.Mutex
	running   map[string]bool         // image asset id → a workload runs it
	packages  map[string][]asset.Edge // image asset id → fresh runs_package edges
	restamped []asset.Edge
}

func (f *fakeImageEdges) EdgesTo(_ context.Context, ids []string) ([]asset.Edge, error) {
	var out []asset.Edge
	for _, id := range ids {
		if f.running[id] {
			out = append(out, asset.Edge{SrcID: "k8s_pod/p", DstID: id, EdgeType: "runs_image"})
		}
		out = append(out, asset.Edge{SrcID: "repo/r", DstID: id, EdgeType: "builds_image"})
	}
	return out, nil
}

func (f *fakeImageEdges) EdgesOutBatch(_ context.Context, ids []string, edgeType string) ([]asset.Edge, error) {
	if edgeType != "runs_package" {
		return nil, fmt.Errorf("unexpected edge type %q", edgeType)
	}
	var out []asset.Edge
	for _, id := range ids {
		out = append(out, f.packages[id]...)
	}
	return out, nil
}

func (f *fakeImageEdges) IngestEdges(_ context.Context, edges []asset.Edge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restamped = append(f.restamped, edges...)
	return nil
}

func imageAsset(digest string) asset.Asset {
	return asset.Asset{ID: "image/" + digest, Type: "container_image",
		Metadata: map[string]string{"image_id": digest, "image_ref": "reg.example/" + digest}}
}

func pkgEdges(digest string, purls ...string) []asset.Edge {
	out := make([]asset.Edge, 0, len(purls))
	for _, p := range purls {
		out = append(out, asset.Edge{SrcID: "image/" + digest, SrcType: "container_image", DstID: p, DstType: "package", EdgeType: "runs_package"})
	}
	return out
}

// A running image whose scan fails keeps its last-known packages live: its
// runs_package edges are re-stamped, so package liveness never reads its CVEs
// as resource_gone, and a scan-failure finding says why it was not scanned. An
// image nothing runs is left to age out, with no finding.
func TestImageVulnWorker_FailedScanKeepsLastKnownPackagesLive(t *testing.T) {
	edges := &fakeImageEdges{
		running: map[string]bool{"image/sha256:run": true},
		packages: map[string][]asset.Edge{
			"image/sha256:run":  pkgEdges("sha256:run", "pkg:deb/debian/openssl@3", "pkg:deb/debian/zlib@1"),
			"image/sha256:dead": pkgEdges("sha256:dead", "pkg:deb/debian/curl@7"),
		},
	}
	findings := &fakeFindingStore{}
	w := &ImageVulnWorker{
		scanner: &scriptedImageScanner{errs: map[string]error{
			"sha256:run":  errors.New("pull: 401 unauthorized"),
			"sha256:dead": errors.New("pull: manifest unknown"),
		}},
		images:   &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:run"), imageAsset("sha256:dead")}},
		assets:   &fakeIngester{},
		findings: findings,
		edges:    edges,
	}
	err := w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{})
	require.Error(t, err, "a sweep that scanned nothing still fails")

	require.ElementsMatch(t, edges.packages["image/sha256:run"], edges.restamped)
	require.Len(t, findings.recorded, 1)
	f := findings.recorded[0]
	require.Equal(t, imagevuln.ScanFailedFindingID("sha256:run"), f.ID)
	require.Equal(t, "container_image", f.ResourceType)
	require.Equal(t, "image/sha256:run", f.ResourceID)
	require.Contains(t, f.Metadata["scan_error"], "401 unauthorized")
}

// An image backing off after failures is not attempted at all — and keeps its
// last-known packages live all the same; the backoff runs to a week, far past
// graph-edge freshness.
func TestImageVulnWorker_BackedOffImageKeepsLastKnownPackagesLive(t *testing.T) {
	edges := &fakeImageEdges{
		running:  map[string]bool{"image/sha256:off": true, "image/sha256:ok": true},
		packages: map[string][]asset.Edge{"image/sha256:off": pkgEdges("sha256:off", "pkg:npm/lodash@4")},
	}
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:off": {failures: 5, attemptedAt: time.Now().Add(-time.Hour), scannedAt: time.Now().Add(-40 * time.Hour)},
	}}
	scanner := &fakeImageScanner{byDigest: map[string]imagevuln.Result{"sha256:ok": {}}}
	w := &ImageVulnWorker{
		scanner: scanner, cursor: cursor, edges: edges,
		images:   &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:off"), imageAsset("sha256:ok")}},
		assets:   &fakeIngester{},
		findings: &fakeFindingStore{},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Equal(t, []string{"sha256:ok"}, scanner.got, "the backed-off digest is not attempted")
	require.ElementsMatch(t, edges.packages["image/sha256:off"], edges.restamped)
}

// An image past the per-sweep cap is not reached; where the chain ends (here:
// no River client, so no continuation) its last-known packages are kept live.
func TestImageVulnWorker_ImagePastTheSweepCapKeepsLastKnownPackagesLive(t *testing.T) {
	imgs := make([]asset.Asset, 0, imagesPerSweep+1)
	results := map[string]imagevuln.Result{}
	for i := range imagesPerSweep + 1 {
		d := fmt.Sprintf("sha256:%04d", i)
		imgs = append(imgs, imageAsset(d))
		results[d] = imagevuln.Result{}
	}
	last := fmt.Sprintf("sha256:%04d", imagesPerSweep) // digest order breaks the tie: last is over the cap
	edges := &fakeImageEdges{
		running:  map[string]bool{"image/" + last: true},
		packages: map[string][]asset.Edge{"image/" + last: pkgEdges(last, "pkg:pypi/requests@2")},
	}
	scanner := &fakeImageScanner{byDigest: results}
	w := &ImageVulnWorker{scanner: scanner, edges: edges, images: &fakeImageStore{imgs: imgs},
		assets: &fakeIngester{}, findings: &fakeFindingStore{}}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.NotContains(t, scanner.got, last)
	require.ElementsMatch(t, edges.packages["image/"+last], edges.restamped)
}

// A clean scan closes an open scan-failure finding. A partial walk closes it
// too — the image WAS scanned — but leaves its OS coverage finding open.
func TestImageVulnWorker_SuccessfulScanResolvesScanFailure(t *testing.T) {
	findings := &fakeFindingStore{list: []finding.Finding{
		{ID: imagevuln.ScanFailedFindingID("sha256:p"), CheckID: "imagevuln-scan-failed"},
		{ID: imagevuln.OSCoverageFindingID("sha256:p"), CheckID: "imagevuln-os-packages-unmatchable"},
	}}
	w := &ImageVulnWorker{
		scanner:  &fakeImageScanner{byDigest: map[string]imagevuln.Result{"sha256:p": {OSCVEGap: asset.CVEGapScanIncomplete}}},
		images:   &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:p")}},
		assets:   &fakeIngester{},
		findings: findings,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Len(t, findings.resolved, 1)
	require.Equal(t, imagevuln.ScanFailedFindingID("sha256:p"), findings.resolved[0].ID)
	require.Equal(t, finding.ReasonFixed, findings.reasons[findings.resolved[0].ID])
}
