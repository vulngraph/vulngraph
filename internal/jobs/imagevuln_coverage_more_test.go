package jobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

// Every eligible digest backing off leaves the hop nothing to scan — and its
// running images' last-known packages are still kept live.
func TestImageVulnWorker_AllBackedOffStillKeepsPackagesLive(t *testing.T) {
	edges := &fakeImageEdges{
		running:  map[string]bool{"image/sha256:off": true},
		packages: map[string][]asset.Edge{"image/sha256:off": pkgEdges("sha256:off", "pkg:npm/lodash@4")},
	}
	cursor := &fakeCursor{states: map[string]imageScanState{
		"sha256:off": {failures: 5, attemptedAt: time.Now().Add(-time.Hour)},
	}}
	scanner := &fakeImageScanner{}
	w := &ImageVulnWorker{scanner: scanner, cursor: cursor, edges: edges,
		images: &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:off")}},
		assets: &fakeIngester{}, findings: &fakeFindingStore{}}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Empty(t, scanner.got)
	require.ElementsMatch(t, edges.packages["image/sha256:off"], edges.restamped)
}

// Targets the sweep's deadline stops it from dispatching are unscanned, not
// failed: no finding, but their last-known packages are kept live.
func TestImageVulnWorker_DeadlineUnreachedTargetsKeepPackagesLive(t *testing.T) {
	edges := &fakeImageEdges{
		running:  map[string]bool{"image/sha256:late": true},
		packages: map[string][]asset.Edge{"image/sha256:late": pkgEdges("sha256:late", "pkg:pypi/requests@2")},
	}
	findings := &fakeFindingStore{}
	scanner := &fakeImageScanner{}
	w := &ImageVulnWorker{scanner: scanner, edges: edges,
		images: &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:late")}},
		assets: &fakeIngester{}, findings: findings}
	// Already inside sweepDeadlineMargin: the dispatch loop stops before the first scan.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.Error(t, w.Work(ctx, &river.Job[RefreshImageVulnArgs]{}), "had work, did none of it")
	require.Empty(t, scanner.got)
	require.ElementsMatch(t, edges.packages["image/sha256:late"], edges.restamped)
	require.Empty(t, findings.recorded, "not reaching an image is not the image's failure")
}

// A scan that succeeded but read the image only in part keeps the earlier
// complete scan's edges live: the lost layers' packages exist nowhere else.
func TestImageVulnWorker_IncompleteScanKeepsLastKnownPackagesLive(t *testing.T) {
	edges := &fakeImageEdges{
		running: map[string]bool{"image/sha256:big": true},
		packages: map[string][]asset.Edge{
			"image/sha256:big": pkgEdges("sha256:big", "pkg:deb/debian/openssl@3", "pkg:npm/lodash@4"),
		},
	}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{"sha256:big": {
			OSCVEGap: asset.CVEGapScanIncomplete,
			Edges:    pkgEdges("sha256:big", "pkg:npm/lodash@4"),
		}}},
		edges:  edges,
		images: &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:big")}},
		assets: &fakeIngester{}, findings: &fakeFindingStore{},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.ElementsMatch(t, edges.packages["image/sha256:big"], edges.restamped)
}

// An image with nothing inventoriable (busybox, pause, a non-Go static binary)
// is told so — not told to grant pull access it already has.
func TestImageVulnWorker_NoManifestsHasItsOwnWording(t *testing.T) {
	findings := &fakeFindingStore{}
	w := &ImageVulnWorker{
		scanner: &scriptedImageScanner{errs: map[string]error{
			"sha256:pause": fmt.Errorf("ScanImage: open image: %w", imagevuln.ErrNoManifests),
		}},
		edges:  &fakeImageEdges{running: map[string]bool{"image/sha256:pause": true}},
		images: &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:pause")}},
		assets: &fakeIngester{}, findings: findings,
	}
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Len(t, findings.recorded, 1)
	f := findings.recorded[0]
	require.Equal(t, "no_manifests", f.Metadata["scan_outcome"])
	require.Contains(t, f.Title, "no package inventory")
	require.NotContains(t, f.Remediation, "pull access")
}

// The language-coverage finding closes when a scan misses no language package,
// and stays open while it still does — independently of the OS gap.
func TestImageVulnWorker_ResolvesLanguageCoverageIndependently(t *testing.T) {
	findings := &fakeFindingStore{list: []finding.Finding{
		{ID: imagevuln.LanguageCoverageFindingID("sha256:fixed")},
		{ID: imagevuln.LanguageCoverageFindingID("sha256:still")},
	}}
	w := &ImageVulnWorker{
		scanner: &fakeImageScanner{byDigest: map[string]imagevuln.Result{
			"sha256:fixed": {OSCVEGap: asset.CVEGapEOLDistro},
			"sha256:still": {LanguageGap: "the 512 MiB Go build-info probe budget was spent"},
		}},
		images:   &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:fixed"), imageAsset("sha256:still")}},
		assets:   &fakeIngester{},
		findings: findings,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Len(t, findings.resolved, 1)
	require.Equal(t, imagevuln.LanguageCoverageFindingID("sha256:fixed"), findings.resolved[0].ID)
}

// A walk cut short at the stream cap reports no language gap only because it
// never reached the lost layers: that is not a reading, and the language
// finding an earlier scan opened stays open.
func TestImageVulnWorker_PartialWalkKeepsLanguageCoverageOpen(t *testing.T) {
	findings := &fakeFindingStore{list: []finding.Finding{{ID: imagevuln.LanguageCoverageFindingID("sha256:big")}}}
	w := &ImageVulnWorker{
		scanner:  &fakeImageScanner{byDigest: map[string]imagevuln.Result{"sha256:big": {OSCVEGap: asset.CVEGapScanIncomplete}}},
		images:   &fakeImageStore{imgs: []asset.Asset{imageAsset("sha256:big")}},
		assets:   &fakeIngester{},
		findings: findings,
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))
	require.Empty(t, findings.resolved)
}
