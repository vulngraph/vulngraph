package jobs

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
)

type refRecordingScanner struct {
	mu   sync.Mutex
	refs map[string][]string // digest → refs it was scanned with
}

func (f *refRecordingScanner) ScanImage(_ context.Context, digest, ref string) (imagevuln.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs[digest] = append(f.refs[digest], ref)
	return imagevuln.Result{}, nil
}

// TestImageVulnWorker_ScansECSAndCloudRunImages pins that the sweep is not
// k8s-only: container_image assets the ECS and Cloud Run collectors emit (via
// the shared collect.ImageAsset) are scanned by digest with their registry
// reference, and a digest run on k8s AND ECS is scanned once.
func TestImageVulnWorker_ScansECSAndCloudRunImages(t *testing.T) {
	now := time.Now()
	const (
		shared = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		run    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	ecr := collect.RunningImage{Ref: "123456789012.dkr.ecr.eu-west-1.amazonaws.com/web:1.2.3", Digest: shared}
	gar := collect.RunningImage{Ref: "europe-docker.pkg.dev/proj/repo/api", Digest: run}
	images := &fakeImageStore{imgs: []asset.Asset{
		collect.ImageAsset(ecr, asset.ProviderAWS, "eu-west-1", "123456789012", now),
		collect.ImageAsset(gar, asset.ProviderGCP, "europe-west1", "proj", now),
		// The k8s collector's row for the same digest — same asset id, one scan.
		{ID: collect.ImageAssetID(shared), Type: "container_image", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"image_id": shared, "image_ref": ecr.Ref}},
	}}
	scanner := &refRecordingScanner{refs: map[string][]string{}}

	w := &ImageVulnWorker{scanner: scanner, images: images, assets: &fakeIngester{}, findings: &fakeFindingStore{}}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshImageVulnArgs]{}))

	require.Equal(t, map[string][]string{
		shared: {ecr.Ref},
		run:    {gar.Ref},
	}, scanner.refs)
}
