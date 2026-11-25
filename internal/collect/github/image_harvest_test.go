package github

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHarvestImageRefs_RealFileShapes(t *testing.T) {
	// Representative shapes of the files in which deployed image refs are found.
	content := []byte(`
image:
  repository: eu.gcr.io/example-project-a/svc-alpha
  tag: 0123456789abcdef0123456789abcdef01234567
sidecar: europe-docker.pkg.dev/example-project-b/default/core/app:abcdef01
script: docker push eu.gcr.io/example-project-d/billing/app-fpm:$CI_COMMIT_SHA
digest: eu.gcr.io/example-project-c/functions@sha256:deadbeef
`)
	require.Equal(t, []string{
		"eu.gcr.io/example-project-a/svc-alpha",
		"eu.gcr.io/example-project-c/functions",
		"eu.gcr.io/example-project-d/billing/app-fpm",
		"europe-docker.pkg.dev/example-project-b/default/core/app",
	}, HarvestImageRefs(content))
}

func TestHarvestImageRefs_DedupesAndSorts(t *testing.T) {
	content := []byte("eu.gcr.io/p/a:1 eu.gcr.io/p/a:2 eu.gcr.io/p/a@sha256:x eu.gcr.io/p/b")
	require.Equal(t, []string{"eu.gcr.io/p/a", "eu.gcr.io/p/b"}, HarvestImageRefs(content))
}

// Public registries are excluded ON PURPOSE: a repo naming docker.io/library/redis
// says nothing about who built it, and matching them would attach a defined_in
// edge from every mirrored upstream to whichever repo happened to mention it.
func TestHarvestImageRefs_IgnoresPublicRegistriesAndFragments(t *testing.T) {
	content := []byte(`
docker.io/library/redis:7
quay.io/prometheus/node-exporter:v1
k8s.gcr.io/pause:3.9
eu.gcr.io/onlyproject
eu.gcr.io/example-x/{{ .Values.service }}
`)
	// k8s.gcr.io/pause matches the gcr.io host pattern but has one segment, and
	// eu.gcr.io/onlyproject is a registry root — both are below the two-segment
	// floor. The templated ref truncates at "eu.gcr.io/example-x", also one segment.
	require.Empty(t, HarvestImageRefs(content))
}

func TestHarvestImageRefs_GHCRAndECR(t *testing.T) {
	content := []byte("ghcr.io/example-corp/thing:v1 123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/svc:abc")
	require.Equal(t, []string{
		"123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/svc",
		"ghcr.io/example-corp/thing",
	}, HarvestImageRefs(content))
}

func TestProjectDeclaredImageBuilds_ShapeAndCap(t *testing.T) {
	now := time.Now()
	assets := projectDeclaredImageBuilds(map[string]string{
		"eu.gcr.io/p/a": "helm/values.yaml",
		"eu.gcr.io/p/b": "deploy/production.yaml",
	}, "org/repo", now)

	require.Len(t, assets, 2)
	require.Equal(t, "declared_image_build:org/repo:eu.gcr.io/p/a", assets[0].ID)
	require.Equal(t, "declared_image_build", assets[0].Type)
	require.Equal(t, "org/repo", assets[0].Metadata["repo"])
	require.Equal(t, "eu.gcr.io/p/a", assets[0].Metadata["image"])
	require.Equal(t, "helm/values.yaml", assets[0].Metadata["path"])

	require.Empty(t, projectDeclaredImageBuilds(nil, "org/repo", now))
}

// The per-repo cap must truncate deterministically: a registry-mirror manifest
// that lists thousands of images must drop the SAME tail every sync, not a
// map-iteration-order sample that churns the asset set on every run.
func TestProjectDeclaredImageBuilds_CapTruncatesDeterministically(t *testing.T) {
	byImage := map[string]string{}
	for i := 0; i < harvestMaxImagesPerRepo+50; i++ {
		byImage[imageKey(i)] = "values.yaml"
	}
	first := projectDeclaredImageBuilds(byImage, "org/repo", time.Now())
	second := projectDeclaredImageBuilds(byImage, "org/repo", time.Now())
	require.Len(t, first, harvestMaxImagesPerRepo)
	for i := range first {
		require.Equal(t, first[i].ID, second[i].ID)
	}
}

func imageKey(i int) string {
	return "eu.gcr.io/p/svc" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + string(rune('0'+i%10))
}
