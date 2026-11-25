package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func liveImage(id, ref string) asset.Asset {
	return asset.Asset{ID: id, Name: ref, Type: "container_image"}
}

func declaredImage(repo, image, path string) asset.Asset {
	return asset.Asset{
		ID: "declared_image_build:" + repo + ":" + image, Name: image, Type: "declared_image_build",
		Metadata: map[string]string{"repo": repo, "image": image, "path": path},
	}
}

func repoAsset(full string) asset.Asset {
	return asset.Asset{ID: full, Type: "github_repo"}
}

func TestImageOwnership_TagFreeJoinIsHighConfidence(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveImage("image/sha256:aaa", "eu.gcr.io/example-project-a/svc-alpha:0123456789abcdef0123456789abcdef01234567"),
		declaredImage("example-corp/data_svc-alpha", "eu.gcr.io/example-project-a/svc-alpha", "helm/values.yaml"),
		repoAsset("example-corp/data_svc-alpha"),
	})
	edges := ImageOwnership{}.Correlate(g)
	require.Len(t, edges, 1)
	e := edges[0]
	require.Equal(t, "defined_in", e.EdgeType)
	require.Equal(t, "image/sha256:aaa", e.SrcID)
	require.Equal(t, "container_image", e.SrcType)
	require.Equal(t, "example-corp/data_svc-alpha", e.DstID)
	require.Equal(t, "github_repo", e.DstType)
	require.Equal(t, "high", e.Properties["confidence"])
	require.Equal(t, "image_ref", e.Properties["provenance"])
	require.Equal(t, "helm/values.yaml", e.Properties["path"])
	require.Equal(t, "correlate", e.Properties["origin"])
}

// One declaration links EVERY deployed tag and digest of that image — this is
// what makes a single harvested reference worth an edge on all live
// container_image rows rather than only the one tag that happened to be written
// down.
func TestImageOwnership_OneDeclarationCoversEveryDeployedTag(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveImage("image/sha256:aaa", "eu.gcr.io/example-project-b/app:1111111111aaaaaaaaaa1111111111aaaaaaaaaa"),
		liveImage("image/sha256:bbb", "eu.gcr.io/example-project-b/app:2222222222bbbbbbbbbb2222222222bbbbbbbbbb"),
		liveImage("image/sha256:ccc", "eu.gcr.io/example-project-b/app@sha256:deadbeef"),
		declaredImage("example-corp/mail-service", "eu.gcr.io/example-project-b/app", "deploy/production.yaml"),
		repoAsset("example-corp/mail-service"),
	})
	edges := ImageOwnership{}.Correlate(g)
	require.Len(t, edges, 3)
	require.Equal(t, []string{"image/sha256:aaa", "image/sha256:bbb", "image/sha256:ccc"},
		[]string{edges[0].SrcID, edges[1].SrcID, edges[2].SrcID}, "edges are emitted in a stable order")
}

// Two repos naming the same image is real ambiguity (a shared deploy-config
// repo alongside the service repo). Both edges are emitted so neither answer is
// silently dropped, but the confidence says the join is no longer exact.
func TestImageOwnership_TwoDeclaringReposDemoteToMedium(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveImage("image/sha256:aaa", "eu.gcr.io/example-project-a/web-frontend:fedcba9876543210fedcba9876543210fedcba98"),
		declaredImage("example-corp/notifier", "eu.gcr.io/example-project-a/web-frontend", "a.yaml"),
		declaredImage("example-corp/catalog", "eu.gcr.io/example-project-a/web-frontend", "b.yaml"),
		repoAsset("example-corp/notifier"),
		repoAsset("example-corp/catalog"),
	})
	edges := ImageOwnership{}.Correlate(g)
	require.Len(t, edges, 2)
	for _, e := range edges {
		require.Equal(t, "medium", e.Properties["confidence"])
	}
}

func TestImageOwnership_DeclaredButNotRunningEmitsNothing(t *testing.T) {
	g := NewGraph([]asset.Asset{
		declaredImage("org/repo", "eu.gcr.io/example-x/retired-service", "values.yaml"),
		repoAsset("org/repo"),
	})
	require.Empty(t, ImageOwnership{}.Correlate(g), "no live image ⇒ no node to anchor the edge to")
}

// A declaration whose repo is not in the inventory (uncollected org, deleted
// repo) must not produce an edge into a node that does not exist — a dangling
// dst is dropped at Ladybug load and reads as an unexplained edge loss.
func TestImageOwnership_UnknownRepoEmitsNothing(t *testing.T) {
	g := NewGraph([]asset.Asset{
		liveImage("image/sha256:aaa", "eu.gcr.io/example-x/svc:v1"),
		declaredImage("org/never-collected", "eu.gcr.io/example-x/svc", "values.yaml"),
	})
	require.Empty(t, ImageOwnership{}.Correlate(g))
}

func TestNormalizeImageRef(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"eu.gcr.io/p/svc:9f2c", "eu.gcr.io/p/svc"},
		{"EU.GCR.IO/p/SVC", "eu.gcr.io/p/svc"},
		{"eu.gcr.io/p/svc@sha256:abc", "eu.gcr.io/p/svc"},
		{"eu.gcr.io/p/svc:tag@sha256:abc", "eu.gcr.io/p/svc"},
		{" eu.gcr.io/p/svc, ", "eu.gcr.io/p/svc"},
		{"localhost:5000/svc", "localhost:5000/svc"}, // host port is not a tag
		{"", ""},
	} {
		require.Equal(t, tc.want, asset.NormalizeImageRef(tc.in), tc.in)
	}
}
