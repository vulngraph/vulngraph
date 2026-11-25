package collect

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

const testDigest = "sha256:abababababababababababababababababababababababababababababababab"

func TestParseImageDigest(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		fallback string
		want     RunningImage
		ok       bool
	}{
		{"full ref with digest, tag recovered from fallback",
			"europe-docker.pkg.dev/p/r/api@" + testDigest, "europe-docker.pkg.dev/p/r/api:v3",
			RunningImage{Ref: "europe-docker.pkg.dev/p/r/api:v3", Digest: testDigest}, true},
		{"full ref with digest, fallback names another repo",
			"europe-docker.pkg.dev/p/r/api@" + testDigest, "other/repo:v1",
			RunningImage{Ref: "europe-docker.pkg.dev/p/r/api", Digest: testDigest}, true},
		{"bare digest takes the declared image (ECS imageDigest)",
			testDigest, "1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2",
			RunningImage{Ref: "1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2", Digest: testDigest}, true},
		{"bare digest with a digest-pinned declared image",
			testDigest, "1.dkr.ecr.eu-west-1.amazonaws.com/web@" + testDigest,
			RunningImage{Ref: "1.dkr.ecr.eu-west-1.amazonaws.com/web", Digest: testDigest}, true},
		{"registry port is not a tag",
			"localhost:5000/app@" + testDigest, "localhost:5000/app",
			RunningImage{Ref: "localhost:5000/app", Digest: testDigest}, true},
		{"tag only is not an identity", "web:latest", "web:latest", RunningImage{}, false},
		{"empty", "", "web:1", RunningImage{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseImageDigest(tt.in, tt.fallback)
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

// The image id and the two metadata keys are the contract with the imagevuln
// sweep (image_ref/image_id) and with the kubernetes collector's id scheme
// (image/<digest>), so the same digest is one node across k8s, ECS and Cloud Run.
func TestImageAssetAndEdge(t *testing.T) {
	now := time.Now()
	img := RunningImage{Ref: "1.dkr.ecr.eu-west-1.amazonaws.com/web:1.2", Digest: testDigest}

	a := ImageAsset(img, asset.ProviderAWS, "eu-west-1", "1", now)
	require.Equal(t, "image/"+testDigest, a.ID)
	require.Equal(t, "container_image", a.Type)
	require.Equal(t, img.Ref, a.Name)
	require.Equal(t, map[string]string{"image_ref": img.Ref, "image_id": testDigest}, a.Metadata)

	e := RunsImageEdge("svc", "ecs_service", img)
	require.Equal(t, asset.Edge{
		SrcID: "svc", SrcType: "ecs_service",
		DstID: a.ID, DstType: "container_image",
		EdgeType: "runs_image", Properties: map[string]string{"image_ref": img.Ref},
	}, e)
}
