package gcp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	run "google.golang.org/api/run/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fakeCloudRun struct {
	services    []cloudRunService
	servicesErr error
	revisions   map[string]revisionImages // "region/revision" → images
	revErr      error
	revReads    []string
	invoker     map[string]bool  // service → public
	invokerErr  map[string]error // service → error
	iamCalls    []string
}

func (f *fakeCloudRun) ListServices(context.Context, string) ([]cloudRunService, error) {
	return f.services, f.servicesErr
}

func (f *fakeCloudRun) RevisionImages(_ context.Context, _, region, revision string) (revisionImages, error) {
	f.revReads = append(f.revReads, region+"/"+revision)
	if f.revErr != nil {
		return revisionImages{}, f.revErr
	}
	return f.revisions[region+"/"+revision], nil
}

func oneImage(img collect.RunningImage) revisionImages {
	return revisionImages{Images: []collect.RunningImage{img}}
}

func (f *fakeCloudRun) InvokerPublic(_ context.Context, _, _, service string) (bool, error) {
	f.iamCalls = append(f.iamCalls, service)
	if err := f.invokerErr[service]; err != nil {
		return false, err
	}
	return f.invoker[service], nil
}

func byType(assets []asset.Asset, typ string) []asset.Asset {
	var out []asset.Asset
	for _, a := range assets {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

func TestCollectCloudRun_ImagesAndEdges(t *testing.T) {
	imgA := collect.RunningImage{Ref: "europe-docker.pkg.dev/proj/repo/api:v1", Digest: digestA}
	imgB := collect.RunningImage{Ref: "europe-docker.pkg.dev/proj/repo/api:v2", Digest: digestB}
	fake := &fakeCloudRun{
		services: []cloudRunService{
			// Traffic split across two revisions → two images.
			{Name: "api", Region: "europe-west1", URL: "https://api.run.app", ServingRevisions: []string{"api-001", "api-002"}},
			// Same digest as api-001 → one image asset, two edges.
			{Name: "worker", Region: "europe-west1", ServingRevisions: []string{"worker-001"}},
			// Revision with no resolved digest → no image.
			{Name: "nodigest", Region: "europe-west1", ServingRevisions: []string{"nodigest-001"}},
		},
		revisions: map[string]revisionImages{
			"europe-west1/api-001":    oneImage(imgA),
			"europe-west1/api-002":    oneImage(imgB),
			"europe-west1/worker-001": oneImage(imgA),
		},
	}

	assets, edges, err := collectCloudRun(context.Background(), fake, "proj", now)
	require.NoError(t, err)

	require.Len(t, byType(assets, "cloudrun_service"), 3)
	images := byType(assets, "container_image")
	require.Len(t, images, 2, "the shared digest dedupes to one image asset")
	ids := []string{images[0].ID, images[1].ID}
	require.ElementsMatch(t, []string{"image/" + digestA, "image/" + digestB}, ids)
	for _, img := range images {
		require.Equal(t, asset.ProviderGCP, img.Provider)
		require.Equal(t, "proj", img.AccountID)
		require.Equal(t, "europe-west1", img.Region)
		require.NotEmpty(t, img.Metadata["image_ref"])
		require.Equal(t, img.ID, "image/"+img.Metadata["image_id"])
	}

	type pair struct{ src, dst string }
	var got []pair
	for _, e := range edges {
		require.Equal(t, "runs_image", e.EdgeType)
		require.Equal(t, "cloudrun_service", e.SrcType)
		require.Equal(t, "container_image", e.DstType)
		got = append(got, pair{e.SrcID, e.DstID})
	}
	require.ElementsMatch(t, []pair{
		{"proj/cloudrun/europe-west1/api", "image/" + digestA},
		{"proj/cloudrun/europe-west1/api", "image/" + digestB},
		{"proj/cloudrun/europe-west1/worker", "image/" + digestA},
	}, got)
	require.ElementsMatch(t, []string{"europe-west1/api-001", "europe-west1/api-002", "europe-west1/worker-001", "europe-west1/nodigest-001"},
		fake.revReads, "only serving revisions are read")
}

// Service names are unique per region only: the same name in two regions is
// two services, and each keeps its own image edges.
func TestCollectCloudRun_SameNameTwoRegions(t *testing.T) {
	imgA := collect.RunningImage{Ref: "r/api:v1", Digest: digestA}
	imgB := collect.RunningImage{Ref: "r/api:v2", Digest: digestB}
	fake := &fakeCloudRun{
		services: []cloudRunService{
			{Name: "api", Region: "europe-west1", ServingRevisions: []string{"api-001"}},
			{Name: "api", Region: "us-central1", ServingRevisions: []string{"api-001"}},
		},
		revisions: map[string]revisionImages{"europe-west1/api-001": oneImage(imgA), "us-central1/api-001": oneImage(imgB)},
	}
	assets, edges, err := collectCloudRun(context.Background(), fake, "proj", now)
	require.NoError(t, err)
	svcs := byType(assets, "cloudrun_service")
	require.Len(t, svcs, 2)
	require.ElementsMatch(t, []string{"proj/cloudrun/europe-west1/api", "proj/cloudrun/us-central1/api"}, []string{svcs[0].ID, svcs[1].ID})
	dst := map[string]string{}
	for _, e := range edges {
		dst[e.SrcID] = e.DstID
	}
	require.Equal(t, "image/"+digestA, dst["proj/cloudrun/europe-west1/api"])
	require.Equal(t, "image/"+digestB, dst["proj/cloudrun/us-central1/api"])
}

func TestCollectCloudRun_UnresolvedSidecarsRecorded(t *testing.T) {
	fake := &fakeCloudRun{
		services: []cloudRunService{{Name: "api", Region: "r", ServingRevisions: []string{"api-001"}}},
		revisions: map[string]revisionImages{"r/api-001": {
			Images: []collect.RunningImage{{Ref: "r/api", Digest: digestA}}, Unresolved: 1,
		}},
	}
	assets, _, err := collectCloudRun(context.Background(), fake, "proj", now)
	require.NoError(t, err)
	require.Equal(t, "1", byType(assets, "cloudrun_service")[0].Metadata["running_images_unresolved"])
}

func TestCollectCloudRun_Exposure(t *testing.T) {
	tests := []struct {
		name          string
		svc           cloudRunService
		invoker       bool
		invokerErr    error
		wantPublic    string
		wantAccess    string
		wantInvoker   string // "" = flag absent (unknown / not applicable)
		wantIAMCalled bool
	}{
		{"public invoker confirms", cloudRunService{Name: "s", Region: "r", PublicNet: true}, true, nil,
			"true", asset.PublicAccessConfirmed, "true", true},
		{"no public binding stays possible", cloudRunService{Name: "s", Region: "r", PublicNet: true}, false, nil,
			"true", asset.PublicAccessPossible, "false", true},
		{"unreadable IAM is unknown, not confirmed or safe", cloudRunService{Name: "s", Region: "r", PublicNet: true}, false, errors.New("403"),
			"true", asset.PublicAccessPossible, "", true},
		{"no region: IAM unread", cloudRunService{Name: "s", PublicNet: true}, true, nil,
			"true", asset.PublicAccessPossible, "", false},
		{"internal ingress ignores IAM", cloudRunService{Name: "s", Region: "r", PublicNet: false}, true, nil,
			"false", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCloudRun{
				services:   []cloudRunService{tc.svc},
				invoker:    map[string]bool{"s": tc.invoker},
				invokerErr: map[string]error{"s": tc.invokerErr},
			}
			assets, _, err := collectCloudRun(context.Background(), fake, "proj", now)
			require.NoError(t, err)
			require.Len(t, assets, 1)
			m := assets[0].Metadata
			require.Equal(t, tc.wantPublic, m["public"])
			require.Equal(t, tc.wantAccess, m["public_access"])
			v, ok := m["invoker_public"]
			require.Equal(t, tc.wantInvoker != "", ok)
			require.Equal(t, tc.wantInvoker, v)
			require.Equal(t, tc.wantIAMCalled, len(fake.iamCalls) == 1)
		})
	}
}

func TestCollectCloudRun_PartialListings(t *testing.T) {
	t.Run("revision list failure keeps services and flags error", func(t *testing.T) {
		fake := &fakeCloudRun{
			services: []cloudRunService{{Name: "api", Region: "r", ServingRevisions: []string{"api-001"}}},
			revErr:   errors.New("boom"),
		}
		assets, edges, err := collectCloudRun(context.Background(), fake, "proj", now)
		require.Error(t, err)
		require.Len(t, assets, 1)
		require.Equal(t, "cloudrun_service", assets[0].Type)
		require.NotContains(t, assets[0].Metadata, "running_images_unresolved", "unread is not zero")
		require.Empty(t, edges)
	})
	t.Run("partial service list keeps what was listed", func(t *testing.T) {
		fake := &fakeCloudRun{
			services:    []cloudRunService{{Name: "api", Region: "r"}},
			servicesErr: errors.New("locations unreachable"),
		}
		assets, _, err := collectCloudRun(context.Background(), fake, "proj", now)
		require.Error(t, err)
		require.Len(t, assets, 1)
	})
	t.Run("total list failure", func(t *testing.T) {
		fake := &fakeCloudRun{servicesErr: errors.New("403")}
		assets, _, err := collectCloudRun(context.Background(), fake, "proj", now)
		require.Error(t, err)
		require.Empty(t, assets)
	})
}

func TestToCloudRunService(t *testing.T) {
	tests := []struct {
		name       string
		status     *run.ServiceStatus
		ingress    string
		wantRevs   []string
		wantPublic bool
	}{
		{"no traffic block uses latest ready", &run.ServiceStatus{LatestReadyRevisionName: "s-002"}, "", []string{"s-002"}, true},
		{"split traffic, zero-percent tag excluded", &run.ServiceStatus{
			LatestReadyRevisionName: "s-003",
			Traffic: []*run.TrafficTarget{
				{RevisionName: "s-001", Percent: 30},
				{RevisionName: "s-002", Percent: 70},
				{RevisionName: "s-003", Percent: 0, Tag: "canary"},
			},
		}, "all", []string{"s-001", "s-002"}, true},
		{"latest revision target resolves to latest ready", &run.ServiceStatus{
			LatestReadyRevisionName: "s-009",
			Traffic:                 []*run.TrafficTarget{{LatestRevision: true, Percent: 100}},
		}, "internal", []string{"s-009"}, false},
		{"nothing ready", &run.ServiceStatus{}, "internal-and-cloud-load-balancing", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := &run.Service{
				Metadata: &run.ObjectMeta{
					Name:        "s",
					Labels:      map[string]string{cloudRunLocationLabel: "us-central1"},
					Annotations: map[string]string{"run.googleapis.com/ingress": tc.ingress},
				},
				Spec:   &run.ServiceSpec{Template: &run.RevisionTemplate{Spec: &run.RevisionSpec{ServiceAccountName: "sa@proj.iam.gserviceaccount.com"}}},
				Status: tc.status,
			}
			got := toCloudRunService(svc)
			require.Equal(t, "s", got.Name)
			require.Equal(t, "us-central1", got.Region)
			require.Equal(t, tc.wantPublic, got.PublicNet)
			require.Equal(t, tc.wantRevs, got.ServingRevisions)
			require.Equal(t, "sa@proj.iam.gserviceaccount.com", got.ServiceAccountEmail)
		})
	}
}

func TestRevisionContainerImages(t *testing.T) {
	ctr := func(image string, port bool) *run.Container {
		c := &run.Container{Image: image}
		if port {
			c.Ports = []*run.ContainerPort{{ContainerPort: 8080}}
		}
		return c
	}
	rev := func(digest string, containers ...*run.Container) *run.Revision {
		return &run.Revision{
			Metadata: &run.ObjectMeta{Name: "api-001"},
			Spec:     &run.RevisionSpec{Containers: containers},
			Status:   &run.RevisionStatus{ImageDigest: digest},
		}
	}
	pinned := "gcr.io/p/envoy@" + digestB
	tests := []struct {
		name           string
		rev            *run.Revision
		wantRefs       []string
		wantUnresolved int
	}{
		{"full digest form keeps the spec tag", rev("europe-docker.pkg.dev/p/r/api@"+digestA, ctr("europe-docker.pkg.dev/p/r/api:v1", false)),
			[]string{"europe-docker.pkg.dev/p/r/api:v1"}, 0},
		{"bare digest falls back to spec image", rev(digestA, ctr("gcr.io/p/api:v1", false)), []string{"gcr.io/p/api:v1"}, 0},
		{"no digest yields no image", rev("", ctr("gcr.io/p/api:latest", false)), nil, 1},
		{"bare digest and no spec image has no pull target", rev(digestA, ctr("", false)), nil, 1},
		{"digest belongs to the ingress container, not containers[0]",
			rev(digestA, ctr("gcr.io/p/envoy:1", false), ctr("gcr.io/p/api:v1", true)), []string{"gcr.io/p/api:v1"}, 1},
		{"digest-pinned sidecar is collected",
			rev(digestA, ctr("gcr.io/p/api:v1", true), ctr(pinned, false)), []string{"gcr.io/p/api:v1", "gcr.io/p/envoy"}, 0},
		{"nil spec", &run.Revision{Metadata: &run.ObjectMeta{Name: "x"}}, nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := revisionContainerImages(tc.rev)
			var refs []string
			for _, img := range got.Images {
				refs = append(refs, img.Ref)
			}
			require.Equal(t, tc.wantRefs, refs)
			require.Equal(t, tc.wantUnresolved, got.Unresolved)
		})
	}
}

func TestInvokerIsPublic(t *testing.T) {
	tests := []struct {
		name   string
		policy *run.Policy
		want   bool
	}{
		{"nil", nil, false},
		{"allUsers invoker", &run.Policy{Bindings: []*run.Binding{{Role: "roles/run.invoker", Members: []string{"allUsers"}}}}, true},
		{"allAuthenticatedUsers invoker", &run.Policy{Bindings: []*run.Binding{{Role: "roles/run.invoker", Members: []string{"allAuthenticatedUsers"}}}}, true},
		{"allUsers on another role", &run.Policy{Bindings: []*run.Binding{{Role: "roles/run.viewer", Members: []string{"allUsers"}}}}, false},
		{"specific principal", &run.Policy{Bindings: []*run.Binding{{Role: "roles/run.invoker", Members: []string{"user:a@b.c"}}}}, false},
		{"conditional binding still confirms", &run.Policy{Bindings: []*run.Binding{{Role: "roles/run.invoker", Members: []string{"allUsers"}, Condition: &run.Expr{Expression: "request.time < x"}}}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, invokerIsPublic(tc.policy))
		})
	}
}
