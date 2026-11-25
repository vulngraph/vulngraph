package kubernetes

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestPodAssetImageIDsAreSorted guards a churn bug, not a security bug — but the
// churn was the loudest thing in the database. image_ids is a SET flattened into
// one comma-separated string, and it was built by ranging a Go map, so the same
// unchanged pod re-serialised its digests in a different order on nearly every
// sweep and the diff engine recorded a change each time, so nearly every
// image_ids change was a pure reordering.
//
// Sorting also makes the value comparable across sweeps at all, which anything
// diffing a pod's images needs.
func TestPodAssetImageIDsAreSorted(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "c1", Image: "reg/c:1"}, {Name: "c2", Image: "reg/b:1"}, {Name: "c3", Image: "reg/a:1"},
		}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c1", Image: "reg/c:1", ImageID: "docker-pullable://reg/c@sha256:cccc"},
			{Name: "c2", Image: "reg/b:1", ImageID: "docker-pullable://reg/b@sha256:bbbb"},
			{Name: "c3", Image: "reg/a:1", ImageID: "docker-pullable://reg/a@sha256:aaaa"},
		}},
	}

	// Map iteration order is randomised per range, so a single pass proves
	// nothing: collect the same pod repeatedly and require one stable answer.
	want := "sha256:aaaa,sha256:bbbb,sha256:cccc"
	for range 20 {
		a, _, _ := podAsset(pod, "cluster", time.Now())
		require.Equal(t, want, a.Metadata["image_ids"],
			"image_ids must be a sorted set, not map-iteration order")
	}
}

// imageAssetFor finds the container_image asset for a digest among podAsset's
// extra assets.
func imageAssetFor(t *testing.T, extra []asset.Asset, imageID string) asset.Asset {
	t.Helper()
	for _, a := range extra {
		if a.Type == "container_image" && a.ID == "image/"+imageID {
			return a
		}
	}
	t.Fatalf("no container_image asset for %s among %d extra assets", imageID, len(extra))
	return asset.Asset{}
}

// TestPodAssetImageRef_PrefersImageIDRegistry covers the docker-pullable://
// form: ImageID carries the registry/repo the image actually resolved to,
// which imagevuln's pullReference needs to build repo@digest correctly. A pod
// spec that names the image bare (no registry host, e.g. a workload written
// against a mirror or an implicit default registry) must not lose that
// registry/repo information — the digest alone is not enough to re-derive it.
// The tag must survive too: ImageID's own repo is always bare (paired with a
// digest, never a tag), so this asserts the splice, not a wholesale replace,
// which would strip the tag off every tagged container_image asset.
func TestPodAssetImageRef_PrefersImageIDRegistry(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c1", Image: "myimage:v1"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c1", Image: "myimage:v1", ImageID: "docker-pullable://registry.internal/team/myimage@sha256:aaaa"},
		}},
	}
	_, extra, _ := podAsset(pod, "cluster", time.Now())
	img := imageAssetFor(t, extra, "sha256:aaaa")
	require.Equal(t, "registry.internal/team/myimage:v1", img.Metadata["image_ref"],
		"image_ref must carry ImageID's registry/repo AND cs.Image's tag, not lose either")
}

// TestPodAssetImageRef_ContainerdFormat covers containerd's ImageID shape,
// which carries the same registry/repo information but without the
// docker-pullable:// prefix docker/dockershim adds. Also covers a pod-spec
// image whose tag differs from the digest-resolved repo path in shape
// (registry.internal/team/myimage vs a shorter alias) to prove the tag is
// spliced from cs.Image, not accidentally re-derived from the repo string.
func TestPodAssetImageRef_ContainerdFormat(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c1", Image: "myimage:v2.3.1"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c1", Image: "myimage:v2.3.1", ImageID: "registry.internal/team/myimage@sha256:bbbb"},
		}},
	}
	_, extra, _ := podAsset(pod, "cluster", time.Now())
	img := imageAssetFor(t, extra, "sha256:bbbb")
	require.Equal(t, "registry.internal/team/myimage:v2.3.1", img.Metadata["image_ref"])
}

// TestPodAssetImageRef_PodSpecTagless covers a pod spec whose image string has
// no tag at all (e.g. an implicit ":latest" the kubelet already resolved) —
// there is no tag to splice, so the ImageID-derived repo stays bare rather
// than fabricating one.
func TestPodAssetImageRef_PodSpecTagless(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c1", Image: "myimage"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c1", Image: "myimage", ImageID: "docker-pullable://registry.internal/team/myimage@sha256:dddd"},
		}},
	}
	_, extra, _ := podAsset(pod, "cluster", time.Now())
	img := imageAssetFor(t, extra, "sha256:dddd")
	require.Equal(t, "registry.internal/team/myimage", img.Metadata["image_ref"])
}

// TestImageTag pins the port-vs-tag ambiguity a naive strings.LastIndex(":")
// would get wrong: a colon before the last '/' is a registry port, not a tag.
func TestImageTag(t *testing.T) {
	cases := []struct{ ref, want string }{
		{"myimage:v1", "v1"},
		{"reg/repo:v1", "v1"},
		{"reg.internal:5000/repo:v1", "v1"},
		{"reg.internal:5000/repo", ""}, // port, no tag
		{"myimage", ""},                // no tag at all
		// A digest ref ("repo@sha256:hex") is NOT tag-safe — the colon inside
		// the digest comes after the last '/', so this returns the digest's
		// hex suffix as if it were a tag. Documented, not fixed: this function
		// is only ever called on cs.Image, which the kubelet never sets to a
		// bare digest ref, so callers must not repurpose it for digest refs.
		{"reg/repo@sha256:aaaa", "aaaa"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, imageTag(c.ref), "imageTag(%q)", c.ref)
	}
}

// TestPodAssetImageRef_BareImageIDFallsBackToPodSpec covers the third
// documented ImageID shape — a bare digest, with no registry/repo at all —
// where cs.Image is the only source of a ref.
func TestPodAssetImageRef_BareImageIDFallsBackToPodSpec(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "ns"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c1", Image: "myimage:v1"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c1", Image: "myimage:v1", ImageID: "sha256:cccc"},
		}},
	}
	_, extra, _ := podAsset(pod, "cluster", time.Now())
	img := imageAssetFor(t, extra, "sha256:cccc")
	require.Equal(t, "myimage:v1", img.Metadata["image_ref"])
}
