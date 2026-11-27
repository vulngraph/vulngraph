package kubernetes

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestConnectorScale(t *testing.T) {
	for _, n := range collectbench.Sizes(t) {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			f := &fakeK8s{pods: map[string][]corev1.Pod{}, sas: map[string][]corev1.ServiceAccount{}}
			for i := 0; i < n/100; i++ {
				ns := fmt.Sprintf("ns-%d", i)
				f.namespaces = append(f.namespaces, corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
				f.sas[ns] = []corev1.ServiceAccount{{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: ns}}}
				for j := range 100 {
					f.pods[ns] = append(f.pods[ns], corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%d", j), Namespace: ns}, Spec: corev1.PodSpec{ServiceAccountName: "default", Containers: []corev1.Container{{Name: "app", Image: "example/app:1"}, {Name: "sidecar", Image: "example/proxy:1"}}, InitContainers: []corev1.Container{{Name: "init", Image: "example/init:1"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning,
						ContainerStatuses:     []corev1.ContainerStatus{{Name: "app", Image: "example/app:1", ImageID: "docker-pullable://example/app@sha256:" + fmt.Sprintf("%064x", 1)}, {Name: "sidecar", Image: "example/proxy:1", ImageID: "docker-pullable://example/proxy@sha256:" + fmt.Sprintf("%064x", 2)}},
						InitContainerStatuses: []corev1.ContainerStatus{{Name: "init", Image: "example/init:1", ImageID: "docker-pullable://example/init@sha256:" + fmt.Sprintf("%064x", 3)}},
					}})
				}
			}
			c := withFakeK8s(f)
			collectbench.Run(t, "kubernetes", "complete client fixture; app, sidecar, init containers across namespaces", "k8s_pod", n, func() {}, func() (collect.Result, int, error) {
				r, err := c.Collect(context.Background(), nil)
				containers, images := 0, 0
				for _, a := range r.Assets {
					if a.Type == "container_image" {
						images++
					}
					if a.Type == "container" {
						containers++
					}
				}
				require.Equal(t, 3*n, containers)
				require.Equal(t, 3, images, "shared images are emitted once, all pod edges retained")
				imageEdges := 0
				for _, e := range r.Edges {
					if e.EdgeType == "runs_image" {
						imageEdges++
					}
				}
				require.Equal(t, 3*n, imageEdges, "every app, sidecar and init image must be linked")
				return r, 0, err
			})
		})
	}
	t.Run("paged_http", testConnectorScalePagedPods)
}

func TestSharedImagesKeepEveryPodEdgeAndDistinctReference(t *testing.T) {
	const ns = "workloads"
	f := &fakeK8s{namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: ns}}}, pods: map[string][]corev1.Pod{}}
	for i := range 100 {
		ref := "example/app:1"
		if i == 99 {
			ref = "example/app:alias"
		}
		f.pods[ns] = append(f.pods[ns], corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("pod-%d", i), Namespace: ns}, Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Image: ref, ImageID: "sha256:" + fmt.Sprintf("%064x", 1)}}}})
	}
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	refs := map[string]bool{}
	count, edges := 0, 0
	for _, a := range res.Assets {
		if a.Type == "container_image" {
			count++
			refs[a.Metadata["image_ref"]] = true
		}
	}
	for _, e := range res.Edges {
		if e.EdgeType == "runs_image" {
			edges++
		}
	}
	require.Equal(t, 2, count)
	require.Len(t, refs, 2)
	require.Equal(t, 100, edges)
}
