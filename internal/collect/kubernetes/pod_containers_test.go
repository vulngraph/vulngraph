package kubernetes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestPodAsset_AllContainerFamilies(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	privileged := true
	limits := corev1.ResourceRequirements{Limits: corev1.ResourceList{
		corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("128Mi"),
	}}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod", UID: "pod-uid"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "shared:v1", Resources: limits}},
			InitContainers: []corev1.Container{
				{Name: "setup", Image: "setup:v1"},
				{Name: "proxy", Image: "shared:v1", RestartPolicy: &always},
			},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: "debug", Image: "debug:v1", SecurityContext: &corev1.SecurityContext{
					Privileged: &privileged, Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_PTRACE"}},
				},
			}}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: "app", Image: "shared:v1", ImageID: "sha256:shared", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "setup", Image: "setup:v1", ImageID: "sha256:setup", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}},
				{Name: "proxy", Image: "shared:v1", ImageID: "sha256:shared", Ready: true, RestartCount: 2, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", Image: "debug:v1", ImageID: "sha256:debug"}},
		},
	}
	a, children, edges := podAsset(pod, "cluster", time.Now())
	containers := map[string]asset.Asset{}
	images := map[string]bool{}
	for _, child := range children {
		switch child.Type {
		case "container":
			containers[child.Name] = child
		case "container_image":
			images[child.Metadata["image_id"]] = true
		}
	}
	require.Len(t, containers, 4)
	for name, kind := range map[string]string{"app": "application", "setup": "init", "proxy": "sidecar", "debug": "ephemeral"} {
		require.Equal(t, "cluster/pod/prod/web/container/"+name, containers[name].ID)
		require.Equal(t, kind, containers[name].Metadata["container_kind"])
		require.Equal(t, "pod-uid", containers[name].Metadata["pod_uid"])
	}
	require.Equal(t, "terminated", containers["setup"].Metadata["state"])
	require.Equal(t, "running", containers["proxy"].Metadata["state"])
	require.Equal(t, "2", containers["proxy"].Metadata["restart_count"])
	require.Equal(t, "true", containers["proxy"].Metadata["ready"])
	require.Len(t, images, 3)
	require.Equal(t, "sha256:debug,sha256:setup,sha256:shared", a.Metadata["image_ids"])
	imageEdges := 0
	for _, edge := range edges {
		if edge.EdgeType == "runs_image" {
			imageEdges++
		}
	}
	require.Equal(t, 3, imageEdges)
	require.Equal(t, "true", a.Metadata["privileged"])
	require.Equal(t, "SYS_PTRACE", a.Metadata["dangerous_capabilities"])
	require.Equal(t, "false", a.Metadata["has_resource_limits"], "native sidecar needs limits")
	pod.Spec.InitContainers[1].Resources = limits
	a, _, _ = podAsset(pod, "cluster", time.Now())
	require.Equal(t, "true", a.Metadata["has_resource_limits"], "ordinary init and ephemeral containers do not require steady-state limits")
}
