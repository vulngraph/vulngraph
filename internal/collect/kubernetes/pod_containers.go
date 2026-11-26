package kubernetes

import (
	"strconv"

	corev1 "k8s.io/api/core/v1"
)

type podContainer struct {
	corev1.Container
	kind   string
	status *corev1.ContainerStatus
}

// podContainers preserves the identity of application, init, native sidecar
// and ephemeral containers while sharing their security-context handling.
func podContainers(pod corev1.Pod) []podContainer {
	out := make([]podContainer, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	add := func(c corev1.Container, kind string, statuses []corev1.ContainerStatus) {
		entry := podContainer{Container: c, kind: kind}
		for i := range statuses {
			if statuses[i].Name == c.Name {
				entry.status = &statuses[i]
				break
			}
		}
		out = append(out, entry)
	}
	for _, c := range pod.Spec.Containers {
		add(c, "application", pod.Status.ContainerStatuses)
	}
	for _, c := range pod.Spec.InitContainers {
		kind := "init"
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			kind = "sidecar"
		}
		add(c, kind, pod.Status.InitContainerStatuses)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		add(corev1.Container{
			Name: c.Name, Image: c.Image, SecurityContext: c.SecurityContext,
			Env: c.Env, EnvFrom: c.EnvFrom, Ports: c.Ports,
		}, "ephemeral", pod.Status.EphemeralContainerStatuses)
	}
	return out
}

func containerState(status *corev1.ContainerStatus) string {
	switch {
	case status == nil:
		return "unknown"
	case status.State.Running != nil:
		return "running"
	case status.State.Waiting != nil:
		return "waiting"
	case status.State.Terminated != nil:
		return "terminated"
	default:
		return "unknown"
	}
}

func (c podContainer) metadata(pod corev1.Pod) map[string]string {
	m := map[string]string{
		"namespace": pod.Namespace, "pod": pod.Name, "pod_uid": string(pod.UID),
		"image": c.Image, "container_kind": c.kind, "state": containerState(c.status),
	}
	if c.status != nil {
		m["ready"] = strconv.FormatBool(c.status.Ready)
		m["restart_count"] = strconv.FormatInt(int64(c.status.RestartCount), 10)
	}
	return m
}

func podImageStatuses(pod corev1.Pod) []corev1.ContainerStatus {
	out := make([]corev1.ContainerStatus, 0, len(pod.Status.ContainerStatuses)+len(pod.Status.InitContainerStatuses)+len(pod.Status.EphemeralContainerStatuses))
	out = append(out, pod.Status.ContainerStatuses...)
	out = append(out, pod.Status.InitContainerStatuses...)
	return append(out, pod.Status.EphemeralContainerStatuses...)
}
