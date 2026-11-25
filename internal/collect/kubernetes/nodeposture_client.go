package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// nodeposture_client.go is the real client's half of the node-posture read
// (nodeposture.go): the pod log tail and the namespace Vulngraph runs in.

// podLogTimeout bounds one log read: the kubelet streams it, and a node that
// does not answer must not stall the sweep.
const podLogTimeout = 15 * time.Second

// podLogTailLines and podLogLimitBytes size the read to a few reader passes.
const (
	podLogTailLines  = 20
	podLogLimitBytes = 4 << 20
)

// PodLogTail returns the last lines of a container's log (pods/log get).
func (r *realK8s) PodLogTail(ctx context.Context, ns, pod, container string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, podLogTimeout)
	defer cancel()
	tail, limit := int64(podLogTailLines), int64(podLogLimitBytes)
	raw, err := r.cs.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{
		Container: container, TailLines: &tail, LimitBytes: &limit,
	}).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("PodLogTail: %w", err)
	}
	return string(raw), nil
}

// OwnNamespace is the namespace Vulngraph itself runs in, "" when unknown.
func (r *realK8s) OwnNamespace() string { return r.ownNamespace }

// saNamespaceFile is where the kubelet projects the pod's own namespace.
const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func readOwnNamespace() string {
	b, err := os.ReadFile(saNamespaceFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
