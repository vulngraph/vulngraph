package kubernetes

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type failedPodNamespace struct{ *fakeK8s }

func (f failedPodNamespace) ListPods(ctx context.Context, ns string) ([]corev1.Pod, error) {
	if ns == "unread" {
		return nil, errors.New("pod page forbidden")
	}
	return f.fakeK8s.ListPods(ctx, ns)
}

func TestPodDeletionCoverageRequiresEveryNamespace(t *testing.T) {
	f := &fakeK8s{namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "read"}}, {ObjectMeta: metav1.ObjectMeta{Name: "unread"}}}, pods: map[string][]corev1.Pod{"read": {{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "read"}}}, "unread": {{ObjectMeta: metav1.ObjectMeta{Name: "two", Namespace: "unread"}}}}}
	for _, failed := range []bool{false, true} {
		c := &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
			if failed {
				return failedPodNamespace{f}, "cluster-a", nil
			}
			return f, "cluster-a", nil
		}}
		result, err := c.Collect(t.Context(), nil)
		if failed {
			require.Error(t, err)
			require.Empty(t, result.CompletedEnumerations)
			continue
		}
		require.NoError(t, err)
		found := false
		for _, se := range result.CompletedEnumerations {
			if se.Scope != "cluster-a/kubernetes:pods" {
				continue
			}
			found = true
			require.Equal(t, 2, se.Count)
			scope, ok := forget.ParseScope(se.Scope)
			require.True(t, ok)
			require.Equal(t, "cluster-a", scope.Region)
			require.Equal(t, []string{"k8s_pod"}, scope.Family.Types)
		}
		require.True(t, found)
	}
	_, ok := forget.ParseScope("read/pods")
	require.False(t, ok, "namespace claims cannot authorize cluster-wide deletion")
}

func TestPodDeletionCoverageIncludesRemovedNamespaces(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return &fakeK8s{}, "empty-cluster", nil
	}}
	result, err := c.Collect(t.Context(), nil)
	require.NoError(t, err)
	found := false
	for _, se := range result.CompletedEnumerations {
		if se.Scope == "empty-cluster/kubernetes:pods" {
			found = true
			require.Zero(t, se.Count)
		}
	}
	require.True(t, found, "a complete namespace walk covers pods in namespaces that disappeared")
}
