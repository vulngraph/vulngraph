package kubernetes

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vulngraph/vulngraph/internal/collect"
)

// completedScope finds one scope's claim in a result, if any — the k8s
// analogue of AWS's completedScopes helper, kept local since this package
// only ever looks a claim up by exact scope key.
func completedScope(res collect.Result, scope string) (collect.ScopeEnumeration, bool) {
	for _, se := range res.CompletedEnumerations {
		if se.Scope == scope {
			return se, true
		}
	}
	return collect.ScopeEnumeration{}, false
}

func namespaces(names ...string) []corev1.Namespace {
	out := make([]corev1.Namespace, len(names))
	for i, n := range names {
		out[i] = corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: n}}
	}
	return out
}

// A fully clean multi-namespace sweep earns every claim this collector can
// make: per-namespace ServiceAccounts, the cluster-wide k8s_namespace
// enumeration, and the cluster-wide RBAC lists.
func TestCollect_CleanSweep_ClaimsEveryEarnedScope(t *testing.T) {
	fake := &fakeK8s{
		namespaces: namespaces("app", "billing"),
		sas: map[string][]corev1.ServiceAccount{
			"app":     {{ObjectMeta: metav1.ObjectMeta{Name: "app-sa", Namespace: "app"}}},
			"billing": {{ObjectMeta: metav1.ObjectMeta{Name: "billing-sa", Namespace: "billing"}}},
		},
	}
	res, err := withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, res.Partial)

	se, ok := completedScope(res, "app/serviceaccounts")
	require.True(t, ok, "app namespace ServiceAccounts must be claimed")
	require.Equal(t, []string{"k8s_service_account"}, se.Types)
	require.Equal(t, 1, se.Count)

	se, ok = completedScope(res, "billing/serviceaccounts")
	require.True(t, ok, "billing namespace ServiceAccounts must be claimed")
	require.Equal(t, 1, se.Count)

	se, ok = completedScope(res, "cluster/namespaces")
	require.True(t, ok, "both namespaces got their asset emitted, so the cluster-wide claim is earned")
	require.Equal(t, []string{"k8s_namespace"}, se.Types)
	require.Equal(t, 2, se.Count)

	for _, scope := range []string{"cluster/clusterroles", "cluster/clusterrolebindings", "cluster/roles", "cluster/rolebindings"} {
		_, ok = completedScope(res, scope)
		require.True(t, ok, "%s must be claimed on a clean sweep", scope)
	}
}

// A ServiceAccount listing failure in one namespace must not suppress the
// claim for a sibling namespace, nor any cluster-wide claim that does not
// depend on ServiceAccounts.
func TestCollect_ServiceAccountError_DoesNotSuppressSiblingClaims(t *testing.T) {
	fake := &fakeK8sPerNamespace{
		fakeK8s:   fakeK8s{namespaces: namespaces("app", "billing")},
		saErrByNS: map[string]error{"app": errors.New("throttled")},
	}
	res, err := (&Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return fake, "prod", nil
	}}).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Partial, "the app namespace's SA failure must still flag Partial")

	_, ok := completedScope(res, "app/serviceaccounts")
	require.False(t, ok, "a failed listing must not be claimed")

	se, ok := completedScope(res, "billing/serviceaccounts")
	require.True(t, ok, "the billing namespace's own successful listing must still be claimed")
	require.Equal(t, 0, se.Count)

	// ServiceAccounts failing does not gate the k8s_namespace claim — that
	// one depends only on NetworkPolicies succeeding everywhere.
	_, ok = completedScope(res, "cluster/namespaces")
	require.True(t, ok, "an SA failure is unrelated to the k8s_namespace enumeration")
}

// A NetworkPolicy failure in ONE namespace drops the k8s_namespace claim for
// the WHOLE cluster (it's a single cluster-wide scope with no per-namespace
// granularity to fall back to), but must not touch any other namespace's
// unrelated claims.
func TestCollect_NetworkPolicyError_DropsClusterWideNamespaceClaimOnly(t *testing.T) {
	fake := &fakeK8sPerNamespace{
		fakeK8s: fakeK8s{
			namespaces: namespaces("app", "billing"),
			sas: map[string][]corev1.ServiceAccount{
				"billing": {{ObjectMeta: metav1.ObjectMeta{Name: "billing-sa", Namespace: "billing"}}},
			},
		},
		npErrByNS: map[string]error{"app": errors.New("throttled")},
	}
	res, err := (&Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return fake, "prod", nil
	}}).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, res.Partial)

	_, ok := completedScope(res, "cluster/namespaces")
	require.False(t, ok, "one namespace's NetworkPolicy failure taints the whole cluster-wide claim")

	se, ok := completedScope(res, "billing/serviceaccounts")
	require.True(t, ok, "billing's own ServiceAccounts listing is unaffected by app's NetworkPolicy error")
	require.Equal(t, 1, se.Count)
}

// A ConfigMap listing failure suppresses only its own namespace's configmaps
// claim, counted by assets actually produced (plaintext-secret hits), not by
// the raw ConfigMap count.
func TestCollect_ConfigMapClaim_CountsAssetsNotRawListing(t *testing.T) {
	fake := &fakeK8s{
		namespaces: namespaces("app"),
		cms: []corev1.ConfigMap{
			{ObjectMeta: metav1.ObjectMeta{Name: "clean", Namespace: "app"}, Data: map[string]string{"foo": "bar"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "leaky", Namespace: "app"}, Data: map[string]string{"password": "supersecretvalue"}},
		},
	}
	res, err := withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, res.Partial)

	se, ok := completedScope(res, "app/configmaps")
	require.True(t, ok)
	require.Equal(t, 1, se.Count, "only the ConfigMap with a plaintext-secret hit becomes a k8s_configmap asset")

	fake.cmErr = errors.New("throttled")
	res, err = withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	_, ok = completedScope(res, "app/configmaps")
	require.False(t, ok, "a failed listing must not be claimed")
}

// A permission gap on the namespaced Roles listing suppresses only its own
// scope — the sibling cluster-wide RBAC claims (ClusterRoles,
// ClusterRoleBindings) must still stand.
func TestCollect_RolePermissionError_DoesNotSuppressSiblingRBACClaims(t *testing.T) {
	fake := &fakeK8s{namespaces: namespaces("app"), roleErr: errors.New("forbidden")}
	res, err := withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	_, ok := completedScope(res, "cluster/roles")
	require.False(t, ok, "a failed Roles listing must not be claimed")

	_, ok = completedScope(res, "cluster/clusterroles")
	require.True(t, ok, "ClusterRoles succeeded independently and must still be claimed")
	_, ok = completedScope(res, "cluster/clusterrolebindings")
	require.True(t, ok, "ClusterRoleBindings succeeded independently and must still be claimed")
}

// --- fakeK8sPerNamespace: a second fake, only for tests needing distinct
// per-namespace error injection that the shared fakeK8s (one error value for
// all namespaces) cannot express. ---

type fakeK8sPerNamespace struct {
	fakeK8s
	saErrByNS map[string]error
	npErrByNS map[string]error
}

func (f *fakeK8sPerNamespace) ListServiceAccounts(_ context.Context, ns string) ([]corev1.ServiceAccount, error) {
	return f.sas[ns], f.saErrByNS[ns]
}

func (f *fakeK8sPerNamespace) ListNetworkPolicies(_ context.Context, ns string) ([]networkingv1.NetworkPolicy, error) {
	return nil, f.npErrByNS[ns]
}
