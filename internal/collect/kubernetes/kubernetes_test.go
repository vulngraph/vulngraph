package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeK8s is a happy-path k8sAPI with per-method error injection for the
// best-effort families, so tests can pin the Partial semantics.
type fakeK8s struct {
	namespaces  []corev1.Namespace
	sas         map[string][]corev1.ServiceAccount // by namespace
	pods        map[string][]corev1.Pod            // by namespace
	netpols     []networkingv1.NetworkPolicy
	crbs        []rbacv1.ClusterRoleBinding
	crs         []rbacv1.ClusterRole
	roles       []rbacv1.Role
	rbs         []rbacv1.RoleBinding
	cms         []corev1.ConfigMap
	saErr       error
	cmErr       error
	npErr       error
	roleErr     error
	rbErr       error
	issuer      string
	issuerErr   error
	daemonSets  map[string][]appsv1.DaemonSet // by namespace
	logs        map[string]string             // by "<pod>/<container>"
	ownNS       string
	webhooks    []admissionv1.ValidatingWebhookConfiguration
	webhookErr  error
	vapBindings []admissionv1.ValidatingAdmissionPolicyBinding
	// customResources and crErr are keyed by plural resource name.
	customResources map[string][]unstructured.Unstructured
	crErr           map[string]error
}

func (f *fakeK8s) ServiceAccountIssuer(context.Context) (string, error) {
	return f.issuer, f.issuerErr
}

func (f *fakeK8s) PodLogTail(_ context.Context, _, pod, container string) (string, error) {
	l, ok := f.logs[pod+"/"+container]
	if !ok {
		return "", errors.New("container not found")
	}
	return l, nil
}

func (f *fakeK8s) OwnNamespace() string { return f.ownNS }

func (f *fakeK8s) ListValidatingWebhookConfigurations(context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error) {
	return f.webhooks, f.webhookErr
}

func (f *fakeK8s) ListValidatingAdmissionPolicyBindings(context.Context) ([]admissionv1.ValidatingAdmissionPolicyBinding, error) {
	return f.vapBindings, nil
}

// ListCustomResources serves f.crs by resource name; a resource with no entry
// is an absent CRD (NotFound), as the dynamic client reports it.
func (f *fakeK8s) ListCustomResources(_ context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
	if err := f.crErr[gvr.Resource]; err != nil {
		return nil, err
	}
	items, ok := f.customResources[gvr.Resource]
	if !ok {
		return nil, apierrors.NewNotFound(gvr.GroupResource(), "")
	}
	return items, nil
}

func (f *fakeK8s) ListNamespaces(context.Context) ([]corev1.Namespace, error) {
	return f.namespaces, nil
}
func (f *fakeK8s) ListPods(_ context.Context, ns string) ([]corev1.Pod, error) {
	return f.pods[ns], nil
}
func (f *fakeK8s) ListServices(context.Context, string) ([]corev1.Service, error) { return nil, nil }
func (f *fakeK8s) ListDeployments(context.Context, string) ([]appsv1.Deployment, error) {
	return nil, nil
}
func (f *fakeK8s) ListStatefulSets(context.Context, string) ([]appsv1.StatefulSet, error) {
	return nil, nil
}
func (f *fakeK8s) ListDaemonSets(_ context.Context, ns string) ([]appsv1.DaemonSet, error) {
	return f.daemonSets[ns], nil
}
func (f *fakeK8s) ListJobs(context.Context, string) ([]batchv1.Job, error) { return nil, nil }
func (f *fakeK8s) ListClusterRoles(context.Context) ([]rbacv1.ClusterRole, error) {
	return f.crs, nil
}
func (f *fakeK8s) ListClusterRoleBindings(context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	return f.crbs, nil
}
func (f *fakeK8s) ListRoles(context.Context) ([]rbacv1.Role, error) { return f.roles, f.roleErr }
func (f *fakeK8s) ListRoleBindings(context.Context) ([]rbacv1.RoleBinding, error) {
	return f.rbs, f.rbErr
}
func (f *fakeK8s) ListServiceAccounts(_ context.Context, ns string) ([]corev1.ServiceAccount, error) {
	return f.sas[ns], f.saErr
}
func (f *fakeK8s) ListIngresses(context.Context, string) ([]networkingv1.Ingress, error) {
	return nil, nil
}
func (f *fakeK8s) ListNetworkPolicies(context.Context, string) ([]networkingv1.NetworkPolicy, error) {
	return f.netpols, f.npErr
}
func (f *fakeK8s) ListConfigMaps(context.Context, string) ([]corev1.ConfigMap, error) {
	return f.cms, f.cmErr
}

func withFakeK8s(f *fakeK8s) *Collector {
	return &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return f, "prod", nil
	}}
}

func appNamespace() []corev1.Namespace {
	return []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app"}}}
}

func TestCollect_BestEffortErrorsFlagPartial(t *testing.T) {
	tests := []struct {
		name string
		fake *fakeK8s
	}{
		{"serviceaccount list error", &fakeK8s{namespaces: appNamespace(), saErr: errors.New("throttled")}},
		{"configmap list error", &fakeK8s{namespaces: appNamespace(), cmErr: errors.New("throttled")}},
		{"networkpolicy list error", &fakeK8s{namespaces: appNamespace(), npErr: errors.New("throttled")}},
		{"role list error", &fakeK8s{namespaces: appNamespace(), roleErr: errors.New("forbidden")}},
		{"rolebinding list error", &fakeK8s{namespaces: appNamespace(), rbErr: errors.New("forbidden")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := withFakeK8s(tt.fake).Collect(context.Background(), nil)
			require.NoError(t, err, "best-effort family errors must not fail the sync")
			require.True(t, res.Partial,
				"a best-effort skip marks the result partial so sync skips deletion reconciliation")
		})
	}
}

func TestCollect_CleanCollectionIsNotPartial(t *testing.T) {
	res, err := withFakeK8s(&fakeK8s{namespaces: appNamespace()}).Collect(context.Background(), nil)
	require.NoError(t, err)
	require.False(t, res.Partial, "a fully successful collection is not partial")
	// The clean run emits the cluster identity asset and the namespace asset
	// (the latter is skipped on a netpol error).
	require.Len(t, res.Assets, 2)
	require.Equal(t, "k8s_cluster", res.Assets[0].Type)
	require.Equal(t, "k8s_namespace", res.Assets[1].Type)
}

// System-namespace ServiceAccounts must be collected. The RBAC producer emits a
// `binds` edge for a subject in ANY namespace, so skipping the asset for
// kube-system made the edge unloadable: dropped `binds` rows are typically
// subjects in kube-system/monitoring/cert-manager whose
// ServiceAccounts exist — and those are the highest-privilege identities in the
// cluster, the ones `binds` exists to connect to the ClusterRoles they hold.
func TestCollect_SystemNamespaceServiceAccountsAreCollected(t *testing.T) {
	fake := &fakeK8s{
		namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}},
		sas: map[string][]corev1.ServiceAccount{"kube-system": {
			{ObjectMeta: metav1.ObjectMeta{Name: "gke-metrics-agent", Namespace: "kube-system"}},
		}},
		crbs: []rbacv1.ClusterRoleBinding{{
			ObjectMeta: metav1.ObjectMeta{Name: "metrics-agent"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "gke-metrics-agent", Namespace: "kube-system"},
			},
		}},
	}
	res, err := withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	saID := "prod/namespace/kube-system/serviceaccount/gke-metrics-agent"
	var found bool
	for _, a := range res.Assets {
		if a.ID == saID {
			found = true
			require.Equal(t, "k8s_service_account", a.Type)
		}
	}
	require.True(t, found, "a system-namespace ServiceAccount must exist as an asset or its binds edge is dangling")

	var bound bool
	for _, e := range res.Edges {
		if e.EdgeType == "binds" && e.SrcID == saID {
			bound = true
		}
	}
	require.True(t, bound, "the binds edge must survive alongside the asset it points at")
}

// A binding subject the collector can PROVE does not exist must not become an
// edge. RoleBindings left behind by uninstalled tooling (e.g. Helm 2's `tiller`
// ServiceAccounts in long-deleted namespaces) still name subjects that no
// longer exist. An edge to a nonexistent endpoint can never load; all it does is inflate
// the dangling counter that is supposed to detect real regressions.
//
// Absence of evidence must fail OPEN, which is the other half of the test: when the
// namespace exists but its ServiceAccount list errored, the collector knows nothing
// and the edge is still emitted.
func TestCollect_BindsEdgeSuppressedForProvablyAbsentSubject(t *testing.T) {
	crb := []rbacv1.ClusterRoleBinding{{
		ObjectMeta: metav1.ObjectMeta{Name: "tiller-admin"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "tiller", Namespace: "billing-helm"}, // namespace is gone
			{Kind: "ServiceAccount", Name: "ghost", Namespace: "app"},           // namespace listed, SA absent
			{Kind: "ServiceAccount", Name: "real", Namespace: "app"},            // collected
		},
	}}
	fake := &fakeK8s{
		namespaces: appNamespace(),
		sas: map[string][]corev1.ServiceAccount{"app": {
			{ObjectMeta: metav1.ObjectMeta{Name: "real", Namespace: "app"}},
		}},
		crbs: crb,
	}
	res, err := withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)

	srcs := map[string]bool{}
	for _, e := range res.Edges {
		if e.EdgeType == "binds" && e.SrcType == "k8s_service_account" {
			srcs[e.SrcID] = true
		}
	}
	require.Equal(t, map[string]bool{"prod/namespace/app/serviceaccount/real": true}, srcs,
		"only the ServiceAccount that exists may produce a binds edge")

	// Fail open: the SA list errored, so nothing is proven and every subject stays.
	fake.saErr = errors.New("throttled")
	res, err = withFakeK8s(fake).Collect(context.Background(), nil)
	require.NoError(t, err)
	open := 0
	for _, e := range res.Edges {
		if e.EdgeType == "binds" && e.SrcType == "k8s_service_account" && e.SrcID != "prod/namespace/billing-helm/serviceaccount/tiller" {
			open++
		}
	}
	require.Equal(t, 2, open,
		"an un-listed namespace proves nothing — suppressing on it would delete real RBAC topology on a throttle")
}

func TestCollect_NetworkPolicyError_SkipsNamespaceAsset(t *testing.T) {
	res, err := withFakeK8s(&fakeK8s{namespaces: appNamespace(), npErr: errors.New("throttled")}).
		Collect(context.Background(), nil)
	require.NoError(t, err)
	// Emitting has_network_policy=false on a failed list would fire the
	// k8s-namespace-no-network-policy check falsely — the asset must be absent.
	// The cluster identity asset is unaffected by a namespace-scoped failure.
	for _, a := range res.Assets {
		require.NotEqual(t, "k8s_namespace", a.Type)
	}
}

func lbService(annotations map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "app", Annotations: annotations},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "10.0.5.5"}},
		}},
	}
}

func lbServiceWithClass(class string, annotations map[string]string) corev1.Service {
	svc := lbService(annotations)
	svc.Spec.LoadBalancerClass = &class
	return svc
}

func TestServiceLBScheme(t *testing.T) {
	const (
		pub      = schemeInternetFacing
		internal = schemeInternal
		unstated = schemeUnstated
	)
	tests := []struct {
		name        string
		annotations map[string]string
		want        lbScheme
	}{
		{"aws nlb type is the in-tree provider: internet-facing", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "nlb"}, pub},
		{"lbc type external without a scheme is unstated", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "external"}, unstated},
		{"lbc type nlb-ip without a scheme is unstated", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "nlb-ip"}, unstated},
		{"lbc type external internal", map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-type":   "external",
			"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
		}, internal},
		{"lbc type external internet-facing", map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-type":   "external",
			"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing",
		}, pub},
		{"lbc deprecated internal=true is internal", map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-type":     "external",
			"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
		}, internal},
		{"lbc deprecated internal=false is internet-facing", map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-type":     "external",
			"service.beta.kubernetes.io/aws-load-balancer-internal": "false",
		}, pub},
		{"lbc scheme wins over deprecated internal", map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-type":     "external",
			"service.beta.kubernetes.io/aws-load-balancer-scheme":   "internet-facing",
			"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
		}, pub},
		{"lbc unrecognised scheme is not private", map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-type":   "external",
			"service.beta.kubernetes.io/aws-load-balancer-scheme": "public",
		}, pub},
		{"external (no annotation)", nil, pub},
		{"aws internal true", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"}, internal},
		{"aws internal legacy cidr", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "0.0.0.0/0"}, internal},
		{"aws scheme internal", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}, internal},
		{"azure internal", map[string]string{"service.beta.kubernetes.io/azure-load-balancer-internal": "true"}, internal},
		{"gcp internal", map[string]string{"cloud.google.com/load-balancer-type": "Internal"}, internal},
		{"gke internal", map[string]string{"networking.gke.io/load-balancer-type": "Internal"}, internal},
		{"aws external scheme", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"}, pub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, serviceLBScheme(lbService(tt.annotations)))
		})
	}
}

// A controller-managed Service with no scheme annotation takes its NLB's
// existing scheme or the controller's configured default, neither of which
// the Service shows, so it is unstated rather than internal.
func TestServiceLBScheme_LoadBalancerClass(t *testing.T) {
	scheme := "service.beta.kubernetes.io/aws-load-balancer-scheme"
	legacyInternal := "service.beta.kubernetes.io/aws-load-balancer-internal"
	tests := []struct {
		name        string
		class       string
		annotations map[string]string
		want        lbScheme
	}{
		{"lbc class without a scheme is unstated", "service.k8s.aws/nlb", nil, schemeUnstated},
		{"lbc class internet-facing", "service.k8s.aws/nlb", map[string]string{scheme: "internet-facing"}, schemeInternetFacing},
		{"lbc class scheme internal", "service.k8s.aws/nlb", map[string]string{scheme: "internal"}, schemeInternal},
		{"lbc class deprecated internal", "service.k8s.aws/nlb", map[string]string{legacyInternal: "true"}, schemeInternal},
		{"auto mode class without a scheme is unstated", "eks.amazonaws.com/nlb", nil, schemeUnstated},
		{"auto mode class internet-facing", "eks.amazonaws.com/nlb", map[string]string{scheme: "internet-facing"}, schemeInternetFacing},
		{"auto mode class scheme internal", "eks.amazonaws.com/nlb", map[string]string{scheme: "internal"}, schemeInternal},
		{"auto mode ignores the deprecated internal annotation", "eks.amazonaws.com/nlb", map[string]string{legacyInternal: "true"}, schemeUnstated},
		{"unknown class keeps the annotation rules", "example.com/lb", nil, schemeInternetFacing},
		{"unknown class with internal annotation", "example.com/lb", map[string]string{legacyInternal: "true"}, schemeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, serviceLBScheme(lbServiceWithClass(tt.class, tt.annotations)))
		})
	}
}

func TestServiceAsset_SourceRanges(t *testing.T) {
	legacy := "service.beta.kubernetes.io/load-balancer-source-ranges"
	tests := []struct {
		name        string
		class       string
		spec        []string
		annotations map[string]string
		ranges      string
		restricted  string
	}{
		{"none set", "", nil, nil, "", "false"},
		{"office range", "", []string{"203.0.113.0/24"}, nil, "203.0.113.0/24", "true"},
		{"world v4", "", []string{"0.0.0.0/0"}, nil, "0.0.0.0/0", "false"},
		{"world v6 alongside a range", "", []string{"203.0.113.0/24", "::/0"}, nil, "203.0.113.0/24,::/0", "false"},
		{"halves of the world", "", []string{"0.0.0.0/1", "128.0.0.0/1"}, nil, "0.0.0.0/1,128.0.0.0/1", "false"},
		{"unparseable entry", "", []string{"203.0.113.0/24", "office"}, nil, "203.0.113.0/24,office", "false"},
		{"legacy annotation", "", nil, map[string]string{legacy: "198.51.100.0/24, 203.0.113.0/24"}, "198.51.100.0/24,203.0.113.0/24", "true"},
		{"spec wins over annotation", "", []string{"203.0.113.0/24"}, map[string]string{legacy: "0.0.0.0/0"}, "203.0.113.0/24", "true"},
		{"lbc class honours the legacy annotation", "service.k8s.aws/nlb", nil, map[string]string{legacy: "203.0.113.0/24"}, "203.0.113.0/24", "true"},
		{"auto mode ignores the legacy annotation", "eks.amazonaws.com/nlb", nil, map[string]string{legacy: "203.0.113.0/24"}, "", "false"},
		{"auto mode spec ranges", "eks.amazonaws.com/nlb", []string{"203.0.113.0/24"}, nil, "203.0.113.0/24", "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := lbService(tt.annotations)
			if tt.class != "" {
				svc = lbServiceWithClass(tt.class, tt.annotations)
			}
			svc.Spec.LoadBalancerSourceRanges = tt.spec
			a := serviceAsset(svc, "c", time.Now())
			require.Equal(t, tt.ranges, a.Metadata["source_ranges"])
			require.Equal(t, tt.restricted, a.Metadata["source_restricted"])
			require.Equal(t, "10.0.5.5", a.PublicIP, "a source restriction does not make the address private")
		})
	}
}

func TestServiceAsset_InternalLBHasNoPublicIP(t *testing.T) {
	now := time.Now()
	// Internal LB: private status IP must NOT surface as PublicIP.
	internal := serviceAsset(lbService(map[string]string{"cloud.google.com/load-balancer-type": "Internal"}), "c", now)
	require.Empty(t, internal.PublicIP, "internal LB must not be treated as internet-reachable")
	require.Equal(t, "true", internal.Metadata["internal"])
	require.Equal(t, "false", internal.Metadata["scheme_assumed"])

	// External LB: status address surfaces as PublicIP.
	external := serviceAsset(lbService(nil), "c", now)
	require.Equal(t, "10.0.5.5", external.PublicIP)
	require.Equal(t, "false", external.Metadata["internal"])
	require.Equal(t, "false", external.Metadata["scheme_assumed"])

	// A controller NLB annotated internal is internal.
	lbcInternal := serviceAsset(lbServiceWithClass("service.k8s.aws/nlb",
		map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}), "c", now)
	require.Empty(t, lbcInternal.PublicIP)
	require.Equal(t, "true", lbcInternal.Metadata["internal"])

	// A controller NLB with no scheme annotation may be internet-facing (an
	// existing NLB's scheme or the controller's default): its address is kept
	// and flagged as resting on an assumed scheme, never read as private.
	lbc := serviceAsset(lbServiceWithClass("service.k8s.aws/nlb", nil), "c", now)
	require.Equal(t, "10.0.5.5", lbc.PublicIP)
	require.Equal(t, "false", lbc.Metadata["internal"])
	require.Equal(t, "true", lbc.Metadata["scheme_assumed"])
	require.Equal(t, "service.k8s.aws/nlb", lbc.Metadata["load_balancer_class"])
}

func TestPodAsset_OwnerWorkloadMetadata(t *testing.T) {
	pod := func(labels map[string]string, refs ...metav1.OwnerReference) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "p", Namespace: "billing", Labels: labels, OwnerReferences: refs,
		}}
	}
	tests := []struct {
		name     string
		pod      corev1.Pod
		wantKind string // "" = no owner metadata expected
		wantName string
	}{
		{
			name: "replicaset pod resolves to deployment via pod-template-hash",
			pod: pod(map[string]string{"pod-template-hash": "7f9c4"},
				metav1.OwnerReference{Kind: "ReplicaSet", Name: "api-7f9c4"}),
			wantKind: "Deployment", wantName: "api",
		},
		{
			name:     "replicaset pod without matching hash keeps the replicaset",
			pod:      pod(nil, metav1.OwnerReference{Kind: "ReplicaSet", Name: "standalone-rs"}),
			wantKind: "ReplicaSet", wantName: "standalone-rs",
		},
		{
			name:     "statefulset owns pods directly",
			pod:      pod(nil, metav1.OwnerReference{Kind: "StatefulSet", Name: "db"}),
			wantKind: "StatefulSet", wantName: "db",
		},
		{
			name:     "daemonset owns pods directly",
			pod:      pod(nil, metav1.OwnerReference{Kind: "DaemonSet", Name: "node-agent"}),
			wantKind: "DaemonSet", wantName: "node-agent",
		},
		{
			name:     "job owns pods directly",
			pod:      pod(nil, metav1.OwnerReference{Kind: "Job", Name: "backup-123"}),
			wantKind: "Job", wantName: "backup-123",
		},
		{
			name: "bare pod has no owner metadata",
			pod:  pod(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, _ := podAsset(tt.pod, "prod", time.Now())
			require.Equal(t, tt.wantKind, a.Metadata["owner_kind"])
			require.Equal(t, tt.wantName, a.Metadata["owner_name"])
		})
	}
}

// TestPodAsset_ContainersPromotedToAssets pins the container asset ID scheme
// ("<pod ID>/container/<name>") that guardduty.go's EKS-container join in
// internal/collect/aws/guardduty.go must match exactly, plus the
// pod->container runs_container edge.
func TestPodAsset_ContainersPromotedToAssets(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api-7f9c4", Namespace: "billing"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "app:1.2.3"},
				{Name: "sidecar", Image: "envoy:1.0"},
			},
		},
	}
	a, extra, edges := podAsset(pod, "prod", time.Now())
	require.Equal(t, "prod/pod/billing/api-7f9c4", a.ID)

	var containers []struct{ id, name, image string }
	for _, e := range extra {
		if e.Type != "container" {
			continue
		}
		containers = append(containers, struct{ id, name, image string }{e.ID, e.Name, e.Metadata["image"]})
	}
	require.Len(t, containers, 2, "one container asset per pod.Spec.Containers entry")
	require.Contains(t, containers, struct{ id, name, image string }{"prod/pod/billing/api-7f9c4/container/app", "app", "app:1.2.3"})
	require.Contains(t, containers, struct{ id, name, image string }{"prod/pod/billing/api-7f9c4/container/sidecar", "sidecar", "envoy:1.0"})

	var runsContainerEdges int
	for _, e := range edges {
		if e.EdgeType != "runs_container" {
			continue
		}
		runsContainerEdges++
		require.Equal(t, "prod/pod/billing/api-7f9c4", e.SrcID)
		require.Equal(t, "k8s_pod", e.SrcType)
		require.Equal(t, "container", e.DstType)
	}
	require.Equal(t, 2, runsContainerEdges)
}

// TestWorkloadAssetIDsMatchOwnerIDScheme pins the ID scheme of the three new
// workload collectors to the ownerID format checks.go's workloadAggregator
// builds from a pod's owner_kind/owner_name metadata
// ("<cluster>/<lowercase kind>/<namespace>/<name>") — a mismatch here means
// aggregated per-pod findings can never resolve to the collected asset.
func TestWorkloadAssetIDsMatchOwnerIDScheme(t *testing.T) {
	now := time.Now()
	replicas := int32(3)

	sts := statefulSetAsset(appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "billing", Labels: map[string]string{"app": "db"}},
		Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
		Status:     appsv1.StatefulSetStatus{AvailableReplicas: 3},
	}, "prod", now)
	require.Equal(t, "prod/statefulset/billing/db", sts.ID)
	require.Equal(t, "k8s_statefulset", sts.Type)
	require.Equal(t, "3", sts.Metadata["replicas"])
	require.Equal(t, "3", sts.Metadata["available_replicas"])
	require.Equal(t, map[string]string{"app": "db"}, sts.Tags, "labels surface as Tags, matching deploymentAsset")

	ds := daemonSetAsset(appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "node-agent", Namespace: "monitoring"},
		Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 5, NumberAvailable: 4},
	}, "prod", now)
	require.Equal(t, "prod/daemonset/monitoring/node-agent", ds.ID)
	require.Equal(t, "k8s_daemonset", ds.Type)
	require.Equal(t, "5", ds.Metadata["desired_scheduled"])
	require.Equal(t, "4", ds.Metadata["available_replicas"])

	job := jobAsset(batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "backup-123", Namespace: "billing"},
		Status:     batchv1.JobStatus{Active: 1, Succeeded: 0, Failed: 2},
	}, "prod", now)
	require.Equal(t, "prod/job/billing/backup-123", job.ID)
	require.Equal(t, "k8s_job", job.Type)
	require.Equal(t, "1", job.Metadata["active"])
	require.Equal(t, "0", job.Metadata["succeeded"])
	require.Equal(t, "2", job.Metadata["failed"])
}

// A missing RBAC permission must NOT make the result Partial. Partial gates all
// deletion detection and finding auto-resolution for the whole connector
// (jobs/sync.go), so flagging it on a Forbidden would permanently disable asset
// pruning for Kubernetes and re-open a previously closed lifecycle hole — the
// collector's ClusterRole is deployed outside this repo and has never granted
// roles/rolebindings list, so this is the FIRST-DEPLOY path, not an edge case.
// A transient failure is different and must still flag Partial.
func TestCollect_MissingRBACPermissionIsNotPartial(t *testing.T) {
	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "roles"}, "", errors.New("nope"))

	c := &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return &fakeK8s{roleErr: forbidden, rbErr: forbidden}, "c1", nil
	}}
	res, err := c.Collect(context.Background(), map[string]string{})
	require.NoError(t, err)
	require.False(t, res.Partial,
		"a Forbidden on namespaced RBAC is an operator-fixable coverage gap, not untrustworthy inventory")
}

func TestCollect_TransientRBACErrorIsPartial(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return &fakeK8s{roleErr: errors.New("dial tcp: i/o timeout")}, "c1", nil
	}}
	res, err := c.Collect(context.Background(), map[string]string{})
	require.NoError(t, err)
	require.True(t, res.Partial,
		"a transient failure means the inventory really is incomplete — deletion detection must pause")
}

// Unlike the RBAC/cert-manager sites, ServiceAccounts, NetworkPolicies, and
// ConfigMaps must NOT carve out permission errors: findDeletedAssets
// (internal/jobs/sync.go) is still a flat global set-difference over the
// whole connector's stored hashes with no per-type/per-scope restriction —
// nothing consumes collect.Result.CompletedEnumerations yet even though the
// success path now populates it (see MarkComplete's doc comment for what a
// future scoped-enforce mode would need). All three families currently have
// stored assets and a live grant, so a Forbidden on any of them — permission
// gap or not — must still flag Partial, or a narrowed/revoked grant would
// silently prune every stored asset of that type and auto-resolve its
// findings.
func TestCollect_MissingPermissionOnOtherBestEffortFamilies_IsStillPartial(t *testing.T) {
	tests := []struct {
		name string
		fake *fakeK8s
	}{
		{"serviceaccount forbidden", &fakeK8s{namespaces: appNamespace(), saErr: apierrors.NewForbidden(
			schema.GroupResource{Resource: "serviceaccounts"}, "", errors.New("nope"))}},
		{"networkpolicy forbidden", &fakeK8s{namespaces: appNamespace(), npErr: apierrors.NewForbidden(
			schema.GroupResource{Group: "networking.k8s.io", Resource: "networkpolicies"}, "", errors.New("nope"))}},
		{"configmap forbidden", &fakeK8s{namespaces: appNamespace(), cmErr: apierrors.NewForbidden(
			schema.GroupResource{Resource: "configmaps"}, "", errors.New("nope"))}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := withFakeK8s(tt.fake).Collect(context.Background(), nil)
			require.NoError(t, err)
			require.True(t, res.Partial,
				"a Forbidden on this family must still flag Partial: findDeletedAssets has no per-type "+
					"scoping and nothing consumes CompletedEnumerations yet, so Partial is the only "+
					"thing stopping stored assets of this type from being pruned as deleted")
		})
	}
}

// The transient counterpart for the same three families: a non-permission
// error must still flag Partial. TestCollect_BestEffortErrorsFlagPartial
// above already covers this with plain errors.New, which is not a permission
// error — this pins it explicitly against isPermissionError's classification
// so the two behaviors can't silently converge.
func TestCollect_TransientErrorOnOtherBestEffortFamilies_IsPartial(t *testing.T) {
	tests := []struct {
		name string
		fake *fakeK8s
	}{
		{"serviceaccount transient", &fakeK8s{namespaces: appNamespace(), saErr: errors.New("dial tcp: i/o timeout")}},
		{"networkpolicy transient", &fakeK8s{namespaces: appNamespace(), npErr: errors.New("dial tcp: i/o timeout")}},
		{"configmap transient", &fakeK8s{namespaces: appNamespace(), cmErr: errors.New("dial tcp: i/o timeout")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := withFakeK8s(tt.fake).Collect(context.Background(), nil)
			require.NoError(t, err)
			require.True(t, res.Partial)
		})
	}
}

// Init containers were never scanned: podAsset iterated pod.Spec.Containers
// only, so the four security-context checks (privileged, run_as_root,
// allow_priv_escalation, dangerous_capabilities) were blind to the container
// that runs FIRST and is routinely the most privileged one in the pod.
//
// The shape below mirrors a chart-deployed pod: a Helm-chart-based
// StatefulSet runs an initContainer "configure-sysctl" with privileged: true
// and runAsUser: 0, in a namespace that is neither exempt nor PSA-labelled,
// and the asset recorded privileged=false with no finding.
func TestPodAsset_InitContainersAggregateSecurityContext(t *testing.T) {
	tr := func(b bool) *bool { return &b }
	u := func(i int64) *int64 { return &i }

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "search-0", Namespace: "search"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:  "configure-sysctl",
				Image: "busybox:1.35",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               tr(true),
					RunAsUser:                u(0),
					AllowPrivilegeEscalation: tr(true),
					Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}},
				},
			}},
			Containers: []corev1.Container{{
				Name:  "elasticsearch",
				Image: "elasticsearch:7.17.0",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               tr(false),
					RunAsNonRoot:             tr(true),
					RunAsUser:                u(1000),
					AllowPrivilegeEscalation: tr(false),
				},
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("1"),
					corev1.ResourceMemory: resource.MustParse("2Gi"),
				}},
			}},
		},
	}

	a, extra, _ := podAsset(pod, "prod", time.Now())
	require.Equal(t, "true", a.Metadata["privileged"], "a privileged init container makes the pod privileged")
	require.Equal(t, "true", a.Metadata["run_as_root"])
	require.Equal(t, "true", a.Metadata["allow_priv_escalation"])
	require.Equal(t, "SYS_ADMIN", a.Metadata["dangerous_capabilities"])

	// Resource limits stay app-container-only: an init container runs to
	// completion in seconds and its limits do not cause a steady-state OOMKill.
	require.Equal(t, "true", a.Metadata["has_resource_limits"])
	// Images likewise stay app-container-only — the pod is not running the
	// init image when a finding lands on it.
	require.Equal(t, "elasticsearch:7.17.0", a.Metadata["images"])
	for _, e := range extra {
		require.NotEqual(t, "configure-sysctl", e.Name, "init containers are not promoted to container assets")
	}
}

// A pod whose init containers are all benign must not be flagged by them.
func TestPodAsset_BenignInitContainerChangesNothing(t *testing.T) {
	tr := func(b bool) *bool { return &b }
	u := func(i int64) *int64 { return &i }
	safe := &corev1.SecurityContext{
		Privileged:               tr(false),
		RunAsNonRoot:             tr(true),
		RunAsUser:                u(1000),
		AllowPrivilegeEscalation: tr(false),
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "app"},
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{Name: "wait-for-db", Image: "busybox", SecurityContext: safe}},
			Containers:     []corev1.Container{{Name: "app", Image: "app:1", SecurityContext: safe}},
		},
	}
	a, _, _ := podAsset(pod, "prod", time.Now())
	require.Equal(t, "false", a.Metadata["privileged"])
	require.Equal(t, "false", a.Metadata["run_as_root"])
	require.Equal(t, "false", a.Metadata["allow_priv_escalation"])
	require.Empty(t, a.Metadata["dangerous_capabilities"])
}

// Partial must accumulate via OR across every best-effort site, never get
// clobbered by a later site's assignment. ServiceAccounts is unconditional
// (an unfetched SA list is always Partial, permission or not — see the
// comment at that site) and runs inside the per-namespace loop, so it sets
// Partial=true first. Roles then hits a Forbidden, which — being a
// permission gap on a namespaced-RBAC call the collector's ClusterRole has
// never granted — is legitimately exempt from raising Partial on its own
// (TestCollect_MissingRBACPermissionIsNotPartial). But it must not erase the
// true SA already set: if that site were ever rewritten from
// `result.Partial = result.Partial || !isPermissionError(err)` to
// `result.Partial = !isPermissionError(err)`, this would go from true to
// false and this test would catch it, even though every other test in this
// file would still pass.
func TestCollect_LaterPermissionCarveOutDoesNotClobberEarlierPartial(t *testing.T) {
	forbidden := apierrors.NewForbidden(
		schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "roles"}, "", errors.New("nope"))

	c := &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) {
		return &fakeK8s{
			namespaces: appNamespace(),
			saErr:      errors.New("dial tcp: i/o timeout"), // earlier site, unconditional Partial=true
			roleErr:    forbidden,                           // later site, permission carve-out
		}, "c1", nil
	}}
	res, err := c.Collect(context.Background(), map[string]string{})
	require.NoError(t, err)
	require.True(t, res.Partial,
		"an earlier family's Partial=true must survive a later family's permission-carve-out site — "+
			"that site must OR into the accumulator, never assign over it")
}
