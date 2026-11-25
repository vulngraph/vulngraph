package kubernetes

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func ptr[T any](v T) *T { return &v }

// A pod whose spec sets nothing: every hardening signal is at its permissive
// Kubernetes default, and every list is an observed "none".
func TestPodHardeningSignals_UnhardenedDefaults(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "app"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:1"}}},
	}
	got := podHardeningSignals(pod)
	require.Equal(t, map[string]string{
		"host_ipc": "false", "host_path_volumes": "", "host_ports": "", "added_capabilities": "",
		"dangerous_capabilities": "", "net_raw_retained": "true", "seccomp_unrestricted": "true",
		"apparmor_unconfined": "false", "writable_root_fs": "true", "secret_env_refs": "",
		"windows_host_process": "false", "pod_os": "",
	}, got)
}

func TestPodHardeningSignals_FullyHardened(t *testing.T) {
	sc := &corev1.SecurityContext{
		ReadOnlyRootFilesystem: ptr(true),
		Capabilities:           &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_BIND_SERVICE"}},
	}
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "app"},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
			InitContainers:  []corev1.Container{{Name: "init", SecurityContext: sc}},
			Containers:      []corev1.Container{{Name: "app", SecurityContext: sc}},
		},
	}
	got := podHardeningSignals(pod)
	require.Equal(t, "false", got["net_raw_retained"])
	require.Equal(t, "false", got["seccomp_unrestricted"])
	require.Equal(t, "false", got["writable_root_fs"])
	require.Equal(t, "NET_BIND_SERVICE", got["added_capabilities"])
	require.Empty(t, got["dangerous_capabilities"])
}

func TestPodHardeningSignals_RecordsEveryWeakening(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "app", Annotations: map[string]string{
			"container.apparmor.security.beta.kubernetes.io/legacy": "unconfined",
		}},
		Spec: corev1.PodSpec{
			HostIPC: true,
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: ptr(true)},
			},
			Volumes: []corev1.Volume{
				{Name: "sock", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}}},
				{Name: "data", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/data"}}},
				{Name: "tmp", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
			},
			InitContainers: []corev1.Container{{
				Name: "init",
				// A capability spelled the other ways runtimes accept, added after
				// a drop ALL: NET_RAW is back, and so is a dangerous capability.
				SecurityContext: &corev1.SecurityContext{
					ReadOnlyRootFilesystem: ptr(true),
					Capabilities: &corev1.Capabilities{
						Drop: []corev1.Capability{"ALL"},
						Add:  []corev1.Capability{"CAP_SYS_ADMIN", "net_raw"},
					},
				},
				EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "bulk"}}}},
			}},
			Containers: []corev1.Container{{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					ReadOnlyRootFilesystem: ptr(true),
					SeccompProfile:         &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined},
					AppArmorProfile:        &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeUnconfined},
					Capabilities:           &corev1.Capabilities{Drop: []corev1.Capability{"NET_RAW"}},
				},
				Ports: []corev1.ContainerPort{{ContainerPort: 8080, HostPort: 8080}, {ContainerPort: 9090}},
				Env: []corev1.EnvVar{
					{Name: "DB_PASSWORD", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "password"}}},
					{Name: "PLAIN", Value: "x"},
				},
			}},
		},
	}
	got := podHardeningSignals(pod)
	require.Equal(t, "true", got["host_ipc"])
	require.Equal(t, "/data,/var/run/docker.sock", got["host_path_volumes"])
	require.Equal(t, "8080", got["host_ports"])
	require.Equal(t, "NET_RAW,SYS_ADMIN", got["added_capabilities"])
	require.Equal(t, "SYS_ADMIN", got["dangerous_capabilities"], "CAP_-prefixed spelling is still SYS_ADMIN")
	require.Equal(t, "true", got["net_raw_retained"], "adding NET_RAW back undoes the drop")
	require.Equal(t, "true", got["seccomp_unrestricted"], "a container-level Unconfined overrides the pod's RuntimeDefault")
	require.Equal(t, "true", got["apparmor_unconfined"])
	require.Equal(t, "false", got["writable_root_fs"])
	require.Equal(t, "bulk,db", got["secret_env_refs"])
	require.Equal(t, "true", got["windows_host_process"])
}

func TestPodOS(t *testing.T) {
	pod := corev1.Pod{Spec: corev1.PodSpec{NodeSelector: map[string]string{"kubernetes.io/os": "windows"}}}
	require.Equal(t, "windows", podHardeningSignals(pod)["pod_os"])
	pod.Spec.OS = &corev1.PodOS{Name: corev1.Linux}
	require.Equal(t, "linux", podHardeningSignals(pod)["pod_os"], "spec.os wins over the node selector")
	hp := corev1.Pod{Spec: corev1.PodSpec{SecurityContext: &corev1.PodSecurityContext{
		WindowsOptions: &corev1.WindowsSecurityContextOptions{HostProcess: ptr(true)}},
		Containers: []corev1.Container{{Name: "c"}}}}
	require.Equal(t, "windows", podHardeningSignals(hp)["pod_os"], "HostProcess exists only on Windows")
	require.Empty(t, podHardeningSignals(corev1.Pod{})["pod_os"])
}

// The beta annotation still counts on a cluster that predates the field, and a
// container-level field overrides it.
func TestPodHardeningSignals_AppArmorAnnotation(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "app", Annotations: map[string]string{
			"container.apparmor.security.beta.kubernetes.io/app": "unconfined",
		}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
	}
	require.Equal(t, "true", podHardeningSignals(pod)["apparmor_unconfined"])
	pod.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
		AppArmorProfile: &corev1.AppArmorProfile{Type: corev1.AppArmorProfileTypeRuntimeDefault}}
	require.Equal(t, "false", podHardeningSignals(pod)["apparmor_unconfined"])
}

// automount_sa_token resolves the way the kubelet does: the pod's own field
// wins, else the ServiceAccount's, else true. When the SA list failed and the
// pod defers to it, the key stays absent — unread is not "mounted".
func TestCollect_AutomountResolvesFromServiceAccount(t *testing.T) {
	pod := func(name, sa string, automount *bool) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "app"},
			Spec: corev1.PodSpec{ServiceAccountName: sa, AutomountServiceAccountToken: automount,
				Containers: []corev1.Container{{Name: "c", Image: "c:1"}}},
		}
	}
	pods := []corev1.Pod{
		pod("inherits-off", "quiet", nil),
		pod("inherits-default", "default", nil),
		pod("pod-overrides", "quiet", ptr(true)),
	}
	sas := map[string][]corev1.ServiceAccount{"app": {
		{ObjectMeta: metav1.ObjectMeta{Name: "quiet", Namespace: "app"}, AutomountServiceAccountToken: ptr(false)},
		{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "app"}},
	}}

	res, err := withFakeK8s(&fakeK8s{namespaces: appNamespace(), sas: sas, pods: map[string][]corev1.Pod{"app": pods}}).
		Collect(context.Background(), nil)
	require.NoError(t, err)
	got := podsByName(res.Assets)
	require.Equal(t, "false", got["inherits-off"].Metadata["automount_sa_token"])
	require.Equal(t, "false", got["inherits-off"].Metadata["automount_sa_token_set_on_pod"])
	require.Equal(t, "true", got["inherits-default"].Metadata["automount_sa_token"])
	require.Equal(t, "true", got["pod-overrides"].Metadata["automount_sa_token"])
	require.Equal(t, "true", got["pod-overrides"].Metadata["automount_sa_token_set_on_pod"])

	sa := assetByID(res.Assets, "prod/namespace/app/serviceaccount/default")
	require.Equal(t, "true", sa.Metadata["automount_token"], "unset on the SA means mount")
	require.Equal(t, "false", assetByID(res.Assets, "prod/namespace/app/serviceaccount/quiet").Metadata["automount_token"])

	res, err = withFakeK8s(&fakeK8s{namespaces: appNamespace(), saErr: errors.New("dial tcp: i/o timeout"),
		pods: map[string][]corev1.Pod{"app": pods}}).Collect(context.Background(), nil)
	require.NoError(t, err)
	got = podsByName(res.Assets)
	_, ok := got["inherits-off"].Metadata["automount_sa_token"]
	require.False(t, ok, "the SA's setting was not read, so the pod's effective automount is unknown")
	require.Equal(t, "true", got["pod-overrides"].Metadata["automount_sa_token"], "the pod's own field needs no SA")
}

func TestCollect_NamespaceRecordsPSAAndDefaultDeny(t *testing.T) {
	ns := []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "app",
		Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}}}}
	allowOne := networkingv1.NetworkPolicy{Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
		PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
	}}
	res, err := withFakeK8s(&fakeK8s{namespaces: ns, netpols: []networkingv1.NetworkPolicy{allowOne}}).Collect(context.Background(), nil)
	require.NoError(t, err)
	a := assetByID(res.Assets, "prod/namespace/app")
	require.Equal(t, "baseline", a.Metadata["psa_enforce"])
	require.Equal(t, "true", a.Metadata["has_network_policy"])
	require.Equal(t, "false", a.Metadata["has_default_deny_ingress"], "a policy selecting some pods is not default-deny")

	res, err = withFakeK8s(&fakeK8s{namespaces: appNamespace()}).Collect(context.Background(), nil)
	require.NoError(t, err)
	a = assetByID(res.Assets, "prod/namespace/app")
	v, ok := a.Metadata["psa_enforce"]
	require.True(t, ok, "an unlabelled namespace is an observed absence")
	require.Empty(t, v)
}

func TestIsDefaultDenyIngress(t *testing.T) {
	all := metav1.LabelSelector{}
	tests := []struct {
		name string
		spec networkingv1.NetworkPolicySpec
		want bool
	}{
		{"explicit ingress deny", networkingv1.NetworkPolicySpec{PodSelector: all, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}, true},
		{"implied ingress deny", networkingv1.NetworkPolicySpec{PodSelector: all}, true},
		{"deny both", networkingv1.NetworkPolicySpec{PodSelector: all, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}}, true},
		{"egress only", networkingv1.NetworkPolicySpec{PodSelector: all, PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}}, false},
		{"allow all ingress", networkingv1.NetworkPolicySpec{PodSelector: all, Ingress: []networkingv1.NetworkPolicyIngressRule{{}}}, false},
		{"some pods only", networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpExists}}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isDefaultDenyIngress(networkingv1.NetworkPolicy{Spec: tt.spec}))
		})
	}
}

func podsByName(assets []asset.Asset) map[string]asset.Asset {
	out := map[string]asset.Asset{}
	for _, a := range assets {
		if a.Type == "k8s_pod" {
			out[a.Name] = a
		}
	}
	return out
}

func assetByID(assets []asset.Asset, id string) asset.Asset {
	for _, a := range assets {
		if a.ID == id {
			return a
		}
	}
	return asset.Asset{}
}
