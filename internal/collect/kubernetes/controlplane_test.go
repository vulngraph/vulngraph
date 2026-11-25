package kubernetes

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// kubeadmMirrorPods loads the default kubeadm control plane (testdata/kubeadm).
func kubeadmMirrorPods(t *testing.T) []corev1.Pod {
	t.Helper()
	raw, err := os.ReadFile("testdata/kubeadm/control-plane-mirror-pods.yaml")
	require.NoError(t, err)
	js, err := utilyaml.ToJSON(raw)
	require.NoError(t, err)
	var list struct {
		Items []corev1.Pod `json:"items"`
	}
	require.NoError(t, json.Unmarshal(js, &list))
	require.Len(t, list.Items, 4)
	return list.Items
}

// A default kubeadm cluster, read the way the collector reads it: every
// setting resolves, with the upstream defaults where kubeadm passes no flag.
func TestControlPlaneSignals_DefaultKubeadm(t *testing.T) {
	got := controlPlaneSignals(kubeadmMirrorPods(t))
	want := map[string]string{
		"apiserver_replicas":                                      "1",
		"apiserver_anonymous_auth":                                "true", // flag default
		"apiserver_token_auth_file_set":                           "false",
		"apiserver_kubelet_client_cert_set":                       "true",
		"apiserver_kubelet_ca_set":                                "false",
		"apiserver_authorization_mode":                            "Node,RBAC",
		"apiserver_profiling":                                     "true",
		"apiserver_audit_log_path":                                "",
		"apiserver_audit_policy_file_set":                         "false",
		"apiserver_audit_log_maxage":                              "0",
		"apiserver_audit_log_maxbackup":                           "0",
		"apiserver_audit_log_maxsize":                             "0",
		"apiserver_service_account_lookup":                        "true",
		"apiserver_service_account_key_file_set":                  "true",
		"apiserver_etcd_client_cert_set":                          "true",
		"apiserver_tls_cert_set":                                  "true",
		"apiserver_client_ca_set":                                 "true",
		"apiserver_etcd_ca_set":                                   "true",
		"apiserver_encryption_provider_config_set":                "false",
		"apiserver_tls_cipher_suites":                             "",
		"apiserver_service_account_extend_token_expiration":       "true",
		"controller_manager_replicas":                             "1",
		"controller_manager_terminated_pod_gc_threshold_set":      "false",
		"controller_manager_profiling":                            "true",
		"controller_manager_use_service_account_credentials":      "true",
		"controller_manager_service_account_private_key_file_set": "true",
		"controller_manager_root_ca_file_set":                     "true",
		"controller_manager_rotate_kubelet_server_certificate":    "true",
		"controller_manager_bind_address":                         "127.0.0.1",
		"scheduler_replicas":                                      "1",
		"scheduler_profiling":                                     "true",
		"scheduler_bind_address":                                  "127.0.0.1",
		"etcd_replicas":                                           "1",
		"etcd_client_tls_set":                                     "true",
		"etcd_client_cert_auth":                                   "true",
		"etcd_auto_tls":                                           "false",
		"etcd_peer_tls_set":                                       "true",
		"etcd_peer_client_cert_auth":                              "true",
		"etcd_peer_auto_tls":                                      "false",
	}
	plugins := got["apiserver_admission_plugins"]
	delete(got, "apiserver_admission_plugins")
	require.Equal(t, want, got)
	require.Contains(t, plugins, "NodeRestriction")
	require.Contains(t, plugins, "ServiceAccount")
	require.NotContains(t, plugins, "AlwaysPullImages")
}

func TestControlPlaneSignals_ReplicasDisagree(t *testing.T) {
	pods := kubeadmMirrorPods(t)
	second := *pods[0].DeepCopy()
	second.Name = "kube-apiserver-cp-2"
	second.Spec.Containers[0].Command = append(second.Spec.Containers[0].Command, "--anonymous-auth=false", "--profiling", "false")
	got := controlPlaneSignals(append(pods, second))
	require.Equal(t, "2", got["apiserver_replicas"])
	require.Equal(t, "false|true", got["apiserver_anonymous_auth"], "every distinct replica value is kept")
	require.Equal(t, "false|true", got["apiserver_profiling"], "a space-separated value parses like --flag=value")
}

// Absence is unknown, never a default: no mirror pod, an unparseable replica,
// or a config file that can override the flags all leave the key out.
func TestControlPlaneSignals_Unknown(t *testing.T) {
	pods := kubeadmMirrorPods(t)

	t.Run("managed control plane", func(t *testing.T) {
		require.Empty(t, controlPlaneSignals(nil))
	})
	t.Run("not a mirror pod", func(t *testing.T) {
		fake := *pods[0].DeepCopy()
		delete(fake.Annotations, mirrorPodAnnotation)
		require.Empty(t, controlPlaneSignals([]corev1.Pod{fake}))
	})
	t.Run("outside kube-system", func(t *testing.T) {
		fake := *pods[0].DeepCopy()
		fake.Namespace = "default"
		require.Empty(t, controlPlaneSignals([]corev1.Pod{fake}))
	})
	t.Run("shell-wrapped replica hides the component", func(t *testing.T) {
		wrapped := *pods[0].DeepCopy()
		wrapped.Name = "kube-apiserver-cp-2"
		wrapped.Spec.Containers[0].Command = []string{"/bin/sh", "-c", "kube-apiserver --anonymous-auth=true"}
		got := controlPlaneSignals([]corev1.Pod{pods[0], wrapped})
		require.NotContains(t, got, "apiserver_anonymous_auth")
		require.NotContains(t, got, "apiserver_replicas")
	})
	t.Run("structured authorization config", func(t *testing.T) {
		p := *pods[0].DeepCopy()
		p.Spec.Containers[0].Command = append(p.Spec.Containers[0].Command, "--authorization-config=/etc/kubernetes/authz.yaml")
		require.NotContains(t, controlPlaneSignals([]corev1.Pod{p}), "apiserver_authorization_mode")
	})
	t.Run("scheduler config file overrides --profiling", func(t *testing.T) {
		p := *pods[2].DeepCopy()
		p.Spec.Containers[0].Command = append(p.Spec.Containers[0].Command, "--config=/etc/kubernetes/scheduler-config.yaml", "--profiling=false")
		got := controlPlaneSignals([]corev1.Pod{p})
		require.NotContains(t, got, "scheduler_profiling", "--profiling is ignored when --config is set")
		require.Equal(t, "127.0.0.1", got["scheduler_bind_address"], "--bind-address is not a config-file field")
	})
	t.Run("etcd config file", func(t *testing.T) {
		p := *pods[3].DeepCopy()
		p.Spec.Containers[0].Command = append(p.Spec.Containers[0].Command, "--config-file=/etc/etcd.yaml")
		got := controlPlaneSignals([]corev1.Pod{p})
		require.NotContains(t, got, "etcd_client_cert_auth")
	})
	t.Run("unparseable boolean", func(t *testing.T) {
		p := *pods[0].DeepCopy()
		p.Spec.Containers[0].Command = append(p.Spec.Containers[0].Command, "--profiling=maybe")
		require.NotContains(t, controlPlaneSignals([]corev1.Pod{p}), "apiserver_profiling")
	})
}

func TestControlPlaneSignals_EtcdEnvAndFlagPrecedence(t *testing.T) {
	p := *kubeadmMirrorPods(t)[3].DeepCopy()
	c := &p.Spec.Containers[0]
	c.Env = []corev1.EnvVar{{Name: "ETCD_AUTO_TLS", Value: "true"}, {Name: "ETCD_CLIENT_CERT_AUTH", Value: "false"}}
	got := controlPlaneSignals([]corev1.Pod{p})
	require.Equal(t, "true", got["etcd_auto_tls"], "an ETCD_ variable sets a flag the command omits")
	require.Equal(t, "true", got["etcd_client_cert_auth"], "the command-line flag wins over the variable")
}

func TestAdmissionPlugins(t *testing.T) {
	got := admissionPlugins("NodeRestriction,AlwaysPullImages", "ServiceAccount")
	require.Contains(t, got, "AlwaysPullImages")
	require.Contains(t, got, "NamespaceLifecycle", "defaults stay on")
	require.NotContains(t, got, "ServiceAccount", "disable wins")
}

func TestFeatureGate(t *testing.T) {
	require.Equal(t, "false", featureGate("A=true, RotateKubeletServerCertificate=False", "RotateKubeletServerCertificate"))
	require.Equal(t, "", featureGate("A=true", "RotateKubeletServerCertificate"))
}

// The collector stamps the settings on the one k8s_cluster asset.
func TestCollect_ControlPlaneOnClusterAsset(t *testing.T) {
	f := &fakeK8s{
		namespaces: append(appNamespace(), corev1.Namespace{}),
		pods:       map[string][]corev1.Pod{"kube-system": kubeadmMirrorPods(t)},
	}
	f.namespaces[1].Name = "kube-system"
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	for _, a := range res.Assets {
		if a.Type == "k8s_cluster" {
			require.Equal(t, "Node,RBAC", a.Metadata["apiserver_authorization_mode"])
			return
		}
	}
	t.Fatal("no k8s_cluster asset")
}

// "-" is a value (stdout), not the next flag, and a non-integer retention value
// is unknown rather than a number the checks would skip.
func TestControlPlaneSignals_AuditStdoutAndGarbage(t *testing.T) {
	p := *kubeadmMirrorPods(t)[0].DeepCopy()
	p.Spec.Containers[0].Command = append(p.Spec.Containers[0].Command, "--audit-log-path", "-", "--audit-log-maxage=thirty", "--audit-log-maxsize=200")
	got := controlPlaneSignals([]corev1.Pod{p})
	require.Equal(t, "-", got["apiserver_audit_log_path"])
	require.NotContains(t, got, "apiserver_audit_log_maxage")
	require.Equal(t, "200", got["apiserver_audit_log_maxsize"])
}
