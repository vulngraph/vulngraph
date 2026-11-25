package checks

import (
	"maps"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// kubeadmDefaultNodes is what collect/kubernetes derives from a default
// kubeadm v1.30 cluster with the node posture reader on every node
// (TestNodeSettings_DefaultKubeadmWorker pins the worker half collector-side).
func kubeadmDefaultNodes() map[string]string {
	return map[string]string{
		"kubelet_anonymous_auth":                        "false",
		"kubelet_authorization_mode":                    "Webhook",
		"kubelet_client_ca_set":                         "true",
		"kubelet_read_only_port":                        "0",
		"kubelet_streaming_idle_timeout":                "4h0m0s",
		"kubelet_make_iptables_util_chains":             "true",
		"kubelet_hostname_override_set":                 "false",
		"kubelet_tls_cert_set":                          "false",
		"kubelet_rotate_certificates":                   "true",
		"kubelet_rotate_server_certificates":            "true",
		"kubelet_tls_cipher_suites":                     "",
		"kubelet_pod_pids_limit":                        "-1",
		"kubelet_seccomp_default":                       "false",
		"kube_proxy_metrics_bind_address":               "127.0.0.1:10249",
		"node_file_kubelet_service_mode":                "0644",
		"node_file_kubelet_service_owner":               "root:root",
		"node_file_kubelet_config_mode":                 "0644",
		"node_file_kubelet_config_owner":                "root:root",
		"node_file_kubelet_kubeconfig_mode":             "0600",
		"node_file_kubelet_kubeconfig_owner":            "root:root",
		"node_file_client_ca_mode":                      "0644",
		"node_file_client_ca_owner":                     "root:root",
		"node_file_kube_proxy_kubeconfig_mode":          "absent",
		"node_file_kube_proxy_kubeconfig_owner":         "absent",
		"node_file_apiserver_manifest_mode":             "0600",
		"node_file_apiserver_manifest_owner":            "root:root",
		"node_file_controller_manager_manifest_mode":    "0600",
		"node_file_controller_manager_manifest_owner":   "root:root",
		"node_file_scheduler_manifest_mode":             "0600",
		"node_file_scheduler_manifest_owner":            "root:root",
		"node_file_etcd_manifest_mode":                  "0600",
		"node_file_etcd_manifest_owner":                 "root:root",
		"node_file_cni_mode":                            "0644",
		"node_file_cni_owner":                           "root:root",
		"node_file_etcd_data_dir_mode":                  "0700",
		"node_file_etcd_data_dir_owner":                 "root:root",
		"node_file_admin_kubeconfig_mode":               "0600",
		"node_file_admin_kubeconfig_owner":              "root:root",
		"node_file_scheduler_kubeconfig_mode":           "0600",
		"node_file_scheduler_kubeconfig_owner":          "root:root",
		"node_file_controller_manager_kubeconfig_mode":  "0600",
		"node_file_controller_manager_kubeconfig_owner": "root:root",
		"node_file_pki_owner":                           "root:root",
		"node_file_pki_cert_mode":                       "0644",
		"node_file_pki_key_mode":                        "0600",
	}
}

func firingNodeChecks(md map[string]string) []string {
	a := asset.Asset{ID: "c/cluster", Type: "k8s_cluster", Provider: asset.ProviderKubernetes, Metadata: md}
	r := NewRegistry()
	r.Register(k8sNodeChecks()...)
	var ids []string
	for _, f := range r.Run([]asset.Asset{a}, time.Now()) {
		ids = append(ids, f.CheckID)
	}
	sort.Strings(ids)
	return ids
}

// kube-bench reports the same failures on a default kubeadm cluster: kubeadm
// writes config.yaml, the kubelet drop-in and the CNI config 644, runs etcd as
// root, and leaves TLS files, cipher suites, PID limits and seccomp at their
// defaults.
func TestNodeChecks_DefaultKubeadm(t *testing.T) {
	require.Equal(t, []string{
		"k8s-cp-cni-config-files",
		"k8s-cp-etcd-data-dir",
		"k8s-kubelet-no-pid-limit",
		"k8s-kubelet-no-tls-cert",
		"k8s-kubelet-seccomp-default-off",
		"k8s-kubelet-weak-tls-ciphers",
		"k8s-node-kubelet-config-file",
		"k8s-node-kubelet-service-file",
	}, firingNodeChecks(kubeadmDefaultNodes()))
}

// CIS EKS and GKE allow 644 on the kubelet config and kubeconfig, which their
// node images ship; CIS Kubernetes demands 600. The cluster's provider decides.
func TestNodeChecks_ManagedFileLimit(t *testing.T) {
	md := map[string]string{
		"node_file_kubelet_config_mode": "0644", "node_file_kubelet_config_owner": "root:root",
		"node_file_kubelet_kubeconfig_mode": "0644", "node_file_kubelet_kubeconfig_owner": "root:root",
	}
	require.ElementsMatch(t, []string{"k8s-node-kubelet-config-file", "k8s-node-kubelet-kubeconfig"}, firingNodeChecks(maps.Clone(md)))
	for _, p := range []string{"aws", "gcp", "azure"} {
		m := maps.Clone(md)
		m["cloud_provider"] = p
		require.Empty(t, firingNodeChecks(m), p)
	}
	m := maps.Clone(md)
	m["cloud_provider"] = "aws"
	m["node_file_kubelet_config_mode"] = "0664"
	require.Equal(t, []string{"k8s-node-kubelet-config-file"}, firingNodeChecks(m), "group-writable still fails on EKS")
}

// Without the reader, no node check fires and none claims to have evaluated
// the cluster: unknown is never passing.
func TestNodeChecks_NoReaderIsUnknown(t *testing.T) {
	md := map[string]string{"configured_name": "prod"}
	require.Empty(t, firingNodeChecks(md))
	a := asset.Asset{Type: "k8s_cluster", Provider: asset.ProviderKubernetes, Metadata: md}
	r := NewRegistry()
	r.Register(k8sNodeChecks()...)
	for _, c := range k8sNodeChecks() {
		reg, _ := r.ByID(c.ID)
		require.False(t, reg.Evaluable(a), "%s must not read missing node data as clean", c.ID)
	}
}

func TestNodeChecks_AnyNodeFails(t *testing.T) {
	md := kubeadmDefaultNodes()
	md["kubelet_read_only_port"] = "0|10255"
	md["node_file_admin_kubeconfig_mode"] = "0600|0644"
	md["kube_proxy_metrics_bind_address"] = "0.0.0.0:10249|127.0.0.1:10249"
	got := firingNodeChecks(md)
	require.Contains(t, got, "k8s-kubelet-read-only-port")
	require.Contains(t, got, "k8s-cp-admin-kubeconfig-file")
	require.Contains(t, got, "k8s-kube-proxy-metrics-exposed")
}

func TestAnyBindNotLoopback(t *testing.T) {
	for v, want := range map[string]bool{
		"127.0.0.1:10249": false, "[::1]:10249": false, "localhost:10249": false,
		"0.0.0.0:10249": true, "10.0.0.5:10249": true, "0.0.0.0": true,
	} {
		a := asset.Asset{Metadata: map[string]string{"kube_proxy_metrics_bind_address": v}}
		require.Equal(t, want, anyBindNotLoopback(a, "kube_proxy_metrics_bind_address"), v)
	}
}
