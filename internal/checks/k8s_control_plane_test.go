package checks

import (
	"maps"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// kubeadmDefaultControlPlane is what collect/kubernetes derives from a default
// `kubeadm init` v1.30 (TestControlPlaneSignals_DefaultKubeadm pins the same
// map on the collector side).
func kubeadmDefaultControlPlane() map[string]string {
	return map[string]string{
		"apiserver_replicas":                                      "1",
		"apiserver_anonymous_auth":                                "true",
		"apiserver_token_auth_file_set":                           "false",
		"apiserver_admission_plugins":                             "CertificateApproval,CertificateSigning,CertificateSubjectRestriction,ClusterTrustBundleAttest,DefaultIngressClass,DefaultStorageClass,DefaultTolerationSeconds,LimitRanger,MutatingAdmissionWebhook,NamespaceLifecycle,NodeRestriction,PersistentVolumeClaimResize,PodSecurity,Priority,ResourceQuota,RuntimeClass,ServiceAccount,StorageObjectInUseProtection,TaintNodesByCondition,ValidatingAdmissionPolicy,ValidatingAdmissionWebhook",
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
}

func firingControlPlaneChecks(md map[string]string) []string {
	a := asset.Asset{ID: "c/cluster", Type: "k8s_cluster", Provider: asset.ProviderKubernetes, Metadata: md}
	r := NewRegistry()
	r.Register(k8sControlPlaneChecks()...)
	var ids []string
	for _, f := range r.Run([]asset.Asset{a}, time.Now()) {
		ids = append(ids, f.CheckID)
	}
	sort.Strings(ids)
	return ids
}

// The findings a default kubeadm cluster gets are exactly the CIS controls
// kubeadm leaves at an insecure default — kube-bench reports the same set.
func TestControlPlaneChecks_DefaultKubeadm(t *testing.T) {
	require.Equal(t, []string{
		"k8s-apiserver-anonymous-auth",
		"k8s-apiserver-no-always-pull-images",
		"k8s-apiserver-no-audit-log",
		"k8s-apiserver-no-deny-external-ips",
		"k8s-apiserver-no-encryption-config",
		"k8s-apiserver-no-event-rate-limit",
		"k8s-apiserver-no-image-policy-webhook",
		"k8s-apiserver-no-kubelet-ca",
		"k8s-apiserver-profiling-enabled",
		"k8s-apiserver-sa-token-expiry-extended",
		"k8s-apiserver-weak-tls-ciphers",
		"k8s-controller-manager-gc-threshold-unset",
		"k8s-controller-manager-profiling-enabled",
		"k8s-scheduler-profiling-enabled",
	}, firingControlPlaneChecks(kubeadmDefaultControlPlane()))
}

// A managed control plane publishes none of these keys: nothing fires and no
// check claims to have evaluated the cluster.
func TestControlPlaneChecks_ManagedClusterIsUnknown(t *testing.T) {
	md := map[string]string{"configured_name": "prod", "cloud_provider": "aws"}
	require.Empty(t, firingControlPlaneChecks(md))
	a := asset.Asset{Type: "k8s_cluster", Provider: asset.ProviderKubernetes, Metadata: md}
	r := NewRegistry()
	r.Register(k8sControlPlaneChecks()...)
	for _, c := range k8sControlPlaneChecks() {
		reg, _ := r.ByID(c.ID)
		require.False(t, reg.Evaluable(a), "%s: absent control-plane data must not read as evaluated-clean", c.ID)
	}
}

// One root cause, one finding: AlwaysAllow alone is reported once, not also as
// "no Node" and "no RBAC"; a cluster writing no audit log is not also told its
// retention is short; etcd without TLS is not also told it skips client certs.
func TestControlPlaneChecks_StepAside(t *testing.T) {
	md := kubeadmDefaultControlPlane()
	md["apiserver_authorization_mode"] = "AlwaysAllow"
	md["etcd_client_tls_set"] = "false"
	md["etcd_client_cert_auth"] = "false"
	got := firingControlPlaneChecks(md)
	require.Contains(t, got, "k8s-apiserver-authz-always-allow")
	require.NotContains(t, got, "k8s-apiserver-authz-no-node")
	require.NotContains(t, got, "k8s-apiserver-authz-no-rbac")
	require.NotContains(t, got, "k8s-apiserver-audit-log-maxage-low")
	require.Contains(t, got, "k8s-etcd-client-no-tls")
	require.NotContains(t, got, "k8s-etcd-no-client-cert-auth")

	hardened := maps.Clone(kubeadmDefaultControlPlane())
	hardened["apiserver_audit_log_path"] = "/var/log/kubernetes/audit.log"
	got = firingControlPlaneChecks(hardened)
	require.Contains(t, got, "k8s-apiserver-audit-log-maxage-low", "with a log written, its retention is graded")
}

// A replica that disagrees is enough: the rollout that left one API server on
// the old flags is still exposed through that replica.
func TestControlPlaneChecks_AnyReplicaFails(t *testing.T) {
	md := kubeadmDefaultControlPlane()
	md["apiserver_profiling"] = "false|true"
	md["scheduler_bind_address"] = "0.0.0.0|127.0.0.1"
	got := firingControlPlaneChecks(md)
	require.Contains(t, got, "k8s-apiserver-profiling-enabled")
	require.Contains(t, got, "k8s-scheduler-not-localhost")
}

func TestCipherListStrong(t *testing.T) {
	require.False(t, cipherListStrong("", apiserverStrongCiphers), "unset is Go's default list")
	require.False(t, cipherListStrong("TLS_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA", apiserverStrongCiphers))
	require.True(t, cipherListStrong("TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", apiserverStrongCiphers))
}

// Audit to stdout meets 1.2.16 and leaves rotation to the log pipeline.
func TestControlPlaneChecks_AuditToStdout(t *testing.T) {
	md := kubeadmDefaultControlPlane()
	md["apiserver_audit_log_path"] = "-"
	md["apiserver_audit_policy_file_set"] = "true"
	got := firingControlPlaneChecks(md)
	for _, id := range []string{"k8s-apiserver-no-audit-log", "k8s-apiserver-audit-log-maxage-low",
		"k8s-apiserver-audit-log-maxbackup-low", "k8s-apiserver-audit-log-maxsize-low", "k8s-apiserver-no-audit-policy"} {
		require.NotContains(t, got, id)
	}
}
