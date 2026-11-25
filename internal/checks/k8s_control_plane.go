package checks

// k8s_control_plane.go — CIS Kubernetes 1.3 (controller manager), 1.4
// (scheduler) and 2 (etcd) flag controls, plus the helpers the API-server
// checks in k8s_apiserver.go share. All read the EFFECTIVE settings the
// collector derives from the control-plane mirror pods of a self-managed
// cluster (collect/kubernetes/controlplane.go, ADR 094) and stamps on the one
// k8s_cluster asset, so a flag misconfigured on every replica is one finding.
//
// A setting's value is every distinct replica value joined with "|"; a check
// fires when any replica fails. A missing key is unknown (a managed control
// plane, an unreadable replica, a config file that can override the flag) and
// never fires.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// replicaValues splits a control-plane setting into its distinct replica values.
func replicaValues(v string) []string { return strings.Split(v, "|") }

// cpAnyIs reports whether any replica's setting equals bad.
func cpAnyIs(a asset.Asset, key, bad string) bool {
	v, ok := a.Metadata[key]
	return ok && slices.Contains(replicaValues(v), bad)
}

// cpAnyBelow reports whether any replica's integer setting is under floor. The
// collector omits a value that does not parse (settingReader.integer), so a
// present key is always a number: a garbage value is unknown, never skipped.
func cpAnyBelow(a asset.Asset, key string, floor int) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if n, err := strconv.Atoi(r); err == nil && n < floor {
			return true
		}
	}
	return false
}

// cpAnyListHas reports whether any replica's comma list contains item.
func cpAnyListHas(a asset.Asset, key, item string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if slices.Contains(strings.Split(r, ","), item) {
			return true
		}
	}
	return false
}

// cpAnyListLacks reports whether any replica's comma list is missing item.
func cpAnyListLacks(a asset.Asset, key, item string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if !slices.Contains(strings.Split(r, ","), item) {
			return true
		}
	}
	return false
}

// cpAnyNotLoopback reports whether any replica binds to a non-loopback address.
func cpAnyNotLoopback(a asset.Asset, key string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if !isLoopbackHost(r) {
			return true
		}
	}
	return false
}

func isLoopbackHost(h string) bool {
	switch h {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// cpAnyWeakCiphers reports whether any replica leaves --tls-cipher-suites unset
// (Go's defaults) or lists a suite outside allowed.
func cpAnyWeakCiphers(a asset.Asset, key string, allowed []string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if !cipherListStrong(r, allowed) {
			return true
		}
	}
	return false
}

func cipherListStrong(list string, allowed []string) bool {
	if strings.TrimSpace(list) == "" {
		return false
	}
	for _, s := range strings.Split(list, ",") {
		if !slices.Contains(allowed, strings.TrimSpace(s)) {
			return false
		}
	}
	return true
}

// cpEvidence copies the named settings (and replica counts) into the finding.
func cpEvidence(keys ...string) func(asset.Asset) map[string]string {
	return func(a asset.Asset) map[string]string {
		ev := map[string]string{}
		for _, k := range keys {
			if v, ok := a.Metadata[k]; ok {
				ev[k] = v
			}
		}
		for _, k := range []string{"apiserver_replicas", "controller_manager_replicas", "scheduler_replicas", "etcd_replicas"} {
			if v, ok := a.Metadata[k]; ok && strings.HasPrefix(keys[0], strings.TrimSuffix(k, "replicas")) {
				ev[k] = v
			}
		}
		return ev
	}
}

// manifestFix is the remediation for a static-pod flag: the manifest edit, the
// kubeadm setting that keeps it across upgrades, and the command that verifies it.
func manifestFix(component, kubeadmSection, change string) string {
	return fmt.Sprintf("On every control-plane node, edit /etc/kubernetes/manifests/%s.yaml and %s; the kubelet restarts the component when the manifest changes. "+
		"On kubeadm clusters also set it under %s in the kubeadm-config ClusterConfiguration so `kubeadm upgrade` keeps it. "+
		"Verify: `kubectl -n kube-system get pod -l component=%s -o jsonpath='{.items[*].spec.containers[0].command}'`.",
		component, change, kubeadmSection, component)
}

// ── 1.3 Controller manager ──────────────────────────────────────────────────

var k8sControllerManagerGCThresholdUnset = Check{
	ID:          "k8s-controller-manager-gc-threshold-unset",
	Title:       "Controller manager does not set a terminated-pod GC threshold",
	Description: "kube-controller-manager runs without --terminated-pod-gc-threshold, so terminated pods are only collected after the 12,500 default. On a busy cluster that many retained pod objects degrade the API server and etcd (CIS Kubernetes 1.3.1).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "add --terminated-pod-gc-threshold=10 (or a value sized to your cluster)"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "controller_manager_terminated_pod_gc_threshold_set", "false")
	},
	EvidenceFor: cpEvidence("controller_manager_terminated_pod_gc_threshold_set"),
}

var k8sControllerManagerProfiling = Check{
	ID:          "k8s-controller-manager-profiling-enabled",
	Title:       "Controller manager exposes the profiling endpoint",
	Description: "kube-controller-manager runs with profiling enabled (the default when --profiling is not false), serving /debug/pprof. Profiling data reveals internal state and the endpoint adds attack surface with no production use (CIS Kubernetes 1.3.2).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "add --profiling=false"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "controller_manager_profiling", "true") },
	EvidenceFor: cpEvidence("controller_manager_profiling"),
}

var k8sControllerManagerSharedCredentials = Check{
	ID:          "k8s-controller-manager-shared-credentials",
	Title:       "Controllers share the controller manager's credentials",
	Description: "kube-controller-manager runs without --use-service-account-credentials=true, so every controller acts with the manager's own broad identity instead of a per-controller ServiceAccount bound to least-privilege roles. A flaw in one controller then carries all of their permissions (CIS Kubernetes 1.3.3).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "add --use-service-account-credentials=true"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "controller_manager_use_service_account_credentials", "false")
	},
	EvidenceFor: cpEvidence("controller_manager_use_service_account_credentials"),
}

var k8sControllerManagerNoSAKey = Check{
	ID:          "k8s-controller-manager-no-sa-signing-key",
	Title:       "Controller manager has no service account signing key",
	Description: "kube-controller-manager runs without --service-account-private-key-file, so it cannot sign service account tokens with a key you manage and rotate (CIS Kubernetes 1.3.4).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "add --service-account-private-key-file=/etc/kubernetes/pki/sa.key (the private half of the API server's --service-account-key-file)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "controller_manager_service_account_private_key_file_set", "false")
	},
	EvidenceFor: cpEvidence("controller_manager_service_account_private_key_file_set"),
}

var k8sControllerManagerNoRootCA = Check{
	ID:          "k8s-controller-manager-no-root-ca",
	Title:       "Controller manager does not publish the cluster root CA",
	Description: "kube-controller-manager runs without --root-ca-file, so service account token Secrets carry no CA bundle and pods cannot verify the API server's serving certificate, which leaves them open to an in-cluster man-in-the-middle (CIS Kubernetes 1.3.5).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "add --root-ca-file=/etc/kubernetes/pki/ca.crt"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "controller_manager_root_ca_file_set", "false") },
	EvidenceFor: cpEvidence("controller_manager_root_ca_file_set"),
}

var k8sControllerManagerServerCertRotationOff = Check{
	ID:          "k8s-controller-manager-server-cert-rotation-off",
	Title:       "Controller manager disables kubelet serving certificate rotation",
	Description: "kube-controller-manager sets the RotateKubeletServerCertificate feature gate to false, so kubelet serving certificate requests are not approved and kubelets keep long-lived serving certificates (CIS Kubernetes 1.3.6).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "remove RotateKubeletServerCertificate=false from --feature-gates (or set it to true)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "controller_manager_rotate_kubelet_server_certificate", "false")
	},
	EvidenceFor: cpEvidence("controller_manager_rotate_kubelet_server_certificate"),
}

var k8sControllerManagerBindAddress = Check{
	ID:          "k8s-controller-manager-not-localhost",
	Title:       "Controller manager listens on a non-loopback address",
	Description: "kube-controller-manager's secure port is bound to a routable address (0.0.0.0 when --bind-address is unset), exposing its health, metrics and debug handlers to the node network. Nothing off the node needs them (CIS Kubernetes 1.3.7).",
	Remediation: manifestFix("kube-controller-manager", "controllerManager.extraArgs", "set --bind-address=127.0.0.1"),
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyNotLoopback(a, "controller_manager_bind_address") },
	EvidenceFor: cpEvidence("controller_manager_bind_address"),
}

// ── 1.4 Scheduler ───────────────────────────────────────────────────────────

var k8sSchedulerProfiling = Check{
	ID:          "k8s-scheduler-profiling-enabled",
	Title:       "Scheduler exposes the profiling endpoint",
	Description: "kube-scheduler runs with profiling enabled (the default when --profiling is not false), serving /debug/pprof with no production use (CIS Kubernetes 1.4.1).",
	Remediation: manifestFix("kube-scheduler", "scheduler.extraArgs", "add --profiling=false"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "scheduler_profiling", "true") },
	EvidenceFor: cpEvidence("scheduler_profiling"),
}

var k8sSchedulerBindAddress = Check{
	ID:          "k8s-scheduler-not-localhost",
	Title:       "Scheduler listens on a non-loopback address",
	Description: "kube-scheduler's secure port is bound to a routable address (0.0.0.0 when --bind-address is unset), exposing its health, metrics and debug handlers to the node network (CIS Kubernetes 1.4.2).",
	Remediation: manifestFix("kube-scheduler", "scheduler.extraArgs", "set --bind-address=127.0.0.1"),
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyNotLoopback(a, "scheduler_bind_address") },
	EvidenceFor: cpEvidence("scheduler_bind_address"),
}

// ── 2 etcd ──────────────────────────────────────────────────────────────────
//
// The client-cert-auth and auto-TLS checks step aside when the listener has no
// certificate at all: k8s-etcd-client-no-tls reports that root cause.

var k8sEtcdClientNoTLS = Check{
	ID:          "k8s-etcd-client-no-tls",
	Title:       "etcd serves clients without TLS",
	Description: "etcd runs without --cert-file and --key-file, so client traffic, which is every Secret in the cluster, crosses the network unencrypted (CIS Kubernetes 2.1).",
	Remediation: manifestFix("etcd", "etcd.local.extraArgs", "set --cert-file and --key-file to the etcd server certificate and key"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "etcd_client_tls_set", "false") },
	EvidenceFor: cpEvidence("etcd_client_tls_set"),
}

var k8sEtcdNoClientCertAuth = Check{
	ID:          "k8s-etcd-no-client-cert-auth",
	Title:       "etcd accepts clients without a certificate",
	Description: "etcd runs without --client-cert-auth=true, so anything that can reach its client port can read and write every key, including all Secrets, without authenticating (CIS Kubernetes 2.2).",
	Remediation: manifestFix("etcd", "etcd.local.extraArgs", "set --client-cert-auth=true and --trusted-ca-file to the etcd CA"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "etcd_client_cert_auth", "false") && !cpAnyIs(a, "etcd_client_tls_set", "false")
	},
	EvidenceFor: cpEvidence("etcd_client_cert_auth"),
}

var k8sEtcdAutoTLS = Check{
	ID:          "k8s-etcd-auto-tls",
	Title:       "etcd uses self-signed automatic TLS for clients",
	Description: "etcd runs with --auto-tls=true, generating a self-signed client certificate that no client can verify, so TLS gives no protection against impersonation (CIS Kubernetes 2.3).",
	Remediation: manifestFix("etcd", "etcd.local.extraArgs", "remove --auto-tls or set it to false, and serve a CA-signed --cert-file/--key-file"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "etcd_auto_tls", "true") },
	EvidenceFor: cpEvidence("etcd_auto_tls"),
}

var k8sEtcdPeerNoTLS = Check{
	ID:          "k8s-etcd-peer-no-tls",
	Title:       "etcd peers replicate without TLS",
	Description: "etcd runs without --peer-cert-file and --peer-key-file, so replication between members, a full copy of the cluster state, is unencrypted (CIS Kubernetes 2.4). Single-member etcd has no peer traffic, but the flag still governs any member added later.",
	Remediation: manifestFix("etcd", "etcd.local.extraArgs", "set --peer-cert-file and --peer-key-file to the etcd peer certificate and key"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "etcd_peer_tls_set", "false") },
	EvidenceFor: cpEvidence("etcd_peer_tls_set"),
}

var k8sEtcdNoPeerCertAuth = Check{
	ID:          "k8s-etcd-no-peer-cert-auth",
	Title:       "etcd accepts peers without a certificate",
	Description: "etcd runs without --peer-client-cert-auth=true, so a host that reaches the peer port can join or impersonate a member without authenticating (CIS Kubernetes 2.5).",
	Remediation: manifestFix("etcd", "etcd.local.extraArgs", "set --peer-client-cert-auth=true and --peer-trusted-ca-file to the etcd CA"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "etcd_peer_client_cert_auth", "false") && !cpAnyIs(a, "etcd_peer_tls_set", "false")
	},
	EvidenceFor: cpEvidence("etcd_peer_client_cert_auth"),
}

var k8sEtcdPeerAutoTLS = Check{
	ID:          "k8s-etcd-peer-auto-tls",
	Title:       "etcd uses self-signed automatic TLS for peers",
	Description: "etcd runs with --peer-auto-tls=true, generating self-signed peer certificates that members cannot verify (CIS Kubernetes 2.6).",
	Remediation: manifestFix("etcd", "etcd.local.extraArgs", "remove --peer-auto-tls or set it to false, and serve CA-signed peer certificates"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "etcd_peer_auto_tls", "true") },
	EvidenceFor: cpEvidence("etcd_peer_auto_tls"),
}

// k8sControlPlaneChecks are the CIS Kubernetes 1.2-1.4 and 2.x flag checks of
// k8s_apiserver.go and this file.
func k8sControlPlaneChecks() []Check {
	return []Check{
		k8sAPIServerAnonymousAuth,
		k8sAPIServerTokenAuthFile,
		k8sAPIServerNoDenyExternalIPs,
		k8sAPIServerNoKubeletClientCert,
		k8sAPIServerNoKubeletCA,
		k8sAPIServerAuthzAlwaysAllow,
		k8sAPIServerAuthzNoNode,
		k8sAPIServerAuthzNoRBAC,
		k8sAPIServerNoEventRateLimit,
		k8sAPIServerAlwaysAdmit,
		k8sAPIServerNoAlwaysPullImages,
		k8sAPIServerServiceAccountAdmissionOff,
		k8sAPIServerNamespaceLifecycleOff,
		k8sAPIServerNoNodeRestriction,
		k8sAPIServerNoImagePolicyWebhook,
		k8sAPIServerProfiling,
		k8sAPIServerNoAuditLog,
		k8sAPIServerNoAuditPolicy,
		k8sAPIServerAuditMaxAge,
		k8sAPIServerAuditMaxBackup,
		k8sAPIServerAuditMaxSize,
		k8sAPIServerSALookupOff,
		k8sAPIServerNoSAKeyFile,
		k8sAPIServerNoEtcdClientCert,
		k8sAPIServerNoTLSCert,
		k8sAPIServerNoClientCA,
		k8sAPIServerNoEtcdCA,
		k8sAPIServerNoEncryptionConfig,
		k8sAPIServerWeakCiphers,
		k8sAPIServerExtendTokenExpiration,
		k8sControllerManagerGCThresholdUnset,
		k8sControllerManagerProfiling,
		k8sControllerManagerSharedCredentials,
		k8sControllerManagerNoSAKey,
		k8sControllerManagerNoRootCA,
		k8sControllerManagerServerCertRotationOff,
		k8sControllerManagerBindAddress,
		k8sSchedulerProfiling,
		k8sSchedulerBindAddress,
		k8sEtcdClientNoTLS,
		k8sEtcdNoClientCertAuth,
		k8sEtcdAutoTLS,
		k8sEtcdPeerNoTLS,
		k8sEtcdNoPeerCertAuth,
		k8sEtcdPeerAutoTLS,
	}
}
