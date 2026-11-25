package checks

// k8s_node_files.go — CIS Kubernetes 1.1 (control-plane node files) and 4.1
// (worker node files), and CIS EKS/GKE 3.1, from the node posture reader's
// stats (ADR 094, collect/kubernetes/nodeposture_files.go). One check per file
// covers its mode and ownership controls: the fix is one chmod/chown on the
// same file, and reporting the pair separately would double every finding.
//
// node_file_<role>_mode is the octal permission union per node ("absent" when
// the benchmark only checks the file if it exists), node_file_<role>_owner the
// node's owners as names; values from different nodes are joined with "|".

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fileModeExceeds reports whether any node's file grants a permission bit
// outside limit ("600 or more restrictive"). The collector writes only octal
// modes or "absent" (nodeposture_files.go); an unstat-able file is omitted.
func fileModeExceeds(a asset.Asset, key string, limit uint64) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if r == "absent" {
			continue
		}
		if m, err := strconv.ParseUint(r, 8, 32); err == nil && m&^limit != 0 {
			return true
		}
	}
	return false
}

// fileOwnerNot reports whether any node's file has an owner other than want.
func fileOwnerNot(a asset.Asset, key, want string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if r == "absent" {
			continue
		}
		for _, o := range strings.Split(r, ",") {
			if o != want {
				return true
			}
		}
	}
	return false
}

// managedNodeFileLimit is the kubelet file mode limit: 600 in CIS Kubernetes
// 4.1.5/4.1.9, 644 in CIS EKS, GKE and AKS 3.1.1/3.1.3, whose node images ship the
// files 644. The cluster's provider decides which benchmark governs it.
func managedNodeFileLimit(a asset.Asset) uint64 {
	switch a.Metadata["cloud_provider"] {
	case "aws", "gcp", "azure":
		return 0o644
	}
	return 0o600
}

func nodeFileFix(file, mode, owner string) string {
	return "On every affected node run `chmod " + mode + " " + file + "` and `chown " + owner + " " + file +
		"`, and fix the node image or bootstrap script that writes it so new nodes start compliant. " +
		"Vulngraph's node posture reader confirms the change on its next pass."
}

var k8sNodeKubeletServiceFile = Check{
	ID:          "k8s-node-kubelet-service-file",
	Title:       "Kubelet service file is writable or not owned by root",
	Description: "The kubelet's systemd unit or drop-in is more permissive than 600 or not owned by root:root. Whoever can write it chooses the kubelet's flags, including its credentials and authorization mode (CIS Kubernetes 4.1.1, 4.1.2).",
	Remediation: nodeFileFix("/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_kubelet_service_mode", 0o600) ||
			fileOwnerNot(a, "node_file_kubelet_service_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_kubelet_service_mode", "node_file_kubelet_service_owner"),
}

var k8sNodeKubeProxyKubeconfig = Check{
	ID:          "k8s-node-kube-proxy-kubeconfig",
	Title:       "kube-proxy kubeconfig file is readable by others or not owned by root",
	Description: "A file-based kube-proxy kubeconfig on the node is more permissive than 600 or not owned by root:root, exposing kube-proxy's credentials to other local users (CIS Kubernetes 4.1.3, 4.1.4). Nodes running kube-proxy from a ConfigMap have no such file and pass.",
	Remediation: nodeFileFix("<kube-proxy --kubeconfig path>", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_kube_proxy_kubeconfig_mode", 0o600) ||
			fileOwnerNot(a, "node_file_kube_proxy_kubeconfig_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_kube_proxy_kubeconfig_mode", "node_file_kube_proxy_kubeconfig_owner"),
}

var k8sNodeKubeletKubeconfig = Check{
	ID:          "k8s-node-kubelet-kubeconfig",
	Title:       "Kubelet kubeconfig file is too permissive or not owned by root",
	Description: "The kubelet's kubeconfig, which holds or points at the node's client credentials, is more permissive than the benchmark allows (600 on self-managed clusters, 644 on EKS and GKE) or not owned by root:root (CIS Kubernetes 4.1.5, 4.1.6; CIS EKS and GKE 3.1.1, 3.1.2).",
	Remediation: nodeFileFix("/etc/kubernetes/kubelet.conf (EKS/GKE: /var/lib/kubelet/kubeconfig)", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_kubelet_kubeconfig_mode", managedNodeFileLimit(a)) ||
			fileOwnerNot(a, "node_file_kubelet_kubeconfig_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_kubelet_kubeconfig_mode", "node_file_kubelet_kubeconfig_owner", "cloud_provider"),
}

var k8sNodeClientCAFile = Check{
	ID:          "k8s-node-client-ca-file",
	Title:       "Kubelet client CA file is writable by others or not owned by root",
	Description: "The CA bundle the kubelet trusts for client certificates is more permissive than 644 or not owned by root:root. Whoever can replace it decides which certificates the kubelet accepts (CIS Kubernetes 4.1.7, 4.1.8).",
	Remediation: nodeFileFix("/etc/kubernetes/pki/ca.crt", "644", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_client_ca_mode", 0o644) ||
			fileOwnerNot(a, "node_file_client_ca_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_client_ca_mode", "node_file_client_ca_owner"),
}

var k8sNodeKubeletConfigFile = Check{
	ID:          "k8s-node-kubelet-config-file",
	Title:       "Kubelet config file is too permissive or not owned by root",
	Description: "The kubelet configuration file is more permissive than the benchmark allows (600 on self-managed clusters, 644 on EKS and GKE) or not owned by root:root. Whoever can write it controls the kubelet's authentication and authorization (CIS Kubernetes 4.1.9, 4.1.10; CIS EKS and GKE 3.1.3, 3.1.4). kubeadm writes it 644.",
	Remediation: nodeFileFix("/var/lib/kubelet/config.yaml (EKS: /etc/kubernetes/kubelet/config.json; GKE: /home/kubernetes/kubelet-config.yaml)", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_kubelet_config_mode", managedNodeFileLimit(a)) ||
			fileOwnerNot(a, "node_file_kubelet_config_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_kubelet_config_mode", "node_file_kubelet_config_owner", "cloud_provider"),
}

// k8sNodeAzureJSONFile is AKS's node cloud-provider config. The reader only
// stats it (files container): it holds the cluster service principal's secret.
var k8sNodeAzureJSONFile = Check{
	ID:          "k8s-node-azure-json-file",
	Title:       "AKS azure.json is writable by others or not owned by root",
	Description: "/etc/kubernetes/azure.json on an AKS node, which holds the cluster's Azure cloud-provider configuration and service principal credentials, is more permissive than 644 or not owned by root:root (CIS AKS 3.1.3, 3.1.4).",
	Remediation: nodeFileFix("/etc/kubernetes/azure.json", "644", "root:root") + " AKS reimages nodes from its node image: reimage or upgrade the node pool (`az aks nodepool upgrade --node-image-only`) rather than editing nodes by hand where possible.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_azure_json_mode", 0o644) ||
			fileOwnerNot(a, "node_file_azure_json_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_azure_json_mode", "node_file_azure_json_owner"),
}

// ── 1.1 Control-plane node files ────────────────────────────────────────────

var k8sCPAPIServerManifest = Check{
	ID:          "k8s-cp-apiserver-manifest-file",
	Title:       "API server static pod manifest is too permissive or not owned by root",
	Description: "/etc/kubernetes/manifests/kube-apiserver.yaml is more permissive than 600 or not owned by root:root. Whoever can write it runs any container, with any flags, as the API server (CIS Kubernetes 1.1.1, 1.1.2).",
	Remediation: nodeFileFix("/etc/kubernetes/manifests/kube-apiserver.yaml", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_apiserver_manifest_mode", 0o600) ||
			fileOwnerNot(a, "node_file_apiserver_manifest_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_apiserver_manifest_mode", "node_file_apiserver_manifest_owner"),
}

var k8sCPControllerManagerManifest = Check{
	ID:          "k8s-cp-controller-manager-manifest-file",
	Title:       "Controller manager static pod manifest is too permissive or not owned by root",
	Description: "/etc/kubernetes/manifests/kube-controller-manager.yaml is more permissive than 600 or not owned by root:root (CIS Kubernetes 1.1.3, 1.1.4).",
	Remediation: nodeFileFix("/etc/kubernetes/manifests/kube-controller-manager.yaml", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_controller_manager_manifest_mode", 0o600) ||
			fileOwnerNot(a, "node_file_controller_manager_manifest_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_controller_manager_manifest_mode", "node_file_controller_manager_manifest_owner"),
}

var k8sCPSchedulerManifest = Check{
	ID:          "k8s-cp-scheduler-manifest-file",
	Title:       "Scheduler static pod manifest is too permissive or not owned by root",
	Description: "/etc/kubernetes/manifests/kube-scheduler.yaml is more permissive than 600 or not owned by root:root (CIS Kubernetes 1.1.5, 1.1.6).",
	Remediation: nodeFileFix("/etc/kubernetes/manifests/kube-scheduler.yaml", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_scheduler_manifest_mode", 0o600) ||
			fileOwnerNot(a, "node_file_scheduler_manifest_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_scheduler_manifest_mode", "node_file_scheduler_manifest_owner"),
}

var k8sCPEtcdManifest = Check{
	ID:          "k8s-cp-etcd-manifest-file",
	Title:       "etcd static pod manifest is too permissive or not owned by root",
	Description: "/etc/kubernetes/manifests/etcd.yaml is more permissive than 600 or not owned by root:root. Whoever can write it controls the store that holds every Secret (CIS Kubernetes 1.1.7, 1.1.8).",
	Remediation: nodeFileFix("/etc/kubernetes/manifests/etcd.yaml", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_etcd_manifest_mode", 0o600) ||
			fileOwnerNot(a, "node_file_etcd_manifest_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_etcd_manifest_mode", "node_file_etcd_manifest_owner"),
}

var k8sCPCNIFiles = Check{
	ID:          "k8s-cp-cni-config-files",
	Title:       "CNI configuration files are too permissive or not owned by root",
	Description: "A file under /etc/cni/net.d on a control-plane node is more permissive than 600 or not owned by root:root. Whoever can change it reroutes or bypasses pod networking on that node (CIS Kubernetes 1.1.9, 1.1.10).",
	Remediation: nodeFileFix("/etc/cni/net.d/*", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_cni_mode", 0o600) || fileOwnerNot(a, "node_file_cni_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_cni_mode", "node_file_cni_owner"),
}

var k8sCPEtcdDataDir = Check{
	ID:          "k8s-cp-etcd-data-dir",
	Title:       "etcd data directory is too permissive or not owned by etcd",
	Description: "The etcd data directory (/var/lib/etcd) is more permissive than 700 or not owned by etcd:etcd. It holds every object in the cluster, Secrets included, in plaintext unless encryption at rest is configured (CIS Kubernetes 1.1.11, 1.1.12). kubeadm runs etcd as root, so its directory is root-owned.",
	Remediation: "On every control-plane node run `chmod 700 /var/lib/etcd` and, if etcd runs as a dedicated user, `chown etcd:etcd /var/lib/etcd` (create the etcd user and set the static pod's securityContext.runAsUser to it first).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_etcd_data_dir_mode", 0o700) ||
			fileOwnerNot(a, "node_file_etcd_data_dir_owner", "etcd:etcd")
	},
	EvidenceFor: nodeEvidence("node_file_etcd_data_dir_mode", "node_file_etcd_data_dir_owner"),
}

var k8sCPAdminKubeconfig = Check{
	ID:          "k8s-cp-admin-kubeconfig-file",
	Title:       "Administrative kubeconfig is readable by others or not owned by root",
	Description: "/etc/kubernetes/admin.conf or super-admin.conf, which carry cluster-admin credentials, is more permissive than 600 or not owned by root:root (CIS Kubernetes 1.1.13, 1.1.14).",
	Remediation: nodeFileFix("/etc/kubernetes/admin.conf /etc/kubernetes/super-admin.conf", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_admin_kubeconfig_mode", 0o600) ||
			fileOwnerNot(a, "node_file_admin_kubeconfig_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_admin_kubeconfig_mode", "node_file_admin_kubeconfig_owner"),
}

var k8sCPSchedulerKubeconfig = Check{
	ID:          "k8s-cp-scheduler-kubeconfig-file",
	Title:       "Scheduler kubeconfig is readable by others or not owned by root",
	Description: "/etc/kubernetes/scheduler.conf, the scheduler's credentials, is more permissive than 600 or not owned by root:root (CIS Kubernetes 1.1.15, 1.1.16).",
	Remediation: nodeFileFix("/etc/kubernetes/scheduler.conf", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_scheduler_kubeconfig_mode", 0o600) ||
			fileOwnerNot(a, "node_file_scheduler_kubeconfig_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_scheduler_kubeconfig_mode", "node_file_scheduler_kubeconfig_owner"),
}

var k8sCPControllerManagerKubeconfig = Check{
	ID:          "k8s-cp-controller-manager-kubeconfig-file",
	Title:       "Controller manager kubeconfig is readable by others or not owned by root",
	Description: "/etc/kubernetes/controller-manager.conf, the controller manager's credentials, is more permissive than 600 or not owned by root:root (CIS Kubernetes 1.1.17, 1.1.18).",
	Remediation: nodeFileFix("/etc/kubernetes/controller-manager.conf", "600", "root:root"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return fileModeExceeds(a, "node_file_controller_manager_kubeconfig_mode", 0o600) ||
			fileOwnerNot(a, "node_file_controller_manager_kubeconfig_owner", "root:root")
	},
	EvidenceFor: nodeEvidence("node_file_controller_manager_kubeconfig_mode", "node_file_controller_manager_kubeconfig_owner"),
}

var k8sCPPKIOwnership = Check{
	ID:          "k8s-cp-pki-ownership",
	Title:       "Kubernetes PKI directory has files not owned by root",
	Description: "/etc/kubernetes/pki, or a file in it, is not owned by root:root, so a non-root account can replace the cluster's CAs or read its keys (CIS Kubernetes 1.1.19).",
	Remediation: "On every control-plane node run `chown -R root:root /etc/kubernetes/pki/`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return fileOwnerNot(a, "node_file_pki_owner", "root:root") },
	EvidenceFor: nodeEvidence("node_file_pki_owner"),
}

var k8sCPPKICertMode = Check{
	ID:          "k8s-cp-pki-cert-mode",
	Title:       "Kubernetes PKI certificates are writable by others",
	Description: "A certificate (*.crt) under /etc/kubernetes/pki is more permissive than 644, so someone other than root can replace a CA or serving certificate (CIS Kubernetes 1.1.20).",
	Remediation: "On every control-plane node run `find /etc/kubernetes/pki -name '*.crt' -exec chmod 644 {} +`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return fileModeExceeds(a, "node_file_pki_cert_mode", 0o644) },
	EvidenceFor: nodeEvidence("node_file_pki_cert_mode"),
}

var k8sCPPKIKeyMode = Check{
	ID:          "k8s-cp-pki-key-mode",
	Title:       "Kubernetes PKI private keys are readable by others",
	Description: "A private key (*.key) under /etc/kubernetes/pki is more permissive than 600, so an account other than root can read a CA or service-account signing key and mint credentials for the whole cluster (CIS Kubernetes 1.1.21).",
	Remediation: "On every control-plane node run `find /etc/kubernetes/pki -name '*.key' -exec chmod 600 {} +`, then rotate any key that may have been read.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return fileModeExceeds(a, "node_file_pki_key_mode", 0o600) },
	EvidenceFor: nodeEvidence("node_file_pki_key_mode"),
}

// k8sNodeChecks are the node posture and kube-proxy checks of k8s_node.go and
// this file.
func k8sNodeChecks() []Check {
	return []Check{
		k8sKubeletAnonymousAuth,
		k8sKubeletAuthzAlwaysAllow,
		k8sKubeletNoClientCA,
		k8sKubeletReadOnlyPort,
		k8sKubeletStreamingTimeout,
		k8sKubeletNoIPTablesChains,
		k8sKubeletHostnameOverride,
		k8sKubeletNoTLSCert,
		k8sKubeletCertRotationDisabled,
		k8sKubeletServerCertRotationDisabled,
		k8sKubeletWeakCiphers,
		k8sKubeletNoPIDLimit,
		k8sKubeletSeccompDefaultOff,
		k8sKubeProxyMetricsExposed,
		k8sNodeKubeletServiceFile,
		k8sNodeKubeProxyKubeconfig,
		k8sNodeKubeletKubeconfig,
		k8sNodeClientCAFile,
		k8sNodeKubeletConfigFile,
		k8sNodeAzureJSONFile,
		k8sCPAPIServerManifest,
		k8sCPControllerManagerManifest,
		k8sCPSchedulerManifest,
		k8sCPEtcdManifest,
		k8sCPCNIFiles,
		k8sCPEtcdDataDir,
		k8sCPAdminKubeconfig,
		k8sCPSchedulerKubeconfig,
		k8sCPControllerManagerKubeconfig,
		k8sCPPKIOwnership,
		k8sCPPKICertMode,
		k8sCPPKIKeyMode,
	}
}
