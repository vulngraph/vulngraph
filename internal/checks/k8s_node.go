package checks

// k8s_node.go — CIS Kubernetes 4.2 (kubelet) and 4.3 (kube-proxy) controls,
// which CIS EKS 3.2 repeats. Kubelet settings come from the opt-in node posture
// reader (ADR 094, collect/kubernetes/nodeposture_kubelet.go); kube-proxy's
// from its pods and ConfigMap. Both are merged across nodes onto the
// k8s_cluster asset, one finding per cluster, firing when any node fails.
// Without the reader every kubelet key is absent and these checks are unknown,
// never passing.

import (
	"net"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// kubeletStrongCiphers is CIS Kubernetes 4.2.12's allowed list.
var kubeletStrongCiphers = []string{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
}

// cpAnyNot reports whether any node's or replica's setting differs from good.
func cpAnyNot(a asset.Asset, key, good string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		if r != good {
			return true
		}
	}
	return false
}

// anyBindNotLoopback reports whether any host:port value binds a non-loopback host.
func anyBindNotLoopback(a asset.Asset, key string) bool {
	v, ok := a.Metadata[key]
	if !ok {
		return false
	}
	for _, r := range replicaValues(v) {
		host := r
		if h, _, err := net.SplitHostPort(r); err == nil {
			host = h
		}
		if !isLoopbackHost(strings.Trim(host, "[]")) {
			return true
		}
	}
	return false
}

func kubeletFix(change string) string {
	return "On every node, " + change + " in the kubelet configuration file (kubeadm: /var/lib/kubelet/config.yaml, and the kubelet-config ConfigMap in kube-system so new nodes inherit it; EKS: the node group's launch template or nodeadm NodeConfig; GKE: the node pool's kubelet config) and restart the kubelet (`systemctl restart kubelet`). A command-line flag overrides the file, so remove any conflicting flag from the kubelet's environment files. Verify on a node: `kubectl get --raw /api/v1/nodes/NODE/proxy/configz` (needs nodes/proxy) or rerun graph's node posture reader."
}

var k8sKubeletAnonymousAuth = Check{
	ID:          "k8s-kubelet-anonymous-auth",
	Title:       "Kubelet accepts anonymous requests",
	Description: "A kubelet serves its API (port 10250) to unauthenticated callers as system:anonymous. Combined with a permissive authorizer that is exec into any pod on the node from anywhere that can reach it (CIS Kubernetes 4.2.1, CIS EKS 3.2.1).",
	Remediation: kubeletFix("set authentication.anonymous.enabled: false (or remove --anonymous-auth=true)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_anonymous_auth", "true") },
	EvidenceFor: nodeEvidence("kubelet_anonymous_auth"),
}

var k8sKubeletAuthzAlwaysAllow = Check{
	ID:          "k8s-kubelet-authz-always-allow",
	Title:       "Kubelet authorizes every request",
	Description: "A kubelet's authorization mode is AlwaysAllow, so any caller it authenticates may exec into, read logs of and port-forward to every pod on the node without the API server being asked (CIS Kubernetes 4.2.2, CIS EKS 3.2.2).",
	Remediation: kubeletFix("set authorization.mode: Webhook (or remove --authorization-mode=AlwaysAllow)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_authorization_mode", "AlwaysAllow") },
	EvidenceFor: nodeEvidence("kubelet_authorization_mode"),
}

var k8sKubeletNoClientCA = Check{
	ID:          "k8s-kubelet-no-client-ca",
	Title:       "Kubelet does not verify client certificates",
	Description: "A kubelet has no client CA file (authentication.x509.clientCAFile / --client-ca-file), so it cannot authenticate the API server or any other client by certificate (CIS Kubernetes 4.2.3, CIS EKS 3.2.3).",
	Remediation: kubeletFix("set authentication.x509.clientCAFile to the cluster CA bundle"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_client_ca_set", "false") },
	EvidenceFor: nodeEvidence("kubelet_client_ca_set"),
}

var k8sKubeletReadOnlyPort = Check{
	ID:          "k8s-kubelet-read-only-port",
	Title:       "Kubelet serves the unauthenticated read-only port",
	Description: "A kubelet's readOnlyPort is not 0, so it serves pod specs, environment and metrics on plain HTTP (usually 10255) to anyone who can reach the node, with no authentication (CIS Kubernetes 4.2.4, CIS EKS 3.2.4).",
	Remediation: kubeletFix("set readOnlyPort: 0 (or remove --read-only-port)"),
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyNot(a, "kubelet_read_only_port", "0") },
	EvidenceFor: nodeEvidence("kubelet_read_only_port"),
}

var k8sKubeletStreamingTimeout = Check{
	ID:          "k8s-kubelet-streaming-timeout-disabled",
	Title:       "Kubelet never closes idle streaming connections",
	Description: "A kubelet's --streaming-connection-idle-timeout is 0, so idle exec, attach and port-forward sessions stay open forever, exhausting the node and keeping abandoned sessions usable (CIS Kubernetes 4.2.5, CIS EKS 3.2.5). A 0s in the config file is defaulted to 4h by the kubelet and is not reported.",
	Remediation: kubeletFix("remove --streaming-connection-idle-timeout=0 or set streamingConnectionIdleTimeout: 4h"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_streaming_idle_timeout", "0s") },
	EvidenceFor: nodeEvidence("kubelet_streaming_idle_timeout"),
}

var k8sKubeletNoIPTablesChains = Check{
	ID:          "k8s-kubelet-no-iptables-util-chains",
	Title:       "Kubelet does not manage its iptables utility chains",
	Description: "A kubelet runs with makeIPTablesUtilChains false, so the KUBE-FIREWALL drop rules it maintains are not kept in step with pod networking (CIS Kubernetes 4.2.6, CIS EKS 3.2.6).",
	Remediation: kubeletFix("set makeIPTablesUtilChains: true (or remove --make-iptables-util-chains=false)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_make_iptables_util_chains", "false") },
	EvidenceFor: nodeEvidence("kubelet_make_iptables_util_chains"),
}

var k8sKubeletHostnameOverride = Check{
	ID:          "k8s-kubelet-hostname-override",
	Title:       "Kubelet overrides its node hostname",
	Description: "A kubelet runs with --hostname-override, so the node's name differs from its hostname and TLS between the API server and the kubelet can stop matching (CIS Kubernetes 4.2.7). Some cloud node images set it on purpose; the flag is read from the kubelet's environment and unit files, not the live command line.",
	Remediation: "Remove --hostname-override from the kubelet's flags (kubeadm: /var/lib/kubelet/kubeadm-flags.env or /etc/default/kubelet) unless the platform requires it, and restart the kubelet with `systemctl restart kubelet`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_hostname_override_set", "true") },
	EvidenceFor: nodeEvidence("kubelet_hostname_override_set"),
}

var k8sKubeletNoTLSCert = Check{
	ID:          "k8s-kubelet-no-tls-cert",
	Title:       "Kubelet serves a self-signed certificate",
	Description: "A kubelet has no tlsCertFile and tlsPrivateKeyFile, so it serves a self-signed certificate the API server cannot verify (CIS Kubernetes 4.2.9). serverTLSBootstrap issues a CA-signed certificate instead, but does not set these fields and is reported here as the benchmark audit reports it.",
	Remediation: kubeletFix("set tlsCertFile and tlsPrivateKeyFile to a CA-signed serving certificate (or enable serverTLSBootstrap and approve the kubelet-serving CSRs)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_tls_cert_set", "false") },
	EvidenceFor: nodeEvidence("kubelet_tls_cert_set"),
}

var k8sKubeletCertRotationDisabled = Check{
	ID:          "k8s-kubelet-cert-rotation-disabled",
	Title:       "Kubelet client certificate rotation is turned off",
	Description: "A kubelet sets rotateCertificates false, so its client certificate is never renewed and the node drops out of the cluster when it expires, or someone extends it by hand with a long lifetime (CIS Kubernetes 4.2.10, CIS EKS 3.2.8).",
	Remediation: kubeletFix("set rotateCertificates: true (or remove --rotate-certificates=false)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_rotate_certificates", "false") },
	EvidenceFor: nodeEvidence("kubelet_rotate_certificates"),
}

var k8sKubeletServerCertRotationDisabled = Check{
	ID:          "k8s-kubelet-server-cert-rotation-disabled",
	Title:       "Kubelet serving certificate rotation is turned off",
	Description: "A kubelet sets the RotateKubeletServerCertificate feature gate to false without serverTLSBootstrap, so its serving certificate is never renewed (CIS Kubernetes 4.2.11, CIS EKS 3.2.9).",
	Remediation: kubeletFix("remove RotateKubeletServerCertificate: false from featureGates (or --feature-gates) and set serverTLSBootstrap: true"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_rotate_server_certificates", "false") },
	EvidenceFor: nodeEvidence("kubelet_rotate_server_certificates"),
}

var k8sKubeletWeakCiphers = Check{
	ID:          "k8s-kubelet-weak-tls-ciphers",
	Title:       "Kubelet does not restrict TLS to strong cipher suites",
	Description: "A kubelet's tlsCipherSuites is unset (Go's default list) or names a suite outside the CIS strong list, so callers can negotiate weaker ciphers (CIS Kubernetes 4.2.12).",
	Remediation: kubeletFix("set tlsCipherSuites to TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyWeakCiphers(a, "kubelet_tls_cipher_suites", kubeletStrongCiphers)
	},
	EvidenceFor: nodeEvidence("kubelet_tls_cipher_suites"),
}

var k8sKubeletNoPIDLimit = Check{
	ID:          "k8s-kubelet-no-pid-limit",
	Title:       "Kubelet does not limit process IDs per pod",
	Description: "A kubelet's podPidsLimit is unset (-1) or 0, so one pod can fork until the node runs out of PIDs and every other pod on it fails (CIS Kubernetes 4.2.13).",
	Remediation: kubeletFix("set podPidsLimit to a bound sized for your workloads (for example 4096)"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyBelow(a, "kubelet_pod_pids_limit", 1) },
	EvidenceFor: nodeEvidence("kubelet_pod_pids_limit"),
}

var k8sKubeletSeccompDefaultOff = Check{
	ID:          "k8s-kubelet-seccomp-default-off",
	Title:       "Kubelet does not apply RuntimeDefault seccomp by default",
	Description: "A kubelet runs with seccompDefault false, so containers that name no seccomp profile run unconfined, with every syscall available (CIS Kubernetes 4.2.14). k8s-pod-seccomp-unrestricted reports the pods that rely on it.",
	Remediation: kubeletFix("set seccompDefault: true (test workloads first: RuntimeDefault blocks some syscalls)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "kubelet_seccomp_default", "false") },
	EvidenceFor: nodeEvidence("kubelet_seccomp_default"),
}

var k8sKubeProxyMetricsExposed = Check{
	ID:          "k8s-kube-proxy-metrics-exposed",
	Title:       "kube-proxy serves metrics on a non-loopback address",
	Description: "kube-proxy's metricsBindAddress (or --metrics-bind-address) is not a loopback address, so its metrics and /debug endpoints are reachable on the node network without authentication (CIS Kubernetes 4.3.1). Read from the kube-proxy pods and the ConfigMap their --config file comes from.",
	Remediation: "Set metricsBindAddress: 127.0.0.1:10249 in the kube-proxy configuration (kubeadm: `kubectl -n kube-system edit configmap kube-proxy`, key config.conf; EKS: the kube-proxy-config ConfigMap or the kube-proxy add-on configuration), then restart the DaemonSet with `kubectl -n kube-system rollout restart daemonset kube-proxy`. Scrape metrics through a node-local agent instead.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return anyBindNotLoopback(a, "kube_proxy_metrics_bind_address") },
	EvidenceFor: nodeEvidence("kube_proxy_metrics_bind_address"),
}

// nodeEvidence copies the named settings and the reader's coverage counts.
func nodeEvidence(keys ...string) func(asset.Asset) map[string]string {
	return func(a asset.Asset) map[string]string {
		ev := map[string]string{}
		for _, k := range append(keys, "node_posture_nodes_reported", "node_posture_cp_nodes_reported") {
			if v, ok := a.Metadata[k]; ok {
				ev[k] = v
			}
		}
		return ev
	}
}
