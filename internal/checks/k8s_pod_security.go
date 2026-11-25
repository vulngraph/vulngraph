package checks

// k8s_pod_security.go — one check per Pod Security Standard control the CIS
// Kubernetes, EKS and GKE benchmarks audit on running workloads, over the
// signals collect/kubernetes/pods_hardening.go records. Each control passes or
// fails on its own check ID; pod findings collapse to one per owning workload
// (Registry.Run), so a Deployment with ten replicas is one finding per control.
//
// Grading: host-namespace and host-filesystem access is a container-escape path
// and is graded High (Critical for Windows HostProcess, which IS the host, like
// k8s-privileged-container). The hardening defaults — seccomp, NET_RAW, a
// writable root filesystem, allowPrivilegeEscalation — are unset on most
// workloads in practice and are Low posture: they shrink what a break-in can do
// rather than open a door.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// k8sBenchmarkChecks are the per-control checks of k8s_pod_security.go,
// k8s_rbac_grants.go, k8s_rbac_bindings.go and k8s_namespace_policy.go.
func k8sBenchmarkChecks() []Check {
	return []Check{
		k8sHostPIDPod,
		k8sHostIPCPod,
		k8sHostPathVolume,
		k8sContainerHostPort,
		k8sWindowsHostProcess,
		k8sContainerAddedCapabilities,
		k8sContainerNetRaw,
		k8sPodSeccompUnrestricted,
		k8sPodAppArmorUnconfined,
		k8sContainerWritableRootFS,
		k8sContainerAllowPrivilegeEscalation,
		k8sPodSecretInEnv,
		k8sWorkloadDefaultNamespace,
		k8sRBACSecretsAccess,
		k8sRBACPodCreate,
		k8sRBACPodExec,
		k8sRBACPVCreate,
		k8sRBACNodeProxy,
		k8sRBACCSRApprove,
		k8sRBACWebhookConfig,
		k8sRBACTokenCreate,
		k8sRBACEscalate,
		k8sClusterRoleBindingAdminEdit,
		k8sBindingSystemMasters,
		k8sBindingToUnauthenticated,
		k8sBindingToAuthenticated,
		k8sNamespaceNoPodSecurityEnforcement,
		k8sNamespaceNoDefaultDeny,
		k8sDefaultSAAutomount,
	}
}

// isLivePod reports whether a pod may still be running: only a Succeeded or
// Failed pod (a finished Job or CronJob run) is excluded — it holds nothing
// and would otherwise add a finding per run, and its spec is the workload's,
// which the next live pod reports. Unknown and an unread phase stay evaluated:
// a pod whose state could not be read fails closed.
func isLivePod(a asset.Asset) bool {
	p := a.Metadata["phase"]
	return p != "Succeeded" && p != "Failed"
}

// isWindowsPod reports whether the collector placed the pod on Windows, where
// NET_RAW, seccomp, readOnlyRootFilesystem and allowPrivilegeEscalation do not
// apply (the Pod Security Standards exempt Windows pods from all four).
func isWindowsPod(a asset.Asset) bool { return a.Metadata["pod_os"] == "windows" }

var k8sHostPIDPod = Check{
	ID:          "k8s-host-pid-pod",
	Title:       "Pod shares the host PID namespace",
	Description: "The Pod has hostPID: true, so its containers see every process on the node. Combined with root or SYS_PTRACE that is a direct container escape (read another process's memory and environment, or inject into it); on its own it still exposes every co-located workload's command line and environment." + k8sSystemPodNote,
	Remediation: "Remove hostPID: true. Node-level agents that genuinely need it belong in a namespace whose Pod Security Admission level is explicitly 'privileged'; enforce 'baseline' or 'restricted' everywhere else.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["host_pid"] == "true" && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sHostIPCPod = Check{
	ID:          "k8s-host-ipc-pod",
	Title:       "Pod shares the host IPC namespace",
	Description: "The Pod has hostIPC: true, so its containers share System V IPC and POSIX shared memory with every process on the node and can read or tamper with another workload's shared memory segments." + k8sSystemPodNote,
	Remediation: "Remove hostIPC: true. Enforce the 'baseline' Pod Security Standard on the namespace so the field is rejected at admission.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["host_ipc"] == "true" && isLivePod(a) && !isK8sSystemPod(a)
	},
}

// sensitiveHostPaths are node paths whose mount is a node compromise on its
// own: the root filesystem, node configuration, kubelet state (every pod's
// ServiceAccount token), etcd's data directory (every Secret on a self-managed
// control-plane node), the node's logs (other workloads' output, and a writable
// /var/log lets the kubelet's log API read arbitrary host files through
// symlinks) and the container runtime sockets (start a privileged container on
// the node).
var sensitiveHostPaths = []string{
	"/", "/etc", "/root", "/proc", "/sys", "/dev", "/boot",
	"/var/lib/kubelet", "/var/lib/docker", "/var/lib/containerd", "/var/lib/etcd", "/var/log",
	"/var/run/docker.sock", "/run/docker.sock", "/var/run/containerd", "/run/containerd",
	"/var/run/crio", "/run/crio",
}

// isSensitiveHostPath reports whether a hostPath mount is, or contains, a
// sensitive node path: mounting "/var" exposes /var/lib/kubelet as surely as
// mounting /var/lib/kubelet does.
func isSensitiveHostPath(p string) bool {
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return true // "/" itself
	}
	for _, s := range sensitiveHostPaths {
		if s == "/" {
			continue
		}
		if p == s || strings.HasPrefix(s, p+"/") || strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return false
}

var k8sHostPathVolume = Check{
	ID:          "k8s-pod-host-path-volume",
	Title:       "Pod mounts a hostPath volume",
	Description: "The Pod mounts a directory from the node's filesystem. A hostPath mount of the root filesystem, node configuration, kubelet state or a container-runtime socket is a node compromise on its own (every pod's ServiceAccount token lives under /var/lib/kubelet; the runtime socket starts a privileged container); any writable hostPath lets the workload plant files the node will read. The mounted paths are in the finding evidence." + k8sSystemPodNote,
	Remediation: "Replace hostPath with an emptyDir, a ConfigMap/Secret volume, or a PersistentVolumeClaim. Node agents that genuinely need host files belong in a namespace explicitly labelled with the 'privileged' Pod Security Standard; mount the narrowest path read-only.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["host_path_volumes"] != "" && isLivePod(a) && !isK8sSystemPod(a)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		for _, p := range strings.Split(a.Metadata["host_path_volumes"], ",") {
			if isSensitiveHostPath(p) {
				return finding.SeverityHigh
			}
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"host_paths": a.Metadata["host_path_volumes"]}
	},
}

var k8sContainerHostPort = Check{
	ID:          "k8s-container-host-port",
	Title:       "Container binds a port on the node (hostPort)",
	Description: "A container declares a hostPort, binding the port on the node's own network interfaces. It bypasses Service and NetworkPolicy controls for that port and exposes the workload on every address the node has, including a public one." + k8sSystemPodNote,
	Remediation: "Remove hostPort and expose the workload through a ClusterIP Service (or an Ingress/LoadBalancer for external traffic).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		// A hostNetwork pod gets hostPort defaulted to every containerPort by the
		// API server; k8s-host-network-pod already reports that pod, and this
		// finding would only restate it.
		return a.Metadata["host_ports"] != "" && a.Metadata["host_network"] == "false" && isLivePod(a) && !isK8sSystemPod(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"host_ports": a.Metadata["host_ports"]}
	},
}

var k8sWindowsHostProcess = Check{
	ID:          "k8s-windows-host-process",
	Title:       "Pod runs a Windows HostProcess container",
	Description: "A container sets securityContext.windowsOptions.hostProcess: true. A HostProcess container runs directly on the Windows node as a host process, with the node's network, filesystem and (typically) SYSTEM privileges — it is the node, not a container on it." + k8sSystemPodNote,
	Remediation: "Remove hostProcess: true. Reserve HostProcess containers for node agents in a namespace explicitly labelled with the 'privileged' Pod Security Standard.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["windows_host_process"] == "true" && isLivePod(a) && !isK8sSystemPod(a)
	},
}

// k8sContainerAddedCapabilities covers every capability a container adds
// beyond the runtime default set. It steps aside when k8s-dangerous-capabilities
// fires — an added SYS_ADMIN already is the capability finding for that pod.
var k8sContainerAddedCapabilities = Check{
	ID:          "k8s-container-added-capabilities",
	Title:       "Container adds Linux capabilities",
	Description: "A container adds Linux capabilities beyond the container runtime's default set. Each one widens what a compromised process can do to the node; the 'restricted' Pod Security Standard allows only NET_BIND_SERVICE. The added capabilities are in the finding evidence." + k8sSystemPodNote,
	Remediation: "Drop ALL capabilities and add back only those the process provably needs (usually none, or NET_BIND_SERVICE to bind a port below 1024).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["added_capabilities"] != "" && observedNone(a, "dangerous_capabilities") && isLivePod(a) && !isK8sSystemPod(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"added_capabilities": a.Metadata["added_capabilities"]}
	},
}

var k8sContainerNetRaw = Check{
	ID:          "k8s-container-net-raw",
	Title:       "Container keeps the NET_RAW capability",
	Description: "A container neither drops NET_RAW nor ALL capabilities, so it keeps NET_RAW from the runtime's default set: it can craft raw packets, spoof addresses and ARP/DNS-poison other pods on the node network." + k8sSystemPodNote,
	Remediation: "Set securityContext.capabilities.drop: [\"ALL\"] (or at least NET_RAW) on every container, and add back only what the process needs.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["net_raw_retained"] == "true" && !isWindowsPod(a) && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sPodSeccompUnrestricted = Check{
	ID:          "k8s-pod-seccomp-unrestricted",
	Title:       "Pod does not run under a RuntimeDefault or Localhost seccomp profile",
	Description: "At least one container has no seccomp profile (or an explicit Unconfined one), so every system call is available to it — including the rarely-used ones most kernel container-escape exploits rely on. Nodes whose kubelet runs with --seccomp-default apply RuntimeDefault to unset profiles; that node setting is not visible to graph, and the benchmark audits the pod spec." + k8sSystemPodNote,
	Remediation: "Set securityContext.seccompProfile.type: RuntimeDefault at the pod level (or Localhost with a reviewed profile). Enforce the 'restricted' Pod Security Standard to make it mandatory.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["seccomp_unrestricted"] == "true" && !isWindowsPod(a) && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sPodAppArmorUnconfined = Check{
	ID:          "k8s-pod-apparmor-unconfined",
	Title:       "Pod explicitly disables AppArmor confinement",
	Description: "A container sets its AppArmor profile to Unconfined (securityContext.appArmorProfile or the container.apparmor.security.beta.kubernetes.io annotation), switching off the runtime's default mandatory-access-control profile on nodes that have AppArmor." + k8sSystemPodNote,
	Remediation: "Remove the Unconfined profile so the runtime default applies, or set appArmorProfile.type: Localhost with a reviewed profile.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["apparmor_unconfined"] == "true" && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sContainerWritableRootFS = Check{
	ID:          "k8s-container-writable-root-fs",
	Title:       "Container root filesystem is writable",
	Description: "At least one container does not set readOnlyRootFilesystem: true, so a compromised process can drop tools and persist changes in the container image layer." + k8sSystemPodNote,
	Remediation: "Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir for the paths the process genuinely writes (e.g. /tmp).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["writable_root_fs"] == "true" && !isWindowsPod(a) && isLivePod(a) && !isK8sSystemPod(a)
	},
}

// k8sContainerAllowPrivilegeEscalation checks allowPrivilegeEscalation apart
// from k8s-container-runs-as-root, so each of the two benchmark controls passes
// or fails on its own check. Low,
// where root is Medium: the field is unset on most workloads, and it only
// matters once something in the container is already setuid-capable.
var k8sContainerAllowPrivilegeEscalation = Check{
	ID:          "k8s-container-allow-privilege-escalation",
	Title:       "Container allows privilege escalation",
	Description: "At least one container does not set allowPrivilegeEscalation: false (the Kubernetes default is true), so a process can gain more privileges than its parent through setuid binaries or file capabilities — a standard step in container breakouts." + k8sSystemPodNote,
	Remediation: "Set securityContext.allowPrivilegeEscalation: false on every container. Enforce the 'restricted' Pod Security Standard to make it mandatory.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["allow_priv_escalation"] == "true" && !isWindowsPod(a) && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sPodSecretInEnv = Check{
	ID:          "k8s-pod-secret-in-env",
	Title:       "Pod passes Secrets as environment variables",
	Description: "A container reads a Secret through env[].valueFrom.secretKeyRef or envFrom[].secretRef. Environment variables leak into crash dumps, debug endpoints, child processes and log lines far more readily than a mounted file, and cannot be rotated without a restart. The referenced Secret names (never values) are in the finding evidence." + k8sSystemPodNote,
	Remediation: "Mount the Secret as a volume and have the application read the file, or fetch it from an external secret manager at runtime.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["secret_env_refs"] != "" && isLivePod(a) && !isK8sSystemPod(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"secrets": a.Metadata["secret_env_refs"]}
	},
}

var k8sWorkloadDefaultNamespace = Check{
	ID:          "k8s-workload-default-namespace",
	Title:       "Workload runs in the default namespace",
	Description: "The workload runs in the 'default' namespace, which carries no RBAC, NetworkPolicy, quota or Pod Security boundary of its own — anything that can create objects without naming a namespace lands next to it.",
	Remediation: "Move the workload to a dedicated namespace with its own RBAC, NetworkPolicy and Pod Security Admission label.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["namespace"] == "default" && isLivePod(a)
	},
}
