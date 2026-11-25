package checks

// k8s_workload.go — checks over the Kubernetes workload asset types (k8s_pod,
// k8s_service, k8s_ingress, k8s_namespace). The RBAC asset types live in
// rbac_cluster.go and rbac_namespaced.go.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var k8sServicePublicLoadBalancer = Check{
	ID:          "k8s-service-public-loadbalancer",
	Title:       "Kubernetes Service is exposed via a public load balancer",
	Description: "The Service has type LoadBalancer and has been assigned a public IP or hostname, making it directly reachable from the internet. This bypasses any ingress or API gateway layer. Two cases are reported at Medium with their own titles. A load balancer whose loadBalancerSourceRanges admit only specific client ranges: the cloud provider enforces those ranges, but one that ignores the field leaves the address open. A Service the AWS Load Balancer Controller or EKS Auto Mode provisions with no aws-load-balancer-scheme annotation: the controller keeps an existing NLB's scheme or applies its configured default (internal unless changed), and the Service does not show which.",
	Remediation: "Use an Ingress resource with a single internet-facing load balancer instead. If direct LoadBalancer exposure is required, restrict spec.loadBalancerSourceRanges to the clients that need it, and protect the service with appropriate network policies and firewall rules. For an AWS NLB, set service.beta.kubernetes.io/aws-load-balancer-scheme explicitly.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_service",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["type"] == "LoadBalancer" && a.PublicIP != ""
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["scheme_assumed"] == "true" || a.Metadata["source_restricted"] == "true" {
			return finding.SeverityMedium
		}
		return finding.SeverityHigh
	},
	TitleFor: func(a asset.Asset) string {
		switch {
		case a.Metadata["scheme_assumed"] == "true":
			return "Kubernetes Service may be exposed via a public load balancer (scheme not set)"
		case a.Metadata["source_restricted"] == "true":
			return "Kubernetes Service is exposed via a public load balancer limited to source ranges"
		}
		return "Kubernetes Service is exposed via a public load balancer"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"source_ranges": a.Metadata["source_ranges"], "scheme_assumed": a.Metadata["scheme_assumed"]}
	},
}

// --- Kubernetes pod security ---

// isK8sSystemPod reports whether a pod is exempt from pod-security checks. A pod
// is exempt when its namespace explicitly enforces the "privileged" Pod Security
// Standard (pod-security.kubernetes.io/enforce=privileged) — an operator's
// deliberate "privileged workloads belong here" decision, independent of name —
// or when it lives in a known system namespace (the static fallback for clusters
// that haven't adopted PSA labels). Every check that calls it ends its
// Description with k8sSystemPodNote (k8s_namespace_exemptions.go).
func isK8sSystemPod(a asset.Asset) bool {
	if a.Metadata["ns_psa_enforce"] == "privileged" {
		return true
	}
	return k8sSystemNamespaces[a.Metadata["namespace"]]
}

// IsK8sSystemNamespace reports whether ns is excluded from pod security checks
// (see k8sSystemNamespaces). Exported for the dangling-finding sweep
// (internal/jobs), which needs the same exclusion list to auto-resolve
// findings that predate a namespace being added to it (a check-ID-based
// registry-change backfill can't see this: the check's ID and count are
// unchanged, only its internal predicate logic moved).
func IsK8sSystemNamespace(ns string) bool { return k8sSystemNamespaces[ns] }

var k8sPrivilegedContainer = Check{
	ID:          "k8s-privileged-container",
	Title:       "Pod runs a privileged container",
	Description: "A container in this Pod has securityContext.privileged: true, giving it root-equivalent access to the host kernel. A privileged container can escape to the host node, access all host devices, and compromise the entire cluster." + k8sSystemPodNote,
	Remediation: "Remove the privileged: true flag. If the workload requires elevated privileges, use specific Linux capabilities (e.g. NET_BIND_SERVICE) rather than blanket privilege. For host access, prefer DaemonSets with minimal capabilities.",
	Type:        "rbac",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["privileged"] == "true" && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sHostNetworkPod = Check{
	ID:          "k8s-host-network-pod",
	Title:       "Pod uses host network namespace",
	Description: "The Pod has hostNetwork: true, sharing the host node's network namespace. The container sees all node network interfaces and can sniff traffic, bind to privileged ports, and reach services bound to 127.0.0.1 on the node." + k8sSystemPodNote,
	Remediation: "Remove hostNetwork: true unless absolutely required (e.g. CNI plugins, specific network tools). Use a ClusterIP Service for inter-pod communication instead.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["host_network"] == "true" && isLivePod(a) && !isK8sSystemPod(a)
	},
}

var k8sDangerousCapabilities = Check{
	ID:          "k8s-dangerous-capabilities",
	Title:       "Pod adds container-escape Linux capabilities",
	Description: "A container adds one or more high-risk Linux capabilities: SYS_ADMIN (container escape via mount/namespace operations), SYS_MODULE (load a kernel module), SYS_RAWIO or DAC_READ_SEARCH (raw device access and arbitrary host file reads), SYS_PTRACE (ptrace on host processes), NET_ADMIN (network traffic interception), BPF, or ALL. The capabilities are in the finding evidence." + k8sSystemPodNote,
	Remediation: "Drop all capabilities and add back only the minimum required. Use AppArmor or seccomp profiles to constrain the effective capability set further.",
	Type:        "rbac",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["dangerous_capabilities"] != "" && isLivePod(a) && !isK8sSystemPod(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"dangerous_capabilities": a.Metadata["dangerous_capabilities"]}
	},
}

// k8sServiceNodePort fires on Kubernetes Services with type=NodePort. NodePort
// services bind a port on every node's external IP (0.0.0.0), bypassing the
// load-balancer/Ingress layer and exposing the service to the node network.
var k8sServiceNodePort = Check{
	ID:          "k8s-service-node-port",
	Title:       "Kubernetes Service exposes a NodePort on all cluster nodes",
	Description: "The Service is of type NodePort, which binds the service port on every node's IP address. This bypasses load-balancer access control and exposes the service on all node IPs, including nodes with public IPs.",
	Remediation: "Change the Service type to ClusterIP (internal only) or LoadBalancer with appropriate firewall rules. Never use NodePort in production clusters unless you control node-level firewalling.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_service",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["type"] == "NodePort"
	},
}

// --- k8s pod hygiene ---

// k8sPodRunsAsRoot reports containers that may run as UID 0. It does not also
// cover allowPrivilegeEscalation — that is k8s-container-allow-privilege-escalation
// — because the benchmarks audit the two as separate controls and an OR of both
// could pass or fail neither on its own.
var k8sPodRunsAsRoot = Check{
	ID:          "k8s-container-runs-as-root",
	Title:       "Kubernetes Pod may run containers as root",
	Description: "One or more containers in the Pod set neither runAsNonRoot: true nor a non-zero runAsUser, so the process runs as UID 0 unless the image happens to say otherwise. A root process can write to host-mounted volumes and reach sensitive paths if it escapes the container.",
	Remediation: "On every container (or the pod securityContext) set runAsNonRoot: true and runAsUser: <non-zero UID>, and build the image to run as an unprivileged user. Enforce cluster-wide with the 'restricted' Pod Security Standard.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return isLivePod(a) && a.Metadata["run_as_root"] == "true"
	},
}

// k8sPodLatestImage fires when a pod references a container image tagged :latest
// or with no tag.
var k8sPodLatestImage = Check{
	ID:          "k8s-image-latest-tag",
	Title:       "Kubernetes Pod uses :latest or untagged container image",
	Description: "One or more containers reference a :latest tag or an image with no explicit tag. This makes deployments non-deterministic — different nodes may pull different image versions, debugging is harder, and rollbacks are unreliable. It also prevents effective image vulnerability scanning on a pinned digest.",
	Remediation: "Pin all images to a specific immutable tag or SHA256 digest. Enforce this via admission webhook (OPA/Gatekeeper or Kyverno). Update CI pipelines to tag images with the git commit SHA.",
	Type:        "misconfiguration",
	// Low, not High: this is mostly an operational problem (non-deterministic
	// deploys, harder debugging, unreliable rollbacks), not a vulnerability. The
	// one security angle is a coverage argument (an unpinned digest is harder
	// to scan), and the platform already rates coverage-blockers Medium
	// (aws-ecr-scanning-disabled).
	Severity:  finding.SeverityLow,
	Provider:  asset.ProviderKubernetes,
	AssetType: "k8s_pod",
	Violates: func(a asset.Asset) bool {
		images := a.Metadata["images"]
		if images == "" || !isLivePod(a) {
			return false
		}
		for _, img := range strings.Split(images, ",") {
			img = strings.TrimSpace(img)
			if img == "" {
				continue
			}
			// Extract the image name part after the last /
			namePart := img
			if idx := strings.LastIndex(img, "/"); idx >= 0 {
				namePart = img[idx+1:]
			}
			// :latest tag or no colon at all in name (implicit latest)
			if strings.HasSuffix(img, ":latest") || !strings.Contains(namePart, ":") {
				return true
			}
		}
		return false
	},
}

// k8sPodAutomountSAToken fires when a running pod has a service account token
// mounted. Every process in the pod can read the token and call the k8s API
// with the SA's permissions; most workloads don't need API access.
//
// The collector resolves automount_sa_token the way the kubelet does: the pod's
// own field, else its ServiceAccount's. A pod on the default ServiceAccount
// that merely inherits the default SA's setting steps aside for
// k8s-default-sa-automount, which reports that setting once per namespace: one
// change there fixes every such pod, so per-workload findings would multiply a
// single root cause. A pod that turns automounting on in its own spec is still
// reported here, whichever ServiceAccount it runs as.
var k8sPodAutomountSAToken = Check{
	ID:          "k8s-automount-sa-token",
	Title:       "Kubernetes Pod automounts service account token unnecessarily",
	Description: "The Pod automounts a service account token into every container. Unless the Pod specifically needs to interact with the Kubernetes API, this is unnecessary and increases the blast radius of a container compromise — an attacker can use the token to pivot to the k8s control plane.",
	Remediation: "Set automountServiceAccountToken: false in the Pod spec (or ServiceAccount spec). Only enable it for Pods that genuinely need API access. Scope SA permissions to the minimum required (RBAC least privilege).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["automount_sa_token"] != "true" || !isLivePod(a) {
			return false
		}
		sa := a.Metadata["service_account"]
		onDefaultSA := sa == "" || sa == "default"
		return !onDefaultSA || a.Metadata["automount_sa_token_set_on_pod"] == "true"
	},
}

// k8sIngressNoTLS fires on Ingress resources that route HTTP without TLS.
var k8sIngressNoTLS = Check{
	ID:          "k8s-ingress-no-tls",
	Title:       "Kubernetes Ingress serves traffic without TLS",
	Description: "The Ingress exposes a hostname over HTTP without TLS termination. On an internet-facing ingress this is high risk — traffic is interceptable (credential theft, MITM); on an internal-only ingress the exposure is limited to the private network, so it is surfaced at a lower severity.",
	Remediation: "Add a spec.tls entry with a valid certificate (cert-manager or managed cert). Redirect HTTP to HTTPS. Ensure the ingress controller is configured to reject plain HTTP.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_ingress",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["tls"] == "false"
	},
	// Internet-facing ingress → high; internal-only (public=false) → low.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["public"] == "true" {
			return finding.SeverityHigh
		}
		return finding.SeverityLow
	},
}

// k8sNamespaceNoNetworkPolicy fires on namespaces that have running pods but
// no NetworkPolicy. Without NetworkPolicies, any pod in the cluster can reach
// any other pod — a compromised pod has unrestricted east-west access.
var k8sNamespaceNoNetworkPolicy = Check{
	ID:          "k8s-namespace-no-network-policy",
	Title:       "Kubernetes Namespace has no NetworkPolicy",
	Description: "The Namespace contains pods but has no NetworkPolicy defined. In the absence of NetworkPolicies, all pods can communicate with all other pods across all namespaces — a compromised workload has unrestricted access to internal services including databases, caches, and control-plane components." + k8sNetworkPolicyNote,
	Remediation: "Add a default-deny-ingress NetworkPolicy to the namespace and whitelist only required traffic. Use Calico/Cilium or native k8s NetworkPolicy. Start with: deny all ingress, then allow specific ports/namespaces.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_namespace",
	Violates: func(a asset.Asset) bool {
		// Only flag Active namespaces (not Terminating), and skip system namespaces
		// where policies are managed by the platform.
		if a.Metadata["phase"] != "Active" {
			return false
		}
		return !k8sNetworkPolicyExemptNamespaces[a.Name] && a.Metadata["has_network_policy"] == "false"
	},
}

// k8sPodNoResourceLimits fires when any container in the pod lacks CPU or memory
// limits.
var k8sPodNoResourceLimits = Check{
	ID:          "k8s-pod-no-resource-limits",
	Title:       "Kubernetes Pod has containers without resource limits",
	Description: "One or more containers do not declare CPU or memory limits. A container without limits can consume all node resources, causing noisy-neighbour OOMKills on other pods on the same node. It also prevents the HPA from scaling accurately." + k8sResourceLimitsExemptNote,
	Remediation: "Set resources.requests and resources.limits for cpu and memory on every container. Use LimitRange objects to enforce defaults at the namespace level.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_pod",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["has_resource_limits"] == "false" &&
			isLivePod(a) &&
			!k8sResourceLimitsExemptNamespaces[a.Metadata["namespace"]]
	},
}
