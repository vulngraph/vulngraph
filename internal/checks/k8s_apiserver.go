package checks

// k8s_apiserver.go — CIS Kubernetes 1.2 (API server) flag controls, evaluated
// from the kube-apiserver mirror pods of a self-managed cluster. See
// k8s_control_plane.go for how the settings are encoded and why they sit on
// the k8s_cluster asset.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// apiserverStrongCiphers is CIS Kubernetes 1.2.29's allowed list.
var apiserverStrongCiphers = []string{
	"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

func apiserverFix(change string) string {
	return manifestFix("kube-apiserver", "apiServer.extraArgs", change)
}

var k8sAPIServerAnonymousAuth = Check{
	ID:          "k8s-apiserver-anonymous-auth",
	Title:       "API server accepts anonymous requests",
	Description: "kube-apiserver runs with anonymous authentication on (the default when --anonymous-auth is not false), so requests without credentials are served as system:anonymous. Any RBAC grant to system:anonymous or system:unauthenticated is then reachable by anyone who can reach the API (CIS Kubernetes 1.2.1).",
	Remediation: apiserverFix("add --anonymous-auth=false (check that load-balancer health checks authenticate or use /livez through an authenticated path first)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_anonymous_auth", "true") },
	EvidenceFor: cpEvidence("apiserver_anonymous_auth"),
}

var k8sAPIServerTokenAuthFile = Check{
	ID:          "k8s-apiserver-token-auth-file",
	Title:       "API server authenticates static tokens from a file",
	Description: "kube-apiserver runs with --token-auth-file. Static tokens never expire and can only be changed by restarting the API server, so a leaked one stays valid indefinitely (CIS Kubernetes 1.2.2).",
	Remediation: apiserverFix("remove --token-auth-file and move its users to client certificates, OIDC or webhook authentication"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_token_auth_file_set", "true") },
	EvidenceFor: cpEvidence("apiserver_token_auth_file_set"),
}

var k8sAPIServerNoDenyExternalIPs = Check{
	ID:          "k8s-apiserver-no-deny-external-ips",
	Title:       "API server does not deny Service externalIPs",
	Description: "The DenyServiceExternalIPs admission plugin is not enabled, so anyone who can create a Service can set spec.externalIPs and intercept traffic to those addresses from inside the cluster (CVE-2020-8554, CIS Kubernetes 1.2.3).",
	Remediation: apiserverFix("add DenyServiceExternalIPs to --enable-admission-plugins"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "DenyServiceExternalIPs")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerNoKubeletClientCert = Check{
	ID:          "k8s-apiserver-no-kubelet-client-cert",
	Title:       "API server does not authenticate to kubelets with a client certificate",
	Description: "kube-apiserver runs without both --kubelet-client-certificate and --kubelet-client-key, so its exec, logs and port-forward calls reach kubelets unauthenticated, which only works if kubelets accept anonymous requests (CIS Kubernetes 1.2.4).",
	Remediation: apiserverFix("set --kubelet-client-certificate and --kubelet-client-key to a client certificate kubelets trust"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_kubelet_client_cert_set", "false") },
	EvidenceFor: cpEvidence("apiserver_kubelet_client_cert_set"),
}

var k8sAPIServerNoKubeletCA = Check{
	ID:          "k8s-apiserver-no-kubelet-ca",
	Title:       "API server does not verify kubelet serving certificates",
	Description: "kube-apiserver runs without --kubelet-certificate-authority, so it connects to kubelets without verifying their serving certificates and a host that intercepts node traffic can impersonate a kubelet (CIS Kubernetes 1.2.5). Kubelets must serve CA-signed certificates (serverTLSBootstrap) before this can be set.",
	Remediation: apiserverFix("set --kubelet-certificate-authority to the CA that signs kubelet serving certificates"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_kubelet_ca_set", "false") },
	EvidenceFor: cpEvidence("apiserver_kubelet_ca_set"),
}

var k8sAPIServerAuthzAlwaysAllow = Check{
	ID:          "k8s-apiserver-authz-always-allow",
	Title:       "API server authorizes every request",
	Description: "kube-apiserver's --authorization-mode includes AlwaysAllow (the default when the flag is unset), so every authenticated request is permitted and RBAC is not enforced (CIS Kubernetes 1.2.6).",
	Remediation: apiserverFix("set --authorization-mode=Node,RBAC"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListHas(a, "apiserver_authorization_mode", "AlwaysAllow")
	},
	EvidenceFor: cpEvidence("apiserver_authorization_mode"),
}

// The Node and RBAC mode checks step aside when AlwaysAllow is in the list: one
// flag is the root cause, and k8s-apiserver-authz-always-allow reports it.

var k8sAPIServerAuthzNoNode = Check{
	ID:          "k8s-apiserver-authz-no-node",
	Title:       "API server authorization omits the Node authorizer",
	Description: "kube-apiserver's --authorization-mode does not include Node, so kubelets are authorized by RBAC alone and each can read every Secret and ConfigMap rather than only those of its own pods (CIS Kubernetes 1.2.7).",
	Remediation: apiserverFix("include Node in --authorization-mode (Node,RBAC), together with the NodeRestriction admission plugin"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_authorization_mode", "Node") &&
			!cpAnyListHas(a, "apiserver_authorization_mode", "AlwaysAllow")
	},
	EvidenceFor: cpEvidence("apiserver_authorization_mode"),
}

var k8sAPIServerAuthzNoRBAC = Check{
	ID:          "k8s-apiserver-authz-no-rbac",
	Title:       "API server authorization omits RBAC",
	Description: "kube-apiserver's --authorization-mode does not include RBAC, so Roles and RoleBindings are not enforced and access falls to ABAC, a webhook or nothing (CIS Kubernetes 1.2.8).",
	Remediation: apiserverFix("include RBAC in --authorization-mode (Node,RBAC)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_authorization_mode", "RBAC") &&
			!cpAnyListHas(a, "apiserver_authorization_mode", "AlwaysAllow")
	},
	EvidenceFor: cpEvidence("apiserver_authorization_mode"),
}

var k8sAPIServerNoEventRateLimit = Check{
	ID:          "k8s-apiserver-no-event-rate-limit",
	Title:       "API server does not rate-limit events",
	Description: "The EventRateLimit admission plugin is not enabled, so a misbehaving or hostile client can flood the API server and etcd with Event objects (CIS Kubernetes 1.2.9).",
	Remediation: apiserverFix("add EventRateLimit to --enable-admission-plugins and point --admission-control-config-file at an EventRateLimit configuration"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "EventRateLimit")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerAlwaysAdmit = Check{
	ID:          "k8s-apiserver-always-admit",
	Title:       "API server enables the AlwaysAdmit admission plugin",
	Description: "The deprecated AlwaysAdmit admission plugin is enabled. It admits every request regardless of the other plugins' intent and has no legitimate production use (CIS Kubernetes 1.2.10).",
	Remediation: apiserverFix("remove AlwaysAdmit from --enable-admission-plugins"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyListHas(a, "apiserver_admission_plugins", "AlwaysAdmit") },
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerNoAlwaysPullImages = Check{
	ID:          "k8s-apiserver-no-always-pull-images",
	Title:       "API server does not force image pulls",
	Description: "The AlwaysPullImages admission plugin is not enabled, so a pod can run a private image already cached on its node without presenting pull credentials for it (CIS Kubernetes 1.2.11). On kubelets 1.33+ with credential verification for cached images this matters less.",
	Remediation: apiserverFix("add AlwaysPullImages to --enable-admission-plugins (weigh the registry dependency it adds to every pod start)"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "AlwaysPullImages")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerServiceAccountAdmissionOff = Check{
	ID:          "k8s-apiserver-serviceaccount-admission-off",
	Title:       "API server disables the ServiceAccount admission plugin",
	Description: "The ServiceAccount admission plugin is disabled, so pods are not checked against their ServiceAccount and token mounting is not managed by the API server (CIS Kubernetes 1.2.12).",
	Remediation: apiserverFix("remove ServiceAccount from --disable-admission-plugins"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "ServiceAccount")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerNamespaceLifecycleOff = Check{
	ID:          "k8s-apiserver-namespace-lifecycle-off",
	Title:       "API server disables the NamespaceLifecycle admission plugin",
	Description: "The NamespaceLifecycle admission plugin is disabled, so objects can be created in namespaces that are terminating or do not exist, and the system namespaces can be deleted (CIS Kubernetes 1.2.13).",
	Remediation: apiserverFix("remove NamespaceLifecycle from --disable-admission-plugins"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "NamespaceLifecycle")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerNoNodeRestriction = Check{
	ID:          "k8s-apiserver-no-node-restriction",
	Title:       "API server does not restrict what kubelets may modify",
	Description: "The NodeRestriction admission plugin is not enabled, so a kubelet's credentials can modify other nodes' Node objects and any pod bound to any node. A compromised node then reaches the whole cluster (CIS Kubernetes 1.2.14).",
	Remediation: apiserverFix("add NodeRestriction to --enable-admission-plugins"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "NodeRestriction")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerNoImagePolicyWebhook = Check{
	ID:          "k8s-apiserver-no-image-policy-webhook",
	Title:       "API server does not check image provenance at admission",
	Description: "The ImagePolicyWebhook admission plugin is not enabled, so the API server admits pods without asking an image-policy backend whether their images are trusted (CIS Kubernetes 5.5.1). A policy engine that verifies signatures through its own webhook (sigstore policy-controller, Kyverno verifyImages) meets the intent but is not this control.",
	Remediation: apiserverFix("add ImagePolicyWebhook to --enable-admission-plugins and configure its backend in --admission-control-config-file"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyListLacks(a, "apiserver_admission_plugins", "ImagePolicyWebhook")
	},
	EvidenceFor: cpEvidence("apiserver_admission_plugins"),
}

var k8sAPIServerProfiling = Check{
	ID:          "k8s-apiserver-profiling-enabled",
	Title:       "API server exposes the profiling endpoint",
	Description: "kube-apiserver runs with profiling enabled (the default when --profiling is not false), serving /debug/pprof to any identity RBAC lets reach it (CIS Kubernetes 1.2.15).",
	Remediation: apiserverFix("add --profiling=false"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_profiling", "true") },
	EvidenceFor: cpEvidence("apiserver_profiling"),
}

var k8sAPIServerNoAuditLog = Check{
	ID:          "k8s-apiserver-no-audit-log",
	Title:       "API server writes no audit log",
	Description: "kube-apiserver runs without --audit-log-path, so there is no record of which identity read a Secret, created a privileged pod or bound cluster-admin (CIS Kubernetes 1.2.16).",
	Remediation: apiserverFix("set --audit-log-path (and --audit-policy-file), and mount the log directory as a hostPath volume"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_audit_log_path", "") },
	EvidenceFor: cpEvidence("apiserver_audit_log_path"),
}

// The policy and retention checks step aside while no audit log is written at
// all: the missing log is the root cause k8s-apiserver-no-audit-log reports.
// An audit log path of "-" writes the log to stdout: CIS 1.2.16 is met (the
// flag is set and events are recorded, in the container log), and the
// retention flags do not apply to a stream the API server does not rotate, so
// 1.2.17-1.2.19 step aside for it too; its retention is the log pipeline's.

// auditLogRotated reports that every replica writes the audit log to a file
// the API server rotates.
func auditLogRotated(a asset.Asset) bool {
	return !cpAnyIs(a, "apiserver_audit_log_path", "") && !cpAnyIs(a, "apiserver_audit_log_path", "-")
}

var k8sAPIServerNoAuditPolicy = Check{
	ID:          "k8s-apiserver-no-audit-policy",
	Title:       "API server has no audit policy",
	Description: "kube-apiserver writes an audit log but runs without --audit-policy-file, so no event matches a policy rule and the log stays empty (CIS Kubernetes 3.2.1). Whether the policy covers the events that matter (3.2.2) is a review of its content.",
	Remediation: apiserverFix("set --audit-policy-file to an audit Policy (at minimum Metadata level for Secrets, ConfigMaps and TokenReviews, RequestResponse for pod exec/attach and RBAC changes) and mount it into the pod"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "apiserver_audit_policy_file_set", "false") && !cpAnyIs(a, "apiserver_audit_log_path", "")
	},
	EvidenceFor: cpEvidence("apiserver_audit_policy_file_set", "apiserver_audit_log_path"),
}

var k8sAPIServerAuditMaxAge = Check{
	ID:          "k8s-apiserver-audit-log-maxage-low",
	Title:       "API server keeps audit logs for under 30 days",
	Description: "kube-apiserver's --audit-log-maxage is below 30 (0, the default, keeps rotated files by count only), so the audit trail can be gone before an incident is noticed (CIS Kubernetes 1.2.17).",
	Remediation: apiserverFix("set --audit-log-maxage=30 or longer"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyBelow(a, "apiserver_audit_log_maxage", 30) && auditLogRotated(a)
	},
	EvidenceFor: cpEvidence("apiserver_audit_log_maxage"),
}

var k8sAPIServerAuditMaxBackup = Check{
	ID:          "k8s-apiserver-audit-log-maxbackup-low",
	Title:       "API server keeps fewer than 10 rotated audit logs",
	Description: "kube-apiserver's --audit-log-maxbackup is below 10, so rotation discards audit history quickly (CIS Kubernetes 1.2.18).",
	Remediation: apiserverFix("set --audit-log-maxbackup=10 or more"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyBelow(a, "apiserver_audit_log_maxbackup", 10) && auditLogRotated(a)
	},
	EvidenceFor: cpEvidence("apiserver_audit_log_maxbackup"),
}

var k8sAPIServerAuditMaxSize = Check{
	ID:          "k8s-apiserver-audit-log-maxsize-low",
	Title:       "API server rotates audit logs below 100 MB",
	Description: "kube-apiserver's --audit-log-maxsize is below 100 (megabytes), so files rotate, and with a low backup count are discarded, faster than an investigation can use them (CIS Kubernetes 1.2.19).",
	Remediation: apiserverFix("set --audit-log-maxsize=100 or more"),
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyBelow(a, "apiserver_audit_log_maxsize", 100) && auditLogRotated(a)
	},
	EvidenceFor: cpEvidence("apiserver_audit_log_maxsize"),
}

var k8sAPIServerSALookupOff = Check{
	ID:          "k8s-apiserver-sa-lookup-off",
	Title:       "API server accepts tokens of deleted service accounts",
	Description: "kube-apiserver runs with --service-account-lookup=false, so it validates service account tokens by signature alone and a token keeps working after its ServiceAccount or Secret is deleted (CIS Kubernetes 1.2.21).",
	Remediation: apiserverFix("remove --service-account-lookup=false (the default is true)"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_service_account_lookup", "false") },
	EvidenceFor: cpEvidence("apiserver_service_account_lookup"),
}

var k8sAPIServerNoSAKeyFile = Check{
	ID:          "k8s-apiserver-no-sa-key-file",
	Title:       "API server has no explicit service account key file",
	Description: "kube-apiserver runs without --service-account-key-file, so service account tokens are verified with the serving TLS key and cannot be rotated separately from it (CIS Kubernetes 1.2.22).",
	Remediation: apiserverFix("set --service-account-key-file to the public key matching the controller manager's --service-account-private-key-file"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_service_account_key_file_set", "false") },
	EvidenceFor: cpEvidence("apiserver_service_account_key_file_set"),
}

var k8sAPIServerNoEtcdClientCert = Check{
	ID:          "k8s-apiserver-no-etcd-client-cert",
	Title:       "API server does not authenticate to etcd with a client certificate",
	Description: "kube-apiserver runs without both --etcd-certfile and --etcd-keyfile, so it can only reach etcd if etcd accepts unauthenticated clients (CIS Kubernetes 1.2.23).",
	Remediation: apiserverFix("set --etcd-certfile and --etcd-keyfile to a client certificate etcd trusts"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_etcd_client_cert_set", "false") },
	EvidenceFor: cpEvidence("apiserver_etcd_client_cert_set"),
}

var k8sAPIServerNoTLSCert = Check{
	ID:          "k8s-apiserver-no-tls-cert",
	Title:       "API server serves a self-generated certificate",
	Description: "kube-apiserver runs without both --tls-cert-file and --tls-private-key-file, so it serves a self-signed certificate clients cannot verify (CIS Kubernetes 1.2.24).",
	Remediation: apiserverFix("set --tls-cert-file and --tls-private-key-file to a CA-signed serving certificate"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_tls_cert_set", "false") },
	EvidenceFor: cpEvidence("apiserver_tls_cert_set"),
}

var k8sAPIServerNoClientCA = Check{
	ID:          "k8s-apiserver-no-client-ca",
	Title:       "API server has no client certificate CA",
	Description: "kube-apiserver runs without --client-ca-file, so client certificate authentication, which kubelets and control-plane components rely on, is not configured (CIS Kubernetes 1.2.25).",
	Remediation: apiserverFix("set --client-ca-file to the cluster CA certificate"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_client_ca_set", "false") },
	EvidenceFor: cpEvidence("apiserver_client_ca_set"),
}

var k8sAPIServerNoEtcdCA = Check{
	ID:          "k8s-apiserver-no-etcd-ca",
	Title:       "API server does not verify etcd's certificate",
	Description: "kube-apiserver runs without --etcd-cafile, so it cannot verify it is talking to the real etcd and a host that intercepts the connection receives every write (CIS Kubernetes 1.2.26).",
	Remediation: apiserverFix("set --etcd-cafile to the etcd CA certificate"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_etcd_ca_set", "false") },
	EvidenceFor: cpEvidence("apiserver_etcd_ca_set"),
}

var k8sAPIServerNoEncryptionConfig = Check{
	ID:          "k8s-apiserver-no-encryption-config",
	Title:       "API server does not encrypt Secrets at rest",
	Description: "kube-apiserver runs without --encryption-provider-config, so Secrets are stored in etcd in plaintext and anyone with an etcd backup or disk image reads them all (CIS Kubernetes 1.2.27). Whether the configured providers are strong (1.2.28) needs the file on the control-plane host.",
	Remediation: apiserverFix("set --encryption-provider-config to an EncryptionConfiguration using kms v2 (or aescbc/secretbox) for secrets, then rewrite existing Secrets with `kubectl get secrets -A -o json | kubectl replace -f -`"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates:    func(a asset.Asset) bool { return cpAnyIs(a, "apiserver_encryption_provider_config_set", "false") },
	EvidenceFor: cpEvidence("apiserver_encryption_provider_config_set"),
}

var k8sAPIServerWeakCiphers = Check{
	ID:          "k8s-apiserver-weak-tls-ciphers",
	Title:       "API server does not restrict TLS to strong cipher suites",
	Description: "kube-apiserver's --tls-cipher-suites is unset (Go's default list) or names a suite outside the CIS strong list (AEAD suites with forward secrecy), so clients can negotiate weaker ciphers (CIS Kubernetes 1.2.29).",
	Remediation: apiserverFix("set --tls-cipher-suites to TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyWeakCiphers(a, "apiserver_tls_cipher_suites", apiserverStrongCiphers)
	},
	EvidenceFor: cpEvidence("apiserver_tls_cipher_suites"),
}

var k8sAPIServerExtendTokenExpiration = Check{
	ID:          "k8s-apiserver-sa-token-expiry-extended",
	Title:       "API server extends projected token lifetimes",
	Description: "kube-apiserver runs with --service-account-extend-token-expiration on (the default), so projected service account tokens are issued valid for up to a year instead of their requested lifetime, widening the window a stolen token works (CIS Kubernetes 1.2.30).",
	Remediation: apiserverFix("add --service-account-extend-token-expiration=false once workloads use a client library that refreshes projected tokens"),
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return cpAnyIs(a, "apiserver_service_account_extend_token_expiration", "true")
	},
	EvidenceFor: cpEvidence("apiserver_service_account_extend_token_expiration"),
}
