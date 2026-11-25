package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func k8sAsset(typ, name string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "prod/" + typ + "/" + name, Name: name, Type: typ, Provider: asset.ProviderKubernetes, Metadata: md}
}

// One check per capability category, so each benchmark control passes or fails
// on its own check ID — the umbrella check folded all of them into one finding.
func TestRBACCapabilityChecks(t *testing.T) {
	tests := []struct {
		check    Check
		category string
		severity finding.Severity
	}{
		{k8sRBACSecretsAccess, "secrets-read", finding.SeverityLow},
		{k8sRBACSecretsAccess, "secrets-write", finding.SeverityLow},
		{k8sRBACPodCreate, "pod-create", finding.SeverityLow},
		{k8sRBACPodCreate, "workload-create", finding.SeverityLow},
		{k8sRBACPodExec, "pod-exec", finding.SeverityLow},
		{k8sRBACPVCreate, "host-mount", finding.SeverityLow},
		{k8sRBACNodeProxy, "node-proxy", finding.SeverityMedium},
		{k8sRBACCSRApprove, "csr-approve", finding.SeverityMedium},
		{k8sRBACWebhookConfig, "admission-webhook", finding.SeverityMedium},
		{k8sRBACTokenCreate, "token-mint", finding.SeverityMedium},
		{k8sRBACEscalate, "rbac-escalate", finding.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.check.ID+"/"+tt.category, func(t *testing.T) {
			for _, typ := range []string{"k8s_cluster_role", "k8s_role"} {
				grant := k8sAsset(typ, "r", map[string]string{"dangerous_perms": "true", "namespace": "billing",
					"dangerous_perms_detail": "pod-exec(scoped)," + tt.category})
				require.True(t, tt.check.Violates(grant), "%s grants %s", typ, tt.category)
				require.Equal(t, tt.severity, tt.check.Severity)
				ev := tt.check.EvidenceFor(grant)
				require.Contains(t, ev["capabilities"], tt.category)

				scoped := k8sAsset(typ, "r", map[string]string{"dangerous_perms": "true", "dangerous_perms_detail": tt.category + "(scoped)"})
				require.True(t, tt.check.Violates(scoped), "a resourceNames-confined grant is still the capability")

				other := k8sAsset(typ, "r", map[string]string{"dangerous_perms": "true", "dangerous_perms_detail": "nothing-relevant"})
				require.False(t, tt.check.Violates(other))
				require.False(t, tt.check.Violates(k8sAsset(typ, "r", map[string]string{})), "absent data is not a grant")
				require.False(t, tt.check.Violates(k8sAsset(typ, "r", map[string]string{"dangerous_perms": "false",
					"dangerous_perms_detail": tt.category})), "platform-managed roles are suppressed by the collector")
			}
			// A binding carries the referenced role's detail too; the finding belongs
			// on the role, not on every binding to it.
			binding := k8sAsset("k8s_role_binding", "b", map[string]string{"dangerous_perms": "true", "dangerous_perms_detail": tt.category})
			require.False(t, tt.check.Violates(binding))
		})
	}
	ev := k8sRBACPodExec.EvidenceFor(k8sAsset("k8s_role", "r", map[string]string{"dangerous_perms": "true",
		"namespace": "billing", "dangerous_perms_detail": "pod-exec(scoped),secrets-read"}))
	require.Equal(t, map[string]string{"capabilities": "pod-exec(scoped)", "scope": "namespace:billing"}, ev)
}

// The old umbrella checks are gone and must stay gone: every category they
// reported now has its own check, so they would duplicate each finding.
func TestRBACUmbrellaChecksRetired(t *testing.T) {
	ids := Default().IDs()
	require.False(t, ids["k8s-cluster-role-dangerous-permissions"])
	require.False(t, ids["k8s-role-dangerous-permissions"])
	require.False(t, ids["k8s-allow-privilege-escalation"], "the split check has its own ID")
}

// resources: ["*"] with read-only verbs is a wildcard too (CIS 5.1.3), graded
// below the write/verb wildcards it used to be invisible next to.
func TestWildcardChecksCoverReadOnlyResourceWildcard(t *testing.T) {
	readOnly := map[string]string{"wildcard_verbs": "false", "wildcard_resources": "true", "platform_managed": "false", "dangerous_perms": "false"}
	cr := k8sAsset("k8s_cluster_role", "r", readOnly)
	require.True(t, k8sClusterRoleWildcardVerbs.Violates(cr))
	require.Equal(t, finding.SeverityLow, k8sClusterRoleWildcardVerbs.SeverityFor(cr))
	role := k8sAsset("k8s_role", "r", readOnly)
	require.True(t, k8sRoleWildcardVerbs.Violates(role))
	require.Equal(t, finding.SeverityLow, k8sRoleWildcardVerbs.SeverityFor(role))

	verbs := map[string]string{"wildcard_verbs": "true", "wildcard_resources": "true", "platform_managed": "false", "dangerous_perms": "false"}
	require.Equal(t, finding.SeverityMedium, k8sClusterRoleWildcardVerbs.SeverityFor(k8sAsset("k8s_cluster_role", "r", verbs)), "capped at Medium: RBAC grants are posture")
	require.Equal(t, finding.SeverityMedium, k8sRoleWildcardVerbs.SeverityFor(k8sAsset("k8s_role", "r", verbs)))

	pm := map[string]string{"wildcard_verbs": "false", "wildcard_resources": "true", "platform_managed": "true"}
	require.False(t, k8sClusterRoleWildcardVerbs.Violates(k8sAsset("k8s_cluster_role", "r", pm)))
}

// k8s-cluster-admin-binding is exactly "cluster-admin bound beyond the
// platform": the built-in admin role moved to its own check, and the bootstrap
// cluster-admin binding to system:masters is not the organisation's.
func TestClusterAdminBindingIsClusterAdminOnly(t *testing.T) {
	crb := func(role, pm string) asset.Asset {
		return k8sAsset("k8s_cluster_role_binding", "b", map[string]string{"role_ref": role, "platform_managed": pm, "subjects": "User/alice"})
	}
	require.True(t, k8sClusterAdminBinding.Violates(crb("cluster-admin", "false")))
	require.False(t, k8sClusterAdminBinding.Violates(crb("admin", "false")), "admin is k8s-clusterrolebinding-admin-edit")
	require.False(t, k8sClusterAdminBinding.Violates(crb("cluster-admin", "true")), "the bootstrap binding is platform-managed")
	require.Equal(t, finding.SeverityMedium, k8sClusterAdminBinding.SeverityFor(crb("cluster-admin", "false")))

	// kubeadm:cluster-admins / eks:addon-cluster-admin: the platform's, still a
	// standing admin grant — reported, at Info.
	standing := crb("cluster-admin", "true")
	standing.Metadata["platform_cluster_admin"] = "true"
	require.True(t, k8sClusterAdminBinding.Violates(standing))
	require.Equal(t, finding.SeverityInfo, k8sClusterAdminBinding.SeverityFor(standing))
	require.True(t, k8sClusterRoleBindingAdminEdit.Violates(crb("admin", "false")))
	require.True(t, k8sClusterRoleBindingAdminEdit.Violates(crb("edit", "false")))
	require.False(t, k8sClusterRoleBindingAdminEdit.Violates(crb("cluster-admin", "false")))
	require.False(t, k8sClusterRoleBindingAdminEdit.Violates(crb("admin", "true")))
}

func TestBindingSubjectChecks(t *testing.T) {
	b := func(typ, subjects, pm string, extra ...string) asset.Asset {
		md := map[string]string{"subjects": subjects, "platform_managed": pm, "role_ref": "pod-reader", "role_ref_kind": "ClusterRole"}
		for i := 0; i+1 < len(extra); i += 2 {
			md[extra[i]] = extra[i+1]
		}
		return k8sAsset(typ, "b", md)
	}
	tests := []struct {
		name  string
		check Check
		a     asset.Asset
		fires bool
	}{
		{"system:masters crb", k8sBindingSystemMasters, b("k8s_cluster_role_binding", "Group/system:masters", "false"), true},
		{"system:masters rb", k8sBindingSystemMasters, b("k8s_role_binding", "User/a,Group/system:masters", "false"), true},
		{"system:masters bootstrap", k8sBindingSystemMasters, b("k8s_cluster_role_binding", "Group/system:masters", "true"), false},
		{"system:masters lookalike", k8sBindingSystemMasters, b("k8s_cluster_role_binding", "Group/system:masters-ops", "false"), false},
		{"system:masters unknown ownership", k8sBindingSystemMasters, b("k8s_cluster_role_binding", "Group/system:masters", ""), false},
		{"unauthenticated", k8sBindingToUnauthenticated, b("k8s_role_binding", "Group/system:unauthenticated", "false"), true},
		{"anonymous user", k8sBindingToUnauthenticated, b("k8s_cluster_role_binding", "User/system:anonymous", "false"), true},
		{"unauthenticated default binding", k8sBindingToUnauthenticated, b("k8s_cluster_role_binding", "Group/system:unauthenticated", "true"), false},
		{"unauthenticated privileged steps aside", k8sBindingToUnauthenticated,
			b("k8s_cluster_role_binding", "Group/system:unauthenticated", "false", "dangerous_perms", "true"), false},
		{"authenticated", k8sBindingToAuthenticated, b("k8s_cluster_role_binding", "Group/system:authenticated", "false"), true},
		{"authenticated default binding", k8sBindingToAuthenticated, b("k8s_cluster_role_binding", "Group/system:authenticated", "true"), false},
		{"authenticated privileged steps aside", k8sBindingToAuthenticated,
			b("k8s_cluster_role_binding", "Group/system:authenticated", "false", "role_ref", "cluster-admin"), false},
		{"authenticated on a role is not a binding", k8sBindingToAuthenticated, b("k8s_cluster_role", "Group/system:authenticated", "false"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, tt.check.Violates(tt.a))
		})
	}
	// The privileged case is the Critical check's, so the pair never double-reports.
	priv := b("k8s_cluster_role_binding", "Group/system:authenticated", "false", "role_ref", "cluster-admin")
	require.True(t, k8sBindingToEveryone.Violates(priv))
}

func TestDefaultSAAutomount(t *testing.T) {
	sa := func(name, ns, automount string) asset.Asset {
		md := map[string]string{"namespace": ns}
		if automount != "" {
			md["automount_token"] = automount
		}
		return k8sAsset("k8s_service_account", name, md)
	}
	require.True(t, k8sDefaultSAAutomount.Violates(sa("default", "billing", "true")))
	require.False(t, k8sDefaultSAAutomount.Violates(sa("default", "billing", "false")))
	require.False(t, k8sDefaultSAAutomount.Violates(sa("default", "billing", "")), "absent data is not a violation")
	require.False(t, k8sDefaultSAAutomount.Violates(sa("api", "billing", "true")), "only the default SA")
	require.False(t, k8sDefaultSAAutomount.Violates(sa("default", "kube-system", "true")), "system namespaces are exempt")
}

// Pods on the default SA used to be skipped outright — the case the benchmark
// cares about most. Now an inherited mount is reported once on the default SA
// and an explicit one on the workload.
func TestAutomountSATokenCoversDefaultServiceAccount(t *testing.T) {
	pod := func(sa, setOnPod, automount string) asset.Asset {
		return k8sAsset("k8s_pod", "p", map[string]string{"phase": "Running", "service_account": sa,
			"automount_sa_token_set_on_pod": setOnPod, "automount_sa_token": automount})
	}
	require.True(t, k8sPodAutomountSAToken.Violates(pod("default", "true", "true")), "explicit automount on the default SA")
	require.False(t, k8sPodAutomountSAToken.Violates(pod("default", "false", "true")), "inherited from the default SA: k8s-default-sa-automount")
	require.False(t, k8sPodAutomountSAToken.Violates(pod("", "false", "true")), "an empty SA name is the default SA")
	require.True(t, k8sPodAutomountSAToken.Violates(pod("api", "false", "true")), "inherited from a dedicated SA")
	require.False(t, k8sPodAutomountSAToken.Violates(pod("api", "false", "false")))
}

func TestHostPathSeverityByPath(t *testing.T) {
	for _, tt := range []struct {
		paths string
		want  finding.Severity
	}{
		{"/", finding.SeverityHigh},
		{"/var/run/docker.sock", finding.SeverityHigh},
		{"/var/run", finding.SeverityHigh},
		{"/var", finding.SeverityHigh},
		{"/var/lib/kubelet/pods", finding.SeverityHigh},
		{"/etc/", finding.SeverityHigh},
		{"/data/cache", finding.SeverityMedium},
		{"/var/log", finding.SeverityHigh},
		{"/var/lib/etcd", finding.SeverityHigh},
		{"/var/lib/app-data", finding.SeverityMedium},
		{"/data/cache,/proc", finding.SeverityHigh},
	} {
		a := k8sAsset("k8s_pod", "p", map[string]string{"namespace": "billing", "phase": "Running", "host_path_volumes": tt.paths})
		require.True(t, k8sHostPathVolume.Violates(a))
		require.Equal(t, tt.want, k8sHostPathVolume.SeverityFor(a), tt.paths)
	}
}

func TestPodSecurityStepAsides(t *testing.T) {
	// A hostNetwork pod gets hostPort defaulted by the API server.
	hn := k8sAsset("k8s_pod", "p", map[string]string{"namespace": "billing", "phase": "Running", "host_network": "true", "host_ports": "80"})
	require.False(t, k8sContainerHostPort.Violates(hn))
	require.True(t, k8sHostNetworkPod.Violates(hn))

	// A dangerous capability is the capability finding for the pod.
	caps := k8sAsset("k8s_pod", "p", map[string]string{"namespace": "billing", "phase": "Running", "added_capabilities": "NET_BIND_SERVICE,SYS_ADMIN", "dangerous_capabilities": "SYS_ADMIN"})
	require.False(t, k8sContainerAddedCapabilities.Violates(caps))
	require.True(t, k8sDangerousCapabilities.Violates(caps))

	// Root and privilege escalation pass or fail on their own now.
	rootOnly := k8sAsset("k8s_pod", "p", map[string]string{"namespace": "billing", "phase": "Running", "run_as_root": "true", "allow_priv_escalation": "false"})
	require.True(t, k8sPodRunsAsRoot.Violates(rootOnly))
	require.False(t, k8sContainerAllowPrivilegeEscalation.Violates(rootOnly))
	escOnly := k8sAsset("k8s_pod", "p", map[string]string{"namespace": "billing", "phase": "Running", "run_as_root": "false", "allow_priv_escalation": "true"})
	require.False(t, k8sPodRunsAsRoot.Violates(escOnly))
	require.True(t, k8sContainerAllowPrivilegeEscalation.Violates(escOnly))
}

// System namespaces and namespaces that explicitly enforce the 'privileged'
// standard are exempt from the host-access and hardening checks, as the
// existing pod checks are.
func TestPodSecurityChecksExemptSystemPods(t *testing.T) {
	md := map[string]string{"phase": "Running", "host_pid": "true", "host_ipc": "true", "host_path_volumes": "/",
		"host_network": "false", "host_ports": "80", "windows_host_process": "true", "added_capabilities": "CHOWN",
		"dangerous_capabilities": "", "net_raw_retained": "true", "seccomp_unrestricted": "true",
		"apparmor_unconfined": "true", "writable_root_fs": "true", "allow_priv_escalation": "true", "secret_env_refs": "s"}
	podChecks := []Check{k8sHostPIDPod, k8sHostIPCPod, k8sHostPathVolume, k8sContainerHostPort, k8sWindowsHostProcess,
		k8sContainerAddedCapabilities, k8sContainerNetRaw, k8sPodSeccompUnrestricted, k8sPodAppArmorUnconfined,
		k8sContainerWritableRootFS, k8sContainerAllowPrivilegeEscalation, k8sPodSecretInEnv}
	for _, c := range podChecks {
		app := map[string]string{"namespace": "billing", "phase": "Running"}
		sys := map[string]string{"namespace": "kube-system"}
		psa := map[string]string{"namespace": "agents", "ns_psa_enforce": "privileged"}
		for k, v := range md {
			app[k], sys[k], psa[k] = v, v, v
		}
		require.True(t, c.Violates(k8sAsset("k8s_pod", "p", app)), c.ID)
		require.False(t, c.Violates(k8sAsset("k8s_pod", "p", sys)), c.ID)
		require.False(t, c.Violates(k8sAsset("k8s_pod", "p", psa)), c.ID)
	}
}

func TestNamespacePolicyChecks(t *testing.T) {
	ns := func(name string, md map[string]string) asset.Asset { return k8sAsset("k8s_namespace", name, md) }
	for _, level := range []string{"", "privileged"} {
		require.True(t, k8sNamespaceNoPodSecurityEnforcement.Violates(ns("billing", map[string]string{"phase": "Active", "psa_enforce": level})), level)
	}
	for _, level := range []string{"baseline", "restricted"} {
		require.False(t, k8sNamespaceNoPodSecurityEnforcement.Violates(ns("billing", map[string]string{"phase": "Active", "psa_enforce": level})), level)
	}
	require.False(t, k8sNamespaceNoPodSecurityEnforcement.Violates(ns("kube-system", map[string]string{"phase": "Active", "psa_enforce": ""})))
	require.False(t, k8sNamespaceNoPodSecurityEnforcement.Violates(ns("billing", map[string]string{"phase": "Terminating", "psa_enforce": ""})))

	// No policy at all is k8s-namespace-no-network-policy's finding.
	none := ns("billing", map[string]string{"phase": "Active", "has_network_policy": "false", "has_default_deny_ingress": "false"})
	require.False(t, k8sNamespaceNoDefaultDeny.Violates(none))
	require.True(t, k8sNamespaceNoNetworkPolicy.Violates(none))
	require.False(t, k8sNamespaceNoDefaultDeny.Violates(ns("kube-system", map[string]string{"phase": "Active",
		"has_network_policy": "true", "has_default_deny_ingress": "false"})))
}

// Every pod check evaluates Running and Pending pods only: a finished CronJob
// run must not add a finding per run.
func TestPodChecksEvaluateLivePodsOnly(t *testing.T) {
	md := map[string]string{"namespace": "billing", "host_pid": "true", "host_ipc": "true", "host_path_volumes": "/",
		"host_network": "false", "host_ports": "80", "windows_host_process": "true", "added_capabilities": "CHOWN",
		"dangerous_capabilities": "", "net_raw_retained": "true", "seccomp_unrestricted": "true",
		"apparmor_unconfined": "true", "writable_root_fs": "true", "allow_priv_escalation": "true", "secret_env_refs": "s",
		"privileged": "true", "run_as_root": "true", "images": "app:latest", "automount_sa_token": "true",
		"service_account": "api", "has_resource_limits": "false"}
	var podChecks []Check
	for _, c := range Default().All() {
		if c.AssetType == "k8s_pod" {
			podChecks = append(podChecks, c)
		}
	}
	// Fields that would otherwise trip a step-aside or miss the condition.
	overrides := map[string]map[string]string{
		"k8s-workload-default-namespace": {"namespace": "default"},
		"k8s-dangerous-capabilities":     {"dangerous_capabilities": "SYS_ADMIN"},
		"k8s-host-network-pod":           {"host_network": "true"},
	}
	require.NotEmpty(t, podChecks)
	for _, c := range podChecks {
		for phase, live := range map[string]bool{"Running": true, "Pending": true, "Unknown": true, "": true, "Succeeded": false, "Failed": false} {
			m := map[string]string{"phase": phase}
			for k, v := range md {
				m[k] = v
			}
			for k, v := range overrides[c.ID] {
				m[k] = v
			}
			require.Equal(t, live, c.Violates(k8sAsset("k8s_pod", "p", m)), "%s in phase %s", c.ID, phase)
		}
	}
}

// NET_RAW, seccomp, readOnlyRootFilesystem and allowPrivilegeEscalation do not
// apply on Windows, and the Pod Security Standards exempt Windows pods from them.
func TestLinuxOnlyHardeningSkipsWindowsPods(t *testing.T) {
	for _, c := range []Check{k8sContainerNetRaw, k8sPodSeccompUnrestricted, k8sContainerWritableRootFS, k8sContainerAllowPrivilegeEscalation} {
		md := map[string]string{"namespace": "billing", "phase": "Running", "net_raw_retained": "true",
			"seccomp_unrestricted": "true", "writable_root_fs": "true", "allow_priv_escalation": "true"}
		require.True(t, c.Violates(k8sAsset("k8s_pod", "p", md)), c.ID)
		md["pod_os"] = "windows"
		require.False(t, c.Violates(k8sAsset("k8s_pod", "p", md)), c.ID)
	}
}

// A grant to everyone is judged on what the role actually allows, not on the
// platform-suppressed flags: the suppression's markers are forgeable.
func TestGrantToEveryoneReadsUnsuppressedRole(t *testing.T) {
	b := func(md map[string]string) asset.Asset {
		md["subjects"] = "Group/system:authenticated"
		md["role_ref"] = "system:ext"
		md["role_ref_kind"] = "ClusterRole"
		md["platform_managed"] = "false"
		return k8sAsset("k8s_cluster_role_binding", "b", md)
	}
	suppressedWildcard := b(map[string]string{"dangerous_perms": "false", "wildcard_verbs": "false", "role_wildcard_verbs": "true", "dangerous_perms_detail": ""})
	require.True(t, k8sBindingToEveryone.Violates(suppressedWildcard))
	require.False(t, k8sBindingToAuthenticated.Violates(suppressedWildcard), "the Critical check owns it")

	suppressedDetail := b(map[string]string{"dangerous_perms": "false", "wildcard_verbs": "false", "role_wildcard_verbs": "false", "dangerous_perms_detail": "secrets-read"})
	require.True(t, k8sBindingToEveryone.Violates(suppressedDetail))

	benign := b(map[string]string{"dangerous_perms": "false", "wildcard_verbs": "false", "role_wildcard_verbs": "false", "dangerous_perms_detail": ""})
	require.False(t, k8sBindingToEveryone.Violates(benign))
	require.True(t, k8sBindingToAuthenticated.Violates(benign))
}
