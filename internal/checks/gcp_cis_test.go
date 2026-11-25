package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func gcpAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "r", Type: typ, Provider: asset.ProviderGCP, Metadata: md}
}

// firing runs the default registry over one asset and returns the check IDs
// that fired, so step-aside pairs are tested as the registry emits them.
func firing(t *testing.T, a asset.Asset) map[string]finding.Finding {
	t.Helper()
	out := map[string]finding.Finding{}
	for _, f := range Default().Run([]asset.Asset{a}, fixedTime) {
		out[f.CheckID] = f
	}
	return out
}

// A flag check grades only its own engine; the instance's other engines'
// flags are never stamped, and the engine gate is what keeps a Postgres flag
// check silent on MySQL.
func TestCloudSQLFlagEngineGate(t *testing.T) {
	mysql := gcpAsset("cloudsql_instance", map[string]string{"version": "MYSQL_8_0", "db_flag_log_connections": ""})
	require.False(t, gcpCloudSQLPostgresLogConnections.Violates(mysql))

	mysqlIAM := gcpAsset("cloudsql_instance", map[string]string{"version": "MYSQL_8_0", "db_flag_cloudsql_iam_authentication": ""})
	require.True(t, gcpCloudSQLIAMAuthDisabled.Violates(mysqlIAM), "IAM database authentication applies to MySQL too")
	sqlserver := gcpAsset("cloudsql_instance", map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_cloudsql_iam_authentication": ""})
	require.False(t, gcpCloudSQLIAMAuthDisabled.Violates(sqlserver))
}

func TestPgLevelBelowWarning(t *testing.T) {
	for _, lvl := range []string{"debug5", "debug1", "info", "notice"} {
		require.True(t, pgLevelBelowWarning(lvl), lvl)
	}
	for _, lvl := range []string{"", "warning", "error", "log", "fatal", "panic"} {
		require.False(t, pgLevelBelowWarning(lvl), lvl)
	}
	pg := func(v string) asset.Asset {
		return gcpAsset("cloudsql_instance", map[string]string{"version": "POSTGRES_15", "db_flag_log_min_error_statement": v})
	}
	require.True(t, gcpCloudSQLPostgresLogMinErrorStatement.Violates(pg("warning")))
	require.False(t, gcpCloudSQLPostgresLogMinErrorStatement.Violates(pg("error")))
	require.False(t, gcpCloudSQLPostgresLogMinErrorStatement.Violates(pg("")), "unset is the default, error")
}

// The fix for the gcp-cloudsql-no-ssl false positive: sslMode decides when it
// is set, and the legacy flag only when it is not.
func TestCloudSQLNoSSL(t *testing.T) {
	cases := []struct {
		md   map[string]string
		want bool
	}{
		{map[string]string{"ssl_mode": "ENCRYPTED_ONLY", "require_ssl": "false"}, false},
		{map[string]string{"ssl_mode": "TRUSTED_CLIENT_CERTIFICATE_REQUIRED", "require_ssl": "true"}, false},
		{map[string]string{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED", "require_ssl": "false"}, true},
		{map[string]string{"ssl_mode": "", "require_ssl": "false"}, true},
		{map[string]string{"ssl_mode": "", "require_ssl": "true"}, false},
		{map[string]string{"require_ssl": "false"}, true}, // collected before ssl_mode existed
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, gcpCloudSQLNoSSL.Violates(gcpAsset("cloudsql_instance", tc.md)), "%v", tc.md)
	}
}

func TestCloudSQLPublicStepsAsideForOpenAuthorizedNetwork(t *testing.T) {
	open := firing(t, gcpAsset("cloudsql_instance", map[string]string{"public": "true", "authorized_networks_world": "true"}))
	require.Contains(t, open, "gcp-cloudsql-open-authorized-network")
	require.NotContains(t, open, "gcp-cloudsql-public-ip", "one public endpoint, one finding")

	restricted := firing(t, gcpAsset("cloudsql_instance", map[string]string{"public": "true", "authorized_networks_world": "false"}))
	require.Contains(t, restricted, "gcp-cloudsql-public-ip")
	require.NotContains(t, restricted, "gcp-cloudsql-open-authorized-network")
}

func TestGCEDefaultSAStepsAsideForFullScope(t *testing.T) {
	sa := "serviceAccount:123-compute@developer.gserviceaccount.com"
	full := firing(t, gcpAsset("gce_instance", map[string]string{"exec_role": sa, "sa_cloud_platform_scope": "true"}))
	require.Contains(t, full, "gcp-gce-default-sa-full-scope")
	require.NotContains(t, full, "gcp-gce-default-sa")

	narrow := firing(t, gcpAsset("gce_instance", map[string]string{"exec_role": sa, "sa_cloud_platform_scope": "false"}))
	require.Contains(t, narrow, "gcp-gce-default-sa")
	require.NotContains(t, narrow, "gcp-gce-default-sa-full-scope")
}

func TestGCEIPForwardingExemptsGKENodes(t *testing.T) {
	node := gcpAsset("gce_instance", map[string]string{"can_ip_forward": "true"})
	node.Tags = map[string]string{"goog-gke-node": ""}
	require.False(t, gcpGCEIPForwarding.Violates(node), "GKE nodes route pod traffic and need forwarding")
	require.True(t, gcpGCEIPForwarding.Violates(gcpAsset("gce_instance", map[string]string{"can_ip_forward": "true"})))
}

func TestGCPSAAdminPrivileges(t *testing.T) {
	sa := func(roles string) asset.Asset {
		return gcpAsset("gcp_service_account", map[string]string{"disabled": "false", "roles": roles})
	}
	require.True(t, gcpSAAdminRole("roles/compute.instanceAdmin.v1"), "service-scoped admin roles count (CIS *Admin)")
	require.False(t, gcpSAAdminRole("roles/viewer,roles/logging.logWriter"))
	require.Equal(t, finding.SeverityHigh, gcpSAAdminPrivileges.SeverityFor(sa("roles/owner")))
	require.Equal(t, finding.SeverityHigh, gcpSAAdminPrivileges.SeverityFor(sa("roles/viewer,roles/resourcemanager.projectIamAdmin")))
	require.Equal(t, finding.SeverityMedium, gcpSAAdminPrivileges.SeverityFor(sa("roles/editor")))
	require.False(t, gcpSAAdminPrivileges.Violates(gcpAsset("gcp_service_account", map[string]string{"disabled": "true", "roles": "roles/owner"})))

	// A dormant admin is gcp-sa-admin-dormant's single finding.
	dormant := gcpAsset("gcp_service_account", map[string]string{"disabled": "false", "roles": "roles/owner", "sa_last_auth_days": "200"})
	got := firing(t, dormant)
	require.Contains(t, got, "gcp-sa-admin-dormant")
	require.NotContains(t, got, "gcp-sa-admin-privileges")
}

// CIS 1.8 is read off the one user-managed-key finding: its title and
// key_rotation_overdue say which side of 90 days the oldest key is on.
func TestGCPSAUserManagedKeyRotationTitle(t *testing.T) {
	key := func(age string) asset.Asset {
		return gcpAsset("gcp_service_account", map[string]string{"key_count": "1", "key_age_days": age, "disabled": "false"})
	}
	require.Equal(t, "Service account has a user-managed key older than 90 days", gcpSAUserManagedKey.TitleFor(key("91")))
	require.Equal(t, "Service account has a user-managed key", gcpSAUserManagedKey.TitleFor(key("90")))
	require.Equal(t, "false", gcpSAUserManagedKey.EvidenceFor(key("30"))["key_rotation_overdue"])
}

func TestGKEControlPlaneFindingsAreExclusive(t *testing.T) {
	cluster := func(md map[string]string) map[string]finding.Finding { return firing(t, gcpAsset("gke_cluster", md)) }

	open := cluster(map[string]string{"public_endpoint": "true", "authorized_networks": "false", "authorized_networks_world": "false"})
	require.Contains(t, open, "gcp-gke-public-endpoint")
	require.NotContains(t, open, "gcp-gke-private-endpoint-disabled")

	world := cluster(map[string]string{"public_endpoint": "true", "authorized_networks": "true", "authorized_networks_world": "true"})
	require.Contains(t, world, "gcp-gke-public-endpoint", "an allowlist admitting 0.0.0.0/0 is no allowlist")

	restricted := cluster(map[string]string{"public_endpoint": "true", "authorized_networks": "true", "authorized_networks_world": "false"})
	require.Contains(t, restricted, "gcp-gke-private-endpoint-disabled")
	require.NotContains(t, restricted, "gcp-gke-public-endpoint")
	require.NotContains(t, restricted, "gcp-gke-authorized-networks-disabled")

	private := cluster(map[string]string{"public_endpoint": "false", "authorized_networks": "false"})
	require.Contains(t, private, "gcp-gke-authorized-networks-disabled")
	require.NotContains(t, private, "gcp-gke-public-endpoint")
}

func TestGKEMetadataServerStepsAsideWhenWorkloadIdentityOff(t *testing.T) {
	off := firing(t, gcpAsset("gke_cluster", map[string]string{"workload_identity": "false", "node_pools_no_gke_metadata": "default-pool"}))
	require.Contains(t, off, "gcp-gke-workload-identity-disabled")
	require.NotContains(t, off, "gcp-gke-metadata-server-disabled", "enabling Workload Identity is the one fix")

	on := firing(t, gcpAsset("gke_cluster", map[string]string{"workload_identity": "true", "node_pools_no_gke_metadata": "legacy"}))
	require.Contains(t, on, "gcp-gke-metadata-server-disabled")
	require.Equal(t, "legacy", on["gcp-gke-metadata-server-disabled"].Metadata["node_pools"])
}

// Network policy is not misread as off on a Dataplane V2 cluster, whose
// networkPolicy addon reports disabled while the datapath enforces policy.
func TestGKENetworkPolicyDataplaneV2(t *testing.T) {
	require.False(t, gcpGKENetworkPolicyDisabled.Violates(gcpAsset("gke_cluster",
		map[string]string{"network_policy": "false", "datapath_provider": "ADVANCED_DATAPATH"})))
	require.True(t, gcpGKENetworkPolicyDisabled.Violates(gcpAsset("gke_cluster",
		map[string]string{"network_policy": "false", "datapath_provider": "LEGACY_DATAPATH"})))
	require.False(t, gcpGKENetworkPolicyDisabled.Violates(gcpAsset("gke_cluster",
		map[string]string{"network_policy": "true", "datapath_provider": ""})))
}

// The lifecycle gate must see these checks' dependence on their keys: a
// finding whose evidence has vanished is not evaluable, so it is not closed
// as fixed. The flag checks read their key through a helper, so this pins
// that the derivation follows it.
func TestGCPChecksNotEvaluableOnAbsentKeys(t *testing.T) {
	r := Default()
	for _, tc := range []struct {
		id string
		md map[string]string
	}{
		{"gcp-cloudsql-postgres-log-connections", map[string]string{"version": "POSTGRES_15"}},
		{"gcp-cloudsql-sqlserver-external-scripts", map[string]string{"version": "SQLSERVER_2019_STANDARD"}},
		{"gcp-cloudsql-iam-auth-disabled", map[string]string{"version": "MYSQL_8_0"}},
		{"gcp-firewall-open-ingress", map[string]string{"open_to_internet": "true"}},
		{"gcp-gke-node-auto-upgrade-disabled", map[string]string{}},
		{"gcp-gke-network-policy-disabled", map[string]string{"network_policy": "false"}},
		{"gcp-audit-logging-not-configured", map[string]string{}},
	} {
		c, ok := r.ByID(tc.id)
		require.True(t, ok, tc.id)
		require.False(t, c.Evaluable(gcpAsset(c.AssetType, tc.md)), "%s must not read absent data as clean", tc.id)
	}
	c, _ := r.ByID("gcp-cloudsql-postgres-log-connections")
	require.True(t, c.Evaluable(gcpAsset("cloudsql_instance", map[string]string{"version": "MYSQL_8_0"})),
		"a Postgres check on a MySQL instance genuinely observed nothing to grade")
}

// One all-ports rule is one finding: the collector does not mark it SSH- or
// RDP-open, and the generic check steps aside for the rollup.
func TestFirewallAllPortsRollup(t *testing.T) {
	got := firing(t, gcpAsset("gcp_firewall", map[string]string{
		"open_to_internet": "true", "shadowed_by_deny": "false", "all_ports_open_to_internet": "true",
		"ssh_open_to_internet": "false", "rdp_open_to_internet": "false", "open_ports": "all",
	}))
	require.Len(t, got, 1)
	require.Contains(t, got, "gcp-firewall-all-ports-open-internet")
}

// Severity grades what stays open after the denies, not the rule's own list.
func TestFirewallOpenSeverity_AfterShadowing(t *testing.T) {
	a := gcpAsset("gcp_firewall", map[string]string{"allowed": "tcp", "open_ports": "tcp:80,443"})
	require.Equal(t, finding.SeverityLow, firewallOpenSeverity(a))
	a.Metadata = map[string]string{"allowed": "tcp:80"}
	require.Equal(t, finding.SeverityLow, firewallOpenSeverity(a), "falls back to allowed before open_ports existed")
}

// A cluster reachable only through its DNS endpoint has no IP endpoint for
// authorized networks to restrict.
func TestGKEAuthorizedNetworksDNSOnly(t *testing.T) {
	md := map[string]string{"public_endpoint": "false", "authorized_networks": "false", "ip_endpoints_enabled": "false"}
	require.False(t, gcpGKEAuthorizedNetworksDisabled.Violates(gcpAsset("gke_cluster", md)))
	md["ip_endpoints_enabled"] = "true"
	require.True(t, gcpGKEAuthorizedNetworksDisabled.Violates(gcpAsset("gke_cluster", md)))
}

// GKE nodes are exempt from CIS GCP 4.1/4.2 per node VM — their default
// account is reported once per cluster by gcp-gke-node-default-sa (CIS GKE
// 5.2.1) — but only when that cluster was read and graded. The label alone
// exempts nothing.
func TestGCEDefaultSAChecksExemptGKENodes(t *testing.T) {
	node := func(md map[string]string) asset.Asset {
		a := gcpAsset("gce_instance", md)
		a.Tags = map[string]string{"goog-gke-node": ""}
		return a
	}
	const sa = "serviceAccount:1-compute@developer.gserviceaccount.com"
	got := firing(t, node(map[string]string{"exec_role": sa, "sa_cloud_platform_scope": "true", "gke_node_pool_graded": "true"}))
	require.NotContains(t, got, "gcp-gce-default-sa-full-scope")
	require.NotContains(t, got, "gcp-gce-default-sa")

	ungraded := firing(t, node(map[string]string{"exec_role": sa, "sa_cloud_platform_scope": "true"}))
	require.Contains(t, ungraded, "gcp-gce-default-sa-full-scope", "cluster unread: the node is graded like any VM")
	public := node(map[string]string{"exec_role": sa, "sa_cloud_platform_scope": "false"})
	public.PublicIP = "34.1.1.1"
	require.Equal(t, finding.SeverityHigh, firing(t, public)["gcp-gce-default-sa"].Severity,
		"an ungraded public node on the default account stays High")
	require.Contains(t, firing(t, gcpAsset("gke_cluster", map[string]string{
		"node_pools_default_sa": "default-pool", "node_pools_default_sa_full_scope": "default-pool",
	})), "gcp-gke-node-default-sa")
}

func TestCloudSQLLocalInfileDefaultsByVersion(t *testing.T) {
	db := func(version, v string) asset.Asset {
		return gcpAsset("cloudsql_instance", map[string]string{"version": version, "db_flag_local_infile": v})
	}
	require.True(t, gcpCloudSQLMySQLLocalInfile.Violates(db("MYSQL_5_7", "")), "unset is on for MySQL 5.x")
	require.False(t, gcpCloudSQLMySQLLocalInfile.Violates(db("MYSQL_8_0", "")), "unset is off from 8.0")
	require.False(t, gcpCloudSQLMySQLLocalInfile.Violates(db("MYSQL_5_7", "off")))
	require.True(t, gcpCloudSQLMySQLLocalInfile.Violates(db("MYSQL_8_0", "on")))
}

// CIS GCP 4.9: any NIC's access config counts, a stopped VM is graded Low,
// and GKE nodes are left to the node-pool finding.
func TestGCEPublicIP_AllNICsAndStoppedVMs(t *testing.T) {
	stopped := gcpAsset("gce_instance", map[string]string{"status": "TERMINATED", "external_ip_configured": "true"})
	require.True(t, gcpGCEPublicIP.Violates(stopped))
	require.Equal(t, finding.SeverityLow, gcpGCEPublicIP.SeverityFor(stopped))
	require.Contains(t, gcpGCEPublicIP.TitleFor(stopped), "Stopped")

	running := gcpAsset("gce_instance", map[string]string{"status": "RUNNING", "external_ip_configured": "true"})
	require.Equal(t, finding.SeverityMedium, gcpGCEPublicIP.SeverityFor(running))
	require.False(t, gcpGCEPublicIP.Violates(gcpAsset("gce_instance", map[string]string{"status": "RUNNING", "external_ip_configured": "false"})))
	require.False(t, gcpGCEPublicIP.Violates(gcpAsset("gce_instance", map[string]string{"status": "RUNNING"})),
		"no external-IP observation and no address is silent")

	node := gcpAsset("gce_instance", map[string]string{"status": "RUNNING", "external_ip_configured": "true"})
	node.Tags = map[string]string{"goog-gke-node": ""}
	require.True(t, gcpGCEPublicIP.Violates(node), "the label alone does not exempt a node")
	node.Metadata["gke_node_pool_graded"] = "true"
	require.False(t, gcpGCEPublicIP.Violates(node), "its graded node pool carries it")
}

// CIS GCP 1.2: consumer accounts are Medium; other outside-domain members Low.
func TestIAMConsumerAccountMember_OutsideDomain(t *testing.T) {
	outside := gcpAsset("cloud_account", map[string]string{"consumer_account_members": "", "non_org_domain_members": "user:c@contractor.example"})
	require.True(t, gcpIAMConsumerAccountMember.Violates(outside))
	require.Equal(t, finding.SeverityLow, gcpIAMConsumerAccountMember.SeverityFor(outside))
	consumer := gcpAsset("cloud_account", map[string]string{"consumer_account_members": "user:x@gmail.com", "non_org_domain_members": ""})
	require.Equal(t, finding.SeverityMedium, gcpIAMConsumerAccountMember.SeverityFor(consumer))
	require.False(t, gcpIAMConsumerAccountMember.Violates(gcpAsset("cloud_account", map[string]string{"consumer_account_members": ""})))
}

// The API-key existence finding steps aside for keys another API-key
// finding already covers.
func TestAPIKeyExistsStepsAside(t *testing.T) {
	key := func(app, api, age string) asset.Asset {
		return gcpAsset("gcp_api_key", map[string]string{"app_restriction": app, "api_restricted": api, "age_days": age})
	}
	got := firing(t, key("server", "true", "5"))
	require.Len(t, got, 1)
	require.Contains(t, got, "gcp-apikey-exists")
	got = firing(t, key("", "false", "200"))
	require.NotContains(t, got, "gcp-apikey-exists")
	require.Contains(t, got, "gcp-apikey-no-app-restriction")
	require.Contains(t, got, "gcp-apikey-no-api-restriction")
	require.Contains(t, got, "gcp-apikey-not-rotated")
}

// A KMS key that cannot rotate automatically is not graded for rotation.
func TestKMSRotationGradesOnlyRotatableKeys(t *testing.T) {
	md := map[string]string{"purpose": "ASYMMETRIC_SIGN", "import_only": "false", "rotation_within_90_days": "false", "next_rotation": "false"}
	require.False(t, gcpKMSKeyRotation.Violates(gcpAsset("gcp_kms_key", md)))
	md["purpose"], md["import_only"] = "ENCRYPT_DECRYPT", "true"
	require.False(t, gcpKMSKeyRotation.Violates(gcpAsset("gcp_kms_key", md)))
	md["import_only"], md["primary_state"] = "false", "DESTROYED"
	require.False(t, gcpKMSKeyRotation.Violates(gcpAsset("gcp_kms_key", md)))
	md["primary_state"] = "ENABLED"
	require.True(t, gcpKMSKeyRotation.Violates(gcpAsset("gcp_kms_key", md)))
}

// Pending OS updates step aside where the CVE match grades the patches.
func TestGCEOSUpdatesPendingStepsAsideForCVEMatchable(t *testing.T) {
	require.False(t, gcpGCEOSUpdatesPending.Violates(gcpAsset("gce_instance", map[string]string{"os_updates_pending": "9", "package_cve_matchable": "true"})))
	require.True(t, gcpGCEOSUpdatesPending.Violates(gcpAsset("gce_instance", map[string]string{"os_updates_pending": "9"})),
		"a platform with no CVE match (Windows, COS) is graded here")
}

// Organization-inherited settings fire once on the organization asset, and
// on a project only when the collector put the key there instead.
func TestOrgInheritedChecksFireOnTheOrganizationAsset(t *testing.T) {
	org := firing(t, gcpAsset("gcp_organization", map[string]string{
		"log_catch_all_sink": "false", "essential_contacts_missing": "LEGAL", "access_approval_enrolled": "false"}))
	for _, id := range []string{"gcp-logging-no-catch-all-sink", "gcp-essential-contacts-missing", "gcp-access-approval-disabled"} {
		require.Contains(t, org, id)
	}
	require.Empty(t, firing(t, gcpAsset("cloud_account", map[string]string{"log_catch_all_sink": "true"})))
}
