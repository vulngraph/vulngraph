package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// TestNoCheckFiresOnEmptyMetadata is the registry-wide floor of the rule that
// TestChecksNeverFireOnAbsentData states: every registered check, given an
// asset of its own type with no metadata at all (the collector read nothing),
// must stay silent. The per-check rows in TestChecksNeverFireOnAbsentData pin
// the subtler case of one key missing beside others.
func TestNoCheckFiresOnEmptyMetadata(t *testing.T) {
	for _, c := range Default().All() {
		if c.Violates == nil {
			continue
		}
		a := asset.Asset{ID: "a", Name: "a", Type: c.AssetType, Provider: c.Provider}
		require.Falsef(t, c.Violates(a), "%s fires on an asset whose collector observed nothing", c.ID)
	}
}

// TestChecksNeverFireOnAbsentData pins, row by row, the rule every check in the
// registry must follow: a check reports what was OBSERVED. A metadata key that is missing means the
// collector could not read the setting — an expired credential, a throttled API,
// a permission the role lost — and turning that into a finding manufactures
// violations across an entire estate at exactly the moment the platform is least
// able to tell truth from noise.
//
// The rows are the checks that once read a missing key as a violation; the
// registry-wide sweep is TestNoCheckFiresOnEmptyMetadata. Each row states
// the three cases explicitly: the confirmed negative (fires), the confirmed
// positive (silent), and the unobserved case (silent).
func TestChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "gcp-gce-no-oslogin", check: gcpGCENoOSLogin,
			violating: map[string]string{"oslogin": "false"},
			compliant: map[string]string{"oslogin": "true"},
			// resolveGCEControl omits the key when the instance does not set it AND
			// project metadata could not be read; != "true" would make every such
			// instance a finding.
			unknown: map[string]string{},
		},
		{
			name: "gcp-gce-project-ssh-keys", check: gcpGCEProjectSSHKeys,
			violating: map[string]string{"project_ssh_keys_blocked": "false"},
			compliant: map[string]string{"project_ssh_keys_blocked": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gcs-logging-disabled", check: gcpGCSLoggingDisabled,
			// logging_bucket, not "logging": the key was renamed apart from the
			// s3_bucket key of the same name, which is an enabled/disabled enum.
			violating: map[string]string{"logging_bucket": ""},
			compliant: map[string]string{"logging_bucket": "audit-logs-bucket"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ec2-imdsv2-not-required", check: awsEC2IMDSv2NotRequired,
			// Latent: http_tokens is normally populated on every instance. One
			// failed describe under the old predicate and every
			// instance becomes a High finding simultaneously.
			violating: map[string]string{"http_tokens": "optional"},
			compliant: map[string]string{"http_tokens": "required"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gcs-uniform-access-disabled", check: gcpGCSUniformAccessDisabled,
			violating: map[string]string{"uniform_access": "false"},
			compliant: map[string]string{"uniform_access": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gcs-versioning-disabled", check: gcpGCSVersioningDisabled,
			violating: map[string]string{"versioning": "false"},
			compliant: map[string]string{"versioning": "true"},
			unknown:   map[string]string{},
		},
		{
			// The collector leaves direct_public_ip out when a NIC could not be
			// read; PublicIP alone would read that VM as having none.
			name: "azure-vm-direct-public-ip", check: azureVMDirectPublicIP,
			violating: map[string]string{"direct_public_ip": "true"},
			compliant: map[string]string{"direct_public_ip": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "azure-webapp-no-https-only", check: azureWebAppNoHTTPSOnly,
			violating: map[string]string{"https_only": "false"},
			compliant: map[string]string{"https_only": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-no-backup", check: awsRDSNoBackup,
			violating: map[string]string{"backup_retention": "0", "db_cluster_id": ""},
			compliant: map[string]string{"backup_retention": "7", "db_cluster_id": ""},
			unknown:   map[string]string{"db_cluster_id": ""},
		},
		{
			name: "aws-ec2-os-end-of-life", check: awsEC2OSEndOfLife,
			// package_ecosystem is stamped only with a real inventory; a VM
			// without one has no known OS release and is never graded.
			violating: map[string]string{"package_ecosystem": "CentOS:7"},
			compliant: map[string]string{"package_ecosystem": "Amazon Linux:2023"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gce-os-end-of-life", check: gcpGCEOSEndOfLife,
			violating: map[string]string{"package_ecosystem": "Debian:10"},
			compliant: map[string]string{"package_ecosystem": "Debian:12"},
			unknown:   map[string]string{},
		},
		{
			name: "container-image-os-end-of-life", check: containerImageOSEndOfLife,
			// base_os is set only for an image whose release the sweep read; an
			// unscanned or unidentified image has no OS release to grade.
			violating: map[string]string{"base_os": "Alpine:v3.18"},
			compliant: map[string]string{"base_os": "Alpine:v3.22"},
			unknown:   map[string]string{"base_image_source": "unknown"},
		},
		{
			name: "aws-lambda-no-vpc", check: awsLambdaNoVPC,
			violating: map[string]string{"vpc_id": ""},
			compliant: map[string]string{"vpc_id": "vpc-0eeee5555ffff6666"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ec2-no-iam-role", check: awsEC2NoIAMRole,
			violating: map[string]string{"iam_instance_profile": ""},
			compliant: map[string]string{"iam_instance_profile": "arn:aws:iam::1:instance-profile/app"},
			unknown:   map[string]string{},
		},
		{
			// The GCP mirror of aws-rds-no-backup, converted a release later. The
			// collector now omits `backups` when the API returned no
			// BackupConfiguration instead of writing the Go zero value "false".
			name: "gcp-cloudsql-no-backup", check: gcpCloudSQLNoBackup,
			violating: map[string]string{"backups": "false"},
			compliant: map[string]string{"backups": "true"},
			unknown:   map[string]string{},
		},
		{
			// log_bin is written as "true" or "" (boolToEnabledStr), so only a
			// present-and-empty value is an observation. The engine gate keeps
			// Postgres/SQL Server out of all three rows.
			name: "gcp-cloudsql-binary-log-disabled", check: gcpCloudSQLBinaryLogDisabled,
			violating: map[string]string{"version": "MYSQL_8_0", "log_bin": ""},
			compliant: map[string]string{"version": "MYSQL_8_0", "log_bin": "true"},
			unknown:   map[string]string{"version": "MYSQL_8_0"},
		},
		{
			// db_flag_* is stamped ("" = engine default) only once Settings was read;
			// the unknown row is an instance whose flag list never came back.
			name: "gcp-cloudsql-mysql-skip-show-database", check: gcpCloudSQLMySQLSkipShowDatabase,
			violating: map[string]string{"version": "MYSQL_8_0", "db_flag_skip_show_database": ""},
			compliant: map[string]string{"version": "MYSQL_8_0", "db_flag_skip_show_database": "on"},
			unknown:   map[string]string{"version": "MYSQL_8_0"},
		},
		{
			name: "gcp-cloudsql-mysql-local-infile", check: gcpCloudSQLMySQLLocalInfile,
			violating: map[string]string{"version": "MYSQL_8_0", "db_flag_local_infile": "on"},
			compliant: map[string]string{"version": "MYSQL_8_0", "db_flag_local_infile": "off"},
			unknown:   map[string]string{"version": "MYSQL_8_0"},
		},
		{
			name: "gcp-cloudsql-postgres-log-error-verbosity", check: gcpCloudSQLPostgresLogErrorVerbosity,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_error_verbosity": "verbose"},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_error_verbosity": ""},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-log-connections", check: gcpCloudSQLPostgresLogConnections,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_connections": ""},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_connections": "on"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-log-disconnections", check: gcpCloudSQLPostgresLogDisconnections,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_disconnections": ""},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_disconnections": "on"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-log-statement", check: gcpCloudSQLPostgresLogStatement,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_statement": "none"},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_statement": "ddl"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-log-min-messages", check: gcpCloudSQLPostgresLogMinMessages,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_min_messages": "info"},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_min_messages": ""},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-log-min-error-statement", check: gcpCloudSQLPostgresLogMinErrorStatement,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_min_error_statement": "warning"},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_min_error_statement": "error"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-log-min-duration", check: gcpCloudSQLPostgresLogMinDuration,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_log_min_duration_statement": "1000"},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_log_min_duration_statement": "-1"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-postgres-pgaudit-disabled", check: gcpCloudSQLPostgresPgAuditDisabled,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_cloudsql_enable_pgaudit": ""},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_cloudsql_enable_pgaudit": "on"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			name: "gcp-cloudsql-sqlserver-external-scripts", check: gcpCloudSQLSQLServerExternalScripts,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_external_scripts_enabled": "on"},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_external_scripts_enabled": ""},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-sqlserver-cross-db-chaining", check: gcpCloudSQLSQLServerCrossDBChaining,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_cross_db_ownership_chaining": "on"},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_cross_db_ownership_chaining": "off"},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-sqlserver-user-connections", check: gcpCloudSQLSQLServerUserConnections,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_user_connections": "100"},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_user_connections": "0"},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-sqlserver-user-options", check: gcpCloudSQLSQLServerUserOptions,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_user_options": "16"},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_user_options": ""},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-sqlserver-remote-access", check: gcpCloudSQLSQLServerRemoteAccess,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_remote_access": ""},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_remote_access": "off"},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-sqlserver-trace-3625", check: gcpCloudSQLSQLServerTrace3625,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_3625": ""},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_3625": "on"},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-sqlserver-contained-db-auth", check: gcpCloudSQLSQLServerContainedDBAuth,
			violating: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_contained_database_authentication": "on"},
			compliant: map[string]string{"version": "SQLSERVER_2019_STANDARD", "db_flag_contained_database_authentication": ""},
			unknown:   map[string]string{"version": "SQLSERVER_2019_STANDARD"},
		},
		{
			name: "gcp-cloudsql-iam-auth-disabled", check: gcpCloudSQLIAMAuthDisabled,
			violating: map[string]string{"version": "POSTGRES_15", "db_flag_cloudsql_iam_authentication": ""},
			compliant: map[string]string{"version": "POSTGRES_15", "db_flag_cloudsql_iam_authentication": "on"},
			unknown:   map[string]string{"version": "POSTGRES_15"},
		},
		{
			// authorized_networks_world is stamped only when ipConfiguration came back.
			name: "gcp-cloudsql-open-authorized-network", check: gcpCloudSQLOpenAuthorizedNetwork,
			violating: map[string]string{"public": "true", "authorized_networks_world": "true"},
			compliant: map[string]string{"public": "true", "authorized_networks_world": "false"},
			unknown:   map[string]string{"public": "true"},
		},
		{
			// sslMode supersedes requireSsl: ENCRYPTED_ONLY with requireSsl=false is
			// compliant, which reading require_ssl alone reported as a violation.
			name: "gcp-cloudsql-no-ssl", check: gcpCloudSQLNoSSL,
			violating: map[string]string{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED", "require_ssl": "false"},
			compliant: map[string]string{"ssl_mode": "ENCRYPTED_ONLY", "require_ssl": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-firewall-all-ports-open-internet", check: gcpFirewallAllPortsOpenInternet,
			violating: map[string]string{"all_ports_open_to_internet": "true"},
			compliant: map[string]string{"all_ports_open_to_internet": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-firewall-ssh-open-internet", check: gcpFirewallSSHOpenInternet,
			violating: map[string]string{"ssh_open_to_internet": "true"},
			compliant: map[string]string{"ssh_open_to_internet": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-firewall-rdp-open-internet", check: gcpFirewallRDPOpenInternet,
			violating: map[string]string{"rdp_open_to_internet": "true"},
			compliant: map[string]string{"rdp_open_to_internet": "false"},
			unknown:   map[string]string{},
		},
		{
			// A rule collected before deny resolution existed has no shadowed_by_deny:
			// whether a higher-priority deny blocks it is unknown.
			name: "gcp-firewall-open-ingress", check: gcpFirewallOpenIngress,
			violating: map[string]string{"open_to_internet": "true", "shadowed_by_deny": "false"},
			compliant: map[string]string{"open_to_internet": "true", "shadowed_by_deny": "true"},
			unknown:   map[string]string{"open_to_internet": "true"},
		},
		{
			name: "gcp-dns-dnssec-disabled", check: gcpDNSDNSSECDisabled,
			violating: map[string]string{"visibility": "public", "dnssec_state": "off"},
			compliant: map[string]string{"visibility": "public", "dnssec_state": "on"},
			unknown:   map[string]string{"visibility": "public"},
		},
		{
			name: "gcp-dns-dnssec-ksk-rsasha1", check: gcpDNSDNSSECKSKRSASHA1,
			violating: map[string]string{"dnssec_state": "on", "dnssec_ksk_algorithms": "rsasha1"},
			compliant: map[string]string{"dnssec_state": "on", "dnssec_ksk_algorithms": "ecdsap256sha256"},
			unknown:   map[string]string{"dnssec_ksk_algorithms": "rsasha1"},
		},
		{
			name: "gcp-dns-dnssec-zsk-rsasha1", check: gcpDNSDNSSECZSKRSASHA1,
			violating: map[string]string{"dnssec_state": "on", "dnssec_zsk_algorithms": "rsasha1"},
			compliant: map[string]string{"dnssec_state": "on", "dnssec_zsk_algorithms": "rsasha256"},
			unknown:   map[string]string{"dnssec_zsk_algorithms": "rsasha1"},
		},
		{
			name: "gcp-gce-default-sa-full-scope", check: gcpGCEDefaultSAFullScope,
			violating: map[string]string{"exec_role": "serviceAccount:1-compute@developer.gserviceaccount.com", "sa_cloud_platform_scope": "true"},
			compliant: map[string]string{"exec_role": "serviceAccount:1-compute@developer.gserviceaccount.com", "sa_cloud_platform_scope": "false"},
			unknown:   map[string]string{"exec_role": "serviceAccount:1-compute@developer.gserviceaccount.com"},
		},
		{
			name: "gcp-gce-ip-forwarding", check: gcpGCEIPForwarding,
			violating: map[string]string{"can_ip_forward": "true"},
			compliant: map[string]string{"can_ip_forward": "false"},
			unknown:   map[string]string{},
		},
		{
			// The shielded_* keys are omitted when no shieldedInstanceConfig came back.
			name: "gcp-gce-shielded-vm-disabled", check: gcpGCEShieldedVMDisabled,
			violating: map[string]string{"shielded_vtpm": "true", "shielded_integrity_monitoring": "false"},
			compliant: map[string]string{"shielded_vtpm": "true", "shielded_integrity_monitoring": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gce-confidential-compute-disabled", check: gcpGCEConfidentialComputeDisabled,
			violating: map[string]string{"confidential_compute": "false"},
			compliant: map[string]string{"confidential_compute": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-sa-admin-privileges", check: gcpSAAdminPrivileges,
			violating: map[string]string{"disabled": "false", "roles": "roles/storage.admin"},
			compliant: map[string]string{"disabled": "false", "roles": "roles/viewer"},
			unknown:   map[string]string{"roles": "roles/storage.admin"},
		},
		{
			name: "gcp-iam-consumer-account-member", check: gcpIAMConsumerAccountMember,
			violating: map[string]string{"consumer_account_members": "user:a@gmail.com"},
			compliant: map[string]string{"consumer_account_members": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-iam-sa-impersonation-project-wide", check: gcpIAMSAImpersonationProjectWide,
			violating: map[string]string{"sa_impersonation_project_members": "user:a@corp.example=roles/iam.serviceAccountUser"},
			compliant: map[string]string{"sa_impersonation_project_members": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-iam-sa-separation-of-duties", check: gcpIAMSASeparationOfDuties,
			violating: map[string]string{"sa_admin_user_members": "user:a@corp.example"},
			compliant: map[string]string{"sa_admin_user_members": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-iam-kms-separation-of-duties", check: gcpIAMKMSSeparationOfDuties,
			violating: map[string]string{"kms_admin_crypto_members": "user:a@corp.example"},
			compliant: map[string]string{"kms_admin_crypto_members": ""},
			unknown:   map[string]string{},
		},
		{
			// Omitted when an ancestor policy was unreadable: the org may enable it.
			name: "gcp-audit-logging-not-configured", check: gcpAuditLoggingNotConfigured,
			violating: map[string]string{"audit_logging_all_services": "false"},
			compliant: map[string]string{"audit_logging_all_services": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-public-endpoint", check: gkePublicEndpoint,
			violating: map[string]string{"public_endpoint": "true", "authorized_networks": "true", "authorized_networks_world": "true"},
			compliant: map[string]string{"public_endpoint": "true", "authorized_networks": "true", "authorized_networks_world": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-private-endpoint-disabled", check: gcpGKEPrivateEndpointDisabled,
			violating: map[string]string{"public_endpoint": "true", "authorized_networks": "true", "authorized_networks_world": "false"},
			compliant: map[string]string{"public_endpoint": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-authorized-networks-disabled", check: gcpGKEAuthorizedNetworksDisabled,
			violating: map[string]string{"public_endpoint": "false", "authorized_networks": "false"},
			compliant: map[string]string{"public_endpoint": "false", "authorized_networks": "true"},
			unknown:   map[string]string{"public_endpoint": "false"},
		},
		{
			name: "gcp-gke-workload-identity-disabled", check: gcpGKEWorkloadIdentityDisabled,
			violating: map[string]string{"workload_identity": "false"},
			compliant: map[string]string{"workload_identity": "true"},
			unknown:   map[string]string{},
		},
		{
			// node_pools_* lists are omitted when a pool's setting was not returned
			// and no pool was seen to violate it.
			name: "gcp-gke-metadata-server-disabled", check: gcpGKEMetadataServerDisabled,
			violating: map[string]string{"workload_identity": "true", "node_pools_no_gke_metadata": "pool-a"},
			compliant: map[string]string{"workload_identity": "true", "node_pools_no_gke_metadata": ""},
			unknown:   map[string]string{"workload_identity": "true"},
		},
		{
			name: "gcp-gke-client-certificate-enabled", check: gcpGKEClientCertificateEnabled,
			violating: map[string]string{"client_certificate_issued": "true"},
			compliant: map[string]string{"client_certificate_issued": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-basic-auth-enabled", check: gcpGKEBasicAuthEnabled,
			violating: map[string]string{"basic_auth": "true"},
			compliant: map[string]string{"basic_auth": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-secrets-not-encrypted", check: gcpGKESecretsNotEncrypted,
			violating: map[string]string{"secrets_encryption": "DECRYPTED"},
			compliant: map[string]string{"secrets_encryption": "ENCRYPTED"},
			unknown:   map[string]string{},
		},
		{
			// Dataplane V2 enforces NetworkPolicy while the addon reads disabled, so
			// network_policy=false without the datapath is not evidence of no enforcement.
			name: "gcp-gke-network-policy-disabled", check: gcpGKENetworkPolicyDisabled,
			violating: map[string]string{"network_policy": "false", "datapath_provider": ""},
			compliant: map[string]string{"network_policy": "false", "datapath_provider": "ADVANCED_DATAPATH"},
			unknown:   map[string]string{"network_policy": "false"},
		},
		{
			name: "gcp-gke-binary-authorization-disabled", check: gcpGKEBinaryAuthorizationDisabled,
			violating: map[string]string{"binary_authorization": "DISABLED"},
			compliant: map[string]string{"binary_authorization": "PROJECT_SINGLETON_POLICY_ENFORCE"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-shielded-nodes-disabled", check: gcpGKEShieldedNodesDisabled,
			violating: map[string]string{"shielded_nodes": "false"},
			compliant: map[string]string{"shielded_nodes": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-private-nodes-disabled", check: gcpGKEPrivateNodesDisabled,
			violating: map[string]string{"node_pools_public_nodes": "pool-a"},
			compliant: map[string]string{"node_pools_public_nodes": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-node-secure-boot-disabled", check: gcpGKENodeSecureBootDisabled,
			violating: map[string]string{"node_pools_no_secure_boot": "pool-a"},
			compliant: map[string]string{"node_pools_no_secure_boot": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-node-integrity-monitoring-disabled", check: gcpGKENodeIntegrityMonitoringDisabled,
			violating: map[string]string{"node_pools_no_integrity_monitoring": "pool-a"},
			compliant: map[string]string{"node_pools_no_integrity_monitoring": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-node-auto-upgrade-disabled", check: gcpGKENodeAutoUpgradeDisabled,
			violating: map[string]string{"node_pools_no_auto_upgrade": "pool-a"},
			compliant: map[string]string{"node_pools_no_auto_upgrade": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-node-auto-repair-disabled", check: gcpGKENodeAutoRepairDisabled,
			violating: map[string]string{"node_pools_no_auto_repair": "pool-a"},
			compliant: map[string]string{"node_pools_no_auto_repair": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-node-image-not-cos", check: gcpGKENodeImageNotCOS,
			violating: map[string]string{"node_pools_not_cos": "pool-a"},
			compliant: map[string]string{"node_pools_not_cos": ""},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-no-release-channel", check: gcpGKENoReleaseChannel,
			violating: map[string]string{"release_channel": ""},
			compliant: map[string]string{"release_channel": "REGULAR"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-logging-disabled", check: gcpGKELoggingDisabled,
			violating: map[string]string{"logging_service": "none"},
			compliant: map[string]string{"logging_service": "logging.googleapis.com/kubernetes", "monitoring_service": "monitoring.googleapis.com/kubernetes"},
			unknown:   map[string]string{},
		},
		{
			name: "gcp-gke-intranode-visibility-disabled", check: gcpGKEIntranodeVisibilityDisabled,
			violating: map[string]string{"intranode_visibility": "false"},
			compliant: map[string]string{"intranode_visibility": "true"},
			unknown:   map[string]string{},
		},
		{
			// bucketLoggingStatus returned "disabled" on AccessDenied/throttle/
			// transport as well as on a genuine 200-with-no-LoggingEnabled, so a
			// read failure was indistinguishable from an observed negative.
			name: "aws-s3-access-logging-disabled", check: awsS3AccessLoggingDisabled,
			violating: map[string]string{"logging": "disabled"},
			compliant: map[string]string{"logging": "enabled"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-s3-no-versioning", check: awsS3NoVersioning,
			violating: map[string]string{"versioning": "disabled"},
			compliant: map[string]string{"versioning": "enabled"},
			unknown:   map[string]string{},
		},
		{
			// mfa_delete shares GetBucketVersioning with `versioning`, so the same
			// failure took out both keys — and != "Enabled" read the absence as a
			// violation where the versioning arm was protected by testing a
			// positive enum value.
			name: "aws-s3-mfa-delete-disabled", check: awsS3MFADeleteDisabled,
			violating: map[string]string{"versioning": "enabled", "mfa_delete": "Disabled"},
			compliant: map[string]string{"versioning": "enabled", "mfa_delete": "Enabled"},
			unknown:   map[string]string{"versioning": "enabled"},
		},
		{
			// The raw inherited setting does not establish effective prevention.
			// Unreadable ancestor policy leaves the check unevaluated.
			name: "gcp-gcs-public-access-not-prevented", check: gcpGCSPublicAccessNotPrevented,
			violating: map[string]string{"public_access_prevention_effective": "not_enforced"},
			compliant: map[string]string{"public_access_prevention_effective": "enforced"},
			unknown:   map[string]string{"public_access_prevention": "inherited"},
		},
		{
			// Latent: when every storage account enforces HTTPS this check has no
			// findings, so the collector writing "false" for an ARM response that
			// omitted EnableHTTPSTrafficOnly would go unnoticed.
			name: "azure-storage-https-not-enforced", check: azureStorageHTTPSOnly,
			violating: map[string]string{"https_only": "false"},
			compliant: map[string]string{"https_only": "true"},
			unknown:   map[string]string{},
		},
		{
			// The cluster states its own name only when its issuer carries one (GKE
			// does, EKS does not). An undiscovered name must never be read as
			// disagreement with the configured one — that would fire this on every
			// EKS cluster at once.
			name: "k8s-cluster-identity-mismatch", check: k8sClusterIdentityMismatch,
			violating: map[string]string{"configured_name": "example-connector-cluster", "discovered_name": "example-cluster"},
			compliant: map[string]string{"configured_name": "example-cluster", "discovered_name": "example-cluster"},
			unknown:   map[string]string{"configured_name": "example-connector-cluster"},
		},
		{
			// in_public_subnet is absent when route tables were not read or a
			// default route goes through a transit gateway/appliance; a public
			// endpoint alone must not be read as public placement.
			name: "aws-rds-public-subnet-igw", check: awsRDSPublicSubnetIGW,
			violating: map[string]string{"in_public_subnet": "true", "publicly_accessible": "true"},
			compliant: map[string]string{"in_public_subnet": "false", "publicly_accessible": "true"},
			unknown:   map[string]string{"publicly_accessible": "true"},
		},
		{
			// 9999 is "no use in GetRole's tracking window", not a day count: it
			// proves dormancy only with an observed age. A failed GetRole omits
			// last-used entirely and must never read as dormant.
			name: "aws-iam-admin-role-dormant", check: awsIAMAdminRoleDormant,
			violating: map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "last_used_observed": "true", "last_used_days": "9999", "created_days": "400", "path": "/"},
			compliant: map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "last_used_observed": "true", "last_used_days": "3", "created_days": "400", "path": "/"},
			unknown:   map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "created_days": "400", "path": "/"},
		},
		{
			// access_key_last_used_days is omitted when any key's lookup failed —
			// the unread key may be the one in daily use.
			name: "aws-iam-admin-user-dormant", check: awsIAMAdminUserDormant,
			violating: map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "-1", "created_days": "900"},
			compliant: map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "2", "created_days": "900"},
			unknown:   map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "password_last_used_days": "200", "created_days": "900"},
		},
		{
			// -1 from Policy Analyzer is "no activity in the window"; with no
			// creation time on the API, only an old key proves the account is not
			// brand new.
			name: "gcp-sa-admin-dormant", check: gcpSAAdminDormant,
			violating: map[string]string{"disabled": "false", "roles": "roles/owner", "sa_last_auth_days": "-1", "key_age_days": "200"},
			compliant: map[string]string{"disabled": "false", "roles": "roles/owner", "sa_last_auth_days": "5", "key_age_days": "200"},
			unknown:   map[string]string{"disabled": "false", "roles": "roles/owner", "sa_last_auth_days": "-1"},
		},
		{
			// A role that only reaches admin by escalation: the CIEM tier is the
			// privilege evidence, and an unread permission set ("unknown") must
			// never stand in for it.
			name: "aws-iam-admin-role-dormant", check: awsIAMAdminRoleDormant,
			violating: map[string]string{"organization_policy_complete": "true", "privilege_tier": "can_escalate_to_admin", "last_used_observed": "true", "last_used_days": "200", "created_days": "400", "path": "/"},
			compliant: map[string]string{"organization_policy_complete": "true", "privilege_tier": "standard", "last_used_observed": "true", "last_used_days": "200", "created_days": "400", "path": "/"},
			unknown:   map[string]string{"organization_policy_complete": "true", "privilege_tier": "unknown", "last_used_observed": "true", "last_used_days": "200", "created_days": "400", "path": "/"},
		},
		{
			name: "aws-iam-admin-user-dormant", check: awsIAMAdminUserDormant,
			violating: map[string]string{"organization_policy_complete": "true", "privilege_tier": "can_escalate_to_admin", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "-1", "created_days": "900"},
			compliant: map[string]string{"organization_policy_complete": "true", "privilege_tier": "high", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "-1", "created_days": "900"},
			unknown:   map[string]string{"organization_policy_complete": "true", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "-1", "created_days": "900"},
		},
		{
			name: "gcp-sa-admin-dormant", check: gcpSAAdminDormant,
			violating: map[string]string{"privilege_tier": "can_escalate_to_admin", "disabled": "false", "roles": "roles/viewer", "sa_last_auth_days": "200"},
			compliant: map[string]string{"privilege_tier": "standard", "disabled": "false", "roles": "roles/viewer", "sa_last_auth_days": "200"},
			unknown:   map[string]string{"privilege_tier": "unknown", "disabled": "false", "roles": "roles/viewer", "sa_last_auth_days": "200"},
		},
		{
			// Needs the MFA device list and the key list: either unread is unknown.
			name: "aws-iam-admin-user-key-no-mfa", check: awsIAMAdminUserKeyNoMFA,
			violating: map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "console_access": "false", "mfa_enabled": "false", "active_key_count": "1", "inactive": "false", "password_last_used_days": "-1", "access_key_last_used_days": "1"},
			compliant: map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "console_access": "false", "mfa_enabled": "true", "active_key_count": "1", "inactive": "false", "password_last_used_days": "-1", "access_key_last_used_days": "1"},
			unknown:   map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "console_access": "false", "active_key_count": "1"},
		},
		{
			name: "azure-nsg-winrm-not-open-internet", check: azureNSGWinRMOpenInternet,
			violating: map[string]string{"ingress": `[{"protocol":"Tcp","from_port":5986,"to_port":5986,"cidrs":["Internet"],"access":"Allow","priority":100}]`},
			compliant: map[string]string{"ingress": `[{"protocol":"Tcp","from_port":5986,"to_port":5986,"cidrs":["10.0.0.0/8"],"access":"Allow","priority":100}]`},
			unknown:   map[string]string{},
		},
		{
			// A trail whose bucket is in another account (organization trail into
			// a log-archive account) has no s3_bucket_logging at all.
			name: "aws-cloudtrail-bucket-no-access-logging", check: awsCloudTrailBucketNoAccessLogging,
			violating: map[string]string{"s3_bucket": "trail-logs", "s3_bucket_logging": "disabled"},
			compliant: map[string]string{"s3_bucket": "trail-logs", "s3_bucket_logging": "enabled"},
			unknown:   map[string]string{"s3_bucket": "org-log-archive"},
		},
		{
			// Only the classical families ACM issues today count; an unreadable or
			// unrecognised algorithm is not filed as classical.
			name: "acm-cert-non-pqc", check: acmCertNonPQC,
			violating: map[string]string{"status": "ISSUED", "key_algorithm": "RSA_2048"},
			compliant: map[string]string{"status": "ISSUED", "key_algorithm": "ML_DSA_65"},
			unknown:   map[string]string{"status": "ISSUED"},
		},
		{
			// iam_role_ecr_push is absent when the node role or its policy set was
			// not observed.
			name: "aws-eks-node-imdsv1-registry-write", check: eksNodeIMDSv1RegistryWrite,
			violating: map[string]string{"http_tokens": "optional", "k8s_node": "true", "iam_role_ecr_push": "true"},
			compliant: map[string]string{"http_tokens": "optional", "k8s_node": "true", "iam_role_ecr_push": "false"},
			unknown:   map[string]string{"http_tokens": "optional", "k8s_node": "true"},
		},
		// AWS account-wide and region-wide settings: every key is written only
		// from a successful read (collect/aws/account_settings.go).
		{
			name: "aws-iam-weak-password-policy", check: awsIAMWeakPasswordPolicy,
			violating: map[string]string{"password_policy": "absent"},
			compliant: strongPasswordPolicy(),
			unknown:   map[string]string{},
		},
		{
			name: "aws-account-no-security-contact", check: awsAccountNoSecurityContact,
			violating: map[string]string{"security_contact": "false"},
			compliant: map[string]string{"security_contact": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-s3-account-bpa-disabled", check: awsS3AccountBPADisabled,
			violating: map[string]string{"s3_bpa_all_enabled": "false"},
			compliant: map[string]string{"s3_bpa_all_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			// Written only from a successful trail listing; a multi-region trail
			// whose status was unreadable leaves it absent.
			name: "aws-cloudtrail-no-multiregion-trail", check: awsCloudTrailNoMultiRegionTrail,
			violating: map[string]string{"cloudtrail_multi_region_logging": "false", "cloudtrail_trail_count": "0"},
			compliant: map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_trail_count": "1"},
			unknown:   map[string]string{"cloudtrail_trail_count": "1"},
		},
		{
			name: "aws-cloudtrail-no-kms-encryption", check: awsCloudTrailNoKMS,
			violating: map[string]string{"kms_key_id": ""},
			compliant: map[string]string{"kms_key_id": "arn:aws:kms:us-east-1:111:key/k"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudtrail-no-cloudwatch-logs", check: awsCloudTrailNoCloudWatchLogs,
			violating: map[string]string{"cloudwatch_log_group": ""},
			compliant: map[string]string{"cloudwatch_log_group": "arn:aws:logs:us-east-1:111:log-group:ct:*"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ebs-default-encryption-disabled", check: awsEBSDefaultEncryptionDisabled,
			violating: map[string]string{"ebs_encryption_by_default": "false"},
			compliant: map[string]string{"ebs_encryption_by_default": "true"},
			unknown:   map[string]string{"snapshot_block_public_access": "unblocked"},
		},
		{
			name: "aws-ebs-snapshot-bpa-disabled", check: awsEBSSnapshotBPADisabled,
			violating: map[string]string{"snapshot_block_public_access": "unblocked"},
			compliant: map[string]string{"snapshot_block_public_access": "block-all-sharing"},
			unknown:   map[string]string{"ebs_encryption_by_default": "false"},
		},
		{
			name: "aws-vpc-block-public-access-off", check: awsVPCBlockPublicAccessOff,
			violating: map[string]string{"vpc_block_public_access": "off"},
			compliant: map[string]string{"vpc_block_public_access": "block-ingress"},
			unknown:   map[string]string{},
		},
		// Logging, monitoring and detection services (aws_logging.go,
		// aws_monitoring.go, aws_detection.go, aws_threat_detection.go): every
		// key is written only from a successful read.
		{
			// The selector half of CIS 4.1: a logging multi-region trail whose
			// selectors were unread leaves cloudtrail_multi_region_mgmt_all absent.
			name: "aws-cloudtrail-no-multiregion-trail", check: awsCloudTrailNoMultiRegionTrail,
			violating: map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "false"},
			compliant: map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "true"},
			unknown:   map[string]string{"cloudtrail_multi_region_logging": "true"},
		},
		{
			name: "aws-cloudtrail-no-s3-write-events", check: awsCloudTrailNoS3WriteEvents,
			violating: map[string]string{"cloudtrail_s3_write_events": "false"},
			compliant: map[string]string{"cloudtrail_s3_write_events": "true"},
			unknown:   map[string]string{"cloudtrail_s3_read_events": "false"},
		},
		{
			name: "aws-cloudtrail-no-s3-read-events", check: awsCloudTrailNoS3ReadEvents,
			violating: map[string]string{"cloudtrail_s3_read_events": "false"},
			compliant: map[string]string{"cloudtrail_s3_read_events": "true"},
			unknown:   map[string]string{"cloudtrail_s3_write_events": "false"},
		},
		{
			// An unread flow-log listing leaves flow_logs_enabled absent; a
			// default VPC whose interfaces were unread is treated as in use.
			name: "aws-vpc-flow-logs-disabled", check: awsVPCFlowLogsDisabled,
			violating: map[string]string{"flow_logs_enabled": "false", "is_default": "true"},
			compliant: map[string]string{"flow_logs_enabled": "true", "is_default": "false"},
			unknown:   map[string]string{"is_default": "false"},
		},
		{
			name: "aws-vpc-flow-logs-disabled", check: awsVPCFlowLogsDisabled,
			violating: map[string]string{"flow_logs_enabled": "false", "is_default": "true", "in_use": "true"},
			compliant: map[string]string{"flow_logs_enabled": "false", "is_default": "true", "in_use": "false"},
			unknown:   map[string]string{"is_default": "true", "in_use": "true"},
		},
		{
			name: "aws-alb-access-logs-disabled", check: awsALBAccessLogsDisabled,
			violating: map[string]string{"access_logs_s3_enabled": "false", "type": "application"},
			compliant: map[string]string{"access_logs_s3_enabled": "true", "type": "application"},
			unknown:   map[string]string{"type": "application"},
		},
		{
			name: "aws-apigateway-access-logging-off", check: awsAPIGatewayAccessLoggingOff,
			violating: map[string]string{"access_log_destination": "", "stage_name": "prod"},
			compliant: map[string]string{"access_log_destination": "arn:aws:logs:eu-west-1:1:log-group:api", "stage_name": "prod"},
			unknown:   map[string]string{"stage_name": "prod"},
		},
		{
			name: "aws-network-firewall-logging-off", check: awsNetworkFirewallLoggingOff,
			violating: map[string]string{"logging_flow": "false", "logging_alert": "false", "logging_tls": "false"},
			compliant: map[string]string{"logging_flow": "false", "logging_alert": "true", "logging_tls": "false"},
			unknown:   map[string]string{"delete_protection": "true"},
		},
		{
			// Written "false" only when the trail listing was read, nothing was
			// unknown and no trail qualifies.
			name: "aws-cloudwatch-no-cis-monitoring-trail", check: awsCWNoCISMonitoringTrail,
			violating: map[string]string{"cw_alarm_monitoring_trail": "false", "cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "true"},
			compliant: map[string]string{"cw_alarm_monitoring_trail": "true", "cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "true"},
			unknown:   map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "true"},
		},
		{
			// A chain with any unread link leaves its cw_alarm_* key absent.
			name: "aws-cloudwatch-alarm-unauthorized-api-calls", check: awsCWAlarmUnauthorizedAPICalls,
			violating: map[string]string{"cw_alarm_unauthorized_api_calls": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_unauthorized_api_calls": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-console-login-no-mfa", check: awsCWAlarmConsoleLoginNoMFA,
			violating: map[string]string{"cw_alarm_console_login_no_mfa": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_console_login_no_mfa": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-root-usage", check: awsCWAlarmRootUsage,
			violating: map[string]string{"cw_alarm_root_usage": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_root_usage": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-iam-policy-changes", check: awsCWAlarmIAMPolicyChanges,
			violating: map[string]string{"cw_alarm_iam_policy_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_iam_policy_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-cloudtrail-changes", check: awsCWAlarmCloudTrailChanges,
			violating: map[string]string{"cw_alarm_cloudtrail_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_cloudtrail_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-console-auth-failures", check: awsCWAlarmConsoleAuthFailures,
			violating: map[string]string{"cw_alarm_console_auth_failures": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_console_auth_failures": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-kms-disable-or-delete", check: awsCWAlarmKMSKeyDisableOrDeletion,
			violating: map[string]string{"cw_alarm_kms_key_disable_or_deletion": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_kms_key_disable_or_deletion": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-s3-bucket-policy-changes", check: awsCWAlarmS3BucketPolicyChanges,
			violating: map[string]string{"cw_alarm_s3_bucket_policy_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_s3_bucket_policy_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-config-changes", check: awsCWAlarmConfigChanges,
			violating: map[string]string{"cw_alarm_config_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_config_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-security-group-changes", check: awsCWAlarmSecurityGroupChanges,
			violating: map[string]string{"cw_alarm_security_group_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_security_group_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-nacl-changes", check: awsCWAlarmNACLChanges,
			violating: map[string]string{"cw_alarm_nacl_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_nacl_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-network-gateway-changes", check: awsCWAlarmNetworkGatewayChanges,
			violating: map[string]string{"cw_alarm_network_gateway_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_network_gateway_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-route-table-changes", check: awsCWAlarmRouteTableChanges,
			violating: map[string]string{"cw_alarm_route_table_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_route_table_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-vpc-changes", check: awsCWAlarmVPCChanges,
			violating: map[string]string{"cw_alarm_vpc_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_vpc_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-cloudwatch-alarm-organizations-changes", check: awsCWAlarmOrganizationsChanges,
			violating: map[string]string{"cw_alarm_organizations_changes": "false", "cw_alarm_monitoring_trail": "true"},
			compliant: map[string]string{"cw_alarm_organizations_changes": "true", "cw_alarm_monitoring_trail": "true"},
			unknown:   map[string]string{"cw_alarm_monitoring_trail": "true"},
		},
		{
			name: "aws-config-recorder-off", check: awsConfigRecorderOff,
			violating: map[string]string{"config_recorder": "absent"},
			compliant: map[string]string{"config_recorder": "present", "config_recording": "true", "config_all_supported": "true",
				"config_delivery_channel": "true", "config_last_status": "Success"},
			unknown: map[string]string{},
		},
		{
			name: "aws-config-recorder-off", check: awsConfigRecorderOff,
			violating: map[string]string{"config_recorder": "present", "config_recording": "false"},
			compliant: map[string]string{"config_recorder": "present", "config_recording": "true"},
			unknown:   map[string]string{"config_recorder": "present"},
		},
		{
			name: "aws-config-not-service-linked-role", check: awsConfigNotServiceLinkedRole,
			violating: map[string]string{"config_recorder": "present", "config_service_linked_role": "false"},
			compliant: map[string]string{"config_recorder": "present", "config_service_linked_role": "true"},
			unknown:   map[string]string{"config_recorder": "present"},
		},
		{
			name: "aws-securityhub-disabled", check: awsSecurityHubDisabled,
			violating: map[string]string{"securityhub_enabled": "false"},
			compliant: map[string]string{"securityhub_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-access-analyzer-disabled", check: awsAccessAnalyzerDisabled,
			violating: map[string]string{"access_analyzer_active": "false"},
			compliant: map[string]string{"access_analyzer_active": "true"},
			unknown:   map[string]string{},
		},
		{
			// A missing macie2 permission is an AccessDenied too; only the
			// "Macie is not enabled" answer becomes NOT_ENABLED.
			name: "aws-macie-disabled", check: awsMacieDisabled,
			violating: map[string]string{"macie_status": "NOT_ENABLED"},
			compliant: map[string]string{"macie_status": "ENABLED"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-macie-automated-discovery-off", check: awsMacieAutomatedDiscoveryOff,
			violating: map[string]string{"macie_status": "ENABLED", "macie_automated_discovery": "DISABLED"},
			compliant: map[string]string{"macie_status": "ENABLED", "macie_automated_discovery": "ENABLED"},
			unknown:   map[string]string{"macie_status": "ENABLED"},
		},
		{
			name: "aws-guardduty-disabled", check: awsGuardDutyDisabled,
			violating: map[string]string{"guardduty_enabled": "false"},
			compliant: map[string]string{"guardduty_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-guardduty-s3-protection-off", check: awsGuardDutyS3ProtectionOff,
			violating: map[string]string{"guardduty_enabled": "true", "guardduty_s3_protection": "false"},
			compliant: map[string]string{"guardduty_enabled": "true", "guardduty_s3_protection": "true"},
			unknown:   map[string]string{"guardduty_enabled": "true"},
		},
		{
			name: "aws-guardduty-eks-audit-logs-off", check: awsGuardDutyEKSAuditLogsOff,
			violating: map[string]string{"guardduty_eks_audit_logs": "false"},
			compliant: map[string]string{"guardduty_eks_audit_logs": "true"},
			unknown:   map[string]string{"guardduty_enabled": "true"},
		},
		{
			name: "aws-guardduty-lambda-protection-off", check: awsGuardDutyLambdaProtectionOff,
			violating: map[string]string{"guardduty_lambda_protection": "false"},
			compliant: map[string]string{"guardduty_lambda_protection": "true"},
			unknown:   map[string]string{"guardduty_enabled": "true"},
		},
		{
			name: "aws-guardduty-malware-protection-off", check: awsGuardDutyMalwareProtectionOff,
			violating: map[string]string{"guardduty_malware_protection": "false"},
			compliant: map[string]string{"guardduty_malware_protection": "true"},
			unknown:   map[string]string{"guardduty_enabled": "true"},
		},
		{
			name: "aws-guardduty-rds-protection-off", check: awsGuardDutyRDSProtectionOff,
			violating: map[string]string{"guardduty_rds_protection": "false"},
			compliant: map[string]string{"guardduty_rds_protection": "true"},
			unknown:   map[string]string{"guardduty_enabled": "true"},
		},
		{
			name: "aws-guardduty-runtime-monitoring-off", check: awsGuardDutyRuntimeMonitoringOff,
			violating: map[string]string{"guardduty_runtime_monitoring": "false"},
			compliant: map[string]string{"guardduty_runtime_monitoring": "true"},
			unknown:   map[string]string{"guardduty_enabled": "true"},
		},
		{
			// Agent keys exist only while Runtime Monitoring is on.
			name: "aws-guardduty-eks-runtime-off", check: awsGuardDutyEKSRuntimeOff,
			violating: map[string]string{"guardduty_eks_runtime": "false"},
			compliant: map[string]string{"guardduty_eks_runtime": "true"},
			unknown:   map[string]string{"guardduty_runtime_monitoring": "false"},
		},
		{
			name: "aws-guardduty-ecs-runtime-off", check: awsGuardDutyECSRuntimeOff,
			violating: map[string]string{"guardduty_ecs_runtime": "false"},
			compliant: map[string]string{"guardduty_ecs_runtime": "true"},
			unknown:   map[string]string{"guardduty_runtime_monitoring": "false"},
		},
		{
			name: "aws-guardduty-ec2-runtime-off", check: awsGuardDutyEC2RuntimeOff,
			violating: map[string]string{"guardduty_ec2_runtime": "false"},
			compliant: map[string]string{"guardduty_ec2_runtime": "true"},
			unknown:   map[string]string{"guardduty_runtime_monitoring": "false"},
		},
		{
			name: "aws-inspector-disabled", check: awsInspectorDisabled,
			violating: map[string]string{"inspector_status": "DISABLED"},
			compliant: map[string]string{"inspector_status": "ENABLED"},
			unknown:   map[string]string{},
		},
		{
			// Scan-type keys exist only while Inspector is on.
			name: "aws-inspector-ec2-scan-off", check: awsInspectorEC2ScanOff,
			violating: map[string]string{"inspector_status": "ENABLED", "inspector_ec2": "DISABLED"},
			compliant: map[string]string{"inspector_status": "ENABLED", "inspector_ec2": "ENABLED"},
			unknown:   map[string]string{"inspector_status": "DISABLED"},
		},
		{
			name: "aws-inspector-ecr-scan-off", check: awsInspectorECRScanOff,
			violating: map[string]string{"inspector_ecr": "SUSPENDED"},
			compliant: map[string]string{"inspector_ecr": "ENABLING"},
			unknown:   map[string]string{"inspector_status": "DISABLED"},
		},
		{
			name: "aws-inspector-lambda-scan-off", check: awsInspectorLambdaScanOff,
			violating: map[string]string{"inspector_lambda": "DISABLED"},
			compliant: map[string]string{"inspector_lambda": "ENABLED"},
			unknown:   map[string]string{"inspector_status": "DISABLED"},
		},
		{
			name: "aws-inspector-lambda-code-scan-off", check: awsInspectorLambdaCodeScanOff,
			violating: map[string]string{"inspector_lambda_code": "DISABLED"},
			compliant: map[string]string{"inspector_lambda_code": "ENABLED"},
			unknown:   map[string]string{"inspector_lambda": "DISABLED"},
		},
		// IAM policy documents: the grant keys are written only when the
		// document was read and parsed, and only for a complete policy set.
		{
			name: "aws-iam-policy-full-admin", check: awsIAMPolicyFullAdmin,
			violating: map[string]string{"managed_by": "customer", "full_admin": "true"},
			compliant: map[string]string{"managed_by": "customer", "full_admin": "false"},
			unknown:   map[string]string{"managed_by": "customer"},
		},
		{
			name: "aws-iam-policy-service-wildcard", check: awsIAMPolicyServiceWildcard,
			violating: map[string]string{"managed_by": "customer", "full_admin": "false", "service_wildcard_actions": "s3:*"},
			compliant: map[string]string{"managed_by": "customer", "full_admin": "false", "service_wildcard_actions": ""},
			unknown:   map[string]string{"managed_by": "customer"},
		},
		{
			name: "aws-iam-policy-kms-decrypt-all", check: awsIAMPolicyKMSDecryptAll,
			violating: map[string]string{"managed_by": "customer", "full_admin": "false", "kms_decrypt_all_resources": "true"},
			compliant: map[string]string{"managed_by": "customer", "full_admin": "false", "kms_decrypt_all_resources": "false"},
			unknown:   map[string]string{"managed_by": "customer"},
		},
		{
			name: "aws-iam-user-inline-kms-decrypt-all", check: awsIAMUserInlineKMSDecryptAll,
			violating: map[string]string{"inline_kms_decrypt_all": "true"},
			compliant: map[string]string{"inline_kms_decrypt_all": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-iam-role-inline-kms-decrypt-all", check: awsIAMRoleInlineKMSDecryptAll,
			violating: map[string]string{"inline_kms_decrypt_all": "true"},
			compliant: map[string]string{"inline_kms_decrypt_all": "false"},
			unknown:   map[string]string{},
		},
		{
			// Effective admin requires the CIEM tier and observed organization coverage.
			name: "aws-iam-user-full-admin", check: awsIAMUserFullAdmin,
			violating: map[string]string{"admin": "true", "privilege_tier": "admin", "organization_policy_complete": "true"},
			compliant: map[string]string{"policies": "[]", "privilege_tier": "standard", "organization_policy_complete": "true"},
			unknown:   map[string]string{"path": "/"},
		},
		{
			name: "aws-iam-role-full-admin", check: awsIAMRoleFullAdmin,
			violating: map[string]string{"admin": "true", "path": "/", "privilege_tier": "admin", "organization_policy_complete": "true"},
			compliant: map[string]string{"path": "/", "policies": "[]", "privilege_tier": "standard", "organization_policy_complete": "true"},
			unknown:   map[string]string{"path": "/"},
		},
		{
			name: "aws-iam-root-virtual-mfa", check: awsIAMRootVirtualMFA,
			violating: map[string]string{"root": "true", "mfa_enabled": "true", "root_virtual_mfa": "true"},
			compliant: map[string]string{"root": "true", "mfa_enabled": "true", "root_virtual_mfa": "false"},
			unknown:   map[string]string{"root": "true", "mfa_enabled": "true"},
		},
		{
			// root_last_used is absent when the credential report was unreadable.
			name: "aws-iam-root-recently-used", check: awsIAMRootRecentlyUsed,
			violating: map[string]string{"root": "true", "root_last_used": daysAgo(2)},
			compliant: map[string]string{"root": "true", "root_last_used": ""},
			unknown:   map[string]string{"root": "true"},
		},
		{
			name: "aws-iam-user-cloudshell-full-access", check: awsIAMUserCloudShellFullAccess,
			violating: map[string]string{"cloudshell_full_access": "true"},
			compliant: map[string]string{"cloudshell_full_access": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-iam-role-cloudshell-full-access", check: awsIAMRoleCloudShellFullAccess,
			violating: map[string]string{"cloudshell_full_access": "true"},
			compliant: map[string]string{"cloudshell_full_access": "false"},
			unknown:   map[string]string{},
		},
		// Data services.
		{
			name: "aws-kms-key-pending-deletion", check: awsKMSKeyPendingDeletion,
			violating: map[string]string{"key_state": "PendingDeletion"},
			compliant: map[string]string{"key_state": "Enabled"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-kms-rotation-disabled", check: awsKMSRotationDisabled,
			violating: map[string]string{"key_state": "Enabled", "key_spec": "SYMMETRIC_DEFAULT", "key_origin": "AWS_KMS", "custom_key_store_id": "", "multi_region_key_type": "", "rotation_enabled": "false"},
			compliant: map[string]string{"key_state": "PendingDeletion", "key_spec": "SYMMETRIC_DEFAULT", "key_origin": "AWS_KMS", "custom_key_store_id": "", "multi_region_key_type": "", "rotation_enabled": "false"},
			unknown:   map[string]string{"key_state": "Enabled", "key_spec": "SYMMETRIC_DEFAULT", "key_origin": "AWS_KMS", "custom_key_store_id": ""},
		},
		{
			// Both policy keys are absent when GetBucketPolicy failed for any
			// reason other than NoSuchBucketPolicy.
			name: "aws-s3-no-tls-enforcement", check: awsS3NoTLSEnforcement,
			violating: map[string]string{"policy_tls_enforced": "false"},
			compliant: map[string]string{"policy_tls_enforced": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-s3-policy-cross-account-write", check: awsS3PolicyCrossAccountWrite,
			violating: map[string]string{"policy_cross_account_write": "true"},
			compliant: map[string]string{"policy_cross_account_write": "false"},
			unknown:   map[string]string{},
		},
		{
			// bpa_all_enabled is absent when the bucket's own block was unread
			// and the account's does not settle it.
			name: "aws-s3-public-bucket", check: awsS3PublicBucket,
			violating: map[string]string{"public_access": "none", "public": "false", "bpa_all_enabled": "false"},
			compliant: map[string]string{"public_access": "none", "public": "false", "bpa_all_enabled": "true"},
			unknown:   map[string]string{"public_access": "none", "public": "false"},
		},
		{
			name: "aws-secretsmanager-rotation-overdue", check: awsSecretRotationOverdue,
			violating: map[string]string{"rotation_enabled": "true", "rotation_interval_days": "30", "last_rotated": daysAgo(45)},
			compliant: map[string]string{"rotation_enabled": "true", "rotation_interval_days": "30", "last_rotated": daysAgo(10)},
			unknown:   map[string]string{"rotation_enabled": "true", "last_rotated": daysAgo(45)},
		},
		{
			name: "aws-secretsmanager-not-rotated-90d", check: awsSecretNotRotated90d,
			violating: map[string]string{"rotation_enabled": "true", "rotation_interval_days": "180", "last_rotated": daysAgo(120)},
			compliant: map[string]string{"rotation_enabled": "true", "rotation_interval_days": "180", "last_rotated": daysAgo(30)},
			unknown:   map[string]string{"rotation_enabled": "true", "rotation_interval_days": "180"},
		},
		{
			name: "aws-secretsmanager-unused", check: awsSecretUnused,
			violating: map[string]string{"last_accessed": daysAgo(120)},
			compliant: map[string]string{"last_accessed": daysAgo(3)},
			unknown:   map[string]string{"created_at": daysAgo(400)},
		},
		{
			name: "aws-acm-rsa-key-too-short", check: awsACMRSAKeyTooShort,
			violating: map[string]string{"key_algorithm": "RSA_1024"},
			compliant: map[string]string{"key_algorithm": "RSA_2048"},
			unknown:   map[string]string{"status": "ISSUED"},
		},
		{
			// ssm_access_denied / ssm_unavailable are gaps in what graph could
			// read, not instances proven unmanaged: the collector writes
			// ssm_managed only from a successful managed-node listing.
			name: "aws-ec2-not-ssm-managed", check: awsEC2NotSSMManaged,
			violating: map[string]string{"state": "running", "ssm_managed": "false"},
			compliant: map[string]string{"state": "running", "ssm_managed": "true"},
			unknown:   map[string]string{"state": "running", "package_inventory_gap": "ssm_access_denied"},
		},
		// ── AWS compute / network / containers / databases (round A) ──
		{
			name: "aws-ec2-stopped-long", check: awsEC2StoppedLong,
			violating: map[string]string{"state": "stopped", "stopped_at": "2020-01-01T00:00:00Z"},
			compliant: map[string]string{"state": "stopped", "stopped_at": "2999-01-01T00:00:00Z"},
			// No parseable stop time in StateTransitionReason: age unknown.
			unknown: map[string]string{"state": "stopped"},
		},
		{
			name: "aws-ec2-multiple-enis", check: awsEC2MultipleENIs,
			violating: map[string]string{"eni_count": "2"},
			compliant: map[string]string{"eni_count": "1"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ec2-paravirtual", check: awsEC2Paravirtual,
			violating: map[string]string{"virtualization_type": "paravirtual"},
			compliant: map[string]string{"virtualization_type": "hvm"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-no-multi-az", check: awsRDSNoMultiAZ,
			violating: map[string]string{"multi_az": "false", "db_cluster_id": "", "engine": "mysql"},
			compliant: map[string]string{"multi_az": "true", "db_cluster_id": "", "engine": "mysql"},
			unknown:   map[string]string{"multi_az": "false", "engine": "mysql"},
		},
		{
			name: "aws-rds-no-deletion-protection", check: awsRDSNoDeletionProtection,
			violating: map[string]string{"deletion_protection": "false", "db_cluster_id": ""},
			compliant: map[string]string{"deletion_protection": "true", "db_cluster_id": ""},
			unknown:   map[string]string{"deletion_protection": "false"},
		},
		{
			name: "aws-rds-snapshot-unencrypted", check: awsRDSSnapshotUnencrypted,
			violating: map[string]string{"encrypted": "false"},
			compliant: map[string]string{"encrypted": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-no-enhanced-monitoring", check: awsRDSNoEnhancedMonitoring,
			violating: map[string]string{"monitoring_interval": "0"},
			compliant: map[string]string{"monitoring_interval": "60"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-no-log-exports", check: awsRDSNoLogExports,
			violating: map[string]string{"engine": "postgres", "db_cluster_id": "", "log_exports": ""},
			compliant: map[string]string{"engine": "postgres", "db_cluster_id": "", "log_exports": "postgresql,upgrade"},
			unknown:   map[string]string{"engine": "postgres", "db_cluster_id": ""},
		},
		{
			name: "aws-rds-no-iam-auth", check: awsRDSNoIAMAuth,
			violating: map[string]string{"engine": "postgres", "db_cluster_id": "", "iam_auth_enabled": "false"},
			compliant: map[string]string{"engine": "postgres", "db_cluster_id": "", "iam_auth_enabled": "true"},
			unknown:   map[string]string{"engine": "postgres", "db_cluster_id": ""},
		},
		{
			name: "aws-rds-auto-minor-upgrade-disabled", check: awsRDSAutoMinorUpgradeDisabled,
			violating: map[string]string{"auto_minor_version_upgrade": "false"},
			compliant: map[string]string{"auto_minor_version_upgrade": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-no-copy-tags-to-snapshot", check: awsRDSNoCopyTagsToSnapshot,
			violating: map[string]string{"copy_tags_to_snapshot": "false", "db_cluster_id": ""},
			compliant: map[string]string{"copy_tags_to_snapshot": "true", "db_cluster_id": ""},
			unknown:   map[string]string{"db_cluster_id": ""},
		},
		{
			name: "aws-rds-engine-default-port", check: awsRDSEngineDefaultPort,
			violating: map[string]string{"engine": "mysql", "port": "3306", "publicly_accessible": "false", "db_cluster_id": ""},
			compliant: map[string]string{"engine": "mysql", "port": "3307", "publicly_accessible": "false", "db_cluster_id": ""},
			unknown:   map[string]string{"engine": "mysql", "publicly_accessible": "false", "db_cluster_id": ""},
		},
		{
			name: "aws-elb-single-az", check: awsELBSingleAZ,
			violating: map[string]string{"availability_zone_count": "1"},
			compliant: map[string]string{"availability_zone_count": "2"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-lambda-single-az", check: awsLambdaSingleAZ,
			violating: map[string]string{"vpc_az_count": "1"},
			compliant: map[string]string{"vpc_az_count": "3"},
			// A subnet the sweep did not collect: zone count unknown.
			unknown: map[string]string{"subnet_ids": "subnet-a"},
		},
		{
			name: "aws-ecr-scanning-disabled", check: awsECRScanningDisabled,
			violating: map[string]string{"scan_on_push": "false", "registry_scan_type": "BASIC", "registry_scan_rule": "none"},
			compliant: map[string]string{"scan_on_push": "false", "registry_scan_type": "BASIC", "registry_scan_rule": "SCAN_ON_PUSH"},
			// Registry configuration unreadable: coverage unknown.
			unknown: map[string]string{"scan_on_push": "false"},
		},
		{
			name: "aws-eks-public-endpoint", check: awsEKSPublicEndpoint,
			violating: map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "0.0.0.0/0"},
			compliant: map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "203.0.113.0/24"},
			unknown:   map[string]string{"endpoint_public_access": "true"},
		},
		{
			name: "aws-eks-secrets-not-encrypted", check: awsEKSSecretsNotEncrypted,
			violating: map[string]string{"secrets_encryption": "false"},
			compliant: map[string]string{"secrets_encryption": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-eks-audit-logging-disabled", check: awsEKSAuditLoggingDisabled,
			violating: map[string]string{"audit_logging": "false"},
			compliant: map[string]string{"audit_logging": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-eks-auth-configmap-only", check: awsEKSAuthConfigMapOnly,
			violating: map[string]string{"authentication_mode": "CONFIG_MAP"},
			compliant: map[string]string{"authentication_mode": "API"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-eks-unsupported-version", check: awsEKSUnsupportedVersion,
			violating: map[string]string{"version": "1.24"},
			compliant: map[string]string{"version": "1.37"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-lambda-deprecated-runtime", check: awsLambdaDeprecatedRuntime,
			violating: map[string]string{"runtime": "python3.8"},
			compliant: map[string]string{"runtime": "python3.13"},
			// Container-image functions report no runtime.
			unknown: map[string]string{"runtime": ""},
		},
		{
			name: "aws-ecs-container-privileged", check: awsECSContainerPrivileged,
			violating: map[string]string{"privileged": "true"},
			compliant: map[string]string{"privileged": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-container-writable-root-fs", check: awsECSContainerWritableRootFS,
			violating: map[string]string{"readonly_root_fs": "false"},
			compliant: map[string]string{"readonly_root_fs": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-container-plaintext-secret-env", check: awsECSContainerPlaintextSecretEnv,
			violating: map[string]string{"plaintext_secret_env": "AWS_SECRET_ACCESS_KEY"},
			compliant: map[string]string{"plaintext_secret_env": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-container-no-logging", check: awsECSContainerNoLogging,
			violating: map[string]string{"log_driver": ""},
			compliant: map[string]string{"log_driver": "awslogs"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-container-runs-as-root", check: awsECSContainerRunsAsRoot,
			violating: map[string]string{"user": "root"},
			compliant: map[string]string{"user": "1000"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-task-shares-host-namespace", check: awsECSTaskSharesHostNamespace,
			violating: map[string]string{"pid_mode": "host", "network_mode": "awsvpc"},
			compliant: map[string]string{"pid_mode": "", "network_mode": "awsvpc"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-task-efs-no-transit-encryption", check: awsECSTaskEFSNoTransitEncryption,
			violating: map[string]string{"efs_volumes_plaintext": "shared"},
			compliant: map[string]string{"efs_volumes_plaintext": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ecs-fargate-old-platform", check: awsECSFargateOldPlatform,
			violating: map[string]string{"launch_type": "FARGATE", "platform_version": "1.3.0"},
			compliant: map[string]string{"launch_type": "FARGATE", "platform_version": "LATEST"},
			unknown:   map[string]string{"launch_type": "FARGATE"},
		},
		{
			name: "aws-ecs-cluster-no-container-insights", check: awsECSClusterNoContainerInsights,
			violating: map[string]string{"container_insights": "disabled"},
			compliant: map[string]string{"container_insights": "enhanced"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-default-master-username", check: awsRDSDefaultMasterUsername,
			violating: map[string]string{"master_username": "postgres", "db_cluster_id": ""},
			compliant: map[string]string{"master_username": "app_owner", "db_cluster_id": ""},
			unknown:   map[string]string{"db_cluster_id": ""},
		},
		{
			name: "k8s-host-pid-pod", check: k8sHostPIDPod,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "host_pid": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "host_pid": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-host-ipc-pod", check: k8sHostIPCPod,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "host_ipc": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "host_ipc": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-pod-host-path-volume", check: k8sHostPathVolume,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "host_path_volumes": "/var/run/docker.sock"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "host_path_volumes": ""},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-container-host-port", check: k8sContainerHostPort,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "host_network": "false", "host_ports": "8080"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "host_network": "false", "host_ports": ""},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running", "host_ports": "8080"},
		},
		{
			name: "k8s-windows-host-process", check: k8sWindowsHostProcess,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "windows_host_process": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "windows_host_process": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			// The step-aside reads dangerous_capabilities as an OBSERVED empty: an
			// absent key must not read as "no dangerous capability" either.
			name: "k8s-container-added-capabilities", check: k8sContainerAddedCapabilities,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "added_capabilities": "NET_BIND_SERVICE", "dangerous_capabilities": ""},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "added_capabilities": "", "dangerous_capabilities": ""},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running", "added_capabilities": "NET_BIND_SERVICE"},
		},
		{
			name: "k8s-container-net-raw", check: k8sContainerNetRaw,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "net_raw_retained": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "net_raw_retained": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-pod-seccomp-unrestricted", check: k8sPodSeccompUnrestricted,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "seccomp_unrestricted": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "seccomp_unrestricted": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-pod-apparmor-unconfined", check: k8sPodAppArmorUnconfined,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "apparmor_unconfined": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "apparmor_unconfined": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-container-writable-root-fs", check: k8sContainerWritableRootFS,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "writable_root_fs": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "writable_root_fs": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-container-allow-privilege-escalation", check: k8sContainerAllowPrivilegeEscalation,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "allow_priv_escalation": "true"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "allow_priv_escalation": "false"},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-container-runs-as-root", check: k8sPodRunsAsRoot,
			violating: map[string]string{"phase": "Running", "run_as_root": "true"},
			compliant: map[string]string{"phase": "Running", "run_as_root": "false", "allow_priv_escalation": "true"},
			unknown:   map[string]string{"phase": "Running"},
		},
		{
			name: "k8s-pod-secret-in-env", check: k8sPodSecretInEnv,
			violating: map[string]string{"namespace": "billing", "phase": "Running", "secret_env_refs": "db-credentials"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running", "secret_env_refs": ""},
			unknown:   map[string]string{"namespace": "billing", "phase": "Running"},
		},
		{
			name: "k8s-workload-default-namespace", check: k8sWorkloadDefaultNamespace,
			violating: map[string]string{"namespace": "default", "phase": "Running"},
			compliant: map[string]string{"namespace": "billing", "phase": "Running"},
			unknown:   map[string]string{"phase": "Running"},
		},
		{
			// automount_sa_token is absent when the pod leaves it to a ServiceAccount
			// whose namespace's SA list failed.
			name: "k8s-automount-sa-token", check: k8sPodAutomountSAToken,
			violating: map[string]string{"phase": "Running", "service_account": "default", "automount_sa_token_set_on_pod": "true", "automount_sa_token": "true"},
			compliant: map[string]string{"phase": "Running", "service_account": "default", "automount_sa_token_set_on_pod": "true", "automount_sa_token": "false"},
			unknown:   map[string]string{"phase": "Running", "service_account": "api", "automount_sa_token_set_on_pod": "false"},
		},
		{
			name: "k8s-namespace-no-pod-security-enforcement", check: k8sNamespaceNoPodSecurityEnforcement,
			violating: map[string]string{"phase": "Active", "psa_enforce": ""},
			compliant: map[string]string{"phase": "Active", "psa_enforce": "baseline"},
			unknown:   map[string]string{"phase": "Active"},
		},
		{
			name: "k8s-namespace-no-default-deny", check: k8sNamespaceNoDefaultDeny,
			violating: map[string]string{"phase": "Active", "has_network_policy": "true", "has_default_deny_ingress": "false"},
			compliant: map[string]string{"phase": "Active", "has_network_policy": "true", "has_default_deny_ingress": "true"},
			unknown:   map[string]string{"phase": "Active", "has_network_policy": "true"},
		},
		{
			name: "k8s-cluster-admin-binding", check: k8sClusterAdminBinding,
			violating: map[string]string{"role_ref": "cluster-admin", "platform_managed": "false", "platform_cluster_admin": "false"},
			compliant: map[string]string{"role_ref": "cluster-admin", "platform_managed": "true", "platform_cluster_admin": "false"},
			unknown:   map[string]string{"role_ref": "cluster-admin"},
		},
		{
			name: "k8s-clusterrolebinding-admin-edit", check: k8sClusterRoleBindingAdminEdit,
			violating: map[string]string{"role_ref": "edit", "platform_managed": "false"},
			compliant: map[string]string{"role_ref": "view", "platform_managed": "false"},
			unknown:   map[string]string{"role_ref": "edit"},
		},
		{
			name: "aws-iam-group-full-admin", check: awsIAMGroupFullAdmin,
			violating: map[string]string{"admin": "true", "full_admin_customer_policy_only": "false"},
			compliant: map[string]string{"admin": "false"},
			// admin is written only from a complete policy set (or an observed
			// grant); an unread group policy is unknown.
			unknown: map[string]string{"member_count": "3"},
		},
		{
			name: "aws-iam-group-cloudshell-full-access", check: awsIAMGroupCloudShellFullAccess,
			violating: map[string]string{"cloudshell_full_access": "true", "admin": "false"},
			compliant: map[string]string{"cloudshell_full_access": "false", "admin": "false"},
			unknown:   map[string]string{"admin": "false"},
		},
		{
			name: "aws-iam-group-inline-kms-decrypt-all", check: awsIAMGroupInlineKMSDecryptAll,
			violating: map[string]string{"inline_kms_decrypt_all": "true", "admin": "false"},
			compliant: map[string]string{"inline_kms_decrypt_all": "false", "admin": "false"},
			unknown:   map[string]string{"admin": "false"},
		},
		{
			name: "aws-iam-server-certificate-expired", check: awsIAMServerCertificateExpired,
			violating: map[string]string{"expiration": "2020-01-01T00:00:00Z"},
			compliant: map[string]string{"expiration": "2999-01-01T00:00:00Z"},
			unknown:   map[string]string{"path": "/"},
		},
		{
			name: "aws-iam-no-support-role", check: awsIAMNoSupportRole,
			violating: map[string]string{"support_role_count": "0"},
			compliant: map[string]string{"support_role_count": "1"},
			// iam:ListEntitiesForPolicy failed: unknown, not "no role".
			unknown: map[string]string{"password_policy": "true"},
		},
		{
			name: "aws-org-root-access-not-centralized", check: awsOrgRootAccessNotCentralized,
			violating: map[string]string{"root_credentials_management": "true", "root_sessions": "false"},
			compliant: map[string]string{"root_credentials_management": "true", "root_sessions": "true"},
			// Read from an account that is neither the management account nor
			// IAM's delegated admin: unknown.
			unknown: map[string]string{"organization_id": "o-1"},
		},
		{
			name: "aws-org-policy-management-not-delegated", check: awsOrgPolicyManagementNotDelegated,
			violating: map[string]string{"policy_management_delegated": "false"},
			compliant: map[string]string{"policy_management_delegated": "true"},
			unknown:   map[string]string{"organization_id": "o-1"},
		},
		{
			name: "aws-org-security-services-not-delegated", check: awsOrgSecurityServicesNotDelegated,
			violating: map[string]string{"undelegated_security_services": "guardduty.amazonaws.com"},
			compliant: map[string]string{"undelegated_security_services": ""},
			unknown:   map[string]string{"organization_id": "o-1"},
		},
		{
			name: "aws-org-guardrail-policy-type-disabled", check: awsOrgGuardrailPolicyTypeDisabled,
			violating: map[string]string{"scp_enabled": "true", "rcp_enabled": "false"},
			compliant: map[string]string{"scp_enabled": "true", "rcp_enabled": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-org-account-no-scp-guardrail", check: awsOrgAccountNoSCPGuardrail,
			violating: map[string]string{"scp_guardrail": "false", "scp_enabled": "true"},
			compliant: map[string]string{"scp_guardrail": "true", "scp_enabled": "true"},
			// The parent walk failed: unknown, not "only FullAWSAccess".
			unknown: map[string]string{"scp_enabled": "true"},
		},
		{
			name: "aws-org-account-no-rcp-guardrail", check: awsOrgAccountNoRCPGuardrail,
			violating: map[string]string{"rcp_guardrail": "false", "rcp_enabled": "true"},
			compliant: map[string]string{"rcp_guardrail": "true", "rcp_enabled": "true"},
			unknown:   map[string]string{"rcp_enabled": "true"},
		},
		{
			name: "aws-iam-user-credential-unused-45d", check: awsIAMUserCredentialUnused45d,
			violating: map[string]string{"active_key_count": "1", "access_key_max_idle_days": "60"},
			compliant: map[string]string{"active_key_count": "1", "access_key_max_idle_days": "3"},
			// A failed GetAccessKeyLastUsed leaves the idle time unknown.
			unknown: map[string]string{"active_key_count": "1"},
		},
		{
			name: "aws-sagemaker-notebook-not-in-custom-vpc", check: awsSageMakerNotebookNoVPC,
			// subnet_id is written only from a successful describe; an
			// unjoined subnet leaves in_default_vpc absent.
			violating: map[string]string{"subnet_id": ""},
			compliant: map[string]string{"subnet_id": "subnet-1", "in_default_vpc": "false"},
			unknown:   map[string]string{"subnet_id": "subnet-1"},
		},
		{
			name: "aws-sagemaker-notebook-direct-internet-access", check: awsSageMakerNotebookDirectInternet,
			violating: map[string]string{"direct_internet_access": "true", "subnet_id": "subnet-1"},
			compliant: map[string]string{"direct_internet_access": "false", "subnet_id": "subnet-1"},
			unknown:   map[string]string{"subnet_id": "subnet-1"},
		},
		{
			name: "aws-sagemaker-notebook-root-access", check: awsSageMakerNotebookRootAccess,
			violating: map[string]string{"root_access": "true"},
			compliant: map[string]string{"root_access": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-sagemaker-notebook-unsupported-platform", check: awsSageMakerNotebookUnsupportedPlatform,
			violating: map[string]string{"platform_identifier": "notebook-al2-v2"},
			compliant: map[string]string{"platform_identifier": "notebook-al2023-v1"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-sagemaker-endpoint-single-instance", check: awsSageMakerEndpointSingleInstance,
			violating: map[string]string{"single_instance_variants": "AllTraffic"},
			compliant: map[string]string{"single_instance_variants": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-sagemaker-model-no-network-isolation", check: awsSageMakerModelNoNetworkIsolation,
			violating: map[string]string{"network_isolation": "false"},
			compliant: map[string]string{"network_isolation": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-sagemaker-model-primary-image-not-vpc-registry", check: awsSageMakerModelPrimaryImageNotVPC,
			// "" is an observed primary container with no ImageConfig.
			violating: map[string]string{"primary_image_access_mode": ""},
			compliant: map[string]string{"primary_image_access_mode": "Vpc"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-sagemaker-model-pipeline-image-not-vpc-registry", check: awsSageMakerModelPipelineImageNotVPC,
			violating: map[string]string{"pipeline_containers_not_vpc_registry": "container-2"},
			compliant: map[string]string{"pipeline_containers_not_vpc_registry": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-sagemaker-monitoring-job-no-network-isolation", check: awsSageMakerMonitoringJobNoNetworkIsolation,
			violating: map[string]string{"job_type": "data_quality", "network_isolation": "false"},
			compliant: map[string]string{"job_type": "data_quality", "network_isolation": "true"},
			unknown:   map[string]string{"job_type": "data_quality"},
		},
		{
			name: "aws-sagemaker-monitoring-job-no-inter-container-encryption", check: awsSageMakerMonitoringJobNoEncryption,
			violating: map[string]string{"job_type": "model_bias", "inter_container_encryption": "false", "instance_count": "2"},
			compliant: map[string]string{"job_type": "model_bias", "inter_container_encryption": "true", "instance_count": "2"},
			// A model-bias definition whose instance count was not read is not graded.
			unknown: map[string]string{"job_type": "model_bias", "inter_container_encryption": "false"},
		},
		{
			name: "aws-sagemaker-monitoring-schedule-no-network-isolation", check: awsSageMakerMonitoringScheduleNoNetworkIsolation,
			violating: map[string]string{"job_definition_inline": "true", "network_isolation": "false"},
			compliant: map[string]string{"job_definition_inline": "true", "network_isolation": "true"},
			unknown:   map[string]string{"job_definition_inline": "true"},
		},
		{
			name: "aws-sagemaker-feature-group-offline-store-no-kms", check: awsSageMakerFeatureGroupOfflineNoKMS,
			violating: map[string]string{"offline_store": "true", "offline_store_kms_key": ""},
			compliant: map[string]string{"offline_store": "true", "offline_store_kms_key": "arn:aws:kms:eu-west-1:1:key/k"},
			unknown:   map[string]string{"offline_store": "true"},
		},
		{
			name: "aws-sagemaker-monitoring-schedule-no-inter-container-encryption", check: awsSageMakerMonitoringScheduleNoEncryption,
			violating: map[string]string{"job_definition_inline": "true", "inter_container_encryption": "false"},
			compliant: map[string]string{"job_definition_inline": "true", "inter_container_encryption": "true"},
			unknown:   map[string]string{"job_definition_inline": "true"},
		},
		{
			name: "aws-sagemaker-notebook-no-customer-managed-key", check: awsSageMakerNotebookNoCMK,
			violating: map[string]string{"kms_key_id": "", "status": "InService"},
			compliant: map[string]string{"kms_key_id": "arn:aws:kms:eu-west-1:1:key/k", "status": "InService"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-rds-postgres-tls-not-enforced", check: awsRDSPostgresTLSNotEnforced,
			violating: map[string]string{"engine": "postgres", "db_cluster_id": "", "force_ssl": "0"},
			compliant: map[string]string{"engine": "postgres", "db_cluster_id": "", "force_ssl": "1"},
			// An unset rds.force_ssl is version-dependent and left absent.
			unknown: map[string]string{"engine": "postgres", "db_cluster_id": ""},
		},
		{
			name: "aws-rds-mysql-tls-not-enforced", check: awsRDSMySQLTLSNotEnforced,
			violating: map[string]string{"engine": "mysql", "db_cluster_id": "", "require_secure_transport": "OFF"},
			compliant: map[string]string{"engine": "mysql", "db_cluster_id": "", "require_secure_transport": "ON"},
			unknown:   map[string]string{"engine": "mysql", "db_cluster_id": ""},
		},
		{
			name: "aws-agentcore-gateway-no-inbound-auth", check: awsAgentCoreGatewayNoInboundAuth,
			violating: map[string]string{"authorizer_type": "NONE"},
			compliant: map[string]string{"authorizer_type": "CUSTOM_JWT"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-agentcore-runtime-public-network", check: awsAgentCoreRuntimePublicNetwork,
			violating: map[string]string{"network_mode": "PUBLIC", "capacity_provider": "false"},
			compliant: map[string]string{"network_mode": "VPC", "capacity_provider": "false"},
			// A runtime whose describe failed carries neither key.
			unknown: map[string]string{"network_mode": "PUBLIC"},
		},
		{
			name: "aws-agentcore-browser-public-network", check: awsAgentCoreBrowserPublicNetwork,
			violating: map[string]string{"network_mode": "PUBLIC"},
			compliant: map[string]string{"network_mode": "VPC"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-agentcore-browser-no-session-recording", check: awsAgentCoreBrowserNoRecording,
			violating: map[string]string{"recording_enabled": "false", "recording_s3_location": "false"},
			compliant: map[string]string{"recording_enabled": "true", "recording_s3_location": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-workspaces-user-volume-unencrypted", check: awsWorkSpacesUserVolumeUnencrypted,
			violating: map[string]string{"user_volume_encrypted": "false"},
			compliant: map[string]string{"user_volume_encrypted": "true"},
			unknown:   map[string]string{"root_volume_encrypted": "false"},
		},
		{
			name: "aws-workspaces-root-volume-unencrypted", check: awsWorkSpacesRootVolumeUnencrypted,
			violating: map[string]string{"root_volume_encrypted": "false"},
			compliant: map[string]string{"root_volume_encrypted": "true"},
			unknown:   map[string]string{"user_volume_encrypted": "false"},
		},
		{
			name: "aws-transfer-server-ftp-enabled", check: awsTransferServerFTPEnabled,
			violating: map[string]string{"ftp_enabled": "true"},
			compliant: map[string]string{"ftp_enabled": "false"},
			unknown:   map[string]string{"endpoint_type": "VPC"},
		},
		{
			name: "aws-transfer-connector-no-logging", check: awsTransferConnectorNoLogging,
			violating: map[string]string{"logging_role": ""},
			compliant: map[string]string{"logging_role": "arn:aws:iam::1:role/log"},
			unknown:   map[string]string{"url": "sftp://partner"},
		},
		{
			name: "aws-cfn-stack-no-termination-protection", check: awsCFNStackNoTerminationProtection,
			violating: map[string]string{"nested": "false", "termination_protection": "false"},
			compliant: map[string]string{"nested": "false", "termination_protection": "true"},
			unknown:   map[string]string{"nested": "false"},
		},
		{
			name: "aws-cfn-stack-no-service-role", check: awsCFNStackNoServiceRole,
			violating: map[string]string{"nested": "false", "role_arn": ""},
			compliant: map[string]string{"nested": "false", "role_arn": "arn:aws:iam::1:role/cfn"},
			unknown:   map[string]string{"nested": "false"},
		},
		{
			name: "aws-stepfunctions-logging-disabled", check: awsStepFunctionsLoggingDisabled,
			violating: map[string]string{"log_level": "OFF"},
			compliant: map[string]string{"log_level": "ERROR"},
			unknown:   map[string]string{"workflow_type": "STANDARD"},
		},
		{
			name: "aws-eventbridge-bus-no-policy", check: awsEventBridgeBusNoPolicy,
			violating: map[string]string{"bus_kind": "custom", "has_resource_policy": "false"},
			compliant: map[string]string{"bus_kind": "custom", "has_resource_policy": "true"},
			unknown:   map[string]string{"bus_kind": "custom"},
		},
		{
			name: "aws-eventbridge-bus-policy-public", check: awsEventBridgeBusPolicyPublic,
			violating: map[string]string{"public_access": asset.PublicAccessConfirmed},
			compliant: map[string]string{"public_access": asset.PublicAccessNone},
			unknown:   map[string]string{"bus_kind": "custom"},
		},
		{
			name: "aws-mq-audit-logs-disabled", check: awsMQAuditLogsDisabled,
			violating: map[string]string{"engine_type": "ACTIVEMQ", "audit_logs": "false"},
			compliant: map[string]string{"engine_type": "ACTIVEMQ", "audit_logs": "true"},
			unknown:   map[string]string{"engine_type": "ACTIVEMQ"},
		},
		{
			name: "aws-ses-tls-not-required", check: awsSESTLSNotRequired,
			violating: map[string]string{"tls_policy": "OPTIONAL"},
			compliant: map[string]string{"tls_policy": "REQUIRE"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-servicecatalog-portfolio-account-share", check: awsServiceCatalogPortfolioAccountShare,
			violating: map[string]string{"account_shares": "222222222222"},
			compliant: map[string]string{"account_shares": ""},
			unknown:   map[string]string{"portfolio_id": "port-1"},
		},
		{
			name: "aws-connect-flow-logs-disabled", check: awsConnectFlowLogsDisabled,
			violating: map[string]string{"contact_flow_logs": "false"},
			compliant: map[string]string{"contact_flow_logs": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-datasync-task-logging-disabled", check: awsDataSyncTaskLoggingDisabled,
			violating: map[string]string{"log_group": "", "task_mode": "BASIC"},
			compliant: map[string]string{"log_group": "arn:aws:logs:us-east-1:1:log-group:/ds", "task_mode": "BASIC", "log_level": "BASIC"},
			unknown:   map[string]string{"status": "AVAILABLE"},
		},
		{
			name: "aws-pca-root-ca-active", check: awsPCARootCAActive,
			violating: map[string]string{"ca_type": "ROOT", "ca_status": "ACTIVE"},
			compliant: map[string]string{"ca_type": "ROOT", "ca_status": "DISABLED"},
			unknown:   map[string]string{"ca_type": "ROOT"},
		},
		{
			name: "aws-codebuild-source-url-credentials", check: awsCodeBuildSourceURLCredentials,
			violating: map[string]string{"source_url_credentials": "primary"},
			compliant: map[string]string{"source_url_credentials": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-codebuild-plaintext-aws-credentials", check: awsCodeBuildPlaintextAWSCredentials,
			violating: map[string]string{"plaintext_aws_credential_env": "AWS_SECRET_ACCESS_KEY"},
			compliant: map[string]string{"plaintext_aws_credential_env": ""},
			// No environment block read: no variables were observed.
			unknown: map[string]string{"source_url_credentials": ""},
		},
		{
			name: "aws-codebuild-s3-logs-unencrypted", check: awsCodeBuildS3LogsUnencrypted,
			violating: map[string]string{"s3_logs_status": "ENABLED", "s3_logs_encryption_disabled": "true"},
			compliant: map[string]string{"s3_logs_status": "ENABLED", "s3_logs_encryption_disabled": "false"},
			unknown:   map[string]string{"s3_logs_status": "ENABLED"},
		},
		{
			name: "aws-codebuild-logging-disabled", check: awsCodeBuildLoggingDisabled,
			violating: map[string]string{"cloudwatch_logs_status": "DISABLED", "s3_logs_status": "DISABLED"},
			compliant: map[string]string{"cloudwatch_logs_status": "ENABLED", "s3_logs_status": "DISABLED"},
			// S3 logging unread: it might be the one sink that is on.
			unknown: map[string]string{"cloudwatch_logs_status": "DISABLED"},
		},
		{
			name: "aws-codebuild-report-export-unencrypted", check: awsCodeBuildReportExportUnencrypted,
			violating: map[string]string{"export_type": "S3", "export_encryption_disabled": "true"},
			compliant: map[string]string{"export_type": "S3", "export_encryption_disabled": "false"},
			unknown:   map[string]string{"export_type": "S3"},
		},
		{
			name: "aws-cognito-identity-pool-guest-access", check: awsCognitoIdentityPoolGuestAccess,
			violating: map[string]string{"allow_unauthenticated_identities": "true"},
			compliant: map[string]string{"allow_unauthenticated_identities": "false"},
			unknown:   map[string]string{"identity_pool_id": "eu-west-1:x"},
		},
		{
			name: "aws-cognito-weak-password-policy", check: awsCognitoWeakPasswordPolicy,
			violating: map[string]string{"password_min_length": "6", "password_require_uppercase": "true", "password_require_lowercase": "true", "password_require_numbers": "true", "password_require_symbols": "true", "temporary_password_validity_days": "7"},
			compliant: map[string]string{"password_min_length": "8", "password_require_uppercase": "true", "password_require_lowercase": "true", "password_require_numbers": "true", "password_require_symbols": "true", "temporary_password_validity_days": "7"},
			unknown:   map[string]string{"user_pool_id": "eu-west-1_x"},
		},
		{
			name: "aws-cognito-user-pool-no-mfa", check: awsCognitoUserPoolNoMFA,
			violating: map[string]string{"mfa_configuration": "OFF", "password_only_sign_in": "true"},
			compliant: map[string]string{"mfa_configuration": "OPTIONAL", "password_only_sign_in": "true"},
			// Sign-in policy unread: the pool may offer a passwordless factor.
			unknown: map[string]string{"mfa_configuration": "OFF"},
		},
		{
			name: "aws-cognito-threat-protection-not-enforced", check: awsCognitoThreatProtectionNotEnforced,
			violating: map[string]string{"threat_protection_mode": "ENFORCED", "threat_protection_custom_auth_mode": "AUDIT"},
			compliant: map[string]string{"threat_protection_mode": "ENFORCED", "threat_protection_custom_auth_mode": "ENFORCED"},
			unknown:   map[string]string{"user_pool_id": "eu-west-1_x"},
		},
		{
			name: "aws-cognito-no-deletion-protection", check: awsCognitoNoDeletionProtection,
			violating: map[string]string{"deletion_protection": "INACTIVE"},
			compliant: map[string]string{"deletion_protection": "ACTIVE"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-emr-primary-public-ip", check: awsEMRPrimaryPublicIP,
			violating: map[string]string{"state": "RUNNING", "primary_public_ips": "3.3.3.3"},
			compliant: map[string]string{"state": "RUNNING", "primary_public_ips": ""},
			unknown:   map[string]string{"state": "WAITING"},
		},
		{
			name: "aws-emr-block-public-access-off", check: awsEMRBlockPublicAccessOff,
			violating: map[string]string{"block_public_security_group_rules": "false", "permitted_public_ports": "22"},
			compliant: map[string]string{"block_public_security_group_rules": "true", "permitted_public_ports": "22"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-emr-security-config-no-at-rest-encryption", check: awsEMRSecurityConfigNoAtRestEncryption,
			violating: map[string]string{"at_rest_encryption": "false"},
			compliant: map[string]string{"at_rest_encryption": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-emr-security-config-no-in-transit-encryption", check: awsEMRSecurityConfigNoInTransitEncryption,
			violating: map[string]string{"in_transit_encryption": "false"},
			compliant: map[string]string{"in_transit_encryption": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-appsync-cache-not-encrypted-at-rest", check: awsAppSyncCacheNotEncryptedAtRest,
			violating: map[string]string{"api_cache": "true", "cache_at_rest_encryption": "false"},
			compliant: map[string]string{"api_cache": "true", "cache_at_rest_encryption": "true"},
			unknown:   map[string]string{"api_id": "a"},
		},
		{
			name: "aws-appsync-cache-not-encrypted-in-transit", check: awsAppSyncCacheNotEncryptedInTransit,
			violating: map[string]string{"api_cache": "true", "cache_transit_encryption": "false"},
			compliant: map[string]string{"api_cache": "false"},
			unknown:   map[string]string{"api_id": "a"},
		},
		{
			name: "aws-appsync-field-logging-disabled", check: awsAppSyncFieldLoggingDisabled,
			violating: map[string]string{"field_log_level": "NONE"},
			compliant: map[string]string{"field_log_level": "ERROR"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-appsync-api-key-auth", check: awsAppSyncAPIKeyAuth,
			violating: map[string]string{"authentication_types": "AWS_IAM,API_KEY"},
			compliant: map[string]string{"authentication_types": "AMAZON_COGNITO_USER_POOLS"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-beanstalk-basic-health-reporting", check: awsBeanstalkBasicHealthReporting,
			violating: map[string]string{"health_reporting": "basic"},
			compliant: map[string]string{"health_reporting": "enhanced"},
			unknown:   map[string]string{"application": "app"},
		},
		{
			name: "aws-beanstalk-managed-updates-disabled", check: awsBeanstalkManagedUpdatesDisabled,
			violating: map[string]string{"managed_actions_enabled": "false"},
			compliant: map[string]string{"managed_actions_enabled": "true"},
			unknown:   map[string]string{"application": "app"},
		},
		{
			name: "aws-beanstalk-log-streaming-disabled", check: awsBeanstalkLogStreamingDisabled,
			violating: map[string]string{"stream_logs": "false"},
			compliant: map[string]string{"stream_logs": "true"},
			unknown:   map[string]string{"application": "app"},
		},
		{
			name: "aws-ecs-task-definition-privileged", check: awsECSTaskDefPrivileged,
			violating: map[string]string{"privileged_containers": "job"},
			compliant: map[string]string{"privileged_containers": ""},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-definition-writable-root-fs", check: awsECSTaskDefWritableRootFS,
			violating: map[string]string{"writable_root_fs_containers": "job"},
			compliant: map[string]string{"writable_root_fs_containers": ""},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-definition-plaintext-secret-env", check: awsECSTaskDefPlaintextSecretEnv,
			violating: map[string]string{"plaintext_secret_env": "DB_PASSWORD"},
			compliant: map[string]string{"plaintext_secret_env": ""},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-definition-no-logging", check: awsECSTaskDefNoLogging,
			violating: map[string]string{"no_log_containers": "job"},
			compliant: map[string]string{"no_log_containers": ""},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-definition-runs-as-root", check: awsECSTaskDefRunsAsRoot,
			violating: map[string]string{"root_user_containers": "", "unset_user_containers": "job"},
			compliant: map[string]string{"root_user_containers": "", "unset_user_containers": ""},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-definition-shares-host-namespace", check: awsECSTaskDefSharesHostNamespace,
			violating: map[string]string{"pid_mode": "host", "network_mode": "awsvpc"},
			compliant: map[string]string{"pid_mode": "", "network_mode": "awsvpc"},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-definition-efs-no-transit-encryption", check: awsECSTaskDefEFSNoTransitEncryption,
			violating: map[string]string{"efs_volumes_plaintext": "shared"},
			compliant: map[string]string{"efs_volumes_plaintext": ""},
			unknown:   map[string]string{"family": "batch"},
		},
		{
			name: "aws-ecs-task-set-public-ip", check: awsECSTaskSetPublicIP,
			violating: map[string]string{"task_sets_public_ip": "ecs-svc/2", "assign_public_ip": ""},
			compliant: map[string]string{"task_sets_public_ip": "", "assign_public_ip": ""},
			unknown:   map[string]string{"assign_public_ip": ""},
		},
		{
			name: "aws-ecs-capacity-provider-no-termination-protection", check: awsECSCapacityProviderNoTerminationProtection,
			violating: map[string]string{"managed_termination_protection": "DISABLED"},
			compliant: map[string]string{"managed_termination_protection": "ENABLED"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-eks-public-endpoint-restricted", check: awsEKSPublicEndpointRestricted,
			violating: map[string]string{"endpoint_public_access": "true", "public_access_cidrs": "203.0.113.0/24"},
			compliant: map[string]string{"endpoint_public_access": "false", "public_access_cidrs": "203.0.113.0/24"},
			// A public endpoint whose allowlist came back empty is unknown.
			unknown: map[string]string{"endpoint_public_access": "true"},
		},
		{
			name: "aws-eks-nodegroup-unsupported-version", check: awsEKSNodegroupUnsupportedVersion,
			violating: map[string]string{"version": "1.20", "cluster_version": "1.37"},
			compliant: map[string]string{"version": "1.37", "cluster_version": "1.37"},
			unknown:   map[string]string{"cluster_version": "1.37"},
		},
		{
			name: "aws-ecr-no-lifecycle-policy", check: awsECRNoLifecyclePolicy,
			violating: map[string]string{"lifecycle_policy": "false"},
			compliant: map[string]string{"lifecycle_policy": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-nacl-world-open-admin-port", check: awsNACLWorldOpenAdminPort,
			violating: map[string]string{"subnet_association_count": "1",
				"ingress_entries": `[{"rule_number":100,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}]`},
			compliant: map[string]string{"subnet_association_count": "1",
				"ingress_entries": `[{"rule_number":100,"protocol":"6","action":"allow","cidr":"0.0.0.0/0","from_port":443,"to_port":443}]`},
			// Entries read but the association count not (and vice versa).
			unknown: map[string]string{"ingress_entries": `[{"rule_number":100,"protocol":"-1","action":"allow","cidr":"0.0.0.0/0","from_port":0,"to_port":65535}]`},
		},
		{
			name: "aws-nacl-unused", check: awsNACLUnused,
			violating: map[string]string{"subnet_association_count": "0", "is_default": "false"},
			compliant: map[string]string{"subnet_association_count": "2", "is_default": "false"},
			unknown:   map[string]string{"is_default": "false"},
		},
		{
			name: "aws-vpc-missing-service-endpoints", check: awsVPCMissingServiceEndpoints,
			violating: map[string]string{"endpoint_services": "ec2,s3"},
			compliant: map[string]string{"endpoint_services": "ec2,ecr.api,ecr.dkr,s3,ssm,ssm-contacts,ssm-incidents"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-tgw-auto-accept-shared-attachments", check: awsTGWAutoAcceptSharedAttachments,
			violating: map[string]string{"auto_accept_shared_attachments": "enable"},
			compliant: map[string]string{"auto_accept_shared_attachments": "disable"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-vpn-tunnel-down", check: awsVPNTunnelDown,
			violating: map[string]string{"state": "available", "tunnels_down": "1"},
			compliant: map[string]string{"state": "available", "tunnels_down": "0"},
			unknown:   map[string]string{"state": "available"},
		},
		{
			name: "aws-vpn-tunnel-logging-disabled", check: awsVPNTunnelLoggingDisabled,
			violating: map[string]string{"tunnels_without_logging": "2"},
			compliant: map[string]string{"tunnels_without_logging": "0"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-vpn-ikev1-allowed", check: awsVPNIKEv1Allowed,
			violating: map[string]string{"tunnels_allowing_ikev1": "1"},
			compliant: map[string]string{"tunnels_allowing_ikev1": "0"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-client-vpn-connection-logging-disabled", check: awsClientVPNConnectionLoggingDisabled,
			violating: map[string]string{"connection_logging": "false"},
			compliant: map[string]string{"connection_logging": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ec2-launch-template-public-ip", check: awsEC2LaunchTemplatePublicIP,
			violating: map[string]string{"public_ip_interfaces": "1"},
			compliant: map[string]string{"public_ip_interfaces": "0"},
			unknown:   map[string]string{"auto_scaling_group_count": "3"},
		},
		{
			name: "aws-ec2-launch-template-imdsv1", check: awsEC2LaunchTemplateIMDSv1,
			violating: map[string]string{"http_tokens": "optional"},
			// Unset takes the account/AMI default: FSBP EC2.170 fails only an explicit optional.
			compliant: map[string]string{"http_tokens": ""},
			unknown:   map[string]string{"http_endpoint": "enabled"},
		},
		{
			name: "aws-ec2-launch-template-unencrypted-ebs", check: awsEC2LaunchTemplateUnencryptedEBS,
			violating: map[string]string{"unencrypted_ebs_volumes": "1"},
			compliant: map[string]string{"unencrypted_ebs_volumes": "0"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-ec2-spot-fleet-unencrypted-ebs", check: awsEC2SpotFleetUnencryptedEBS,
			violating: map[string]string{"unencrypted_ebs_volumes": "2"},
			compliant: map[string]string{"unencrypted_ebs_volumes": "0"},
			unknown:   map[string]string{"launch_specification_count": "1"},
		},
		{
			name: "aws-ec2-eni-source-dest-check-disabled", check: awsEC2ENISourceDestCheckDisabled,
			violating: map[string]string{"source_dest_check_disabled_enis": "eni-1"},
			compliant: map[string]string{"source_dest_check_disabled_enis": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-asg-no-elb-health-check", check: awsASGNoELBHealthCheck,
			violating: map[string]string{"load_balanced": "true", "health_check_type": "EC2"},
			compliant: map[string]string{"load_balanced": "true", "health_check_type": "ELB"},
			unknown:   map[string]string{"load_balanced": "true"},
		},
		{
			name: "aws-asg-single-az", check: awsASGSingleAZ,
			violating: map[string]string{"availability_zone_count": "1"},
			compliant: map[string]string{"availability_zone_count": "3"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-asg-launch-config-imdsv1", check: awsASGLaunchConfigIMDSv1,
			// FSBP AutoScaling.3 fails a configuration with no metadata options.
			violating: map[string]string{"http_tokens": ""},
			compliant: map[string]string{"http_tokens": "required"},
			unknown:   map[string]string{"auto_scaling_group_count": "1"},
		},
		{
			name: "aws-asg-launch-config-public-ip", check: awsASGLaunchConfigPublicIP,
			violating: map[string]string{"associate_public_ip": "true"},
			compliant: map[string]string{"associate_public_ip": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-asg-single-instance-type", check: awsASGSingleInstanceType,
			violating: map[string]string{"multiple_instance_types": "false"},
			compliant: map[string]string{"multiple_instance_types": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-asg-uses-launch-configuration", check: awsASGUsesLaunchConfiguration,
			violating: map[string]string{"launch_source": "launch_configuration"},
			compliant: map[string]string{"launch_source": "launch_template"},
			unknown:   map[string]string{},
		},
		// Load balancer posture (aws_elb.go): every key is written only after its
		// read succeeded, so absence is an unread balancer.
		{
			name: "aws-elb-http-no-https-redirect", check: awsELBHTTPNoHTTPSRedirect,
			violating: map[string]string{"type": "application", "http_listeners_without_https_redirect": "80"},
			compliant: map[string]string{"type": "application", "http_listeners_without_https_redirect": ""},
			// A failed DescribeRules leaves the verdict out.
			unknown: map[string]string{"type": "application", "plaintext_listeners": "HTTP:80"},
		},
		{
			name: "aws-elb-plaintext-listener", check: awsELBPlaintextListener,
			violating: map[string]string{"type": "network", "plaintext_listeners": "TCP:22"},
			compliant: map[string]string{"type": "network", "plaintext_listeners": ""},
			unknown:   map[string]string{"type": "network"},
		},
		{
			name: "aws-elb-weak-tls-policy", check: awsELBWeakTLSPolicy,
			violating: map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-2016-08"},
			compliant: map[string]string{"type": "application", "tls_listener_policies": "HTTPS:443=ELBSecurityPolicy-TLS13-1-2-Res-2021-06"},
			unknown:   map[string]string{"type": "classic"},
		},
		{
			name: "aws-elb-desync-mitigation-weak", check: awsELBDesyncMitigationWeak,
			violating: map[string]string{"type": "classic", "desync_mitigation_mode": "monitor"},
			compliant: map[string]string{"type": "classic", "desync_mitigation_mode": "defensive"},
			// A Classic balancer whose attributes carried no desync entry.
			unknown: map[string]string{"type": "classic", "connection_draining": "true"},
		},
		{
			name: "aws-elb-alb-invalid-headers-allowed", check: awsELBInvalidHeadersAllowed,
			violating: map[string]string{"type": "application", "drop_invalid_header_fields": "false", "desync_mitigation_mode": "defensive"},
			compliant: map[string]string{"type": "application", "drop_invalid_header_fields": "true", "desync_mitigation_mode": "defensive"},
			unknown:   map[string]string{"type": "application"},
		},
		{
			name: "aws-elb-no-deletion-protection", check: awsELBNoDeletionProtection,
			violating: map[string]string{"type": "network", "deletion_protection": "false"},
			compliant: map[string]string{"type": "network", "deletion_protection": "true"},
			unknown:   map[string]string{"type": "network"},
		},
		{
			name: "aws-elb-classic-connection-draining-disabled", check: awsELBClassicConnectionDraining,
			violating: map[string]string{"type": "classic", "connection_draining": "false"},
			compliant: map[string]string{"type": "classic", "connection_draining": "true"},
			unknown:   map[string]string{"type": "classic"},
		},
		{
			name: "aws-elb-classic-cross-zone-disabled", check: awsELBClassicCrossZoneDisabled,
			violating: map[string]string{"type": "classic", "cross_zone_load_balancing": "false"},
			compliant: map[string]string{"type": "classic", "cross_zone_load_balancing": "true"},
			unknown:   map[string]string{"type": "classic"},
		},
		{
			name: "aws-elb-classic-non-acm-certificate", check: awsELBClassicNonACMCertificate,
			violating: map[string]string{"type": "classic", "non_acm_certificate_listeners": "HTTPS:443"},
			compliant: map[string]string{"type": "classic", "non_acm_certificate_listeners": ""},
			unknown:   map[string]string{"type": "classic"},
		},
		{
			name: "aws-elb-target-group-unencrypted", check: awsELBTargetGroupUnencrypted,
			violating: map[string]string{"target_type": "instance", "protocol": "HTTP"},
			compliant: map[string]string{"target_type": "instance", "protocol": "HTTPS"},
			unknown:   map[string]string{"target_type": "instance"},
		},
		{
			name: "aws-elb-target-group-health-check-unencrypted", check: awsELBTargetGroupHealthCheckUnencrypted,
			violating: map[string]string{"target_type": "ip", "protocol": "HTTPS", "health_check_protocol": "HTTP"},
			compliant: map[string]string{"target_type": "ip", "protocol": "HTTPS", "health_check_protocol": "HTTPS"},
			unknown:   map[string]string{"target_type": "ip", "protocol": "HTTPS"},
		},
		// CloudFront: list keys name the offending origins/behaviours; "" is an
		// observed none, absent is an unread distribution.
		{
			name: "aws-cloudfront-dangling-s3-origin", check: awsCloudFrontDanglingS3Origin,
			violating: map[string]string{"s3_origin_buckets_missing": "old-assets"},
			compliant: map[string]string{"s3_origin_buckets_missing": ""},
			// A HeadBucket that was throttled: neither present nor missing.
			unknown: map[string]string{"s3_origins_without_oac": ""},
		},
		{
			name: "aws-cloudfront-viewer-http-allowed", check: awsCloudFrontViewerHTTP,
			violating: map[string]string{"viewer_http_behaviors": "default"},
			compliant: map[string]string{"viewer_http_behaviors": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-origin-unencrypted", check: awsCloudFrontOriginUnencrypted,
			violating: map[string]string{"custom_origins_unencrypted": "app"},
			compliant: map[string]string{"custom_origins_unencrypted": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-origin-sslv3", check: awsCloudFrontOriginSSLv3,
			violating: map[string]string{"custom_origins_sslv3": "app"},
			compliant: map[string]string{"custom_origins_sslv3": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-s3-origin-no-oac", check: awsCloudFrontS3OriginNoOAC,
			violating: map[string]string{"s3_origins_without_oac": "assets"},
			compliant: map[string]string{"s3_origins_without_oac": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-lambda-url-origin-no-oac", check: awsCloudFrontLambdaURLNoOAC,
			violating: map[string]string{"lambda_url_origins_without_oac": "fn"},
			compliant: map[string]string{"lambda_url_origins_without_oac": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-weak-viewer-tls", check: awsCloudFrontWeakViewerTLS,
			violating: map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.2_2019"},
			compliant: map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.2_2021"},
			unknown:   map[string]string{"default_certificate": "false"},
		},
		{
			name: "aws-cloudfront-legacy-trusted-signers", check: awsCloudFrontLegacyTrustedSigners,
			violating: map[string]string{"trusted_signer_behaviors": "/private/*"},
			compliant: map[string]string{"trusted_signer_behaviors": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-no-waf", check: awsCloudFrontNoWAF,
			violating: map[string]string{"web_acl_id": ""},
			compliant: map[string]string{"web_acl_id": "arn:aws:wafv2:us-east-1:1:global/webacl/a/b"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-logging-disabled", check: awsCloudFrontLoggingDisabled,
			violating: map[string]string{"logging_enabled": "false"},
			compliant: map[string]string{"logging_enabled": "true"},
			// GetDistributionConfig denied and no v2 delivery: unknown.
			unknown: map[string]string{"web_acl_id": ""},
		},
		{
			name: "aws-cloudfront-no-default-root-object", check: awsCloudFrontNoDefaultRootObject,
			violating: map[string]string{"default_root_object": "", "has_s3_origin": "true"},
			compliant: map[string]string{"default_root_object": "index.html", "has_s3_origin": "true"},
			unknown:   map[string]string{"has_s3_origin": "true"},
		},
		{
			name: "aws-cloudfront-default-certificate", check: awsCloudFrontDefaultCertificate,
			violating: map[string]string{"default_certificate": "true"},
			compliant: map[string]string{"default_certificate": "false"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-cloudfront-dedicated-ip-ssl", check: awsCloudFrontDedicatedIPSSL,
			violating: map[string]string{"default_certificate": "false", "ssl_support_method": "vip"},
			compliant: map[string]string{"default_certificate": "false", "ssl_support_method": "sni-only"},
			unknown:   map[string]string{"ssl_support_method": "vip"},
		},
		{
			name: "aws-cloudfront-no-origin-failover", check: awsCloudFrontNoOriginFailover,
			violating: map[string]string{"origin_group_count": "0"},
			compliant: map[string]string{"origin_group_count": "1"},
			unknown:   map[string]string{},
		},
		// WAF: counts are absent when the per-resource Get failed.
		{
			name: "aws-waf-web-acl-empty", check: awsWAFWebACLEmpty,
			violating: map[string]string{"rule_count": "0", "classic": "false"},
			compliant: map[string]string{"rule_count": "2", "classic": "false"},
			unknown:   map[string]string{"classic": "false"},
		},
		{
			name: "aws-waf-classic-rule-group-empty", check: awsWAFClassicRuleGroupEmpty,
			violating: map[string]string{"rule_count": "0", "classic": "true"},
			compliant: map[string]string{"rule_count": "1", "classic": "true"},
			unknown:   map[string]string{"classic": "true"},
		},
		{
			name: "aws-waf-classic-rule-no-conditions", check: awsWAFClassicRuleNoConditions,
			violating: map[string]string{"condition_count": "0"},
			compliant: map[string]string{"condition_count": "1"},
			unknown:   map[string]string{"classic": "true"},
		},
		{
			name: "aws-waf-classic-logging-disabled", check: awsWAFClassicLoggingDisabled,
			violating: map[string]string{"logging_enabled": "false"},
			compliant: map[string]string{"logging_enabled": "true"},
			// waf:ListLoggingConfigurations denied, or a regional/v2 ACL.
			unknown: map[string]string{"rule_count": "1"},
		},
		{
			name: "aws-wafv2-web-acl-rule-metrics-disabled", check: awsWAFv2WebACLRuleMetricsDisabled,
			violating: map[string]string{"rules_without_metrics": "geo-block"},
			compliant: map[string]string{"rules_without_metrics": ""},
			unknown:   map[string]string{},
		},
		{
			name: "aws-wafv2-rule-group-rule-metrics-disabled", check: awsWAFv2RuleGroupRuleMetricsDisabled,
			violating: map[string]string{"rules_without_metrics": "rate-limit"},
			compliant: map[string]string{"rules_without_metrics": ""},
			unknown:   map[string]string{},
		},
		// API Gateway (aws_apigateway.go).
		{
			name: "aws-apigateway-stage-execution-logging-disabled", check: awsAPIGatewayStageExecutionLoggingDisabled,
			violating: map[string]string{"execution_logging": "false", "logging_level": "OFF"},
			compliant: map[string]string{"execution_logging": "true", "logging_level": "ERROR"},
			// An HTTP API stage carries no logging keys at all.
			unknown: map[string]string{"api_type": "HTTP"},
		},
		{
			name: "aws-apigateway-stage-no-client-certificate", check: awsAPIGatewayStageNoClientCertificate,
			violating: map[string]string{"api_type": "REST", "client_certificate_id": ""},
			compliant: map[string]string{"api_type": "REST", "client_certificate_id": "abc123"},
			unknown:   map[string]string{"api_type": "REST"},
		},
		{
			name: "aws-apigateway-stage-xray-disabled", check: awsAPIGatewayStageXRayDisabled,
			violating: map[string]string{"api_type": "REST", "tracing_enabled": "false"},
			compliant: map[string]string{"api_type": "REST", "tracing_enabled": "true"},
			unknown:   map[string]string{"api_type": "REST"},
		},
		{
			name: "aws-apigateway-stage-no-waf", check: awsAPIGatewayStageNoWAF,
			violating: map[string]string{"api_type": "REST", "waf_web_acl_arn": ""},
			compliant: map[string]string{"api_type": "REST", "waf_web_acl_arn": "arn:aws:wafv2:eu-west-1:1:regional/webacl/a/b"},
			unknown:   map[string]string{"api_type": "REST"},
		},
		{
			name: "aws-apigateway-stage-cache-unencrypted", check: awsAPIGatewayStageCacheUnencrypted,
			violating: map[string]string{"api_type": "REST", "cache_cluster_enabled": "true", "cache_unencrypted_methods": "*/*"},
			compliant: map[string]string{"api_type": "REST", "cache_cluster_enabled": "true", "cache_unencrypted_methods": ""},
			unknown:   map[string]string{"api_type": "REST", "cache_cluster_enabled": "true"},
		},
		{
			name: "aws-apigatewayv2-route-no-authorization", check: awsAPIGatewayV2RouteNoAuthorization,
			violating: map[string]string{"api_type": "HTTP", "public": "true", "unauthenticated_routes": "$default", "route_count": "1"},
			compliant: map[string]string{"api_type": "HTTP", "public": "true", "unauthenticated_routes": "", "route_count": "3"},
			// A failed GetRoutes leaves both keys absent.
			unknown: map[string]string{"api_type": "HTTP", "public": "true"},
		},
		{
			name: "aws-apigatewayv2-private-integration-no-tls", check: awsAPIGatewayV2PrivateIntegrationNoTLS,
			violating: map[string]string{"private_integrations_without_tls": "abc1", "private_integration_count": "1"},
			compliant: map[string]string{"private_integrations_without_tls": "", "private_integration_count": "1"},
			unknown:   map[string]string{"api_type": "HTTP"},
		},
		{
			name: "aws-apigateway-domain-weak-tls-policy", check: awsAPIGatewayDomainWeakTLSPolicy,
			violating: map[string]string{"security_policy": "TLS_1_2"},
			compliant: map[string]string{"security_policy": "SecurityPolicy_TLS13_1_3_2025_09"},
			unknown:   map[string]string{"domain_name": "api.example.com"},
		},
		// Network Firewall (aws_network_firewall.go).
		{
			name: "aws-network-firewall-policy-no-rule-groups", check: awsNetworkFirewallPolicyNoRuleGroups,
			violating: map[string]string{"stateful_rule_group_count": "0", "stateless_rule_group_count": "0"},
			compliant: map[string]string{"stateful_rule_group_count": "1", "stateless_rule_group_count": "0"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-network-firewall-policy-stateless-default-pass", check: awsNetworkFirewallPolicyStatelessDefaultPass,
			violating: map[string]string{"stateless_default_actions": "aws:pass,MyMetricAction"},
			compliant: map[string]string{"stateless_default_actions": "aws:forward_to_sfe"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-network-firewall-policy-fragment-default-pass", check: awsNetworkFirewallPolicyFragmentDefaultPass,
			violating: map[string]string{"stateless_fragment_default_actions": "aws:pass"},
			compliant: map[string]string{"stateless_fragment_default_actions": "aws:drop"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-network-firewall-rule-group-empty", check: awsNetworkFirewallRuleGroupEmpty,
			violating: map[string]string{"stateless_rule_count": "0"},
			compliant: map[string]string{"stateless_rule_count": "4"},
			unknown:   map[string]string{"rule_group_type": "STATELESS"},
		},
		{
			name: "aws-network-firewall-no-deletion-protection", check: awsNetworkFirewallNoDeletionProtection,
			violating: map[string]string{"delete_protection": "false"},
			compliant: map[string]string{"delete_protection": "true"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-network-firewall-no-subnet-change-protection", check: awsNetworkFirewallNoSubnetChangeProtection,
			violating: map[string]string{"subnet_change_protection": "false"},
			compliant: map[string]string{"subnet_change_protection": "true"},
			unknown:   map[string]string{},
		},
		// Systems Manager and Route 53 (aws_ssm.go).
		{
			name: "aws-ec2-ssm-patch-noncompliant", check: awsEC2SSMPatchNonCompliant,
			violating: map[string]string{"ssm_patch_compliance": "NON_COMPLIANT"},
			compliant: map[string]string{"ssm_patch_compliance": "COMPLIANT"},
			// A managed instance Patch Manager does not cover has no record.
			unknown: map[string]string{"ssm_managed": "true"},
		},
		{
			name: "aws-ec2-ssm-association-noncompliant", check: awsEC2SSMAssociationNonCompliant,
			violating: map[string]string{"ssm_association_compliance": "NON_COMPLIANT"},
			compliant: map[string]string{"ssm_association_compliance": "COMPLIANT"},
			unknown:   map[string]string{"ssm_managed": "true"},
		},
		{
			name: "aws-ssm-document-public", check: awsSSMDocumentPublic,
			violating: map[string]string{"publicly_shared": "true", "shared_account_count": "1"},
			compliant: map[string]string{"publicly_shared": "false", "shared_account_count": "0"},
			// A denied DescribeDocumentPermission.
			unknown: map[string]string{"document_type": "Command"},
		},
		{
			name: "aws-ssm-document-public-sharing-not-blocked", check: awsSSMDocumentPublicSharingNotBlocked,
			violating: map[string]string{"ssm_document_public_sharing": "Enable"},
			compliant: map[string]string{"ssm_document_public_sharing": "Disable"},
			unknown:   map[string]string{"ebs_encryption_by_default": "true"},
		},
		{
			name: "aws-ssm-automation-logging-disabled", check: awsSSMAutomationLoggingDisabled,
			violating: map[string]string{"ssm_automation_log_destination": ""},
			compliant: map[string]string{"ssm_automation_log_destination": "CloudWatch"},
			unknown:   map[string]string{"ebs_encryption_by_default": "true"},
		},
		{
			name: "aws-route53-zone-query-logging-disabled", check: awsRoute53ZoneQueryLoggingDisabled,
			violating: map[string]string{"private_zone": "false", "query_logging": "false"},
			compliant: map[string]string{"private_zone": "false", "query_logging": "true"},
			// A failed ListQueryLoggingConfigs leaves query_logging absent.
			unknown: map[string]string{"private_zone": "false"},
		},
	})
	runAbsentDataRows(t, gcpPostureAbsentRows)
}

// absentDataRow is one check's three observations of the same resource: the
// confirmed negative (fires), the confirmed positive (silent) and the
// unobserved case (silent). Service check files keep their rows beside their
// own tests and run them through runAbsentDataRows.
type absentDataRow struct {
	name      string
	check     Check
	violating map[string]string
	compliant map[string]string
	unknown   map[string]string
}

func runAbsentDataRows(t *testing.T, rows []absentDataRow) {
	t.Helper()
	for _, tt := range rows {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.name, tt.check.ID, "table row is wired to the wrong check")
			build := func(md map[string]string) asset.Asset {
				return asset.Asset{
					ID: "res-1", Type: tt.check.AssetType, Provider: tt.check.Provider, Metadata: md,
				}
			}
			require.True(t, tt.check.Violates(build(tt.violating)),
				"the confirmed-negative observation must still fire — the point is not to go silent")
			require.False(t, tt.check.Violates(build(tt.compliant)),
				"the compliant state must not fire")
			require.False(t, tt.check.Violates(build(tt.unknown)),
				"absent data is not a violation")
			require.False(t, tt.check.Violates(build(nil)),
				"a nil metadata map is absent data too")
		})
	}
}

// observedNone distinguishes "the collector looked and there is none" from "the
// collector never looked". Both read as "" through a plain map index, which is
// why the string-valued checks needed a helper rather than a comparison.
func TestObservedNone(t *testing.T) {
	require.True(t, observedNone(asset.Asset{Metadata: map[string]string{"k": ""}}, "k"))
	require.False(t, observedNone(asset.Asset{Metadata: map[string]string{"k": "v"}}, "k"))
	require.False(t, observedNone(asset.Asset{Metadata: map[string]string{}}, "k"))
	require.False(t, observedNone(asset.Asset{}, "k"))
}

// A ClusterRoleBinding's roleRef can only name a ClusterRole — the Kubernetes API
// rejects anything else — so the collector does not stamp role_ref_kind on one
// (absent on every ClusterRoleBinding). Reading its absence as "not a
// ClusterRole" made every cluster-scoped branch of privilegedRoleRef return
// false, so k8s-privileged-binding-to-everyone, a Critical check whose 25-line
// doc comment is entirely about the cluster-scoped case, could never fire on it.
func TestPrivilegedBindingToEveryone_ClusterRoleBindingWithoutRoleRefKind(t *testing.T) {
	tests := []struct {
		name  string
		a     asset.Asset
		fires bool
	}{
		{
			name: "cluster-admin to system:authenticated, no role_ref_kind (the collected shape)",
			a: asset.Asset{ID: "crb-world", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"role_ref": "cluster-admin", "subjects": "Group/system:authenticated"}},
			fires: true,
		},
		{
			name: "edit to system:anonymous, no role_ref_kind",
			a: asset.Asset{ID: "crb-anon", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"role_ref": "edit", "subjects": "User/system:anonymous"}},
			fires: true,
		},
		{
			// The three default bindings that reference an everyone-group on a
			// standard cluster. They must stay silent or the check is pure noise.
			name: "system:basic-user default stays silent",
			a: asset.Asset{ID: "crb-basic", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"role_ref": "system:basic-user", "subjects": "Group/system:authenticated,Group/system:unauthenticated"}},
			fires: false,
		},
		{
			name: "system:discovery default stays silent",
			a: asset.Asset{ID: "crb-disc", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"role_ref": "system:discovery", "subjects": "Group/system:authenticated"}},
			fires: false,
		},
		{
			name: "system:public-info-viewer default stays silent",
			a: asset.Asset{ID: "crb-pub", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"role_ref": "system:public-info-viewer", "subjects": "Group/system:authenticated,Group/system:unauthenticated"}},
			fires: false,
		},
		{
			// A RoleBinding DOES choose between Role and ClusterRole, so there the
			// absent kind stays ambiguous and must not be assumed.
			name: "RoleBinding without role_ref_kind is still ambiguous",
			a: asset.Asset{ID: "rb-amb", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"namespace": "billing", "role_ref": "admin", "subjects": "Group/system:authenticated"}},
			fires: false,
		},
		{
			name: "RoleBinding naming the built-in ClusterRole admin still fires",
			a: asset.Asset{ID: "rb-admin", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
				Metadata: map[string]string{"namespace": "billing", "role_ref": "admin", "role_ref_kind": "ClusterRole", "subjects": "Group/system:authenticated"}},
			fires: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, k8sBindingToEveryone.Violates(tt.a))
		})
	}
}

// Severity re-ratings, each measured against a sibling check on the same data.
func TestSeverityReRatings(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		a     asset.Asset
		want  finding.Severity
	}{
		{
			// Its own Description argues determinism and
			// rollback; the coverage argument is rated Medium elsewhere
			// (aws-ecr-scanning-disabled), so High was never defensible.
			name: "k8s-image-latest-tag is Low, not High", check: k8sPodLatestImage,
			a:    asset.Asset{Metadata: map[string]string{"images": "app:latest", "phase": "Running"}},
			want: finding.SeverityLow,
		},
		{
			// Age alone past rotation, on an ordinary user: in-use and monitored
			// is plausible, so it stays Medium.
			name: "aws-iam-access-key-old past rotation is Medium", check: awsIAMAccessKeyOld,
			a:    asset.Asset{Metadata: map[string]string{"access_key_age_days": "120"}},
			want: finding.SeverityMedium,
		},
		{
			// A year without rotation means nobody manages the key, whoever holds it.
			name: "aws-iam-access-key-old past a year is High", check: awsIAMAccessKeyOld,
			a:    asset.Asset{Metadata: map[string]string{"access_key_age_days": "400"}},
			want: finding.SeverityHigh,
		},
		{
			// A leaked admin key is the whole account: privilege raises the tier.
			name: "aws-iam-access-key-old on an admin is High", check: awsIAMAccessKeyOld,
			a:    asset.Asset{Metadata: map[string]string{"access_key_age_days": "120", "admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin"}},
			want: finding.SeverityHigh,
		},
		{
			name: "gcp-gce-default-sa on a private instance is Medium", check: gcpGCEDefaultServiceAccount,
			a:    asset.Asset{Metadata: map[string]string{"exec_role": "serviceAccount:1-compute@developer.gserviceaccount.com"}},
			want: finding.SeverityMedium,
		},
		{
			// The pairing gcp-function-open-ingress-default-sa already makes for
			// Cloud Functions: a broad-permission identity is a live path only when
			// something can reach the thing that holds it.
			name: "gcp-gce-default-sa on a public instance is High", check: gcpGCEDefaultServiceAccount,
			a: asset.Asset{PublicIP: "34.1.1.1",
				Metadata: map[string]string{"exec_role": "serviceAccount:1-compute@developer.gserviceaccount.com"}},
			want: finding.SeverityHigh,
		},
		{
			// GKE node pools are graded per cluster: the cloud-platform scope
			// on the default account raises the pool finding to High.
			name: "gcp-gke-node-default-sa with the cloud-platform scope is High", check: gcpGKENodeDefaultSA,
			a: asset.Asset{Metadata: map[string]string{
				"node_pools_default_sa": "default-pool", "node_pools_default_sa_full_scope": "default-pool"}},
			want: finding.SeverityHigh,
		},
		{
			name: "gcp-gke-node-default-sa without the scope is Medium", check: gcpGKENodeDefaultSA,
			a:    asset.Asset{Metadata: map[string]string{"node_pools_default_sa": "default-pool", "node_pools_default_sa_full_scope": ""}},
			want: finding.SeverityMedium,
		},
		{
			// A common shape is a templated GKE CRD role such as backendconfig-admin:
			// one rule, wildcard verbs, no dangerous capability.
			name: "k8s-role-wildcard-verbs without a dangerous capability is Medium", check: k8sRoleWildcardVerbs,
			a:    asset.Asset{Metadata: map[string]string{"wildcard_verbs": "true", "dangerous_perms": "false", "rule_count": "1"}},
			want: finding.SeverityMedium,
		},
		{
			name: "k8s-role-wildcard-verbs with a dangerous capability is capped at Medium", check: k8sRoleWildcardVerbs,
			a: asset.Asset{Metadata: map[string]string{"wildcard_verbs": "true", "dangerous_perms": "true",
				"dangerous_perms_detail": "secrets-read", "rule_count": "4"}},
			want: finding.SeverityMedium,
		},
		{
			name: "aws-rds-publicly-accessible off a default port is Low", check: awsRDSPubliclyAccessible,
			a:    asset.Asset{Metadata: map[string]string{"publicly_accessible": "true", "port": "51433"}},
			want: finding.SeverityLow,
		},
		{
			name: "aws-rds-publicly-accessible on a default port is Medium", check: awsRDSPubliclyAccessible,
			a:    asset.Asset{Metadata: map[string]string{"publicly_accessible": "true", "port": "5432"}},
			want: finding.SeverityMedium,
		},
		{
			// The absorbed aws-rds-default-port tested only 3306 and 5432, so
			// instances on 27017 were invisible to it while its own
			// sibling aws-sg-open-database-ports treated 27017 as a database port.
			name: "aws-rds-publicly-accessible on 27017 is Medium too", check: awsRDSPubliclyAccessible,
			a:    asset.Asset{Metadata: map[string]string{"publicly_accessible": "true", "port": "27017"}},
			want: finding.SeverityMedium,
		},
		{
			name: "aws-rds-public-subnet-igw on a publicly accessible instance is High", check: awsRDSPublicSubnetIGW,
			a:    asset.Asset{Metadata: map[string]string{"in_public_subnet": "true", "publicly_accessible": "true"}},
			want: finding.SeverityHigh,
		},
		{
			name: "aws-rds-public-subnet-igw on a private-endpoint instance is Medium", check: awsRDSPublicSubnetIGW,
			a:    asset.Asset{Metadata: map[string]string{"in_public_subnet": "true", "publicly_accessible": "false"}},
			want: finding.SeverityMedium,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.True(t, tt.check.Violates(tt.a), "the check must still fire — only its grade changed")
			got := tt.check.Severity
			if tt.check.SeverityFor != nil {
				got = tt.check.SeverityFor(tt.a)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// isDefaultDatabasePort must cover the same port set the security-group check
// calls a database port, or an instance is a finding to one check and invisible
// to the other.
func TestIsDefaultDatabasePortMatchesSGPortSet(t *testing.T) {
	for _, p := range []string{"3306", "5432", "6379", "27017", "1433", "5984", "9200", "9300"} {
		require.True(t, isDefaultDatabasePort(p), "port %s is a database port to aws-sg-open-database-ports", p)
	}
	for _, p := range []string{"", "443", "51433", "not-a-port"} {
		require.False(t, isDefaultDatabasePort(p))
	}
}

// platform_managed is collected on ClusterRoles and Roles and, until now, was
// read by nothing. Kubernetes' own bootstrap RBAC and
// GKE's managed roles carry wildcard rules by design and are reverted by the
// control plane if edited — a finding nobody can act on is how a check gets
// muted. The dangerous-permission siblings already get this exclusion because
// the collector folds platform_managed into dangerous_perms itself; the raw
// wildcard signal did not.
func TestWildcardChecksExemptPlatformManagedRBAC(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		a     asset.Asset
		fires bool
	}{
		{"org ClusterRole with a wildcard fires", k8sClusterRoleWildcardVerbs,
			asset.Asset{Metadata: map[string]string{"wildcard_verbs": "true", "platform_managed": "false"}}, true},
		{"platform-managed ClusterRole is exempt", k8sClusterRoleWildcardVerbs,
			asset.Asset{Metadata: map[string]string{"wildcard_verbs": "true", "platform_managed": "true"}}, false},
		{"org Role with a wildcard fires", k8sRoleWildcardVerbs,
			asset.Asset{Metadata: map[string]string{"wildcard_verbs": "true", "platform_managed": "false"}}, true},
		{"platform-managed Role is exempt", k8sRoleWildcardVerbs,
			asset.Asset{Metadata: map[string]string{"wildcard_verbs": "true", "platform_managed": "true"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, tt.check.Violates(tt.a))
		})
	}
	// The capability checks need no gate here: the collector already writes
	// dangerous_perms=false for a platform-managed role, so none of them produce
	// one. Pin that so a collector change that stops folding it in is caught
	// here rather than in the page band.
	for _, typ := range []string{"k8s_cluster_role", "k8s_role"} {
		pm := asset.Asset{Type: typ, Metadata: map[string]string{"dangerous_perms": "false", "platform_managed": "true",
			"dangerous_perms_detail": "secrets-read,rbac-escalate"}}
		require.False(t, k8sRBACSecretsAccess.Violates(pm))
		require.False(t, k8sRBACEscalate.Violates(pm))
	}
}

// gcp-cloudsql-no-backup also carried a second disjunct, `backup_enabled ==
// "false"`, on a key no collector in the tree has ever written. It could only ever match a hand-crafted
// asset, and it hid the fact that the real key is `backups`.
func TestGCPCloudSQLNoBackupReadsOnlyTheKeyTheCollectorWrites(t *testing.T) {
	a := func(md map[string]string) asset.Asset {
		return asset.Asset{ID: "db", Type: "cloudsql_instance", Provider: asset.ProviderGCP, Metadata: md}
	}
	require.True(t, gcpCloudSQLNoBackup.Violates(a(map[string]string{"backups": "false"})))
	require.False(t, gcpCloudSQLNoBackup.Violates(a(map[string]string{"backup_enabled": "false"})),
		"backup_enabled is written by no collector — reading it is dead code pretending to be coverage")
	require.False(t, gcpCloudSQLNoBackup.Violates(a(map[string]string{"backups": "true", "backup_enabled": "false"})),
		"and it must not override the key that IS observed")
}

// `logging` used to mean two incompatible things: an enabled/disabled enum on
// s3_bucket and the destination log-bucket NAME on gcs_bucket. The GCS side is
// now logging_bucket. Neither check may read the other's key, and the S3 check
// in particular must never be satisfied by a bucket name.
func TestLoggingKeysAreNotCrossWired(t *testing.T) {
	s3 := func(md map[string]string) asset.Asset {
		return asset.Asset{ID: "b", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: md}
	}
	gcs := func(md map[string]string) asset.Asset {
		return asset.Asset{ID: "b", Type: "gcs_bucket", Provider: asset.ProviderGCP, Metadata: md}
	}
	require.False(t, awsS3AccessLoggingDisabled.Violates(s3(map[string]string{"logging_bucket": ""})),
		"the S3 check must not read the GCS key")
	require.False(t, awsS3AccessLoggingDisabled.Violates(s3(map[string]string{"logging": "audit-logs-bucket"})),
		"a log-bucket NAME is not the S3 enum and must never be read as 'disabled'")
	require.False(t, gcpGCSLoggingDisabled.Violates(gcs(map[string]string{"logging": ""})),
		"the GCS check must not read the S3 key")
	require.False(t, gcpGCSLoggingDisabled.Violates(gcs(map[string]string{"logging": "disabled"})),
		"and an S3-shaped enum must not satisfy it either")
}

func TestIsDefaultDatabasePort(t *testing.T) {
	for name, tc := range map[string]struct {
		port string
		want bool
	}{
		"postgres":      {"5432", true},
		"not database":  {"8080", false},
		"empty":         {"", false},
		"garbage":       {"abc", false},
		"wraps to 5432": {"4294972728", false},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, isDefaultDatabasePort(tc.port))
		})
	}
}
