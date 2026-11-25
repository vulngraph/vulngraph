package checks

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// EMR (FSBP EMR.1-4), AppSync (AppSync.1/2/5/6) and Elastic Beanstalk
// (ElasticBeanstalk.1-3) posture.

// ── EMR ──────────────────────────────────────────────────────────────────────

var awsEMRPrimaryPublicIP = Check{
	ID:          "aws-emr-primary-public-ip",
	Title:       "EMR cluster primary node has a public IP address",
	Description: "A running EMR cluster's primary node has a public IPv4 address. The primary node serves the Hadoop/Spark web UIs, YARN ResourceManager and SSH; with a public address, a single permissive security-group rule puts them on the internet, and exposed YARN APIs are a long-standing remote-code-execution target.",
	Remediation: "A public address cannot be removed from a running instance: launch a replacement cluster in a private subnet (MapPublicIpOnLaunch=false) and reach it through a bastion, Session Manager or a VPN. `aws emr create-cluster ... --ec2-attributes SubnetId=PRIVATE_SUBNET`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "emr_cluster",
	Violates: func(a asset.Asset) bool {
		st := a.Metadata["state"]
		return (st == "RUNNING" || st == "WAITING") && a.Metadata["primary_public_ips"] != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_ips": a.Metadata["primary_public_ips"]}
	},
}

// emrPortsBeyondSSH lists the permitted public port ranges other than 22,
// which FSBP EMR.2 allows as the only exception.
func emrPortsBeyondSSH(a asset.Asset) []string {
	v, ok := a.Metadata["permitted_public_ports"]
	if !ok || v == "" {
		return nil
	}
	return slices.DeleteFunc(strings.Split(v, ","), func(p string) bool { return p == "22" })
}

var awsEMRBlockPublicAccessOff = Check{
	ID:          "aws-emr-block-public-access-off",
	Title:       "EMR block public access is off or permits ports beyond SSH",
	Description: "EMR block public access, which stops clusters launching with security-group rules open to 0.0.0.0/0 or ::/0, is disabled in this region, or it allows public ingress on ports other than 22. Every new cluster in the region can then be launched world-reachable on its web UI and API ports. Region-wide, so it is one finding per region where EMR is in use.",
	Remediation: "Console: EMR → Block public access → Edit → Turn on, and keep only port 22 as an exception. CLI: `aws emr put-block-public-access-configuration --block-public-access-configuration '{\"BlockPublicSecurityGroupRules\":true,\"PermittedPublicSecurityGroupRuleRanges\":[{\"MinRange\":22,\"MaxRange\":22}]}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "emr_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["block_public_security_group_rules"] == "false" || len(emrPortsBeyondSSH(a)) > 0
	},
	// Fully off is Medium; on but with extra exceptions is Low.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["block_public_security_group_rules"] == "false" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"block_public_security_group_rules": a.Metadata["block_public_security_group_rules"],
			"permitted_public_ports":            a.Metadata["permitted_public_ports"],
		}
	},
}

var awsEMRSecurityConfigNoAtRestEncryption = Check{
	ID:          "aws-emr-security-config-no-at-rest-encryption",
	Title:       "EMR security configuration does not encrypt data at rest",
	Description: "The security configuration leaves at-rest encryption off, so clusters launched with it write EMRFS data in S3 and local disks (HDFS, spill, EBS) without the encryption the configuration exists to apply.",
	Remediation: "Security configurations are immutable: create a new one with at-rest encryption (Console: EMR → Security configurations → Create → Encryption → enable at-rest encryption for S3 and local disk; CLI: `aws emr create-security-configuration --name NAME --security-configuration file://sc.json` with EncryptionConfiguration.EnableAtRestEncryption=true) and launch clusters with it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "emr_security_configuration",
	Violates:    func(a asset.Asset) bool { return a.Metadata["at_rest_encryption"] == "false" },
}

var awsEMRSecurityConfigNoInTransitEncryption = Check{
	ID:          "aws-emr-security-config-no-in-transit-encryption",
	Title:       "EMR security configuration does not encrypt data in transit",
	Description: "The security configuration leaves in-transit encryption off, so shuffle traffic, HDFS block transfer and the web UIs of clusters launched with it move data between nodes in plaintext.",
	Remediation: "Create a new security configuration with in-transit encryption (TLS certificate provider) — Console: EMR → Security configurations → Create → In-transit encryption; CLI: `aws emr create-security-configuration --name NAME --security-configuration file://sc.json` with EncryptionConfiguration.EnableInTransitEncryption=true — and launch clusters with it.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "emr_security_configuration",
	Violates:    func(a asset.Asset) bool { return a.Metadata["in_transit_encryption"] == "false" },
}

// ── AppSync ──────────────────────────────────────────────────────────────────

var awsAppSyncCacheNotEncryptedAtRest = Check{
	ID:          "aws-appsync-cache-not-encrypted-at-rest",
	Title:       "AppSync API cache is not encrypted at rest",
	Description: "The GraphQL API's resolver cache stores responses unencrypted at rest. Cached responses are application data — often user records — held outside the data source's own encryption.",
	Remediation: "Encryption cannot be changed on an existing cache: delete and recreate it with encryption. Console: AppSync → API → Caching → Delete cache, then Create cache (current caches always encrypt). CLI: `aws appsync delete-api-cache --api-id ID` then `aws appsync create-api-cache --api-id ID --ttl 3600 --api-caching-behavior FULL_REQUEST_CACHING --type SMALL --at-rest-encryption-enabled`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "appsync_graphql_api",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["api_cache"] == "true" && a.Metadata["cache_at_rest_encryption"] == "false"
	},
}

var awsAppSyncCacheNotEncryptedInTransit = Check{
	ID:          "aws-appsync-cache-not-encrypted-in-transit",
	Title:       "AppSync API cache is not encrypted in transit",
	Description: "Traffic between AppSync and the API's cache nodes is not encrypted, so cached response data crosses the network in plaintext.",
	Remediation: "Delete and recreate the cache with transit encryption. CLI: `aws appsync delete-api-cache --api-id ID` then `aws appsync create-api-cache --api-id ID --ttl 3600 --api-caching-behavior FULL_REQUEST_CACHING --type SMALL --transit-encryption-enabled`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "appsync_graphql_api",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["api_cache"] == "true" && a.Metadata["cache_transit_encryption"] == "false"
	},
}

var awsAppSyncFieldLoggingDisabled = Check{
	ID:          "aws-appsync-field-logging-disabled",
	Title:       "AppSync API has field-level logging turned off",
	Description: "The GraphQL API logs no resolver activity (no log configuration, or field log level NONE), so resolver errors and the requests behind them leave no trace in CloudWatch.",
	Remediation: "Console: AppSync → API → Settings → Logging → Enable, field resolver log level ERROR (or ALL). CLI: `aws appsync update-graphql-api --api-id ID --name NAME --log-config fieldLogLevel=ERROR,cloudWatchLogsRoleArn=ROLE_ARN`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "appsync_graphql_api",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "field_log_level") || a.Metadata["field_log_level"] == "NONE"
	},
}

var awsAppSyncAPIKeyAuth = Check{
	ID:          "aws-appsync-api-key-auth",
	Title:       "AppSync GraphQL API accepts API-key authentication",
	Description: "The API's default or an additional authorization mode is API_KEY. An API key is a static bearer value embedded in client apps; whoever extracts it can call the API as an anonymous client until the key expires, with no per-user identity to audit or revoke.",
	Remediation: "Switch to IAM, Cognito user pools, OIDC or Lambda authorization. Console: AppSync → API → Settings → Authorization modes. CLI: `aws appsync update-graphql-api --api-id ID --name NAME --authentication-type AMAZON_COGNITO_USER_POOLS --user-pool-config ...` and remove API_KEY from additional providers; delete the keys with `aws appsync delete-api-key`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "appsync_graphql_api",
	Violates: func(a asset.Asset) bool {
		return slices.Contains(strings.Split(a.Metadata["authentication_types"], ","), "API_KEY")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"authentication_types": a.Metadata["authentication_types"]}
	},
}

// ── Elastic Beanstalk ────────────────────────────────────────────────────────

var awsBeanstalkBasicHealthReporting = Check{
	ID:          "aws-beanstalk-basic-health-reporting",
	Title:       "Elastic Beanstalk environment uses basic health reporting",
	Description: "The environment reports basic health only, so instance-level OS and application metrics that would show a degraded or misbehaving host are not collected. Operational visibility only.",
	Remediation: "Console: Elastic Beanstalk → environment → Configuration → Monitoring → Health reporting → Enhanced. CLI: `aws elasticbeanstalk update-environment --environment-name NAME --option-settings Namespace=aws:elasticbeanstalk:healthreporting:system,OptionName=SystemType,Value=enhanced`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticbeanstalk_environment",
	Violates:    func(a asset.Asset) bool { return a.Metadata["health_reporting"] == "basic" },
}

var awsBeanstalkManagedUpdatesDisabled = Check{
	ID:          "aws-beanstalk-managed-updates-disabled",
	Title:       "Elastic Beanstalk environment has managed platform updates disabled",
	Description: "Managed platform updates are off, so the environment's platform — OS, language runtime, web server — receives security patches only when someone applies them by hand, and in practice falls behind.",
	Remediation: "Console: Elastic Beanstalk → environment → Configuration → Updates, monitoring, and logging → Managed platform updates → Activated (choose a maintenance window and minor or patch level). CLI: `aws elasticbeanstalk update-environment --environment-name NAME --option-settings Namespace=aws:elasticbeanstalk:managedactions,OptionName=ManagedActionsEnabled,Value=true Namespace=aws:elasticbeanstalk:managedactions,OptionName=PreferredStartTime,Value=Sun:02:00 Namespace=aws:elasticbeanstalk:managedactions:platformupdate,OptionName=UpdateLevel,Value=minor`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticbeanstalk_environment",
	Violates:    func(a asset.Asset) bool { return a.Metadata["managed_actions_enabled"] == "false" },
}

var awsBeanstalkLogStreamingDisabled = Check{
	ID:          "aws-beanstalk-log-streaming-disabled",
	Title:       "Elastic Beanstalk environment does not stream logs to CloudWatch",
	Description: "Instance logs (application, web-server access and Beanstalk activity logs) are not streamed to CloudWatch Logs, so they disappear when an instance is replaced or scaled in.",
	Remediation: "Console: Elastic Beanstalk → environment → Configuration → Updates, monitoring, and logging → Instance log streaming to CloudWatch Logs → Activated. CLI: `aws elasticbeanstalk update-environment --environment-name NAME --option-settings Namespace=aws:elasticbeanstalk:cloudwatch:logs,OptionName=StreamLogs,Value=true`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elasticbeanstalk_environment",
	Violates:    func(a asset.Asset) bool { return a.Metadata["stream_logs"] == "false" },
}

func awsEMRAppSyncBeanstalkChecks() []Check {
	return []Check{
		awsEMRPrimaryPublicIP,
		awsEMRBlockPublicAccessOff,
		awsEMRSecurityConfigNoAtRestEncryption,
		awsEMRSecurityConfigNoInTransitEncryption,
		awsAppSyncCacheNotEncryptedAtRest,
		awsAppSyncCacheNotEncryptedInTransit,
		awsAppSyncFieldLoggingDisabled,
		awsAppSyncAPIKeyAuth,
		awsBeanstalkBasicHealthReporting,
		awsBeanstalkManagedUpdatesDisabled,
		awsBeanstalkLogStreamingDisabled,
	}
}
