package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Posture of AWS application-integration and end-user services: WorkSpaces,
// Transfer Family, CloudFormation, Step Functions, EventBridge, Amazon MQ, SES,
// Service Catalog, Connect, DataSync and Private CA (AWS FSBP WorkSpaces.1/.2,
// Transfer.2/.3, CloudFormation.3/.4, StepFunctions.1, EventBridge.3, MQ.2,
// SES.3, ServiceCatalog.1, Connect.2, DataSync.1, PCA.1; CIS AWS 2.21 for
// event buses). Collectors: internal/collect/aws/{workspaces,transfer,
// cloudformation,stepfunctions,eventbridge,mq,ses,servicecatalog,connect,
// datasync,acmpca}.go.

var awsWorkSpacesUserVolumeUnencrypted = Check{
	ID:          "aws-workspaces-user-volume-unencrypted",
	Title:       "WorkSpaces user volume is not encrypted at rest",
	Description: "The WorkSpace's user volume (D:, the user's profile and documents) is not encrypted with KMS, so a snapshot or the underlying storage holds the user's files in clear.",
	Remediation: "Volume encryption can only be set when a WorkSpace is created: create a replacement with encryption on (console: WorkSpaces → Launch WorkSpaces → Encrypt user volume; CLI `aws workspaces create-workspaces --workspaces '[{\"DirectoryId\":\"d-…\",\"UserName\":\"…\",\"BundleId\":\"wsb-…\",\"UserVolumeEncryptionEnabled\":true,\"RootVolumeEncryptionEnabled\":true,\"VolumeEncryptionKey\":\"KEY_ARN\"}]'`), migrate the user, then terminate the old one.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "workspaces_workspace",
	Violates:    func(a asset.Asset) bool { return a.Metadata["user_volume_encrypted"] == "false" },
}

var awsWorkSpacesRootVolumeUnencrypted = Check{
	ID:          "aws-workspaces-root-volume-unencrypted",
	Title:       "WorkSpaces root volume is not encrypted at rest",
	Description: "The WorkSpace's root volume (C:, the operating system and cached credentials) is not encrypted with KMS.",
	Remediation: "Create a replacement WorkSpace with RootVolumeEncryptionEnabled=true (console: Launch WorkSpaces → Encrypt root volume; CLI `aws workspaces create-workspaces` as for the user volume), migrate the user and terminate the old one — encryption cannot be added in place.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "workspaces_workspace",
	Violates:    func(a asset.Asset) bool { return a.Metadata["root_volume_encrypted"] == "false" },
}

var awsTransferServerFTPEnabled = Check{
	ID:          "aws-transfer-server-ftp-enabled",
	Title:       "Transfer Family server accepts plain FTP",
	Description: "The server lists FTP among its protocols. FTP sends the user name, password and every file in clear text, so anyone on the network path between the client and the server's VPC endpoint can read the credentials and the data.",
	Remediation: "Remove FTP and keep SFTP or FTPS: console Transfer Family → server → Edit protocols, or `aws transfer update-server --server-id ID --protocols SFTP FTPS` (FTPS needs a certificate).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "transfer_server",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ftp_enabled"] == "true" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"protocols": a.Metadata["protocols"]}
	},
}

var awsTransferConnectorNoLogging = Check{
	ID:          "aws-transfer-connector-no-logging",
	Title:       "Transfer Family connector has no CloudWatch logging",
	Description: "The connector has no logging role, so the files it sends to or pulls from the remote partner endpoint leave no record in CloudWatch Logs.",
	Remediation: "Attach a logging role: console Transfer Family → Connectors → Edit → Logging role, or `aws transfer update-connector --connector-id ID --logging-role ROLE_ARN` (the role needs logs:CreateLogStream/PutLogEvents).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "transfer_connector",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "logging_role") },
}

// Nested stacks inherit termination protection and the service role from
// their root stack and cannot change either themselves, so both checks grade
// root stacks only — one finding per root cause.

var awsCFNStackNoTerminationProtection = Check{
	ID:          "aws-cfn-stack-no-termination-protection",
	Title:       "CloudFormation stack has no termination protection",
	Description: "Termination protection is off, so one delete-stack call — by mistake or by a compromised deployer — tears down every resource the stack manages, including its nested stacks.",
	Remediation: "Console CloudFormation → stack → Stack actions → Edit termination protection, or `aws cloudformation update-termination-protection --enable-termination-protection --stack-name NAME`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "cloudformation_stack",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["nested"] == "false" && a.Metadata["termination_protection"] == "false"
	},
}

var awsCFNStackNoServiceRole = Check{
	ID:          "aws-cfn-stack-no-service-role",
	Title:       "CloudFormation stack has no service role",
	Description: "The stack has no service role, so CloudFormation acts with the credentials of whoever runs each update: everyone who deploys it needs every permission the template's resources need, instead of only iam:PassRole on one scoped role. A stack named like a StackSet stack instance (StackSet-<set>-<id>) is graded Info: a StackSet deploys through its execution or service-linked role, never the caller's credentials, but the name is the only evidence a member account can read and anyone can choose it.",
	Remediation: "A service role can only be set at stack creation or update: `aws cloudformation update-stack --stack-name NAME --use-previous-template --role-arn ROLE_ARN` (console: Update stack → Permissions → IAM role). Grant the role least privilege — anyone who can update the stack can use it.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "cloudformation_stack",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["nested"] == "false" && observedNone(a, "role_arn")
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["stackset_instance"] == "true" {
			return finding.SeverityInfo
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["stackset_instance"] == "true" {
			return "CloudFormation stack named as a StackSet instance has no service role"
		}
		return "CloudFormation stack has no service role"
	},
}

var awsStepFunctionsLoggingDisabled = Check{
	ID:          "aws-stepfunctions-logging-disabled",
	Title:       "Step Functions state machine has logging turned off",
	Description: "The state machine's log level is OFF, so its executions — inputs, failures and which service integrations ran — are not recorded in CloudWatch Logs.",
	Remediation: "Console Step Functions → state machine → Edit → Logging (level ALL, ERROR or FATAL), or `aws stepfunctions update-state-machine --state-machine-arn ARN --logging-configuration level=ERROR,includeExecutionData=false,destinations=[{cloudWatchLogsLogGroup={logGroupArn=LOG_GROUP_ARN}}]`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "stepfunctions_state_machine",
	Violates:    func(a asset.Asset) bool { return a.Metadata["log_level"] == "OFF" },
}

var awsEventBridgeBusNoPolicy = Check{
	ID:          "aws-eventbridge-bus-no-policy",
	Title:       "EventBridge custom event bus has no resource-based policy",
	Description: "The custom bus has no resource-based policy, so access to it is decided only by identity policies in this account and nothing on the bus itself states who may put events onto it. This is the AWS default for a new bus; a policy makes the intended producers explicit.",
	Remediation: "Attach a policy naming the allowed producers: console EventBridge → Event buses → bus → Permissions, or `aws events put-permission --event-bus-name NAME --policy file://policy.json`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "eventbridge_bus",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["bus_kind"] == "custom" && a.Metadata["has_resource_policy"] == "false"
	},
}

var awsEventBridgeBusPolicyPublic = Check{
	ID:          "aws-eventbridge-bus-policy-public",
	Title:       "EventBridge event bus policy lets any principal put events",
	Description: "The bus's resource-based policy grants events:PutEvents to everyone (Principal \"*\", or an Allow with NotPrincipal, which covers every principal it does not list) with no condition that restricts the caller. Any AWS account can inject events, and every rule on the bus runs its targets — Lambda functions, Step Functions, queues — on attacker-chosen input as if it came from a trusted producer.",
	Remediation: "Replace Principal \"*\" (or the Allow with NotPrincipal) with the producer accounts, or add a Condition on aws:PrincipalOrgID: `aws events remove-permission --event-bus-name NAME --statement-id SID` then `aws events put-permission --event-bus-name NAME --policy file://policy.json`.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "eventbridge_bus",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access"] == asset.PublicAccessConfirmed
	},
	TableProbes: []string{asset.PublicAccessConfirmed},
}

var awsMQAuditLogsDisabled = Check{
	ID:          "aws-mq-audit-logs-disabled",
	Title:       "ActiveMQ broker does not stream audit logs to CloudWatch",
	Description: "Audit logging is off on the ActiveMQ broker, so management actions — users, destinations and configuration changed through JMX or the web console — leave no record.",
	Remediation: "Console Amazon MQ → broker → Edit → CloudWatch Logs → Audit, or `aws mq update-broker --broker-id ID --logs Audit=true,General=true`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "mq_broker",
	Violates:    func(a asset.Asset) bool { return a.Metadata["audit_logs"] == "false" },
}

var awsSESTLSNotRequired = Check{
	ID:          "aws-ses-tls-not-required",
	Title:       "SES configuration set does not require TLS for delivery",
	Description: "The configuration set's TLS policy is OPTIONAL: SES tries TLS but delivers in plain text when the receiving mail server cannot negotiate it, so mail sent through this set can cross the internet unencrypted.",
	Remediation: "Console SES → Configuration sets → set → Delivery options → Require TLS, or `aws sesv2 put-configuration-set-delivery-options --configuration-set-name NAME --tls-policy REQUIRE` (mail to servers without TLS then bounces).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ses_configuration_set",
	Violates:    func(a asset.Asset) bool { return a.Metadata["tls_policy"] == "OPTIONAL" },
}

var awsServiceCatalogPortfolioAccountShare = Check{
	ID:          "aws-servicecatalog-portfolio-account-share",
	Title:       "Service Catalog portfolio is shared directly with individual accounts",
	Description: "The portfolio is shared account by account rather than through AWS Organizations. An account share outlives the account's membership — it keeps working after the account leaves the organization — and nothing bounds it to the organization, so the products and their launch roles can end up provisionable from outside it.",
	Remediation: "Enable the Organizations integration (`aws servicecatalog enable-aws-organizations-access` from the management account), share to the organization or an OU (`aws servicecatalog create-portfolio-share --portfolio-id ID --organization-node Type=ORGANIZATIONAL_UNIT,Value=ou-…`), then remove each account share (`aws servicecatalog delete-portfolio-share --portfolio-id ID --account-id ACCOUNT`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "servicecatalog_portfolio",
	Violates:    func(a asset.Asset) bool { return a.Metadata["account_shares"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"accounts": a.Metadata["account_shares"]}
	},
}

var awsConnectFlowLogsDisabled = Check{
	ID:          "aws-connect-flow-logs-disabled",
	Title:       "Amazon Connect instance does not log flows to CloudWatch",
	Description: "Flow logging is off on the Connect instance, so what each contact flow did with a caller — the blocks run, the data collected, the Lambda functions invoked — is not recorded.",
	Remediation: "Console Amazon Connect → instance → Flows → Enable flow logs, or `aws connect update-instance-attribute --instance-id ID --attribute-type CONTACTFLOW_LOGS --value true`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "connect_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["contact_flow_logs"] == "false" },
}

var awsDataSyncTaskLoggingDisabled = Check{
	ID:          "aws-datasync-task-logging-disabled",
	Title:       "DataSync task does not log to CloudWatch",
	Description: "The task either publishes at log level OFF or, in Basic mode, has no CloudWatch log group, so which files it copied, skipped or failed to verify is not recorded. Enhanced-mode tasks log to /aws/datasync without a log group set and are graded on the log level only.",
	Remediation: "Console DataSync → task → Edit → Task logging (log level Basic or Transfer, and a log group), or `aws datasync update-task --task-arn ARN --cloud-watch-log-group-arn LOG_GROUP_ARN --options LogLevel=BASIC`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "datasync_task",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["log_level"] == "OFF" || (observedNone(a, "log_group") && a.Metadata["task_mode"] != "ENHANCED")
	},
}

var awsPCARootCAActive = Check{
	ID:          "aws-pca-root-ca-active",
	Title:       "AWS Private CA root certificate authority is enabled",
	Description: "A root CA is active. Best practice is to use the root only to sign subordinate CAs and keep it disabled otherwise, so its key — the trust anchor for every certificate below it — cannot be used to issue end-entity certificates day to day.",
	Remediation: "Issue end-entity certificates from a subordinate CA, then disable the root until it is next needed: console AWS Private CA → root CA → Actions → Disable, or `aws acm-pca update-certificate-authority --certificate-authority-arn ARN --status DISABLED`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "acmpca_certificate_authority",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["ca_type"] == "ROOT" && a.Metadata["ca_status"] == "ACTIVE"
	},
}

func awsAppIntegrationChecks() []Check {
	return []Check{
		awsWorkSpacesUserVolumeUnencrypted,
		awsWorkSpacesRootVolumeUnencrypted,
		awsTransferServerFTPEnabled,
		awsTransferConnectorNoLogging,
		awsCFNStackNoTerminationProtection,
		awsCFNStackNoServiceRole,
		awsStepFunctionsLoggingDisabled,
		awsEventBridgeBusNoPolicy,
		awsEventBridgeBusPolicyPublic,
		awsMQAuditLogsDisabled,
		awsSESTLSNotRequired,
		awsServiceCatalogPortfolioAccountShare,
		awsConnectFlowLogsDisabled,
		awsDataSyncTaskLoggingDisabled,
		awsPCARootCAActive,
	}
}
