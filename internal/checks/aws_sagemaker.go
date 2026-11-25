package checks

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// SageMaker notebook, model, endpoint-configuration, Model Monitor and
// Feature Store posture (AWS FSBP SageMaker.1-5, .8-.17, .19-.22, .25).

// sageMakerSupportedPlatforms is FSBP SageMaker.8's supportedPlatformIdentifierVersions
// (not customizable): every other notebook platform no longer gets security updates.
var sageMakerSupportedPlatforms = map[string]bool{"notebook-al2023-v1": true}

var awsSageMakerNotebookNoVPC = Check{
	ID:          "aws-sagemaker-notebook-not-in-custom-vpc",
	Title:       "SageMaker notebook instance is not in a custom VPC",
	Description: "The notebook instance runs either outside any customer VPC — in the SageMaker service network, where it always has direct internet access and none of the VPC's security groups, NACLs, endpoints or flow logs apply — or in the account's default VPC, whose subnets are public by default and which nothing about the notebook's data or role was designed for. A notebook holds an IAM role and usually training data.",
	Remediation: "The VPC cannot be changed in place: stop and delete the notebook (`aws sagemaker stop-notebook-instance` / `delete-notebook-instance`), then recreate it with `--subnet-id` and `--security-group-ids` in a private subnet of a VPC you built, and `--direct-internet-access Disabled`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_notebook",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "subnet_id") || a.Metadata["in_default_vpc"] == "true"
	},
	// Outside any VPC is Medium (direct internet, no network controls); the
	// default VPC still has network controls and is Low.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if observedNone(a, "subnet_id") {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if observedNone(a, "subnet_id") {
			return "SageMaker notebook instance runs outside any VPC with direct internet access"
		}
		return "SageMaker notebook instance runs in the default VPC"
	},
}

var awsSageMakerNotebookDirectInternet = Check{
	ID:          "aws-sagemaker-notebook-direct-internet-access",
	Title:       "SageMaker notebook instance in a VPC still has direct internet access",
	Description: "The notebook is attached to a VPC subnet but DirectInternetAccess is Enabled, so SageMaker gives it a second network interface with its own route to the internet that bypasses the VPC's NAT, firewalls, endpoints and flow logs. Code in the notebook — or anyone who obtains its presigned URL — can move data and the notebook role's credentials straight out. A notebook outside any VPC is reported by aws-sagemaker-notebook-not-in-custom-vpc instead.",
	Remediation: "The setting cannot be changed in place: stop and delete the notebook, then recreate it in the same subnet with `--direct-internet-access Disabled` and give the VPC a NAT gateway or VPC endpoints for the services it needs.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_notebook",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["direct_internet_access"] == "true" && a.Metadata["subnet_id"] != ""
	},
}

var awsSageMakerNotebookRootAccess = Check{
	ID:          "aws-sagemaker-notebook-root-access",
	Title:       "SageMaker notebook instance grants users root access",
	Description: "RootAccess is Enabled, so every user who can open the notebook can become root on the instance: install software, read other users' files and undo what the lifecycle configuration set up. It is the SageMaker default, and anyone who can open the notebook already acts with its IAM role, so this is a hardening gap (Low) rather than an escalation.",
	Remediation: "Console: SageMaker > Notebook instances > stop the instance > Edit > Root access: Disable. CLI: `aws sagemaker stop-notebook-instance --notebook-instance-name NAME` then `aws sagemaker update-notebook-instance --notebook-instance-name NAME --root-access Disabled`. Lifecycle configurations still run as root.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_notebook",
	Violates:    func(a asset.Asset) bool { return a.Metadata["root_access"] == "true" },
}

var awsSageMakerNotebookUnsupportedPlatform = Check{
	ID:          "aws-sagemaker-notebook-unsupported-platform",
	Title:       "SageMaker notebook instance runs on an unsupported platform",
	Description: "The notebook's platform identifier is not one SageMaker still supports (notebook-al2023-v1), so the instance no longer receives SageMaker security patches or fixes for its operating system and Jupyter stack.",
	Remediation: "Platform identifiers cannot be changed in place: create a new notebook instance with `--platform-identifier notebook-al2023-v1`, move notebooks and data across, and delete the old instance.",
	Type:        "vulnerability",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_notebook",
	Violates: func(a asset.Asset) bool {
		p := a.Metadata["platform_identifier"]
		return p != "" && !sageMakerSupportedPlatforms[p]
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"platform_identifier": a.Metadata["platform_identifier"]}
	},
}

var awsSageMakerEndpointSingleInstance = Check{
	ID:          "aws-sagemaker-endpoint-single-instance",
	Title:       "SageMaker endpoint configuration starts a variant on a single instance",
	Description: "An instance-based production variant has InitialInstanceCount 1, so the endpoint runs on one instance in one Availability Zone and an instance or zone failure takes it down. Availability only.",
	Remediation: "Create a new endpoint configuration with InitialInstanceCount of 2 or more for each production variant and update the endpoint to it (`aws sagemaker create-endpoint-config` then `aws sagemaker update-endpoint`).",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_endpoint_config",
	Violates:    func(a asset.Asset) bool { return a.Metadata["single_instance_variants"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"variants": a.Metadata["single_instance_variants"]}
	},
}

var awsSageMakerModelNoNetworkIsolation = Check{
	ID:          "aws-sagemaker-model-no-network-isolation",
	Title:       "SageMaker model does not enable network isolation",
	Description: "EnableNetworkIsolation is false, so the model's inference container can make outbound network calls and receives AWS credentials at runtime. A compromised or malicious model artefact can then reach the internet or other AWS services from inside the endpoint.",
	Remediation: "Network isolation is set at creation: create a new model with `aws sagemaker create-model ... --enable-network-isolation`, point a new endpoint configuration at it and update the endpoint.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_model",
	Violates:    func(a asset.Asset) bool { return a.Metadata["network_isolation"] == "false" },
}

var awsSageMakerModelPrimaryImageNotVPC = Check{
	ID:          "aws-sagemaker-model-primary-image-not-vpc-registry",
	Title:       "SageMaker model's primary container image is not pulled through the VPC",
	Description: "The model's primary container sets no image configuration, or RepositoryAccessMode Platform, so SageMaker pulls the image over its own network rather than from a private registry reached through your VPC endpoints. The pull path is outside the VPC's controls.",
	Remediation: "Recreate the model with `PrimaryContainer.ImageConfig.RepositoryAccessMode=Vpc` and an image in a registry reachable from the model's VPC (see 'Use a private Docker registry for real-time inference containers').",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_model",
	Violates: func(a asset.Asset) bool {
		mode, ok := a.Metadata["primary_image_access_mode"]
		return ok && mode != "Vpc"
	},
}

var awsSageMakerModelPipelineImageNotVPC = Check{
	ID:          "aws-sagemaker-model-pipeline-image-not-vpc-registry",
	Title:       "SageMaker inference pipeline pulls container images outside the VPC",
	Description: "At least one container in the model's multi-container inference pipeline sets no image configuration or uses RepositoryAccessMode Platform, so its image is pulled over SageMaker's network rather than from a private registry through your VPC.",
	Remediation: "Recreate the model with `ImageConfig.RepositoryAccessMode=Vpc` on every entry in `Containers`, using images in a registry reachable from the model's VPC.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_model",
	Violates:    func(a asset.Asset) bool { return a.Metadata["pipeline_containers_not_vpc_registry"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"containers": a.Metadata["pipeline_containers_not_vpc_registry"]}
	},
}

var awsSageMakerMonitoringJobNoNetworkIsolation = Check{
	ID:          "aws-sagemaker-monitoring-job-no-network-isolation",
	Title:       "SageMaker Model Monitor job definition does not enable network isolation",
	Description: "The data-quality, model-bias, model-quality or model-explainability job definition leaves EnableNetworkIsolation off, so the monitoring container — which reads captured inference data and baselines — can make outbound network calls.",
	Remediation: "Job definitions cannot be edited: create a new one with `--network-config EnableNetworkIsolation=true` (e.g. `aws sagemaker create-data-quality-job-definition`), point the monitoring schedule at it and delete the old definition.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_monitoring_job_definition",
	Violates:    func(a asset.Asset) bool { return a.Metadata["network_isolation"] == "false" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"job_type": a.Metadata["job_type"]}
	},
}

// sageMakerEncryptionApplies reports whether FSBP grades inter-container
// encryption for this definition: always, except model-bias definitions,
// which SageMaker.15 grades only when they run on two or more instances.
func sageMakerEncryptionApplies(a asset.Asset) bool {
	if a.Metadata["job_type"] != "model_bias" {
		return true
	}
	n, err := strconv.Atoi(a.Metadata["instance_count"])
	return err == nil && n >= 2
}

var awsSageMakerMonitoringJobNoEncryption = Check{
	ID:          "aws-sagemaker-monitoring-job-no-inter-container-encryption",
	Title:       "SageMaker Model Monitor job definition does not encrypt inter-container traffic",
	Description: "EnableInterContainerTrafficEncryption is off, so when the monitoring job runs on several instances the data, baselines and intermediate results they exchange cross the network unencrypted.",
	Remediation: "Job definitions cannot be edited: create a new one with `--network-config EnableInterContainerTrafficEncryption=true`, point the monitoring schedule at it and delete the old definition.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_monitoring_job_definition",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["inter_container_encryption"] == "false" && sageMakerEncryptionApplies(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"job_type": a.Metadata["job_type"], "instance_count": a.Metadata["instance_count"]}
	},
}

var awsSageMakerMonitoringScheduleNoNetworkIsolation = Check{
	ID:          "aws-sagemaker-monitoring-schedule-no-network-isolation",
	Title:       "SageMaker monitoring schedule's inline job does not enable network isolation",
	Description: "The monitoring schedule defines its job inline without EnableNetworkIsolation, so each scheduled monitoring run can make outbound network calls while it reads captured inference data. A schedule that references a separate job definition is graded on that definition by aws-sagemaker-monitoring-job-no-network-isolation.",
	Remediation: "`aws sagemaker update-monitoring-schedule --monitoring-schedule-name NAME --monitoring-schedule-config file://config.json` with `MonitoringJobDefinition.NetworkConfig.EnableNetworkIsolation=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_monitoring_schedule",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["job_definition_inline"] == "true" && a.Metadata["network_isolation"] == "false"
	},
}

var awsSageMakerFeatureGroupOfflineNoKMS = Check{
	ID:          "aws-sagemaker-feature-group-offline-store-no-kms",
	Title:       "SageMaker feature group offline store is not encrypted with a KMS key",
	Description: "The feature group's offline store sets no KMS key, so its S3 data is encrypted only by the bucket's default encryption, with no key policy you control and no CloudTrail record of each decrypt.",
	Remediation: "The offline store's key is set at creation: create a new feature group with `--offline-store-config S3StorageConfig={S3Uri=...,KmsKeyId=KEY_ARN}` and re-ingest, then delete the old group.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_feature_group",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["offline_store"] == "true" && observedNone(a, "offline_store_kms_key")
	},
}

func awsSageMakerChecks() []Check {
	return []Check{
		awsSageMakerNotebookNoVPC,
		awsSageMakerNotebookDirectInternet,
		awsSageMakerNotebookRootAccess,
		awsSageMakerNotebookUnsupportedPlatform,
		awsSageMakerEndpointSingleInstance,
		awsSageMakerModelNoNetworkIsolation,
		awsSageMakerModelPrimaryImageNotVPC,
		awsSageMakerModelPipelineImageNotVPC,
		awsSageMakerMonitoringJobNoNetworkIsolation,
		awsSageMakerMonitoringJobNoEncryption,
		awsSageMakerMonitoringScheduleNoNetworkIsolation,
		awsSageMakerMonitoringScheduleNoEncryption,
		awsSageMakerFeatureGroupOfflineNoKMS,
		awsSageMakerNotebookNoCMK,
	}
}

var awsSageMakerMonitoringScheduleNoEncryption = Check{
	ID:          "aws-sagemaker-monitoring-schedule-no-inter-container-encryption",
	Title:       "SageMaker monitoring schedule's inline job does not encrypt inter-container traffic",
	Description: "The monitoring schedule defines its job inline without EnableInterContainerTrafficEncryption, so when a scheduled run uses several instances the captured data and intermediate results they exchange cross the network unencrypted (FSBP SageMaker.22). A schedule that references a separate job definition is graded on that definition by aws-sagemaker-monitoring-job-no-inter-container-encryption.",
	Remediation: "`aws sagemaker update-monitoring-schedule --monitoring-schedule-name NAME --monitoring-schedule-config file://config.json` with `MonitoringJobDefinition.NetworkConfig.EnableInterContainerTrafficEncryption=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_monitoring_schedule",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["job_definition_inline"] == "true" && a.Metadata["inter_container_encryption"] == "false"
	},
}

var awsSageMakerNotebookNoCMK = Check{
	ID:          "aws-sagemaker-notebook-no-customer-managed-key",
	Title:       "SageMaker notebook storage volume is not encrypted with a customer managed key",
	Description: "The notebook instance sets no KmsKeyId, so its ML storage volume — notebooks, datasets, model artifacts — is encrypted with the AWS managed key, with no key policy you control and no CloudTrail record of each use (FSBP SageMaker.21).",
	Remediation: "KmsKeyId is set only at creation: create a new notebook instance with `aws sagemaker create-notebook-instance ... --kms-key-id KEY_ARN`, move the data across, then delete the old instance.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sagemaker_notebook",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "kms_key_id") },
}
