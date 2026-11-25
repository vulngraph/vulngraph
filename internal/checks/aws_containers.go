package checks

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// EKS cluster and ECS task-definition posture from fields eks:DescribeCluster,
// ecs:DescribeTaskDefinition, ecs:DescribeServices and ecs:DescribeClusters
// already return (AWS FSBP EKS.3/EKS.8, ECS.3/4/5/8/9/10/12/18/20/21).
//
// ECS task-definition checks grade the per-service "container" asset (one per
// container definition) or the ecs_service for task-level settings, because
// the collector reads task definitions through the services that run them.

// ── EKS ──────────────────────────────────────────────────────────────────────

var awsEKSSecretsNotEncrypted = Check{
	ID:          "aws-eks-secrets-not-encrypted",
	Title:       "EKS cluster does not envelope-encrypt Kubernetes secrets with a KMS key",
	Description: "No KMS key is configured to envelope-encrypt the cluster's Kubernetes secrets. EKS encrypts etcd volumes at rest and, on current platform versions, envelope-encrypts API data with an AWS-owned key; a customer-managed key adds a control you own — key policy, CloudTrail on every decrypt, and the ability to revoke — over secrets that hold service-account tokens and application credentials.",
	Remediation: "Associate a KMS key: `aws eks associate-encryption-config --cluster-name NAME --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"KEY_ARN\"}}]'` (it cannot be removed once enabled).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["secrets_encryption"] == "false" },
}

var awsEKSAuditLoggingDisabled = Check{
	ID:          "aws-eks-audit-logging-disabled",
	Title:       "EKS control-plane audit logging is disabled",
	Description: "The cluster does not ship Kubernetes audit logs to CloudWatch. The audit log is the only record of who called the API server — which identity read a secret, created a privileged pod or bound cluster-admin — so without it an intrusion through the control plane leaves no trail.",
	Remediation: "`aws eks update-cluster-config --name NAME --logging '{\"clusterLogging\":[{\"types\":[\"audit\"],\"enabled\":true}]}'` (add authenticator for IAM-to-Kubernetes mapping events).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["audit_logging"] == "false" },
}

var awsEKSAuthConfigMapOnly = Check{
	ID:          "aws-eks-auth-configmap-only",
	Title:       "EKS cluster authorizes IAM principals only through the aws-auth ConfigMap",
	Description: "The cluster's authentication mode is CONFIG_MAP, so IAM-to-Kubernetes access lives only in the aws-auth ConfigMap — an object anyone with edit rights in kube-system can rewrite to grant themselves cluster-admin, invisible to IAM and to EKS's access-entry APIs, and one malformed edit away from locking every administrator out. AWS has deprecated it in favour of access entries.",
	Remediation: "Switch to access entries: `aws eks update-cluster-config --name NAME --access-config authenticationMode=API_AND_CONFIG_MAP`, migrate the aws-auth mappings to access entries, then move to API.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["authentication_mode"] == "CONFIG_MAP" },
}

// ── ECS containers ───────────────────────────────────────────────────────────

var awsECSContainerPrivileged = Check{
	ID:          "aws-ecs-container-privileged",
	Title:       "ECS container runs privileged",
	Description: "The task definition sets privileged=true for this container, giving it root on the host: every device, every kernel capability, and the ability to load modules or mount the host file system. A compromise of the container is a compromise of the EC2 instance and every task on it.",
	Remediation: "Remove privileged=true; grant only the specific Linux capabilities the workload needs (linuxParameters.capabilities.add) and register a new task definition revision.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "container",
	Violates:    func(a asset.Asset) bool { return a.Metadata["privileged"] == "true" },
}

var awsECSContainerWritableRootFS = Check{
	ID:          "aws-ecs-container-writable-root-fs",
	Title:       "ECS container has a writable root file system",
	Description: "readonlyRootFilesystem is not set, so a process in the container can modify its own binaries and drop tooling anywhere in the image, which makes persistence after a compromise trivial.",
	Remediation: "Set readonlyRootFilesystem=true and mount writable volumes only where the application writes (e.g. /tmp).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "container",
	// Windows containers cannot use a read-only root file system (FSBP ECS.5
	// does not apply to them).
	Violates: func(a asset.Asset) bool {
		return a.Metadata["readonly_root_fs"] == "false" && !strings.HasPrefix(a.Metadata["os_family"], "WINDOWS")
	},
}

// awsCredentialEnvNames mirrors the collector's FSBP ECS.8 list: these names
// hold a static AWS (or registry) credential.
var awsCredentialEnvNames = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "ECS_ENGINE_AUTH_DATA"}

func plaintextSecretEnvNames(a asset.Asset) []string {
	raw := a.Metadata["plaintext_secret_env"]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

var awsECSContainerPlaintextSecretEnv = Check{
	ID:          "aws-ecs-container-plaintext-secret-env",
	Title:       "ECS container definition holds a credential in a plaintext environment variable",
	Description: "An environment variable in the task definition carries a credential in clear — an AWS access key, registry auth data, or a password/token-named variable with a literal value. Task definitions are readable by anyone with ecs:DescribeTaskDefinition, kept forever across revisions, and printed by deployment tooling; the secret is effectively published to everyone with read access to ECS.",
	Remediation: "Move the value to Secrets Manager or SSM Parameter Store and reference it through the container definition's `secrets` field; rotate the exposed credential, since every existing revision still contains it. Replace static AWS keys with the task role.",
	// Not "exposure": the secret is readable by principals with ECS read
	// access, not reachable from the internet, and enrichment treats the
	// exposure type as an internet-facing asset.
	Type:      "misconfiguration",
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderAWS,
	AssetType: "container",
	Violates:  func(a asset.Asset) bool { return a.Metadata["plaintext_secret_env"] != "" },
	// A static AWS credential is High: it authenticates as an IAM principal
	// from anywhere. Other secret-named literals are Medium.
	SeverityFor: func(a asset.Asset) finding.Severity {
		for _, n := range plaintextSecretEnvNames(a) {
			if slices.Contains(awsCredentialEnvNames, strings.ToUpper(n)) {
				return finding.SeverityHigh
			}
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"variables": a.Metadata["plaintext_secret_env"]}
	},
}

var awsECSContainerNoLogging = Check{
	ID:          "aws-ecs-container-no-logging",
	Title:       "ECS container has no log configuration",
	Description: "The container definition sets no logConfiguration, so its stdout/stderr go nowhere durable and the evidence of what ran in the container disappears with the task.",
	Remediation: "Add a logConfiguration (e.g. logDriver awslogs or awsfirelens) to the container definition.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "container",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "log_driver") },
}

// ecsRootUser reports an explicit administrative user: root/UID 0 on Linux,
// ContainerAdministrator on Windows.
func ecsRootUser(user string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	name, _, _ := strings.Cut(u, ":")
	return name == "root" || name == "0" || u == "containeradministrator"
}

var awsECSContainerRunsAsRoot = Check{
	ID:          "aws-ecs-container-runs-as-root",
	Title:       "ECS container may run as root",
	Description: "The container definition either names an administrative user (root, UID 0, or ContainerAdministrator on Windows) or sets no user at all, in which case the image's USER decides and most images default to root. A process running as root inside the container needs one kernel or runtime bug to become root on the host.",
	Remediation: "Set `user` in the container definition to a non-root UID (Linux) or ContainerUser (Windows), and build images with a non-root USER.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "container",
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "user") || ecsRootUser(a.Metadata["user"])
	},
	// Explicit root is Medium; an unset user defers to the image, which the
	// task definition cannot show, so it is Low.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if ecsRootUser(a.Metadata["user"]) {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if ecsRootUser(a.Metadata["user"]) {
			return "ECS container runs as root"
		}
		return "ECS container sets no user and may run as root"
	},
}

// ── ECS task and service ─────────────────────────────────────────────────────

var awsECSTaskSharesHostNamespace = Check{
	ID:          "aws-ecs-task-shares-host-namespace",
	Title:       "ECS task shares the host's process or network namespace",
	Description: "The task definition sets pidMode=host or networkMode=host. With the host PID namespace, containers see and can signal every process on the instance; with host networking, they bind host ports directly and bypass the task-level security groups awsvpc mode gives each task.",
	Remediation: "Remove pidMode=host and use awsvpc network mode unless the workload is a node-level agent that genuinely needs host access.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_service",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["pid_mode"] == "host" || a.Metadata["network_mode"] == "host"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"pid_mode": a.Metadata["pid_mode"], "network_mode": a.Metadata["network_mode"]}
	},
}

var awsECSTaskEFSNoTransitEncryption = Check{
	ID:          "aws-ecs-task-efs-no-transit-encryption",
	Title:       "ECS task mounts EFS without in-transit encryption",
	Description: "An EFS volume in the task definition has transitEncryption disabled, so file data travels between the task and the file system as plaintext NFS on the VPC network.",
	Remediation: "Set efsVolumeConfiguration.transitEncryption=ENABLED for every EFS volume and register a new task definition revision.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["efs_volumes_plaintext"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"volumes": a.Metadata["efs_volumes_plaintext"]}
	},
}

// fargateCurrentPlatform reports whether a Fargate platform version is the
// latest for its OS family (Linux 1.4.0, Windows 1.0.0) or tracks LATEST.
func fargateCurrentPlatform(version, osFamily string) bool {
	if version == "LATEST" {
		return true
	}
	if strings.HasPrefix(osFamily, "WINDOWS") {
		return version == "1.0.0"
	}
	return version == "1.4.0"
}

var awsECSFargateOldPlatform = Check{
	ID:          "aws-ecs-fargate-old-platform",
	Title:       "Fargate service is pinned to an old platform version",
	Description: "The service runs on Fargate (launch type FARGATE, or a FARGATE / FARGATE_SPOT capacity-provider strategy) on a platform version older than the current one (Linux 1.4.0, Windows 1.0.0). Platform versions bundle the kernel and container runtime the tasks run on; an old pin misses their security fixes.",
	Remediation: "Update the service to platform version LATEST (`aws ecs update-service --platform-version LATEST --force-new-deployment`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_service",
	Violates: func(a asset.Asset) bool {
		pv := a.Metadata["platform_version"]
		fargate := a.Metadata["launch_type"] == "FARGATE" || a.Metadata["capacity_provider_fargate"] == "true"
		return fargate && pv != "" && !fargateCurrentPlatform(pv, a.Metadata["os_family"])
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"platform_version": a.Metadata["platform_version"]}
	},
}

var awsECSClusterNoContainerInsights = Check{
	ID:          "aws-ecs-cluster-no-container-insights",
	Title:       "ECS cluster has Container Insights disabled",
	Description: "Container Insights is disabled on the cluster, so per-task CPU, memory, network and restart metrics are not collected. Operational visibility only.",
	Remediation: "`aws ecs update-cluster-settings --cluster NAME --settings name=containerInsights,value=enhanced`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["container_insights"] == "disabled" },
}

func awsContainerChecks() []Check {
	return []Check{
		awsEKSSecretsNotEncrypted,
		awsEKSAuditLoggingDisabled,
		awsEKSAuthConfigMapOnly,
		awsECSContainerPrivileged,
		awsECSContainerWritableRootFS,
		awsECSContainerPlaintextSecretEnv,
		awsECSContainerNoLogging,
		awsECSContainerRunsAsRoot,
		awsECSTaskSharesHostNamespace,
		awsECSTaskEFSNoTransitEncryption,
		awsECSFargateOldPlatform,
		awsECSClusterNoContainerInsights,
	}
}
