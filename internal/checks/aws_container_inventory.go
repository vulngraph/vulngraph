package checks

import (
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Container-platform resources graded outside the ECS services and EKS
// clusters aws_containers.go covers (AWS FSBP ECS.3/4/5/8/9/16/18/19/20/21,
// EKS.1, EKS.9, ECR.3).
//
// ecs_task_definition is the latest ACTIVE revision of a task-definition
// family that NO service runs (scheduled and standalone tasks, families a
// service has moved off): the collector does not emit a revision a service
// runs, so these checks and the container/service checks never grade the same
// revision twice. Each mirrors its container/service counterpart's condition
// and severity; the container facts arrive as comma-separated container names.

const ecsTaskDefinitionType = "ecs_task_definition"

func containerList(a asset.Asset, key string) map[string]string {
	return map[string]string{"containers": a.Metadata[key]}
}

var awsECSTaskDefPrivileged = Check{
	ID:          "aws-ecs-task-definition-privileged",
	Title:       "ECS task definition runs a container privileged",
	Description: "The latest active revision of this task definition, which no service runs (scheduled or standalone tasks), sets privileged=true on a container, giving it root on the host: every device, every kernel capability, and the ability to mount the host file system. Any task launched from it compromises the instance it lands on. FSBP ECS.4.",
	Remediation: "Remove privileged=true, grant only the Linux capabilities the workload needs (linuxParameters.capabilities.add), and register a new revision (console: ECS → Task definitions → Create new revision; CLI: `aws ecs register-task-definition`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["privileged_containers"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return containerList(a, "privileged_containers") },
}

var awsECSTaskDefWritableRootFS = Check{
	ID:          "aws-ecs-task-definition-writable-root-fs",
	Title:       "ECS task definition has containers with a writable root file system",
	Description: "readonlyRootFilesystem is not set on these containers of the task definition's latest active revision (one no service runs), so a process in them can modify its own binaries and drop tooling anywhere in the image. Windows task definitions are exempt, as FSBP ECS.5 does not apply to them.",
	Remediation: "Set readonlyRootFilesystem=true on each container, mount writable volumes only where the application writes (e.g. /tmp), and register a new revision (`aws ecs register-task-definition`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["writable_root_fs_containers"] != "" && !strings.HasPrefix(a.Metadata["os_family"], "WINDOWS")
	},
	EvidenceFor: func(a asset.Asset) map[string]string { return containerList(a, "writable_root_fs_containers") },
}

var awsECSTaskDefPlaintextSecretEnv = Check{
	ID:          "aws-ecs-task-definition-plaintext-secret-env",
	Title:       "ECS task definition holds a credential in a plaintext environment variable",
	Description: "A container environment variable in the task definition's latest active revision (one no service runs) carries a credential in clear — an AWS access key, registry auth data, or a password/token-named variable with a literal value. Task definitions are readable by anyone with ecs:DescribeTaskDefinition and kept forever across revisions. FSBP ECS.8.",
	Remediation: "Move the value to Secrets Manager or SSM Parameter Store and reference it through the container definition's `secrets` field; rotate the exposed credential, since every existing revision still contains it, and deregister the old revisions (`aws ecs deregister-task-definition`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["plaintext_secret_env"] != "" },
	// The same grade as the container check: a static AWS credential is High.
	SeverityFor: awsECSContainerPlaintextSecretEnv.SeverityFor,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"variables": a.Metadata["plaintext_secret_env"]}
	},
}

var awsECSTaskDefNoLogging = Check{
	ID:          "aws-ecs-task-definition-no-logging",
	Title:       "ECS task definition has containers with no log configuration",
	Description: "These containers of the task definition's latest active revision (one no service runs) set no logConfiguration, so what a scheduled or standalone task did disappears with it. FSBP ECS.9.",
	Remediation: "Add a logConfiguration (e.g. logDriver awslogs) to each container and register a new revision (`aws ecs register-task-definition`).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["no_log_containers"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return containerList(a, "no_log_containers") },
}

var awsECSTaskDefRunsAsRoot = Check{
	ID:          "aws-ecs-task-definition-runs-as-root",
	Title:       "ECS task definition has containers that may run as root",
	Description: "Containers in the task definition's latest active revision (one no service runs) either name an administrative user (root, UID 0, or ContainerAdministrator on Windows) or set no user, in which case the image's USER decides and most images default to root. FSBP ECS.20 / ECS.21.",
	Remediation: "Set `user` on each container to a non-root UID (Linux) or ContainerUser (Windows), build images with a non-root USER, and register a new revision (`aws ecs register-task-definition`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["root_user_containers"] != "" || a.Metadata["unset_user_containers"] != ""
	},
	// Explicit root is Medium; an unset user defers to the image (Low), as on
	// the container check.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["root_user_containers"] != "" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["root_user_containers"] != "" {
			return "ECS task definition has containers that run as root"
		}
		return "ECS task definition has containers that set no user and may run as root"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"root_user": a.Metadata["root_user_containers"], "no_user": a.Metadata["unset_user_containers"]}
	},
}

var awsECSTaskDefSharesHostNamespace = Check{
	ID:          "aws-ecs-task-definition-shares-host-namespace",
	Title:       "ECS task definition shares the host's process or network namespace",
	Description: "The task definition's latest active revision (one no service runs) sets pidMode=host or networkMode=host: its containers see and can signal every process on the instance, or bind host ports directly outside task-level security groups. FSBP ECS.3.",
	Remediation: "Remove pidMode=host, use awsvpc network mode, and register a new revision (`aws ecs register-task-definition`), unless the task is a node-level agent that genuinely needs host access.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["pid_mode"] == "host" || a.Metadata["network_mode"] == "host"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"pid_mode": a.Metadata["pid_mode"], "network_mode": a.Metadata["network_mode"]}
	},
}

var awsECSTaskDefEFSNoTransitEncryption = Check{
	ID:          "aws-ecs-task-definition-efs-no-transit-encryption",
	Title:       "ECS task definition mounts EFS without in-transit encryption",
	Description: "An EFS volume in the task definition's latest active revision (one no service runs) has transitEncryption disabled, so file data travels as plaintext NFS on the VPC network. FSBP ECS.18.",
	Remediation: "Set efsVolumeConfiguration.transitEncryption=ENABLED for every EFS volume and register a new revision (`aws ecs register-task-definition`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   ecsTaskDefinitionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["efs_volumes_plaintext"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"volumes": a.Metadata["efs_volumes_plaintext"]}
	},
}

var awsECSTaskSetPublicIP = Check{
	ID:          "aws-ecs-task-set-public-ip",
	Title:       "ECS task set assigns public IPs to its tasks",
	Description: "A task set of this service (an EXTERNAL or CODE_DEPLOY deployment) sets assignPublicIp=ENABLED, so each of its tasks gets a public IP and is directly reachable from the internet. A service whose own network configuration assigns public IPs is reported by ecs-service-assign-public-ip instead. FSBP ECS.16.",
	Remediation: "Recreate the task set with assignPublicIp=DISABLED in private subnets behind a load balancer (`aws ecs create-task-set ... --network-configuration 'awsvpcConfiguration={subnets=[...],assignPublicIp=DISABLED}'`, then delete the public one).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_service",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["task_sets_public_ip"] != "" && a.Metadata["assign_public_ip"] != "ENABLED"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"task_sets": a.Metadata["task_sets_public_ip"]}
	},
}

var awsECSCapacityProviderNoTerminationProtection = Check{
	ID:          "aws-ecs-capacity-provider-no-termination-protection",
	Title:       "ECS capacity provider has managed termination protection disabled",
	Description: "Managed termination protection is off on this Auto Scaling group capacity provider, so a scale-in can terminate EC2 instances that still run tasks instead of draining them first. Availability only. FSBP ECS.19.",
	Remediation: "Enable scale-in protection on the Auto Scaling group, then `aws ecs update-capacity-provider --name NAME --auto-scaling-group-provider 'managedScaling={status=ENABLED},managedTerminationProtection=ENABLED'` (console: ECS → cluster → Infrastructure → capacity provider → Update). Managed scaling must be on for it to take effect.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_capacity_provider",
	Violates:    func(a asset.Asset) bool { return a.Metadata["managed_termination_protection"] == "DISABLED" },
}

// ── EKS ──────────────────────────────────────────────────────────────────────

var awsEKSPublicEndpointRestricted = Check{
	ID:          "aws-eks-public-endpoint-restricted",
	Title:       "EKS cluster API server is public, restricted to specific CIDRs",
	Description: "The cluster's Kubernetes API endpoint is publicly reachable, limited by publicAccessCidrs to specific ranges rather than the whole internet. Narrower than a world-open endpoint (aws-eks-public-endpoint), but the control plane still answers from the internet within those ranges and the allowlist must be maintained by hand. FSBP EKS.1 fails any public endpoint.",
	Remediation: "Turn on private endpoint access and turn off public access (`aws eks update-cluster-config --name NAME --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=false`; console: EKS → cluster → Networking → Manage endpoint access), reaching the API over VPN or a bastion.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	// An empty allowlist was not reported and is unknown; a world-open one is
	// aws-eks-public-endpoint's finding.
	Violates: func(a asset.Asset) bool {
		cidrs := a.Metadata["public_access_cidrs"]
		return a.Metadata["endpoint_public_access"] == "true" && cidrs != "" && !csvHasWorldCIDR(cidrs)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_access_cidrs": a.Metadata["public_access_cidrs"]}
	},
}

// eksPastStandardSupport reports a version in extended support or past it.
func eksPastStandardSupport(version string, now time.Time) bool {
	return slices.Contains([]string{"extended", "ended"}, eksSupportPhase(version, now))
}

var awsEKSNodegroupUnsupportedVersion = Check{
	ID:          "aws-eks-nodegroup-unsupported-version",
	Title:       "EKS node group runs a Kubernetes version past standard support",
	Description: "This managed node group's Kubernetes minor version is past the end of EKS standard support while its cluster's control plane is not: EKS does not upgrade node groups, so the nodes (kubelet and the EKS-optimized AMI) miss the fixes the control plane gets. A node group on a cluster that is itself past standard support is covered by that cluster's aws-eks-unsupported-version finding, whose upgrade includes its node groups. FSBP EKS.9.",
	Remediation: "Update the node group to the cluster's version (`aws eks update-nodegroup-version --cluster-name CLUSTER --nodegroup-name NAME`; console: EKS → cluster → Compute → node group → Update now).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_nodegroup",
	Violates: func(a asset.Asset) bool {
		now := time.Now()
		return eksPastStandardSupport(a.Metadata["version"], now) && !eksPastStandardSupport(a.Metadata["cluster_version"], now)
	},
	// As the cluster check: still patched in extended support (Low), unpatched past it (High).
	SeverityFor: func(a asset.Asset) finding.Severity {
		if eksSupportPhase(a.Metadata["version"], time.Now()) == "ended" {
			return finding.SeverityHigh
		}
		return finding.SeverityLow
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"version": a.Metadata["version"], "cluster_version": a.Metadata["cluster_version"],
			"support_phase": eksSupportPhase(a.Metadata["version"], time.Now()),
		}
	},
	TableProbes: append([]string{"1.20"}, eksCalendarKeys()...),
}

// ── ECR ──────────────────────────────────────────────────────────────────────

var awsECRNoLifecyclePolicy = Check{
	ID:          "aws-ecr-no-lifecycle-policy",
	Title:       "ECR repository has no lifecycle policy",
	Description: "The repository keeps every image ever pushed. Old images with known vulnerabilities stay pullable by tag or digest, and storage grows without bound. Hygiene. FSBP ECR.3.",
	Remediation: "Add a lifecycle policy that expires untagged and old images (console: ECR → repository → Lifecycle policy; CLI: `aws ecr put-lifecycle-policy --repository-name NAME --lifecycle-policy-text file://policy.json`).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecr_repository",
	Violates:    func(a asset.Asset) bool { return a.Metadata["lifecycle_policy"] == "false" },
}

func awsContainerInventoryChecks() []Check {
	return []Check{
		awsECSTaskDefPrivileged,
		awsECSTaskDefWritableRootFS,
		awsECSTaskDefPlaintextSecretEnv,
		awsECSTaskDefNoLogging,
		awsECSTaskDefRunsAsRoot,
		awsECSTaskDefSharesHostNamespace,
		awsECSTaskDefEFSNoTransitEncryption,
		awsECSTaskSetPublicIP,
		awsECSCapacityProviderNoTerminationProtection,
		awsEKSPublicEndpointRestricted,
		awsEKSNodegroupUnsupportedVersion,
		awsECRNoLifecyclePolicy,
	}
}
