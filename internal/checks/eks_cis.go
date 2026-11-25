package checks

// eks_cis.go — CIS EKS 1.8.0 controls from data the collectors already hold:
// eks:DescribeCluster fields on eks_cluster (logging, endpoint access), the
// node role's ECR grants joined onto EKS worker instances, and the cluster's
// NetworkPolicy enforcers read through the Kubernetes API.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// awsEKSControlPlaneLogsIncomplete steps aside while audit logging itself is
// off: aws-eks-audit-logging-disabled reports that, the more important half of
// the same setting.
var awsEKSControlPlaneLogsIncomplete = Check{
	ID:          "aws-eks-control-plane-logs-incomplete",
	Title:       "EKS cluster does not ship every control-plane log type",
	Description: "Audit logging is on, but one or more of the api, authenticator, controllerManager and scheduler log types is not sent to CloudWatch. The authenticator log is the only record of which IAM principal became which Kubernetes user (CIS EKS 2.1.1).",
	Remediation: "Console: EKS > cluster > Observability > Manage logging, enable all five types. CLI: `aws eks update-cluster-config --name NAME --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["logging_disabled_types"]
		return ok && v != "" && a.Metadata["audit_logging"] == "true"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"logging_disabled_types": a.Metadata["logging_disabled_types"]}
	},
}

// awsEKSPublicEndpointEnabled steps aside for a world-open endpoint, which
// aws-eks-public-endpoint reports at High.
var awsEKSPublicEndpointEnabled = Check{
	ID:          "aws-eks-public-endpoint-enabled",
	Title:       "EKS cluster API server has a public endpoint",
	Description: "The cluster's public API endpoint is enabled, restricted to the CIDRs in public_access_cidrs. CIS EKS 5.4.2 asks for the private endpoint only, so the API server cannot be reached from the internet at all, even by an allowlisted address whose credentials leaked.",
	Remediation: "Console: EKS > cluster > Networking > Manage endpoint access, choose Private. CLI: `aws eks update-cluster-config --name NAME --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true`. Reach the API from inside the VPC (VPN, bastion or a CI runner in the VPC) first.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["endpoint_public_access"] == "true" && !csvHasWorldCIDR(a.Metadata["public_access_cidrs"])
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_access_cidrs": a.Metadata["public_access_cidrs"]}
	},
}

// awsEKSNodeRoleECRWrite is graded on the instance role, once however many
// nodes use it (the collector stamps the node facts onto the role,
// collect/aws/node_registry.go). It steps aside when any of those nodes
// answers IMDSv1: aws-eks-node-imdsv1-registry-write reports that combination
// at High on the instance.
var awsEKSNodeRoleECRWrite = Check{
	ID:          "aws-eks-node-role-ecr-write",
	Title:       "Kubernetes node instance role can push to ECR",
	Description: "This IAM role is the instance role of EKS worker nodes and grants ecr:PutImage. Any pod that reaches the node's credentials, through the metadata endpoint or a host compromise, can overwrite images the cluster pulls. Nodes need only AmazonEC2ContainerRegistryReadOnly (CIS EKS 5.1.3).",
	Remediation: "Detach the ECR write policy from the role and attach AmazonEC2ContainerRegistryReadOnly. Console: IAM > Roles > ROLE > Permissions. CLI: `aws iam detach-role-policy --role-name ROLE --policy-arn ARN` then `aws iam attach-role-policy --role-name ROLE --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly`. Push from CI with its own role.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["k8s_node_role"] == "true" && a.Metadata["ecr_push"] == "true" && a.Metadata["k8s_node_imdsv1"] != "true"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"k8s_node_count": a.Metadata["k8s_node_count"]}
	},
}

// k8sNoNetworkPolicyEngine steps aside on GKE, where the networkPolicy addon
// and Dataplane V2 are read from the GKE API by gcp-gke checks (CIS GKE 4.3.1).
// Off EKS the engine list (collect/kubernetes/netpol_engine.go) is a closed
// set an unknown enforcer is missing from, so it reports at Low there.
var k8sNoNetworkPolicyEngine = Check{
	ID:          "k8s-no-network-policy-engine",
	Title:       "Cluster runs no known NetworkPolicy enforcer",
	Description: "No NetworkPolicy enforcer was found: the Amazon VPC CNI's network policy controller is off (kube-system/amazon-vpc-cni enable-network-policy-controller) and no Calico, Cilium, Antrea, kube-router, Weave, Azure NPM or GKE Dataplane V2 node agent runs. NetworkPolicy objects are then accepted and ignored, so every pod can reach every other (CIS Kubernetes 5.3.1, CIS EKS 4.3.1, 5.4.4). An enforcer outside that list is not recognised.",
	Remediation: "EKS: enable network policy in the VPC CNI add-on. Console: EKS > cluster > Add-ons > Amazon VPC CNI > Edit, configuration values {\"enableNetworkPolicy\": \"true\"}. CLI: `aws eks update-addon --cluster-name NAME --addon-name vpc-cni --configuration-values '{\"enableNetworkPolicy\":\"true\"}'`. Elsewhere install a policy-capable CNI (Calico, Cilium) or, on AKS, create the cluster with --network-policy azure|calico|cilium.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloud_provider"] != "gcp" && observedNone(a, "network_policy_engines")
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["cloud_provider"] == "aws" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
}

// eksCISChecks are this file's checks.
func eksCISChecks() []Check {
	return []Check{
		awsEKSControlPlaneLogsIncomplete,
		awsEKSPublicEndpointEnabled,
		awsEKSNodeRoleECRWrite,
		k8sNoNetworkPolicyEngine,
	}
}
