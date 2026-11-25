package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// eksNodeIMDSv1RegistryWrite is the pairing that turns aws-ec2-imdsv2-not-required
// from a hygiene gap into a supply-chain path: every pod on a node shares the
// node's metadata endpoint, so one SSRF in any workload returns the node role's
// credentials over IMDSv1, and a node role that can push to ECR lets the
// attacker replace images the whole cluster pulls.
//
// k8s_node (from the instance's EKS/Kubernetes tags) and iam_role_ecr_push (from
// the instance role's policies) are joined onto the instance by the AWS
// collector (internal/collect/aws/node_registry.go). iam_role_ecr_push is
// absent when the role or its policy set was not observed, which keeps this
// silent and leaves aws-ec2-imdsv2-not-required to report the instance. When
// this fires, that check steps aside so the instance carries one finding.
var eksNodeIMDSv1RegistryWrite = Check{
	ID:          "aws-eks-node-imdsv1-registry-write",
	Title:       "Kubernetes node allows IMDSv1 and its instance role can push to ECR",
	Description: "This EC2 instance is a Kubernetes (EKS) worker node, its instance metadata service accepts IMDSv1 requests (HttpTokens=optional), and its instance role grants ecr:PutImage. Every pod on the node can reach the metadata endpoint, so a server-side request forgery in any workload returns the node role's credentials without a session token — and with push access to ECR those credentials can overwrite the images the cluster pulls, turning one SSRF into code execution wherever those images run.",
	Remediation: "Require IMDSv2 on the node and its launch template (`aws ec2 modify-instance-metadata-options --instance-id ID --http-tokens required --http-put-response-hop-limit 1`; hop limit 1 also keeps pods off the endpoint where they use IRSA or Pod Identity). Remove ECR push actions from the node role — nodes need only AmazonEC2ContainerRegistryReadOnly — and push from CI with a dedicated role instead.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates:    eksNodeIMDSv1RegistryWriteViolates,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"iam_role_arn": a.Metadata["iam_role_arn"], "http_tokens": "optional"}
	},
}

// imdsV1Reachable reports an instance whose metadata endpoint answers
// token-less IMDSv1 requests: HttpTokens=optional on an endpoint that is not
// switched off. With HttpEndpoint=disabled nothing answers at all, so the
// optional token setting is moot (CIS 6.7 / FSBP EC2.8 both pass it). An
// absent http_endpoint (a sweep before the collector read it) keeps the old
// reading rather than suppressing on missing data.
func imdsV1Reachable(a asset.Asset) bool {
	return a.Metadata["http_tokens"] == "optional" && a.Metadata["http_endpoint"] != "disabled"
}

func eksNodeIMDSv1RegistryWriteViolates(a asset.Asset) bool {
	return imdsV1Reachable(a) && a.Metadata["k8s_node"] == "true" && a.Metadata["iam_role_ecr_push"] == "true"
}
