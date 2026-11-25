package checks

// aws_edge_tls.go — edge exposure and TLS-policy posture: Lambda function URLs
// without IAM auth, EKS clusters without private endpoint access, CloudFront
// and ELBv2 TLS policies without post-quantum or FIPS support, and ELBv2
// balancers with no listeners.

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsEdgeTLSChecks() []Check {
	return []Check{
		awsLambdaFunctionURLNoIAM,
		awsEKSNoPrivateEndpoint,
		awsCloudFrontNoPQCTLS,
		awsELBv2ListenerNoFIPS,
		awsELBv2ListenerNoPQC,
		awsELBv2NoListeners,
	}
}

// cloudFrontPQCPolicies are the viewer security policies that allow TLS 1.3
// only, the one place CloudFront offers hybrid post-quantum key exchange.
var cloudFrontPQCPolicies = []string{"TLSv1.3_2025"}

// elbv2PQCPolicies are the ALB/NLB security policies that negotiate hybrid
// ML-KEM key exchange.
var elbv2PQCPolicies = []string{
	"ELBSecurityPolicy-TLS13-1-2-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext0-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-2-Res-FIPS-PQ-2025-09",
	"ELBSecurityPolicy-TLS13-1-3-FIPS-PQ-2025-09",
}

var awsLambdaFunctionURLNoIAM = Check{
	ID:          "aws-lambda-function-url-no-iam-auth",
	Title:       "Lambda function URL does not require IAM authentication",
	Description: "The function has a URL whose auth type is not AWS_IAM (NONE), so anyone on the internet can invoke it with a plain HTTPS request, with no signature and no credentials. They can trigger arbitrary executions, exhaust concurrency and reach whatever the execution role can. Functions without a URL, or with AWS_IAM auth, are not flagged. Graded High.",
	Remediation: "Console: Lambda → the function → Configuration → Function URL → Edit → Auth type AWS_IAM, then sign requests with SigV4. CLI: `aws lambda update-function-url-config --function-name NAME --auth-type AWS_IAM`. If the URL is not needed, delete it: `aws lambda delete-function-url-config --function-name NAME`.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "lambda_function",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["url_auth_type"]
		return v != "" && v != "AWS_IAM"
	},
	TableProbes: []string{"NONE"},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"url_auth_type": a.Metadata["url_auth_type"]}
	},
}

var awsEKSNoPrivateEndpoint = Check{
	ID:          "aws-eks-private-endpoint-disabled",
	Title:       "EKS cluster API endpoint has no private access",
	Description: "Private endpoint access is off, so worker nodes and in-VPC clients reach the Kubernetes API server only over its public endpoint, and node-to-control-plane traffic leaves the VPC. Enabling private access keeps that traffic inside the VPC. Graded High.",
	Remediation: "Console: EKS → the cluster → Networking → Manage endpoint access → enable Private access. CLI: `aws eks update-cluster-config --name NAME --resources-vpc-config endpointPrivateAccess=true`. Consider also turning public access off once clients reach the VPC.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["endpoint_private_access"] == "false" },
}

// cloudFrontNoPQC reports a distribution whose viewer policy cannot offer
// post-quantum key exchange: the default CloudFront certificate (pinned to
// TLSv1) or any policy outside the TLS 1.3-only list. A custom certificate
// with no recorded policy is unknown, not a violation.
func cloudFrontNoPQC(a asset.Asset) bool {
	if a.Metadata["default_certificate"] == "true" {
		return true
	}
	policy := a.Metadata["minimum_protocol_version"]
	return policy != "" && !slices.Contains(cloudFrontPQCPolicies, policy)
}

var awsCloudFrontNoPQCTLS = Check{
	ID:          "aws-cloudfront-no-pqc-tls",
	Title:       "CloudFront distribution does not use a post-quantum TLS policy",
	Description: "The viewer security policy is not TLSv1.3_2025, or the distribution uses the default CloudFront certificate, which pins the policy to TLSv1. Hybrid post-quantum key exchange is only offered on TLS 1.3, so recorded viewer traffic stays open to harvest-now-decrypt-later attacks. Graded Low.",
	Remediation: "Console: CloudFront → the distribution → General → Settings → Edit → Security policy TLSv1.3_2025 (this needs a custom certificate; attach an ACM certificate and alternate domain name first). CLI: fetch the config with `aws cloudfront get-distribution-config --id ID`, set ViewerCertificate.MinimumProtocolVersion to TLSv1.3_2025, then `aws cloudfront update-distribution --id ID --if-match ETAG --distribution-config file://config.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "cloudfront_distribution",
	Violates:    cloudFrontNoPQC,
	TableProbes: []string{"true"},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return edgeEvidence(a, "default_certificate", "minimum_protocol_version")
	},
}

// elbv2NonMatchingTLS returns the HTTPS/TLS listeners of an ALB or NLB
// whose policy fails ok. Classic balancers record the same key in a different
// vocabulary and are out of scope.
func elbv2NonMatchingTLS(a asset.Asset, ok func(policy string) bool) []string {
	if !lbType(a, lbTypeApplication, lbTypeNetwork) {
		return nil
	}
	var out []string
	for _, entry := range listedValues(a, "tls_listener_policies") {
		listener, policy, _ := strings.Cut(entry, "=")
		if !ok(policy) {
			out = append(out, listener+"="+policy)
		}
	}
	return out
}

func isFIPSPolicy(policy string) bool {
	return slices.Contains(strings.Split(policy, "-"), "FIPS")
}

func isPQCPolicy(policy string) bool { return slices.Contains(elbv2PQCPolicies, policy) }

func tlsPolicyEvidence(a asset.Asset) map[string]string {
	return map[string]string{"tls_listener_policies": a.Metadata["tls_listener_policies"]}
}

var awsELBv2ListenerNoFIPS = Check{
	ID:          "aws-elbv2-listener-no-fips-tls",
	Title:       "Load balancer TLS listener does not use a FIPS security policy",
	Description: "An HTTPS (ALB) or TLS (NLB) listener uses a security policy whose name has no FIPS component, so TLS is terminated with cipher suites not restricted to FIPS 140 approved algorithms. Required wherever a FIPS-validated posture is a compliance obligation. Balancers with no TLS listener are not flagged. Graded Low.",
	Remediation: "Console: EC2 → Load Balancers → the balancer → Listeners → the listener → Edit → Security policy, pick a FIPS policy such as ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04. CLI: `aws elbv2 modify-listener --listener-arn ARN --ssl-policy ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04`. Check client compatibility first.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return len(elbv2NonMatchingTLS(a, isFIPSPolicy)) > 0
	},
	TableProbes: []string{"HTTPS:443=ELBSecurityPolicy-2016-08"},
	EvidenceFor: tlsPolicyEvidence,
}

var awsELBv2ListenerNoPQC = Check{
	ID:          "aws-elbv2-listener-no-pqc-tls",
	Title:       "Load balancer TLS listener does not use a post-quantum security policy",
	Description: "An HTTPS (ALB) or TLS (NLB) listener uses a security policy outside the AWS post-quantum set (the PQ-2025-09 policies with hybrid ML-KEM key exchange), so recorded traffic stays open to harvest-now-decrypt-later attacks. Balancers with no TLS listener are not flagged. Graded Low.",
	Remediation: "Console: EC2 → Load Balancers → the balancer → Listeners → the listener → Edit → Security policy ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 (or a FIPS-PQ variant). CLI: `aws elbv2 modify-listener --listener-arn ARN --ssl-policy ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`. Check client compatibility first.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return len(elbv2NonMatchingTLS(a, isPQCPolicy)) > 0
	},
	TableProbes: []string{"HTTPS:443=ELBSecurityPolicy-2016-08"},
	EvidenceFor: tlsPolicyEvidence,
}

var awsELBv2NoListeners = Check{
	ID:          "aws-elbv2-no-listeners",
	Title:       "Load balancer has no listeners",
	Description: "An Application, Network or Gateway Load Balancer has no listeners, so it accepts no traffic and forwards nothing. It is usually a leftover from a failed or half-finished teardown that still costs money and holds subnet addresses. Graded Medium.",
	Remediation: "Add the intended listener, or delete the balancer. Console: EC2 → Load Balancers → the balancer → Listeners → Add listener, or Actions → Delete. CLI: `aws elbv2 create-listener --load-balancer-arn ARN --protocol HTTPS --port 443 --certificates CertificateArn=CERT --default-actions Type=forward,TargetGroupArn=TG`, or `aws elbv2 delete-load-balancer --load-balancer-arn ARN`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return lbType(a, lbTypeApplication, lbTypeNetwork, lbTypeGateway) && a.Metadata["listener_count"] == "0"
	},
}
