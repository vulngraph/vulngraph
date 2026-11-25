package checks

// aws_cloudfront.go — CloudFront distribution posture (AWS FSBP
// CloudFront.1, .3-.10, .12, .13, .15-.17) on the cloudfront_distribution
// asset. List-valued keys hold the offending origin ids or behaviour path
// patterns ("" = observed none); every key is absent when its read failed.

import (
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const cloudfrontAsset = "cloudfront_distribution"

func awsCloudFrontChecks() []Check {
	return []Check{
		awsCloudFrontDanglingS3Origin,
		awsCloudFrontViewerHTTP,
		awsCloudFrontOriginUnencrypted,
		awsCloudFrontOriginSSLv3,
		awsCloudFrontS3OriginNoOAC,
		awsCloudFrontLambdaURLNoOAC,
		awsCloudFrontWeakViewerTLS,
		awsCloudFrontLegacyTrustedSigners,
		awsCloudFrontNoWAF,
		awsCloudFrontLoggingDisabled,
		awsCloudFrontNoDefaultRootObject,
		awsCloudFrontDefaultCertificate,
		awsCloudFrontDedicatedIPSSL,
		awsCloudFrontNoOriginFailover,
	}
}

func edgeEvidence(a asset.Asset, keys ...string) map[string]string {
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = a.Metadata[k]
	}
	return out
}

var awsCloudFrontDanglingS3Origin = Check{
	ID:          "aws-cloudfront-dangling-s3-origin",
	Title:       "CloudFront distribution serves from an S3 bucket that no longer exists",
	Description: "An origin of this distribution names an S3 bucket that does not exist (S3 answered 404), or one that exists but is not among this account's buckets. Bucket names are global: anyone can create a bucket with a free name in their own account and CloudFront will then serve their content under your domain — a subdomain takeover. A missing bucket is High; a bucket owned by another account is Medium, since it may be a deliberate cross-account origin or a takeover that has already happened. Both REST and static-website origins are checked. FSBP CloudFront.12.",
	Remediation: "Point the origin at a bucket you own or delete the origin (console: CloudFront > distribution > Origins > Edit/Delete; CLI: `aws cloudfront get-distribution-config --id ID`, edit Origins, `aws cloudfront update-distribution --id ID --if-match ETAG --distribution-config file://config.json`). If the name must stay, recreate the bucket in your own account first.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["s3_origin_buckets_missing"] != "" || a.Metadata["s3_origin_buckets_foreign"] != ""
	},
	// A disabled distribution serves nothing, so the takeover is not live yet.
	SeverityFor: func(a asset.Asset) finding.Severity {
		switch {
		case a.Metadata["enabled"] == "false":
			return finding.SeverityLow
		case a.Metadata["s3_origin_buckets_missing"] != "":
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["s3_origin_buckets_missing"] != "" {
			return "CloudFront distribution serves from an S3 bucket that no longer exists"
		}
		return "CloudFront distribution serves from an S3 bucket owned by another account"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return edgeEvidence(a, "s3_origin_buckets_missing", "s3_origin_buckets_foreign", "enabled")
	},
}

var awsCloudFrontViewerHTTP = Check{
	ID:          "aws-cloudfront-viewer-http-allowed",
	Title:       "CloudFront distribution serves content over plain HTTP",
	Description: "A cache behaviour uses the viewer protocol policy allow-all, so viewers can fetch content and send cookies or form data unencrypted; anyone on the path can read or alter it. FSBP CloudFront.3.",
	Remediation: "Set the behaviour's viewer protocol policy to redirect-to-https or https-only (console: CloudFront > distribution > Behaviors > Edit; CLI: edit ViewerProtocolPolicy in `aws cloudfront get-distribution-config` output and apply with `aws cloudfront update-distribution`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["viewer_http_behaviors"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "viewer_http_behaviors") },
}

var awsCloudFrontOriginUnencrypted = Check{
	ID:          "aws-cloudfront-origin-unencrypted",
	Title:       "CloudFront sends traffic to a custom origin over plain HTTP",
	Description: "A custom origin uses origin protocol policy http-only, or match-viewer behind a behaviour that accepts HTTP viewers, so requests between CloudFront and the origin — headers, cookies, bodies — cross the internet unencrypted. S3 static-website origins only speak HTTP and are reported too. FSBP CloudFront.9.",
	Remediation: "Set the origin protocol policy to https-only (console: CloudFront > distribution > Origins > Edit > Protocol; CLI: CustomOriginConfig.OriginProtocolPolicy via `aws cloudfront update-distribution`). For an S3 website origin, switch to the bucket's REST endpoint with origin access control.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["custom_origins_unencrypted"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "custom_origins_unencrypted") },
}

var awsCloudFrontOriginSSLv3 = Check{
	ID:          "aws-cloudfront-origin-sslv3",
	Title:       "CloudFront allows SSLv3 to a custom origin",
	Description: "A custom origin that CloudFront reaches over HTTPS still lists SSLv3 among its origin SSL protocols. SSLv3 is broken (POODLE); an origin that negotiates it exposes the edge-to-origin hop. Origins that only use HTTP are reported by aws-cloudfront-origin-unencrypted. FSBP CloudFront.10.",
	Remediation: "Remove SSLv3 from the origin's SSL protocols and keep TLSv1.2 (console: CloudFront > distribution > Origins > Edit > Minimum origin SSL protocol; CLI: CustomOriginConfig.OriginSslProtocols via `aws cloudfront update-distribution`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["custom_origins_sslv3"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "custom_origins_sslv3") },
}

var awsCloudFrontS3OriginNoOAC = Check{
	ID:          "aws-cloudfront-s3-origin-no-oac",
	Title:       "CloudFront S3 origin does not use origin access control",
	Description: "An S3 (REST) origin has no origin access control. Either the bucket must be readable without CloudFront signing (anyone can bypass the distribution, its WAF and its signed URLs and read the bucket directly), or it relies on a legacy origin access identity, which lacks SSE-KMS support and newer regions. FSBP CloudFront.13. An origin whose bucket no longer exists is reported as a dangling origin instead.",
	Remediation: "Create an origin access control and attach it to the origin, then restrict the bucket policy to the cloudfront.amazonaws.com service principal with an AWS:SourceArn condition on the distribution (console: CloudFront > Origin access > Create control setting; CLI: `aws cloudfront create-origin-access-control`, then update the distribution's OriginAccessControlId).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["s3_origins_without_oac"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "s3_origins_without_oac") },
}

var awsCloudFrontLambdaURLNoOAC = Check{
	ID:          "aws-cloudfront-lambda-url-origin-no-oac",
	Title:       "CloudFront Lambda function URL origin does not use origin access control",
	Description: "A Lambda function URL origin has no origin access control, so the function URL must accept unauthenticated calls and anyone can invoke it directly, bypassing the distribution's WAF, caching and access controls. FSBP CloudFront.16.",
	Remediation: "Create a Lambda origin access control, attach it to the origin, set the function URL auth type to AWS_IAM and grant cloudfront.amazonaws.com lambda:InvokeFunctionUrl scoped to the distribution ARN (CLI: `aws cloudfront create-origin-access-control --origin-access-control-config OriginAccessControlOriginType=lambda,...`).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["lambda_url_origins_without_oac"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "lambda_url_origins_without_oac") },
}

// weakViewerTLS are the viewer security policies older than the
// recommended TLSv1.2_2021 (FSBP CloudFront.15). Listed explicitly so a
// newer policy AWS adds later is not reported as weak.
var weakViewerTLS = []string{"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016", "TLSv1.2_2018", "TLSv1.2_2019"}

// prehistoricViewerTLS still accept TLS 1.0 / 1.1 (or SSLv3) from viewers.
var prehistoricViewerTLS = []string{"SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"}

var awsCloudFrontWeakViewerTLS = Check{
	ID:          "aws-cloudfront-weak-viewer-tls",
	Title:       "CloudFront distribution uses an outdated viewer TLS policy",
	Description: "The distribution's custom certificate is served with a security policy older than TLSv1.2_2021. Policies that still accept TLS 1.0/1.1 (or SSLv3) are Medium; the older TLS 1.2 policies, which only add weak cipher suites, are Low. A distribution on the default *.cloudfront.net certificate cannot set a policy and is reported by aws-cloudfront-default-certificate instead. FSBP CloudFront.15.",
	Remediation: "Set the security policy to TLSv1.2_2021 or newer (console: CloudFront > distribution > General > Edit > Security policy; CLI: ViewerCertificate.MinimumProtocolVersion via `aws cloudfront update-distribution`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates: func(a asset.Asset) bool {
		return a.Metadata["default_certificate"] == "false" && slices.Contains(weakViewerTLS, a.Metadata["minimum_protocol_version"])
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if slices.Contains(prehistoricViewerTLS, a.Metadata["minimum_protocol_version"]) {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	// The policy list lives outside the predicate, where the derived probes
	// cannot see it: without this an unread policy would read as "evaluated, clean".
	TableProbes: []string{"TLSv1"},
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "minimum_protocol_version") },
}

var awsCloudFrontLegacyTrustedSigners = Check{
	ID:          "aws-cloudfront-legacy-trusted-signers",
	Title:       "CloudFront signed URLs rely on account key pairs (trusted signers)",
	Description: "A cache behaviour verifies signed URLs or cookies against trusted signers — CloudFront key pairs that only the root user can create or rotate. Key groups replace them and are managed through IAM without root credentials. FSBP CloudFront.17.",
	Remediation: "Create a public key and key group (console: CloudFront > Key management; CLI: `aws cloudfront create-public-key`, `aws cloudfront create-key-group`), switch the behaviour to TrustedKeyGroups, re-sign URLs with the new key, then delete the root CloudFront key pairs.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["trusted_signer_behaviors"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "trusted_signer_behaviors") },
}

var awsCloudFrontNoWAF = Check{
	ID:          "aws-cloudfront-no-waf",
	Title:       "CloudFront distribution has no WAF web ACL",
	Description: "No AWS WAF web ACL is associated with the distribution, so requests reach the origin without managed-rule, rate-based or bot filtering at the edge. Defense in depth; the origin's own controls still apply. FSBP CloudFront.6.",
	Remediation: "Associate a CLOUDFRONT-scope web ACL (console: CloudFront > distribution > Security > Edit; CLI: set WebACLId via `aws cloudfront update-distribution`, or `aws wafv2 create-web-acl --scope CLOUDFRONT --region us-east-1` first).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return observedNone(a, "web_acl_id") },
}

var awsCloudFrontLoggingDisabled = Check{
	ID:          "aws-cloudfront-logging-disabled",
	Title:       "CloudFront distribution has no access logging",
	Description: "Neither legacy standard logging nor a standard-logging (v2) delivery is configured, so there is no record of who requested what from the edge. FSBP CloudFront.5.",
	Remediation: "Enable standard logging (console: CloudFront > distribution > Logging > Add; CLI: `aws logs put-delivery-source --resource-arn DIST_ARN --log-type ACCESS_LOGS` then `aws logs create-delivery` to an S3, CloudWatch Logs or Firehose destination, in us-east-1).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["logging_enabled"] == "false" },
}

var awsCloudFrontNoDefaultRootObject = Check{
	ID:          "aws-cloudfront-no-default-root-object",
	Title:       "CloudFront distribution has no default root object",
	Description: "Requests for the distribution root (/) are forwarded to the S3 origin as-is, which can return a bucket listing or an error disclosing the bucket. Distributions without an S3 origin are not graded: the application answers the root path itself. FSBP CloudFront.1.",
	Remediation: "Set a default root object such as index.html (console: CloudFront > distribution > General > Edit > Default root object; CLI: DefaultRootObject via `aws cloudfront update-distribution`).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates: func(a asset.Asset) bool {
		return observedNone(a, "default_root_object") && a.Metadata["has_s3_origin"] == "true"
	},
}

var awsCloudFrontDefaultCertificate = Check{
	ID:          "aws-cloudfront-default-certificate",
	Title:       "CloudFront distribution uses the default CloudFront certificate",
	Description: "The distribution serves HTTPS only on its *.cloudfront.net name with the shared default certificate, whose security policy is fixed at TLSv1 and cannot be raised. FSBP CloudFront.7.",
	Remediation: "Request an ACM certificate in us-east-1 for your domain, add the domain as an alternate name and select the certificate (console: CloudFront > distribution > General > Edit; CLI: ViewerCertificate.ACMCertificateArn via `aws cloudfront update-distribution`).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["default_certificate"] == "true" },
}

var awsCloudFrontDedicatedIPSSL = Check{
	ID:          "aws-cloudfront-dedicated-ip-ssl",
	Title:       "CloudFront distribution serves its custom certificate from dedicated IPs",
	Description: "The custom certificate is served with SSL support method vip (or static-ip) instead of SNI. Dedicated-IP SSL exists only for clients from before 2010 and is billed per distribution. FSBP CloudFront.8.",
	Remediation: "Set the SSL support method to sni-only (console: CloudFront > distribution > General > Edit > Legacy clients support off; CLI: ViewerCertificate.SSLSupportMethod=sni-only via `aws cloudfront update-distribution`).",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates: func(a asset.Asset) bool {
		m := a.Metadata["ssl_support_method"]
		return a.Metadata["default_certificate"] == "false" && (m == "vip" || m == "static-ip")
	},
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "ssl_support_method") },
}

var awsCloudFrontNoOriginFailover = Check{
	ID:          "aws-cloudfront-no-origin-failover",
	Title:       "CloudFront distribution has no origin failover",
	Description: "The distribution has no origin group, so an outage of its origin is an outage of the site. Resilience only. FSBP CloudFront.4.",
	Remediation: "Create an origin group with a primary and secondary origin and route the behaviours to it (console: CloudFront > distribution > Origins > Create origin group).",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   cloudfrontAsset,
	Violates:    func(a asset.Asset) bool { return a.Metadata["origin_group_count"] == "0" },
}
