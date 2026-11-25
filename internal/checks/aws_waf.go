package checks

// aws_waf.go — AWS WAF posture (AWS FSBP WAF.1-4, WAF.6-8, WAF.10, WAF.12)
// on waf_web_acl, waf_rule_group and waf_rule assets. v2 and Classic share
// the asset types (`classic` tells them apart), so one empty-ACL check covers
// WAF.4, WAF.8 and WAF.10. All of it is hygiene: an empty or unlogged ACL
// protects nothing, but the exposure it fails to filter is graded where it
// lives (the distribution, load balancer or API).

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsWAFChecks() []Check {
	return []Check{
		awsWAFWebACLEmpty,
		awsWAFClassicRuleGroupEmpty,
		awsWAFClassicRuleNoConditions,
		awsWAFClassicLoggingDisabled,
		awsWAFv2WebACLRuleMetricsDisabled,
		awsWAFv2RuleGroupRuleMetricsDisabled,
	}
}

var awsWAFWebACLEmpty = Check{
	ID:          "aws-waf-web-acl-empty",
	Title:       "WAF web ACL has no rules",
	Description: "The web ACL contains no rules or rule groups, so every request it inspects falls through to the default action: it filters nothing while looking like protection to whoever reads the association. Covers WAF v2 (FSBP WAF.10) and WAF Classic global and regional ACLs (WAF.8, WAF.4).",
	Remediation: "Add rules or managed rule groups (console: AWS WAF > Web ACLs > Rules > Add rules; CLI: `aws wafv2 update-web-acl --scope REGIONAL|CLOUDFRONT --rules file://rules.json ...`), or delete the ACL if it is unused. Migrate Classic ACLs to WAF v2.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "waf_web_acl",
	Violates:    func(a asset.Asset) bool { return a.Metadata["rule_count"] == "0" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "scope", "classic") },
}

var awsWAFClassicRuleGroupEmpty = Check{
	ID:          "aws-waf-classic-rule-group-empty",
	Title:       "WAF Classic rule group has no rules",
	Description: "The WAF Classic rule group activates no rules, so any web ACL that includes it gains nothing from it. FSBP WAF.3 (regional) and WAF.7 (global).",
	Remediation: "Add rules to the group or remove it (console: WAF Classic > Rule groups; CLI: `aws waf update-rule-group` / `aws waf-regional update-rule-group`). Migrate to WAF v2.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "waf_rule_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["classic"] == "true" && a.Metadata["rule_count"] == "0" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "scope") },
}

var awsWAFClassicRuleNoConditions = Check{
	ID:          "aws-waf-classic-rule-no-conditions",
	Title:       "WAF Classic rule has no conditions",
	Description: "The WAF Classic rule has no conditions (predicates), so it matches nothing and the ACLs that use it are not filtering what its name suggests. FSBP WAF.2 (regional) and WAF.6 (global).",
	Remediation: "Add conditions to the rule or delete it (console: WAF Classic > Rules > Edit; CLI: `aws waf update-rule` / `aws waf-regional update-rule`). Migrate to WAF v2.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "waf_rule",
	Violates:    func(a asset.Asset) bool { return a.Metadata["condition_count"] == "0" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "scope") },
}

var awsWAFClassicLoggingDisabled = Check{
	ID:          "aws-waf-classic-logging-disabled",
	Title:       "WAF Classic global web ACL has no logging",
	Description: "The global (CloudFront) WAF Classic web ACL has no logging configuration, so there is no record of the requests it allowed or blocked. FSBP WAF.1.",
	Remediation: "Send the ACL's logs to a Kinesis Data Firehose stream named aws-waf-logs-* (console: WAF Classic > Web ACLs > Logging; CLI: `aws waf put-logging-configuration --logging-configuration ResourceArn=ACL_ARN,LogDestinationConfigs=FIREHOSE_ARN`).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "waf_web_acl",
	Violates:    func(a asset.Asset) bool { return a.Metadata["logging_enabled"] == "false" },
}

const wafMetricsDescription = "Rules whose visibility config publishes no CloudWatch metric cannot be monitored or alarmed on: a rule that starts blocking legitimate traffic, or stops matching an attack, goes unnoticed. FSBP WAF.12."

const wafMetricsRemediation = "Enable CloudWatch metrics on each listed rule (console: AWS WAF > the ACL or rule group > Rules > Edit > CloudWatch metrics; CLI: set VisibilityConfig.CloudWatchMetricsEnabled=true in the rules passed to `aws wafv2 update-web-acl` / `aws wafv2 update-rule-group`)."

var awsWAFv2WebACLRuleMetricsDisabled = Check{
	ID:          "aws-wafv2-web-acl-rule-metrics-disabled",
	Title:       "WAF web ACL has rules without CloudWatch metrics",
	Description: wafMetricsDescription,
	Remediation: wafMetricsRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "waf_web_acl",
	Violates:    func(a asset.Asset) bool { return a.Metadata["rules_without_metrics"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "rules_without_metrics") },
}

var awsWAFv2RuleGroupRuleMetricsDisabled = Check{
	ID:          "aws-wafv2-rule-group-rule-metrics-disabled",
	Title:       "WAF rule group has rules without CloudWatch metrics",
	Description: wafMetricsDescription,
	Remediation: wafMetricsRemediation,
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "waf_rule_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["rules_without_metrics"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string { return edgeEvidence(a, "rules_without_metrics") },
}
