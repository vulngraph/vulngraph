package checks

import (
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// AWS Network Firewall posture (AWS FSBP NetworkFirewall.3-.6, .9, .10) from
// the network_firewall, network_firewall_policy and
// network_firewall_rule_group assets (collect/aws/networkfirewall.go).

// statelessDefaultPasses reports a policy whose stateless default for key
// passes traffic (aws:pass: through with no further inspection). The list holds one standard action (pass, drop or
// forward_to_sfe) plus optional custom actions; an unread policy has no key.
func statelessDefaultPasses(a asset.Asset, key string) bool {
	return slices.Contains(strings.Split(a.Metadata[key], ","), "aws:pass")
}

var awsNetworkFirewallPolicyNoRuleGroups = Check{
	ID:          "aws-network-firewall-policy-no-rule-groups",
	Title:       "Network Firewall policy has no rule groups",
	Description: "The firewall policy references no stateful and no stateless rule group, so a firewall using it filters nothing beyond its default actions. It looks like inspection is in place when it is not.",
	Remediation: "Console: VPC → Network Firewall → Firewall policies → the policy → Add rule groups (stateless or stateful, e.g. an AWS managed threat-signature group). CLI: `aws network-firewall update-firewall-policy --firewall-policy-arn ARN --update-token TOKEN --firewall-policy file://policy.json` with StatefulRuleGroupReferences set.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall_policy",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["stateful_rule_group_count"] == "0" && a.Metadata["stateless_rule_group_count"] == "0"
	},
}

var awsNetworkFirewallPolicyStatelessDefaultPass = Check{
	ID:          "aws-network-firewall-policy-stateless-default-pass",
	Title:       "Network Firewall policy passes unmatched packets uninspected",
	Description: "The policy's default stateless action for full packets is Pass: a packet that matches no stateless rule leaves the firewall without reaching the stateful engine, so stateful rules and threat signatures never see it.",
	Remediation: "Set the default to Forward to stateful rule groups (or Drop): Console: Firewall policies → the policy → Stateless default actions → Edit → Forward to stateful rule groups. CLI: update-firewall-policy with `StatelessDefaultActions: [\"aws:forward_to_sfe\"]`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall_policy",
	Violates:    func(a asset.Asset) bool { return statelessDefaultPasses(a, "stateless_default_actions") },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"stateless_default_actions": a.Metadata["stateless_default_actions"]}
	},
}

var awsNetworkFirewallPolicyFragmentDefaultPass = Check{
	ID:          "aws-network-firewall-policy-fragment-default-pass",
	Title:       "Network Firewall policy passes unmatched fragmented packets uninspected",
	Description: "The policy's default stateless action for fragmented packets is Pass, so an IP fragment that matches no stateless rule skips the stateful engine — a classic way to slip traffic past inspection.",
	Remediation: "Console: Firewall policies → the policy → Stateless default actions → Edit → Fragmented packets: Forward to stateful rule groups (or Drop). CLI: update-firewall-policy with `StatelessFragmentDefaultActions: [\"aws:forward_to_sfe\"]`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall_policy",
	Violates:    func(a asset.Asset) bool { return statelessDefaultPasses(a, "stateless_fragment_default_actions") },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"stateless_fragment_default_actions": a.Metadata["stateless_fragment_default_actions"]}
	},
}

var awsNetworkFirewallRuleGroupEmpty = Check{
	ID:          "aws-network-firewall-rule-group-empty",
	Title:       "Stateless Network Firewall rule group has no rules",
	Description: "The stateless rule group contains no rules, so any policy referencing it processes nothing through it while appearing to.",
	Remediation: "Add rules (Console: Network Firewall → Network Firewall rule groups → the group → Edit rules), or remove the group from its policies and delete it: `aws network-firewall delete-rule-group --rule-group-arn ARN`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall_rule_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["stateless_rule_count"] == "0" },
}

var awsNetworkFirewallNoDeletionProtection = Check{
	ID:          "aws-network-firewall-no-deletion-protection",
	Title:       "Network Firewall has deletion protection off",
	Description: "The firewall can be deleted in one call, taking its inspection out of the traffic path. Change-control hygiene; no change to exposure today.",
	Remediation: "`aws network-firewall update-firewall-delete-protection --firewall-arn ARN --delete-protection`. Console: Network Firewall → Firewalls → the firewall → Firewall details → Change protections → Edit → Deletion protection.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall",
	Violates:    func(a asset.Asset) bool { return a.Metadata["delete_protection"] == "false" },
}

var awsNetworkFirewallNoSubnetChangeProtection = Check{
	ID:          "aws-network-firewall-no-subnet-change-protection",
	Title:       "Network Firewall has subnet change protection off",
	Description: "The firewall's subnet associations can be changed without first turning protection off, so an accidental or hostile change can move inspection away from the subnets it guards. Change-control hygiene.",
	Remediation: "`aws network-firewall update-subnet-change-protection --firewall-arn ARN --subnet-change-protection`. Console: Firewalls → the firewall → Firewall details → Change protections → Edit → Subnet change protection.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall",
	Violates:    func(a asset.Asset) bool { return a.Metadata["subnet_change_protection"] == "false" },
}

func awsNetworkFirewallChecks() []Check {
	return []Check{
		awsNetworkFirewallPolicyNoRuleGroups,
		awsNetworkFirewallPolicyStatelessDefaultPass,
		awsNetworkFirewallPolicyFragmentDefaultPass,
		awsNetworkFirewallRuleGroupEmpty,
		awsNetworkFirewallNoDeletionProtection,
		awsNetworkFirewallNoSubnetChangeProtection,
	}
}
