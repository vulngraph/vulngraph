package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	nfwtypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AWS Network Firewall: firewalls (change protections, AWS FSBP
// NetworkFirewall.9/.10), firewall policies (rule groups and stateless
// default actions, .3/.4/.5) and stateless rule groups (.6), each its own
// asset because each is the resource its control grades.
//
// The three listings are independent; any page error fails the read (the
// resources are assets, and a short list would make the rest look deleted).
// A failed per-resource Describe keeps the resource but leaves its posture
// keys absent, so its checks read it as unknown.

const (
	networkFirewallType          = "network_firewall"
	networkFirewallPolicyType    = "network_firewall_policy"
	networkFirewallRuleGroupType = "network_firewall_rule_group"
)

// networkFirewallConcurrency bounds per-resource Describe calls.
const networkFirewallConcurrency = 4

type networkFirewallAPI interface {
	ListFirewalls(context.Context, *networkfirewall.ListFirewallsInput, ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallsOutput, error)
	DescribeFirewall(context.Context, *networkfirewall.DescribeFirewallInput, ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallOutput, error)
	DescribeLoggingConfiguration(context.Context, *networkfirewall.DescribeLoggingConfigurationInput, ...func(*networkfirewall.Options)) (*networkfirewall.DescribeLoggingConfigurationOutput, error)
	ListFirewallPolicies(context.Context, *networkfirewall.ListFirewallPoliciesInput, ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallPoliciesOutput, error)
	DescribeFirewallPolicy(context.Context, *networkfirewall.DescribeFirewallPolicyInput, ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallPolicyOutput, error)
	ListRuleGroups(context.Context, *networkfirewall.ListRuleGroupsInput, ...func(*networkfirewall.Options)) (*networkfirewall.ListRuleGroupsOutput, error)
	DescribeRuleGroup(context.Context, *networkfirewall.DescribeRuleGroupInput, ...func(*networkfirewall.Options)) (*networkfirewall.DescribeRuleGroupOutput, error)
}

func collectNetworkFirewall(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectNetworkFirewall: %w", err)
	}
	return readNetworkFirewall(ctx, networkfirewall.NewFromConfig(awsCfg), region, accountID, now)
}

func readNetworkFirewall(ctx context.Context, client networkFirewallAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	firewalls, err := listFirewalls(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readNetworkFirewall: %w", err)
	}
	policies, err := listFirewallPolicies(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readNetworkFirewall: %w", err)
	}
	groups, err := listStatelessRuleGroups(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readNetworkFirewall: %w", err)
	}
	var (
		mu      sync.Mutex
		assets  []asset.Asset
		failed  int
		lastErr error
	)
	emit := func(a asset.Asset, err error) {
		mu.Lock()
		defer mu.Unlock()
		if a.ID == "" {
			return // a listing entry without an ARN cannot be an asset
		}
		assets = append(assets, a)
		if err != nil {
			failed++
			lastErr = err
		}
	}
	n := len(firewalls) + len(policies) + len(groups)
	if err := forEachBounded(n, networkFirewallConcurrency, func(i int) error {
		switch {
		case i < len(firewalls):
			emit(describeFirewall(ctx, client, firewalls[i], region, accountID, now))
		case i < len(firewalls)+len(policies):
			emit(describeFirewallPolicy(ctx, client, policies[i-len(firewalls)], region, accountID, now))
		default:
			emit(describeStatelessRuleGroup(ctx, client, groups[i-len(firewalls)-len(policies)], region, accountID, now))
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("readNetworkFirewall: %w", err)
	}
	if failed > 0 {
		log.FromContext(ctx).Warn().Err(lastErr).Str("region", region).Int("failed", failed).
			Msg("network firewall describe failed; those resources carry no posture keys this sweep")
	}
	return assets, nil
}

func listFirewalls(ctx context.Context, client networkFirewallAPI) ([]nfwtypes.FirewallMetadata, error) {
	var (
		out   []nfwtypes.FirewallMetadata
		token *string
	)
	for {
		page, err := client.ListFirewalls(ctx, &networkfirewall.ListFirewallsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("listFirewalls: %w", err)
		}
		out = append(out, page.Firewalls...)
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

func listFirewallPolicies(ctx context.Context, client networkFirewallAPI) ([]nfwtypes.FirewallPolicyMetadata, error) {
	var (
		out   []nfwtypes.FirewallPolicyMetadata
		token *string
	)
	for {
		page, err := client.ListFirewallPolicies(ctx, &networkfirewall.ListFirewallPoliciesInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("listFirewallPolicies: %w", err)
		}
		out = append(out, page.FirewallPolicies...)
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

// listStatelessRuleGroups lists the account's own stateless rule groups — the
// only kind FSBP NetworkFirewall.6 grades. AWS-managed groups are not listed
// (Scope defaults to ACCOUNT) and cannot be edited anyway.
func listStatelessRuleGroups(ctx context.Context, client networkFirewallAPI) ([]nfwtypes.RuleGroupMetadata, error) {
	var (
		out   []nfwtypes.RuleGroupMetadata
		token *string
	)
	for {
		page, err := client.ListRuleGroups(ctx, &networkfirewall.ListRuleGroupsInput{
			NextToken: token, Type: nfwtypes.RuleGroupTypeStateless,
		})
		if err != nil {
			return nil, fmt.Errorf("listStatelessRuleGroups: %w", err)
		}
		out = append(out, page.RuleGroups...)
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

func describeFirewall(ctx context.Context, client networkFirewallAPI, fw nfwtypes.FirewallMetadata, region, accountID string, now time.Time) (asset.Asset, error) {
	a := nfwAsset(awssdk.ToString(fw.FirewallArn), awssdk.ToString(fw.FirewallName), networkFirewallType, region, accountID, now)
	out, err := client.DescribeFirewall(ctx, &networkfirewall.DescribeFirewallInput{FirewallArn: fw.FirewallArn})
	if err == nil && (out == nil || out.Firewall == nil) {
		err = errEmptyResponse
	}
	if err != nil {
		return a, fmt.Errorf("describeFirewall %s: %w", a.ID, err)
	}
	f := out.Firewall
	a.Metadata["vpc_id"] = awssdk.ToString(f.VpcId)
	a.Metadata["firewall_policy_arn"] = awssdk.ToString(f.FirewallPolicyArn)
	a.Metadata["delete_protection"] = strconv.FormatBool(f.DeleteProtection)
	a.Metadata["subnet_change_protection"] = strconv.FormatBool(f.SubnetChangeProtection)
	stampFirewallLogging(ctx, client, a)
	return a, nil
}

// nfwLogTypeKeys maps each Network Firewall log type to the firewall key
// recording whether it is delivered anywhere ("true"/"false"). Read for the
// logging checks (NetworkFirewall.2), not graded here.
var nfwLogTypeKeys = map[nfwtypes.LogType]string{
	nfwtypes.LogTypeFlow:  "logging_flow",
	nfwtypes.LogTypeAlert: "logging_alert",
	nfwtypes.LogTypeTls:   "logging_tls",
}

// stampFirewallLogging records which log types the firewall delivers. A
// failed read leaves all three keys absent (unknown, never "off") and does not
// cost the firewall's other posture.
func stampFirewallLogging(ctx context.Context, client networkFirewallAPI, a asset.Asset) {
	out, err := client.DescribeLoggingConfiguration(ctx, &networkfirewall.DescribeLoggingConfigurationInput{FirewallArn: awssdk.String(a.ID)})
	if err != nil || out == nil {
		log.FromContext(ctx).Warn().Err(orEmpty(err)).Str("firewall", a.ID).
			Msg("network firewall logging configuration unreadable; its log types are unknown this sweep")
		return
	}
	on := map[nfwtypes.LogType]bool{}
	if out.LoggingConfiguration != nil {
		for _, d := range out.LoggingConfiguration.LogDestinationConfigs {
			on[d.LogType] = true
		}
	}
	for t, key := range nfwLogTypeKeys {
		a.Metadata[key] = strconv.FormatBool(on[t])
	}
}

func describeFirewallPolicy(ctx context.Context, client networkFirewallAPI, p nfwtypes.FirewallPolicyMetadata, region, accountID string, now time.Time) (asset.Asset, error) {
	a := nfwAsset(awssdk.ToString(p.Arn), awssdk.ToString(p.Name), networkFirewallPolicyType, region, accountID, now)
	out, err := client.DescribeFirewallPolicy(ctx, &networkfirewall.DescribeFirewallPolicyInput{FirewallPolicyArn: p.Arn})
	if err == nil && (out == nil || out.FirewallPolicy == nil) {
		err = errEmptyResponse
	}
	if err != nil {
		return a, fmt.Errorf("describeFirewallPolicy %s: %w", a.ID, err)
	}
	pol := out.FirewallPolicy
	a.Metadata["stateful_rule_group_count"] = strconv.Itoa(len(pol.StatefulRuleGroupReferences))
	a.Metadata["stateless_rule_group_count"] = strconv.Itoa(len(pol.StatelessRuleGroupReferences))
	a.Metadata["stateless_default_actions"] = strings.Join(pol.StatelessDefaultActions, ",")
	a.Metadata["stateless_fragment_default_actions"] = strings.Join(pol.StatelessFragmentDefaultActions, ",")
	if r := out.FirewallPolicyResponse; r != nil && r.NumberOfAssociations != nil {
		a.Metadata["association_count"] = strconv.Itoa(int(*r.NumberOfAssociations))
	}
	return a, nil
}

func describeStatelessRuleGroup(ctx context.Context, client networkFirewallAPI, g nfwtypes.RuleGroupMetadata, region, accountID string, now time.Time) (asset.Asset, error) {
	a := nfwAsset(awssdk.ToString(g.Arn), awssdk.ToString(g.Name), networkFirewallRuleGroupType, region, accountID, now)
	a.Metadata["rule_group_type"] = string(nfwtypes.RuleGroupTypeStateless)
	out, err := client.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
		RuleGroupArn: g.Arn, Type: nfwtypes.RuleGroupTypeStateless,
	})
	if err == nil && (out == nil || out.RuleGroup == nil) {
		err = errEmptyResponse
	}
	if err != nil {
		return a, fmt.Errorf("describeStatelessRuleGroup %s: %w", a.ID, err)
	}
	n := 0
	if src := out.RuleGroup.RulesSource; src != nil && src.StatelessRulesAndCustomActions != nil {
		n = len(src.StatelessRulesAndCustomActions.StatelessRules)
	}
	a.Metadata["stateless_rule_count"] = strconv.Itoa(n)
	return a, nil
}

func nfwAsset(arn, name, typ, region, accountID string, now time.Time) asset.Asset {
	if name == "" {
		name = arn
	}
	return asset.Asset{
		ID:           arn,
		Name:         name,
		Type:         typ,
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Metadata:     map[string]string{},
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
