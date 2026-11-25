package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	nfwtypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/stretchr/testify/require"
)

type fakeNetworkFirewall struct {
	firewallPages [][]nfwtypes.FirewallMetadata
	firewalls     map[string]*nfwtypes.Firewall
	policies      []nfwtypes.FirewallPolicyMetadata
	policy        map[string]*networkfirewall.DescribeFirewallPolicyOutput
	groups        []nfwtypes.RuleGroupMetadata
	group         map[string]*nfwtypes.RuleGroup
	groupType     nfwtypes.RuleGroupType
	listErr       error
	logging       map[string]*nfwtypes.LoggingConfiguration
	loggingErr    error
}

func (f *fakeNetworkFirewall) DescribeLoggingConfiguration(_ context.Context, in *networkfirewall.DescribeLoggingConfigurationInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.DescribeLoggingConfigurationOutput, error) {
	if f.loggingErr != nil {
		return nil, f.loggingErr
	}
	return &networkfirewall.DescribeLoggingConfigurationOutput{LoggingConfiguration: f.logging[awssdk.ToString(in.FirewallArn)]}, nil
}

func (f *fakeNetworkFirewall) ListFirewalls(_ context.Context, in *networkfirewall.ListFirewallsInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if len(f.firewallPages) == 0 {
		return &networkfirewall.ListFirewallsOutput{}, nil
	}
	page := 0
	if in.NextToken != nil {
		page = 1
	}
	out := &networkfirewall.ListFirewallsOutput{Firewalls: f.firewallPages[page]}
	if page+1 < len(f.firewallPages) {
		out.NextToken = awssdk.String("n")
	}
	return out, nil
}

func (f *fakeNetworkFirewall) DescribeFirewall(_ context.Context, in *networkfirewall.DescribeFirewallInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallOutput, error) {
	fw, ok := f.firewalls[awssdk.ToString(in.FirewallArn)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return &networkfirewall.DescribeFirewallOutput{Firewall: fw}, nil
}

func (f *fakeNetworkFirewall) ListFirewallPolicies(context.Context, *networkfirewall.ListFirewallPoliciesInput, ...func(*networkfirewall.Options)) (*networkfirewall.ListFirewallPoliciesOutput, error) {
	return &networkfirewall.ListFirewallPoliciesOutput{FirewallPolicies: f.policies}, nil
}

func (f *fakeNetworkFirewall) DescribeFirewallPolicy(_ context.Context, in *networkfirewall.DescribeFirewallPolicyInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.DescribeFirewallPolicyOutput, error) {
	return f.policy[awssdk.ToString(in.FirewallPolicyArn)], nil
}

func (f *fakeNetworkFirewall) ListRuleGroups(_ context.Context, in *networkfirewall.ListRuleGroupsInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.ListRuleGroupsOutput, error) {
	f.groupType = in.Type
	return &networkfirewall.ListRuleGroupsOutput{RuleGroups: f.groups}, nil
}

func (f *fakeNetworkFirewall) DescribeRuleGroup(_ context.Context, in *networkfirewall.DescribeRuleGroupInput, _ ...func(*networkfirewall.Options)) (*networkfirewall.DescribeRuleGroupOutput, error) {
	return &networkfirewall.DescribeRuleGroupOutput{RuleGroup: f.group[awssdk.ToString(in.RuleGroupArn)]}, nil
}

func TestReadNetworkFirewall(t *testing.T) {
	f := &fakeNetworkFirewall{
		firewallPages: [][]nfwtypes.FirewallMetadata{
			{{FirewallArn: awssdk.String("arn:fw/a"), FirewallName: awssdk.String("a")}},
			{{FirewallArn: awssdk.String("arn:fw/b"), FirewallName: awssdk.String("b")}},
		},
		firewalls: map[string]*nfwtypes.Firewall{
			"arn:fw/a": {VpcId: awssdk.String("vpc-1"), FirewallPolicyArn: awssdk.String("arn:pol/p"), DeleteProtection: true},
			// arn:fw/b: describe denied → posture unknown
		},
		policies: []nfwtypes.FirewallPolicyMetadata{{Arn: awssdk.String("arn:pol/p"), Name: awssdk.String("p")}, {Arn: awssdk.String("arn:pol/empty")}},
		policy: map[string]*networkfirewall.DescribeFirewallPolicyOutput{
			"arn:pol/p": {
				FirewallPolicy: &nfwtypes.FirewallPolicy{
					StatelessDefaultActions:         []string{"aws:forward_to_sfe"},
					StatelessFragmentDefaultActions: []string{"aws:pass"},
					StatefulRuleGroupReferences:     []nfwtypes.StatefulRuleGroupReference{{ResourceArn: awssdk.String("arn:rg/s")}},
				},
				FirewallPolicyResponse: &nfwtypes.FirewallPolicyResponse{NumberOfAssociations: awssdk.Int32(1)},
			},
			"arn:pol/empty": {}, // an empty response is unknown, not a policy with nothing in it
		},
		groups: []nfwtypes.RuleGroupMetadata{{Arn: awssdk.String("arn:rg/empty")}, {Arn: awssdk.String("arn:rg/full")}},
		group: map[string]*nfwtypes.RuleGroup{
			"arn:rg/empty": {RulesSource: &nfwtypes.RulesSource{StatelessRulesAndCustomActions: &nfwtypes.StatelessRulesAndCustomActions{}}},
			"arn:rg/full": {RulesSource: &nfwtypes.RulesSource{StatelessRulesAndCustomActions: &nfwtypes.StatelessRulesAndCustomActions{
				StatelessRules: []nfwtypes.StatelessRule{{Priority: awssdk.Int32(1)}},
			}}},
		},
	}
	got, err := readNetworkFirewall(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 6, "both firewall pages, both policies, both groups")
	require.Equal(t, nfwtypes.RuleGroupTypeStateless, f.groupType, "only stateless groups are listed")
	m := byID(got)

	require.Equal(t, map[string]string{"vpc_id": "vpc-1", "firewall_policy_arn": "arn:pol/p",
		"delete_protection": "true", "subnet_change_protection": "false",
		"logging_flow": "false", "logging_alert": "false", "logging_tls": "false"}, m["arn:fw/a"].Metadata,
		"no logging configuration is an observed none")
	require.Empty(t, m["arn:fw/b"].Metadata, "a denied describe leaves posture unknown")
	require.Equal(t, networkFirewallType, m["arn:fw/b"].Type)

	p := m["arn:pol/p"].Metadata
	require.Equal(t, "1", p["stateful_rule_group_count"])
	require.Equal(t, "0", p["stateless_rule_group_count"])
	require.Equal(t, "aws:forward_to_sfe", p["stateless_default_actions"])
	require.Equal(t, "aws:pass", p["stateless_fragment_default_actions"])
	require.Equal(t, "1", p["association_count"])
	require.Empty(t, m["arn:pol/empty"].Metadata)

	require.Equal(t, "0", m["arn:rg/empty"].Metadata["stateless_rule_count"])
	require.Equal(t, "1", m["arn:rg/full"].Metadata["stateless_rule_count"])

	f.listErr = errors.New("throttled")
	_, err = readNetworkFirewall(context.Background(), f, "eu-west-1", "111", time.Now())
	require.Error(t, err, "a failed listing page fails the read")
}

func TestDescribeFirewallLogging(t *testing.T) {
	fw := nfwtypes.FirewallMetadata{FirewallArn: awssdk.String("arn:fw/a"), FirewallName: awssdk.String("a")}
	f := &fakeNetworkFirewall{
		firewalls: map[string]*nfwtypes.Firewall{"arn:fw/a": {VpcId: awssdk.String("vpc-1")}},
		logging: map[string]*nfwtypes.LoggingConfiguration{"arn:fw/a": {LogDestinationConfigs: []nfwtypes.LogDestinationConfig{
			{LogType: nfwtypes.LogTypeAlert}, {LogType: nfwtypes.LogTypeFlow},
		}}},
	}
	a, err := describeFirewall(context.Background(), f, fw, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "true", a.Metadata["logging_flow"])
	require.Equal(t, "true", a.Metadata["logging_alert"])
	require.Equal(t, "false", a.Metadata["logging_tls"])

	f.loggingErr = errors.New("AccessDeniedException")
	a, err = describeFirewall(context.Background(), f, fw, "eu-west-1", "111", time.Now())
	require.NoError(t, err, "an unread logging configuration keeps the firewall's other posture")
	require.Equal(t, "vpc-1", a.Metadata["vpc_id"])
	for _, k := range []string{"logging_flow", "logging_alert", "logging_tls"} {
		require.NotContains(t, a.Metadata, k, "unread logging is unknown, never off")
	}
}
