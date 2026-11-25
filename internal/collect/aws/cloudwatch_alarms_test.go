package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeMonitoring answers all three chain reads; pages split filters across
// NextToken pages to exercise pagination.
type fakeMonitoring struct {
	filterPages [][]cwltypes.MetricFilter
	filterErr   error
	alarms      []cwtypes.MetricAlarm
	alarmErr    error
	subs        map[string][]snstypes.Subscription // topic ARN → subscriptions
	subErr      error
	regions     []string
}

func (f *fakeMonitoring) DescribeMetricFilters(_ context.Context, in *cloudwatchlogs.DescribeMetricFiltersInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error) {
	if f.filterErr != nil {
		return nil, f.filterErr
	}
	i := 0
	if in.NextToken != nil {
		i = int((*in.NextToken)[0] - '0')
	}
	out := &cloudwatchlogs.DescribeMetricFiltersOutput{}
	if i < len(f.filterPages) {
		out.MetricFilters = f.filterPages[i]
	}
	if i+1 < len(f.filterPages) {
		out.NextToken = awssdk.String(string(rune('0' + i + 1)))
	}
	return out, nil
}

func (f *fakeMonitoring) DescribeAlarms(_ context.Context, in *cloudwatch.DescribeAlarmsInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error) {
	if f.alarmErr != nil {
		return nil, f.alarmErr
	}
	// Two pages: the alarms arrive on the second.
	if in.NextToken == nil {
		return &cloudwatch.DescribeAlarmsOutput{NextToken: awssdk.String("p2")}, nil
	}
	return &cloudwatch.DescribeAlarmsOutput{MetricAlarms: f.alarms}, nil
}

func (f *fakeMonitoring) ListSubscriptionsByTopic(_ context.Context, in *sns.ListSubscriptionsByTopicInput, _ ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error) {
	if f.subErr != nil {
		return nil, f.subErr
	}
	return &sns.ListSubscriptionsByTopicOutput{Subscriptions: f.subs[awssdk.ToString(in.TopicArn)]}, nil
}

func (f *fakeMonitoring) clients(region string) (metricFilterAPI, metricAlarmAPI, topicSubscriptionAPI) {
	f.regions = append(f.regions, region)
	return f, f, f
}

const (
	cwTopic    = "arn:aws:sns:us-east-1:111:security-alerts"
	cwLogGroup = "arn:aws:logs:us-east-1:111:log-group:CloudTrail/org:*"
)

var cwQualifyingTrail = metaAsset("multi_region", "true", "is_logging", "true", "management_events", "all",
	"cloudwatch_log_group", cwLogGroup)

func rootUsageFilter(metric string) cwltypes.MetricFilter {
	return cwltypes.MetricFilter{
		FilterPattern:         awssdk.String(`{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`),
		MetricTransformations: []cwltypes.MetricTransformation{{MetricName: awssdk.String(metric), MetricNamespace: awssdk.String("CISBenchmark")}},
	}
}

func subscribed() map[string][]snstypes.Subscription {
	return map[string][]snstypes.Subscription{cwTopic: {{SubscriptionArn: awssdk.String(cwTopic + ":abc")}}}
}

func alarmOn(metric string, enabled *bool, actions ...string) []cwtypes.MetricAlarm {
	return []cwtypes.MetricAlarm{
		{AlarmName: awssdk.String("other"), MetricName: awssdk.String("Other"), Namespace: awssdk.String("CISBenchmark"), AlarmActions: []string{cwTopic}},
		{AlarmName: awssdk.String(metric), MetricName: awssdk.String(metric), Namespace: awssdk.String("CISBenchmark"), ActionsEnabled: enabled, AlarmActions: actions},
	}
}

func TestCISAlarmSettings_Chain(t *testing.T) {
	tests := []struct {
		name string
		f    fakeMonitoring
		want string // cw_alarm_root_usage; "" = absent
	}{
		{"complete chain, filter on the second page",
			fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{}, {rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", nil, cwTopic), subs: subscribed()}, "true"},
		{"no filter", fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{}}}, "false"},
		{"filter without an alarm", fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}}, "false"},
		{"alarm with actions disabled",
			fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", awssdk.Bool(false), cwTopic), subs: subscribed()}, "false"},
		{"alarm whose only action is not SNS",
			fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", nil, "arn:aws:automate:us-east-1:ec2:stop"), subs: subscribed()}, "false"},
		{"topic with only a pending subscription",
			fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", nil, cwTopic),
				subs: map[string][]snstypes.Subscription{cwTopic: {{SubscriptionArn: awssdk.String("PendingConfirmation")}}}}, "false"},
		{"filter read denied: unknown", fakeMonitoring{filterErr: apiErr{code: "AccessDeniedException"}}, ""},
		{"alarm read denied: unknown",
			fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarmErr: apiErr{code: "AccessDenied"}}, ""},
		{"subscription read denied: unknown",
			fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", nil, cwTopic), subErr: apiErr{code: "AuthorizationError"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := cisAlarmSettings(context.Background(), tt.f.clients, "111", []asset.Asset{cwQualifyingTrail})
			v, ok := got["cw_alarm_root_usage"]
			if tt.want == "" {
				require.False(t, ok, "an unread link in the chain is unknown, got %q", v)
				return
			}
			require.Equal(t, tt.want, v)
		})
	}
}

// A denied filter read must not settle patterns another read never reached;
// a completed chain on one pattern leaves the other fourteen false.
func TestCISAlarmSettings_OtherPatternsFalseWhenEverythingWasRead(t *testing.T) {
	f := fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", nil, cwTopic), subs: subscribed()}
	got, err := cisAlarmSettings(context.Background(), f.clients, "111", []asset.Asset{cwQualifyingTrail})
	require.NoError(t, err)
	require.Equal(t, "CloudTrail/org", got["cw_alarm_log_groups"])
	for _, def := range cisAlarms {
		want := "false"
		if def.key == "cw_alarm_root_usage" {
			want = "true"
		}
		require.Equal(t, want, got[def.key], def.key)
	}
	require.Contains(t, f.regions, "us-east-1", "clients are built for the log group's and the topic's region")
}

func TestCISAlarmSettings_TrailQualification(t *testing.T) {
	tests := []struct {
		name   string
		trails []asset.Asset
		want   string // cw_alarm_root_usage; "" = absent
		trail  string // cw_alarm_monitoring_trail; "" = absent
	}{
		{"no trail at all: no chain can exist", nil, "false", "false"},
		{"qualifying trail without a log group",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true", "management_events", "all", "cloudwatch_log_group", "")}, "false", "false"},
		{"read-only management trail does not qualify",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true", "management_events", "read", "cloudwatch_log_group", cwLogGroup)}, "false", "false"},
		{"unread selectors: unknown",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true", "cloudwatch_log_group", cwLogGroup)}, "", ""},
		{"unread logging status: unknown",
			[]asset.Asset{metaAsset("multi_region", "true", "management_events", "all", "cloudwatch_log_group", cwLogGroup)}, "", ""},
		{"organization trail delivering to another account's log group: unknown",
			[]asset.Asset{metaAsset("multi_region", "true", "is_logging", "true", "management_events", "all",
				"cloudwatch_log_group", "arn:aws:logs:us-east-1:999:log-group:org-trail:*")}, "", ""},
		{"qualifying trail", []asset.Asset{cwQualifyingTrail}, "true", "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{rootUsageFilter("RootUsage")}}, alarms: alarmOn("RootUsage", nil, cwTopic), subs: subscribed()}
			got, _ := cisAlarmSettings(context.Background(), f.clients, "111", tt.trails)
			tr, ok := got["cw_alarm_monitoring_trail"]
			if tt.trail == "" {
				require.False(t, ok, "monitoring trail: got %q", tr)
			} else {
				require.Equal(t, tt.trail, tr)
			}
			v, ok := got["cw_alarm_root_usage"]
			if tt.want == "" {
				require.False(t, ok, "got %q", v)
				return
			}
			require.Equal(t, tt.want, v)
		})
	}
}

// Each CIS pattern, written the way the benchmark prints it, satisfies its
// own definition; whitespace and quoting do not matter, and a filter that
// lists only some of the events does not count.
func TestCISAlarmPatterns(t *testing.T) {
	cisText := map[string]string{
		"cw_alarm_unauthorized_api_calls":      `{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }`,
		"cw_alarm_console_login_no_mfa":        `{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }`,
		"cw_alarm_root_usage":                  `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`,
		"cw_alarm_iam_policy_changes":          `{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}`,
		"cw_alarm_cloudtrail_changes":          `{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }`,
		"cw_alarm_console_auth_failures":       `{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }`,
		"cw_alarm_kms_key_disable_or_deletion": `{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }`,
		"cw_alarm_s3_bucket_policy_changes":    `{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }`,
		"cw_alarm_config_changes":              `{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel) ||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }`,
		"cw_alarm_security_group_changes":      `{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }`,
		"cw_alarm_nacl_changes":                `{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }`,
		"cw_alarm_network_gateway_changes":     `{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }`,
		"cw_alarm_route_table_changes":         `{($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)) }`,
		"cw_alarm_vpc_changes":                 `{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }`,
		"cw_alarm_organizations_changes":       `{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit")) }`,
	}
	require.Len(t, cisAlarms, 15)
	for _, def := range cisAlarms {
		text, ok := cisText[def.key]
		require.True(t, ok, "no CIS text for %s", def.key)
		require.True(t, alarmMatches(t, def, text), "%s does not match its own CIS pattern", def.key)
	}
}

func alarmMatches(t *testing.T, def cisAlarm, pattern string) bool {
	t.Helper()
	groups, err := filterGroups(pattern)
	if err != nil {
		return false
	}
	return def.matches(groups)
}

func alarmDef(t *testing.T, key string) cisAlarm {
	t.Helper()
	for _, d := range cisAlarms {
		if d.key == key {
			return d
		}
	}
	t.Fatalf("no CIS alarm %s", key)
	return cisAlarm{}
}

// The cases substring matching let through, and the layout variants that
// must still pass.
func TestCISAlarmPatterns_Semantics(t *testing.T) {
	cloudtrailAll := `($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)`
	tests := []struct {
		name, key, pattern string
		want               bool
	}{
		{"CreateRouteTable is not CreateRoute", "cw_alarm_route_table_changes",
			`{ ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }`, false},
		{"CreateNetworkAclEntry is not CreateNetworkAcl", "cw_alarm_nacl_changes",
			`{ ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }`, false},
		{"CreatePolicyVersion is not CreatePolicy", "cw_alarm_iam_policy_changes",
			`{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}`, false},
		{"event names chained with && can never fire", "cw_alarm_cloudtrail_changes",
			`{ ($.eventName = CreateTrail) && ($.eventName = UpdateTrail) && ($.eventName = DeleteTrail) && ($.eventName = StartLogging) && ($.eventName = StopLogging) }`, false},
		{"extra narrowing term", "cw_alarm_cloudtrail_changes",
			`{ (` + cloudtrailAll + `) && $.userIdentity.arn = "arn:aws:iam::111:user/bob" }`, false},
		{"narrowing on one event only", "cw_alarm_cloudtrail_changes",
			`{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging && $.awsRegion = "us-east-1") }`, false},
		{"missing events", "cw_alarm_cloudtrail_changes", `{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) }`, false},
		{"negated terms", "cw_alarm_cloudtrail_changes",
			`{ ($.eventName != CreateTrail) || ($.eventName != UpdateTrail) || ($.eventName != DeleteTrail) || ($.eventName != StartLogging) || ($.eventName != StopLogging) }`, false},
		{"root usage narrowed to one user agent", "cw_alarm_root_usage",
			`{ $.userIdentity.type = "Root" && $.userAgent = "console.amazonaws.com" }`, false},
		{"console failures filter does not answer no-MFA", "cw_alarm_console_login_no_mfa",
			`{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }`, false},
		{"text pattern is not a JSON filter", "cw_alarm_cloudtrail_changes", `CreateTrail UpdateTrail`, false},
		{"order and whitespace variants", "cw_alarm_cloudtrail_changes",
			"{\n  $.eventName=\"StopLogging\"||$.eventName = StartLogging ||\t($.eventName=DeleteTrail)||($.eventName = \"UpdateTrail\") || $.eventName=CreateTrail\n}", true},
		{"one filter covering two controls satisfies each", "cw_alarm_cloudtrail_changes",
			`{ ` + cloudtrailAll + ` || ($.eventName = StopConfigurationRecorder) }`, true},
		{"eventSource beside the names is allowed", "cw_alarm_cloudtrail_changes",
			`{ ($.eventSource = cloudtrail.amazonaws.com) && (` + cloudtrailAll + `) }`, true},
		{"root usage without the benchmark's exclusions alerts on more", "cw_alarm_root_usage", `{ $.userIdentity.type = Root }`, true},
		{"route table with eventSource, reordered", "cw_alarm_route_table_changes",
			`{ (($.eventName = DisassociateRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DeleteRouteTable) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = ReplaceRoute) || ($.eventName = CreateRouteTable) || ($.eventName = CreateRoute)) && ($.eventSource = ec2.amazonaws.com) }`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, alarmMatches(t, alarmDef(t, tt.key), tt.pattern))
		})
	}
}

func TestFilterGroups(t *testing.T) {
	g, err := filterGroups(`{ ($.a = 1 || $.b = "x y") && $.c NOT EXISTS }`)
	require.NoError(t, err)
	require.Equal(t, [][]filterTerm{
		{{"$.a", "=", "1"}, {"$.c", "NOT EXISTS", ""}},
		{{"$.b", "=", "x y"}, {"$.c", "NOT EXISTS", ""}},
	}, g, "&& distributes over ||")
	g, err = filterGroups(`{ $.a = 1 || $.b = 2 && $.c = 3 }`)
	require.NoError(t, err)
	require.Len(t, g, 2, "&& binds tighter than ||")
	for _, bad := range []string{`{ $.a = }`, `{ ($.a = 1 }`, `{ a = 1 }`, `$.a = 1`, `{ $.a = "open }`} {
		_, err := filterGroups(bad)
		require.Error(t, err, bad)
	}
}

// A metric filter that emits dimensions puts them on its alarm; the chain
// still finds it by metric name and namespace.
func TestCISAlarmSettings_DimensionedMetric(t *testing.T) {
	f := rootUsageFilter("RootUsage")
	f.MetricTransformations[0].Dimensions = map[string]string{"user": "$.userIdentity.arn"}
	alarms := alarmOn("RootUsage", nil, cwTopic)
	alarms[1].Dimensions = []cwtypes.Dimension{{Name: awssdk.String("user"), Value: awssdk.String("root")}}
	m := fakeMonitoring{filterPages: [][]cwltypes.MetricFilter{{f}}, alarms: alarms, subs: subscribed()}
	got, err := cisAlarmSettings(context.Background(), m.clients, "111", []asset.Asset{cwQualifyingTrail})
	require.NoError(t, err)
	require.Equal(t, "true", got["cw_alarm_root_usage"])
}

func TestParseLogGroupARN(t *testing.T) {
	g, acct, ok := parseLogGroupARN("arn:aws:logs:eu-west-1:111:log-group:aws-cloudtrail-logs-111:*")
	require.True(t, ok)
	require.Equal(t, alarmLogGroup{region: "eu-west-1", name: "aws-cloudtrail-logs-111"}, g)
	require.Equal(t, "111", acct)
	g, _, ok = parseLogGroupARN("arn:aws:logs:eu-west-1:111:log-group:/aws/cloudtrail:with:colons")
	require.True(t, ok)
	require.Equal(t, "/aws/cloudtrail:with:colons", g.name)
	_, _, ok = parseLogGroupARN("not-an-arn")
	require.False(t, ok)
}
