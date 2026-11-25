package aws

// cloudwatch_alarms.go — the CIS AWS 5.1–5.15 monitoring chains.
//
// Each CIS monitoring control is the same chain with a different event
// pattern: a metric filter on the log group of a multi-region trail that
// records all management events, a CloudWatch alarm on the filter's metric,
// and an SNS topic in the alarm's actions with at least one confirmed
// subscriber. One evaluator walks the chain for all fifteen patterns and
// writes one cw_alarm_<pattern> key each to aws_account_settings.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sns"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// cisAlarm is one CIS monitoring pattern. A metric filter satisfies it when,
// for every event term in any, one of the filter's AND-groups contains that
// term and nothing else but terms CIS itself puts beside it (allowed: an
// eventSource, the benchmark's own exclusions). So the event terms must be
// OR'd — `A && B` matches no single event — and a group narrowed by any other
// condition does not count. A filter covering more events than the benchmark
// lists, or several controls at once, still alerts on everything the control
// asks for and satisfies it.
type cisAlarm struct {
	key     string
	any     []filterTerm
	allowed []filterTerm
}

// eventNames renders the `$.eventName = X` term for each name.
func eventNames(names ...string) []filterTerm {
	src := make([]string, len(names))
	for i, n := range names {
		src[i] = "$.eventName = " + n
	}
	return mustTerms(src...)
}

func eventSource(service string) []filterTerm {
	return mustTerms("$.eventSource = " + service + ".amazonaws.com")
}

// cisAlarms are the CIS AWS Foundations 5.1–5.15 patterns, in control order.
var cisAlarms = []cisAlarm{
	{"cw_alarm_unauthorized_api_calls",
		mustTerms(`$.errorCode = "*UnauthorizedOperation"`, `$.errorCode = "AccessDenied*"`),
		mustTerms(`$.sourceIPAddress != "delivery.logs.amazonaws.com"`, `$.eventName != "HeadBucket"`)},
	{"cw_alarm_console_login_no_mfa",
		eventNames("ConsoleLogin"),
		mustTerms(`$.additionalEventData.MFAUsed != "Yes"`, `$.userIdentity.type = "IAMUser"`, `$.responseElements.ConsoleLogin = "Success"`)},
	{"cw_alarm_root_usage",
		mustTerms(`$.userIdentity.type = "Root"`),
		mustTerms(`$.userIdentity.invokedBy NOT EXISTS`, `$.eventType != "AwsServiceEvent"`)},
	{"cw_alarm_iam_policy_changes", eventNames("DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy",
		"PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
		"CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy",
		"AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"), eventSource("iam")},
	{"cw_alarm_cloudtrail_changes", eventNames("CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"),
		eventSource("cloudtrail")},
	{"cw_alarm_console_auth_failures", eventNames("ConsoleLogin"), mustTerms(`$.errorMessage = "Failed authentication"`)},
	{"cw_alarm_kms_key_disable_or_deletion", eventNames("DisableKey", "ScheduleKeyDeletion"), eventSource("kms")},
	{"cw_alarm_s3_bucket_policy_changes", eventNames("PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle",
		"PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors", "DeleteBucketLifecycle", "DeleteBucketReplication"),
		eventSource("s3")},
	{"cw_alarm_config_changes", eventNames("StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel",
		"PutConfigurationRecorder"), eventSource("config")},
	{"cw_alarm_security_group_changes", eventNames("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
		"RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"), eventSource("ec2")},
	{"cw_alarm_nacl_changes", eventNames("CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl",
		"DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"), eventSource("ec2")},
	{"cw_alarm_network_gateway_changes", eventNames("CreateCustomerGateway", "DeleteCustomerGateway",
		"AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"), eventSource("ec2")},
	{"cw_alarm_route_table_changes", eventNames("CreateRoute", "CreateRouteTable", "ReplaceRoute",
		"ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"), eventSource("ec2")},
	{"cw_alarm_vpc_changes", eventNames("CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection",
		"CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection",
		"AttachClassicLinkVpc", "DetachClassicLinkVpc", "DisableVpcClassicLink", "EnableVpcClassicLink"), eventSource("ec2")},
	{"cw_alarm_organizations_changes", eventNames("AcceptHandshake", "AttachPolicy", "CreateAccount",
		"CreateOrganizationalUnit", "CreatePolicy", "DeclineHandshake", "DeleteOrganization", "DeleteOrganizationalUnit",
		"DeletePolicy", "DetachPolicy", "DisablePolicyType", "EnablePolicyType", "InviteAccountToOrganization",
		"LeaveOrganization", "MoveAccount", "RemoveAccountFromOrganization", "UpdatePolicy", "UpdateOrganizationalUnit"),
		eventSource("organizations")},
}

// matches reports whether a filter, parsed to its AND-groups, satisfies the
// pattern.
func (c cisAlarm) matches(groups [][]filterTerm) bool {
	for _, want := range c.any {
		if !slices.ContainsFunc(groups, func(g []filterTerm) bool { return c.groupAlerts(g, want) }) {
			return false
		}
	}
	return true
}

// groupAlerts reports whether an AND-group fires on every event the term
// selects: it contains the term, and every other condition is one CIS puts
// beside it.
func (c cisAlarm) groupAlerts(g []filterTerm, want filterTerm) bool {
	if !slices.Contains(g, want) {
		return false
	}
	for _, t := range g {
		if t != want && !slices.Contains(c.allowed, t) {
			return false
		}
	}
	return true
}

type metricFilterAPI interface {
	DescribeMetricFilters(context.Context, *cloudwatchlogs.DescribeMetricFiltersInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeMetricFiltersOutput, error)
}

type metricAlarmAPI interface {
	DescribeAlarms(context.Context, *cloudwatch.DescribeAlarmsInput, ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

type topicSubscriptionAPI interface {
	ListSubscriptionsByTopic(context.Context, *sns.ListSubscriptionsByTopicInput, ...func(*sns.Options)) (*sns.ListSubscriptionsByTopicOutput, error)
}

// monitoringClients builds the three clients for one region: a trail's log
// group, its alarms and their topics each live in a region of their own.
type monitoringClients func(region string) (metricFilterAPI, metricAlarmAPI, topicSubscriptionAPI)

// collectCISAlarms evaluates the monitoring chains for the account. It never
// errors: a failed read leaves the affected keys absent, and the warning names
// the permissions.
func collectCISAlarms(ctx context.Context, cfg map[string]string, accountID string, trails []asset.Asset) map[string]string {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("cis alarm chains: no AWS config; monitoring checks cannot evaluate this sweep")
		return nil
	}
	clients := func(region string) (metricFilterAPI, metricAlarmAPI, topicSubscriptionAPI) {
		c := awsCfg.Copy()
		c.Region = region
		return cloudwatchlogs.NewFromConfig(c), cloudwatch.NewFromConfig(c), sns.NewFromConfig(c)
	}
	out, err := cisAlarmSettings(ctx, clients, accountID, trails)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("cis alarm chain read failed; affected monitoring checks cannot evaluate this sweep (check logs:DescribeMetricFilters, cloudwatch:DescribeAlarms, sns:ListSubscriptionsByTopic)")
	}
	return out
}

// alarmLogGroup is a CloudWatch Logs group a qualifying trail delivers to.
type alarmLogGroup struct{ region, name string }

// alarmLogGroups returns the log groups of the trails CIS 5.x evaluates:
// multi-region, logging, recording read and write management events. unknown
// is true when a trail that might qualify could not be judged — its logging
// status or selectors are unread, or its log group sits in another account
// (an organization trail viewed from a member), where this connector cannot
// read the filters.
func alarmLogGroups(accountID string, trails []asset.Asset) (groups []alarmLogGroup, unknown bool) {
	for _, t := range trails {
		md := t.Metadata
		if md["multi_region"] != "true" || md["is_logging"] == "false" {
			continue
		}
		mgmt, ok := md["management_events"]
		if md["is_logging"] == "" || !ok {
			unknown = true
			continue
		}
		if mgmt != recordsAll || md["cloudwatch_log_group"] == "" {
			continue
		}
		g, acct, ok := parseLogGroupARN(md["cloudwatch_log_group"])
		if !ok || acct != accountID {
			unknown = true
			continue
		}
		groups = append(groups, g)
	}
	return groups, unknown
}

// parseLogGroupARN splits arn:<p>:logs:<region>:<account>:log-group:<name>[:*].
func parseLogGroupARN(arn string) (alarmLogGroup, string, bool) {
	parts := strings.SplitN(arn, ":", 7)
	if len(parts) < 7 || parts[2] != "logs" || parts[5] != "log-group" {
		return alarmLogGroup{}, "", false
	}
	name := strings.TrimSuffix(parts[6], ":*")
	if parts[3] == "" || name == "" {
		return alarmLogGroup{}, "", false
	}
	return alarmLogGroup{region: parts[3], name: name}, parts[4], true
}

// cisAlarmSettings walks the chain for every pattern over every qualifying
// log group. A key is "true" once one chain is complete, "false" when every
// read succeeded and none is, and absent otherwise.
//
// cw_alarm_monitoring_trail says whether there is a log group to search at
// all: "false" only when every trail was judged and none qualifies — then the
// one aws-cloudwatch-no-cis-monitoring-trail finding stands for all fifteen
// patterns. The error joins every failed read, for the caller's warning.
func cisAlarmSettings(ctx context.Context, clients monitoringClients, accountID string, trails []asset.Asset) (map[string]string, error) {
	groups, unknown := alarmLogGroups(accountID, trails)
	out := map[string]string{}
	switch {
	case len(groups) > 0:
		out["cw_alarm_monitoring_trail"] = "true"
	case !unknown:
		out["cw_alarm_monitoring_trail"] = "false"
	}
	satisfied := make([]bool, len(cisAlarms))
	undecided := make([]bool, len(cisAlarms))
	ch := &alarmChain{clients: clients, alarms: map[string]alarmList{}, topics: map[string]topicResult{}}
	var errs []error
	var names []string
	for _, g := range groups {
		names = append(names, g.name)
		logs, _, _ := clients(g.region)
		filters, err := listMetricFilters(ctx, logs, g.name)
		if err != nil {
			errs = append(errs, err)
			unknown = true
			continue
		}
		for _, f := range filters {
			parsed, err := filterGroups(awssdk.ToString(f.FilterPattern))
			if err != nil {
				// Text patterns and syntax this parser does not know cannot be
				// shown to alert on the CIS events; they count as no filter.
				continue
			}
			for i, def := range cisAlarms {
				if satisfied[i] || !def.matches(parsed) {
					continue
				}
				for _, m := range f.MetricTransformations {
					ok, err := ch.alarmed(ctx, g.region, awssdk.ToString(m.MetricName), awssdk.ToString(m.MetricNamespace))
					if err != nil {
						errs = append(errs, err)
						undecided[i] = true
					}
					satisfied[i] = satisfied[i] || ok
				}
			}
		}
	}
	if len(names) > 0 {
		out["cw_alarm_log_groups"] = strings.Join(names, ",")
	}
	for i, def := range cisAlarms {
		switch {
		case satisfied[i]:
			out[def.key] = "true"
		case !unknown && !undecided[i]:
			out[def.key] = "false"
		}
	}
	return out, errors.Join(errs...)
}

func listMetricFilters(ctx context.Context, client metricFilterAPI, group string) ([]cwltypes.MetricFilter, error) {
	var (
		out  []cwltypes.MetricFilter
		next *string
	)
	for {
		page, err := client.DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{
			LogGroupName: awssdk.String(group), NextToken: next,
		})
		if err != nil {
			return nil, fmt.Errorf("listMetricFilters %s: %w", group, err)
		}
		out = append(out, page.MetricFilters...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		next = page.NextToken
	}
}

type topicResult struct {
	subscribed bool
	err        error
}

type alarmList struct {
	alarms []cwtypes.MetricAlarm
	err    error
}

// alarmChain caches the region's alarm listing and each topic's subscription
// answer across the fifteen patterns.
type alarmChain struct {
	clients monitoringClients
	alarms  map[string]alarmList
	topics  map[string]topicResult
}

// alarmed reports whether an enabled alarm on the metric notifies an SNS
// topic with at least one confirmed subscription. Alarms are matched on
// metric name and namespace from the region's full listing, not with
// DescribeAlarmsForMetric: a filter that emits dimensions puts them on the
// alarm, and a dimensionless metric query would not find it.
func (c *alarmChain) alarmed(ctx context.Context, region, name, namespace string) (bool, error) {
	if name == "" || namespace == "" {
		return false, nil
	}
	list, seen := c.alarms[region]
	if !seen {
		_, cw, _ := c.clients(region)
		list.alarms, list.err = listMetricAlarms(ctx, cw)
		c.alarms[region] = list
	}
	if list.err != nil {
		return false, list.err
	}
	var errs []error
	for _, a := range list.alarms {
		// Omitted ActionsEnabled is the API default: actions on.
		if awssdk.ToString(a.MetricName) != name || awssdk.ToString(a.Namespace) != namespace ||
			(a.ActionsEnabled != nil && !*a.ActionsEnabled) {
			continue
		}
		for _, action := range a.AlarmActions {
			topicRegion, ok := snsTopicRegion(action)
			if !ok {
				continue
			}
			r, seen := c.topics[action]
			if !seen {
				_, _, subs := c.clients(topicRegion)
				r.subscribed, r.err = topicSubscribed(ctx, subs, action)
				c.topics[action] = r
			}
			if r.subscribed {
				return true, nil
			}
			if r.err != nil {
				errs = append(errs, r.err)
			}
		}
	}
	return false, errors.Join(errs...)
}

// listMetricAlarms reads every page of the region's metric alarms.
func listMetricAlarms(ctx context.Context, cw metricAlarmAPI) ([]cwtypes.MetricAlarm, error) {
	var (
		out  []cwtypes.MetricAlarm
		next *string
	)
	for {
		page, err := cw.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
			AlarmTypes: []cwtypes.AlarmType{cwtypes.AlarmTypeMetricAlarm}, NextToken: next,
		})
		if err != nil {
			return nil, fmt.Errorf("listMetricAlarms: %w", err)
		}
		out = append(out, page.MetricAlarms...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		next = page.NextToken
	}
}

// snsTopicRegion returns the region of an SNS topic ARN, or false for any
// other alarm action (Auto Scaling, EC2 actions, Systems Manager).
func snsTopicRegion(arn string) (string, bool) {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "sns" || parts[3] == "" {
		return "", false
	}
	return parts[3], true
}

// topicSubscribed reports whether the topic has a confirmed subscription: a
// pending one (SubscriptionArn "PendingConfirmation") delivers nothing.
func topicSubscribed(ctx context.Context, client topicSubscriptionAPI, topic string) (bool, error) {
	var next *string
	for {
		out, err := client.ListSubscriptionsByTopic(ctx, &sns.ListSubscriptionsByTopicInput{TopicArn: awssdk.String(topic), NextToken: next})
		if err != nil {
			return false, fmt.Errorf("topicSubscribed %s: %w", topic, err)
		}
		for _, s := range out.Subscriptions {
			if arn := awssdk.ToString(s.SubscriptionArn); strings.HasPrefix(arn, "arn:") {
				return true, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return false, nil
		}
		next = out.NextToken
	}
}
