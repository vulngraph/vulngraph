package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/api/googleapi"
	logging "google.golang.org/api/logging/v2"
	monitoring "google.golang.org/api/monitoring/v3"
)

type fakeLogging struct {
	sinks       map[string][]*logging.LogSink
	sinkErr     map[string]error
	metrics     []*logging.LogMetric
	metricErr   error
	policies    []*monitoring.AlertPolicy
	policyErr   error
	locked      map[string]bool
	bucketErr   map[string]error
	ancestors   []string
	ancestryErr error
}

func (f fakeLogging) Sinks(_ context.Context, parent string) ([]*logging.LogSink, error) {
	return f.sinks[parent], f.sinkErr[parent]
}
func (f fakeLogging) Metrics(context.Context, string) ([]*logging.LogMetric, error) {
	return f.metrics, f.metricErr
}
func (f fakeLogging) AlertPolicies(context.Context, string) ([]*monitoring.AlertPolicy, error) {
	return f.policies, f.policyErr
}
func (f fakeLogging) BucketLocked(_ context.Context, b string) (bool, error) {
	return f.locked[b], f.bucketErr[b]
}
func (f fakeLogging) Ancestry(context.Context, string) ([]string, error) {
	return f.ancestors, f.ancestryErr
}

// The CIS v5 recommended filters, verbatim.
const (
	cisOwnershipFilter = `(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")`
	cisFirewallFilter  = `resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.patch" OR protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.delete")`
	cisAuditFilter     = `protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*`
)

// cisFilters are the CIS v5 recommended filters for every alert, verbatim.
var cisFilters = map[string]string{
	"project_ownership_changes": cisOwnershipFilter,
	"audit_config_changes":      cisAuditFilter,
	"custom_role_changes":       `resource.type="iam_role" AND (protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole")`,
	"firewall_changes":          cisFirewallFilter,
	"route_changes":             `resource.type="gce_route" AND (protoPayload.methodName:"compute.routes.delete" OR protoPayload.methodName:"compute.routes.insert")`,
	"network_changes":           `resource.type="gce_network" AND (protoPayload.methodName:"compute.networks.insert" OR protoPayload.methodName:"compute.networks.patch" OR protoPayload.methodName:"compute.networks.delete" OR protoPayload.methodName:"compute.networks.removePeering" OR protoPayload.methodName:"compute.networks.addPeering")`,
	"storage_iam_changes":       `resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"`,
	"sql_config_changes":        `protoPayload.methodName="cloudsql.instances.update"`,
}

func alertByName(name string) logAlert {
	for _, a := range logAlerts {
		if a.Name == name {
			return a
		}
	}
	panic(name)
}

func TestFilterCovers_CISFiltersCoverTheirOwnChange(t *testing.T) {
	require.Len(t, cisFilters, len(logAlerts))
	for name, f := range cisFilters {
		require.True(t, filterCovers(f, alertByName(name)), name)
	}
}

func TestFilterCovers(t *testing.T) {
	fw := alertByName("firewall_changes")
	for _, tc := range []struct {
		name   string
		filter string
		want   bool
	}{
		{"reordered, re-spaced, single quotes", `( protoPayload.methodName : 'compute.firewalls.delete' OR protoPayload.methodName:'compute.firewalls.insert'
		  OR protoPayload.methodName:"compute.firewalls.patch" ) resource.type = "gce_firewall_rule"`, true},
		{"broader: every compute call on firewalls", `resource.type="gce_firewall_rule"`, true},
		{"regex over the methods", `resource.type="gce_firewall_rule" AND protoPayload.methodName=~"compute\.firewalls\.(patch|insert|delete)"`, true},
		{"one method missing", `resource.type="gce_firewall_rule" AND (protoPayload.methodName:"compute.firewalls.insert" OR protoPayload.methodName:"compute.firewalls.patch")`, false},
		{"methods AND-ed where CIS ORs them", `resource.type="gce_firewall_rule" AND protoPayload.methodName:"compute.firewalls.patch" AND protoPayload.methodName:"compute.firewalls.insert" AND protoPayload.methodName:"compute.firewalls.delete"`, false},
		{"narrowing AND clause", cisFirewallFilter + ` AND severity>=ERROR`, false},
		{"narrowing to one project", cisFirewallFilter + ` AND resource.labels.project_id="dev"`, false},
		{"NOT of the change", `resource.type="gce_firewall_rule" AND NOT protoPayload.methodName:"compute.firewalls.delete"`, false},
		{"leading minus negates", `resource.type="gce_firewall_rule" -protoPayload.methodName:"compute.firewalls.patch"`, false},
		{"exact match on a method suffix misses the v1. prefix", `resource.type="gce_firewall_rule" AND (protoPayload.methodName="compute.firewalls.patch" OR protoPayload.methodName="compute.firewalls.insert" OR protoPayload.methodName="compute.firewalls.delete")`, false},
		{"unparsable", `resource.type="gce_firewall_rule" AND (`, false},
		{"empty", ``, false},
	} {
		require.Equal(t, tc.want, filterCovers(tc.filter, fw), tc.name)
	}
	sql := alertByName("sql_config_changes")
	require.False(t, filterCovers(`protoPayload.methodName!="cloudsql.instances.update"`, sql))
	require.True(t, filterCovers(`NOT protoPayload.methodName="cloudsql.instances.delete" AND protoPayload.methodName:"cloudsql.instances"`, sql))
	// OR binds tighter than AND in the Logging query language.
	own := alertByName("project_ownership_changes")
	require.False(t, filterCovers(`protoPayload.serviceName="cloudresourcemanager.googleapis.com" AND ProjectOwnership`, own))
}

func TestMissingLogAlerts(t *testing.T) {
	channel := []string{"projects/p/notificationChannels/1"}
	metrics := []*logging.LogMetric{
		{Name: "fw-changes", Filter: cisFirewallFilter},
		{Name: "owner", Filter: cisOwnershipFilter},
		{Name: "audit-disabled", Filter: cisAuditFilter, Disabled: true},
		{Name: "routes", Filter: cisFilters["route_changes"]},
	}
	policies := []*monitoring.AlertPolicy{
		{Enabled: true, NotificationChannels: channel, Conditions: []*monitoring.Condition{{ConditionThreshold: &monitoring.MetricThreshold{
			Filter: `metric.type="logging.googleapis.com/user/fw-changes" AND resource.type="global"`}}}},
		// Alerting on the ownership metric, but the policy is off.
		{Enabled: false, NotificationChannels: channel, Conditions: []*monitoring.Condition{{ConditionThreshold: &monitoring.MetricThreshold{
			Filter: `metric.type="logging.googleapis.com/user/owner"`}}}},
		// Enabled, but notifies nobody.
		{Enabled: true, Conditions: []*monitoring.Condition{{ConditionThreshold: &monitoring.MetricThreshold{
			Filter: `metric.type="logging.googleapis.com/user/routes"`}}}},
		// A log-match alert carries the filter itself.
		{Enabled: true, NotificationChannels: channel, Conditions: []*monitoring.Condition{{ConditionMatchedLog: &monitoring.LogMatch{
			Filter: `resource.type="gcs_bucket" AND protoPayload.methodName="storage.setIamPermissions"`}}}},
		{Enabled: true, NotificationChannels: channel, Conditions: []*monitoring.Condition{nil, {ConditionPrometheusQueryLanguage: &monitoring.PrometheusQueryLanguageCondition{
			Query: `rate(logging_googleapis_com:user_audit-disabled[5m]) > 0`}}}},
	}
	missing := missingLogAlerts(metrics, policies)
	require.NotContains(t, missing, "firewall_changes")
	require.NotContains(t, missing, "storage_iam_changes")
	require.Contains(t, missing, "project_ownership_changes", "a disabled policy alerts nobody")
	require.Contains(t, missing, "route_changes", "a policy with no notification channel alerts nobody")
	require.Contains(t, missing, "audit_config_changes", "a disabled metric counts nothing")
	require.Contains(t, missing, "sql_config_changes")
	require.Len(t, missingLogAlerts(nil, nil), len(logAlerts))
}

func allAlertNames() string {
	var n []string
	for _, a := range logAlerts {
		n = append(n, a.Name)
	}
	return strings.Join(n, ",")
}

func TestCollectLoggingSettings(t *testing.T) {
	f := fakeLogging{
		sinks: map[string][]*logging.LogSink{
			"projects/p": {
				{Name: "filtered", Filter: `severity>=ERROR`, Destination: "storage.googleapis.com/errors-bucket"},
				{Name: "all-but-excluded", Destination: "storage.googleapis.com/locked-bucket",
					Exclusions: []*logging.LogExclusion{{Name: "noisy", Filter: "resource.type=k8s_container"}}},
			},
			"organizations/1": {{Name: "org-all", IncludeChildren: true, Destination: "bigquery.googleapis.com/projects/sec/datasets/logs"}},
		},
		locked:    map[string]bool{"locked-bucket": true},
		ancestors: []string{"folders/9", "organizations/1"},
	}
	md, org, err := collectLoggingSettings(context.Background(), f, "p")
	require.NoError(t, err)
	require.Equal(t, "true", md["log_catch_all_sink"], "an aggregated org sink exports the project's entries")
	require.Equal(t, "organizations/1/sinks/org-all", md["log_catch_all_sinks"])
	require.Equal(t, "organizations/1", org.org)
	require.Equal(t, "true", org.md["log_catch_all_sink"])
	require.Equal(t, "errors-bucket", md["log_sink_buckets_unlocked"])
	require.Equal(t, allAlertNames(), md["log_alerts_missing"])
	require.Equal(t, "true", md["log_compute_alert_missing"])
}

// One finding per root cause: with the organization readable and no
// aggregated sink there, the gap is the organization's — the project stays
// silent. Without an organization, the project carries it.
func TestCollectLoggingSettings_OrgCarriesTheMissingSink(t *testing.T) {
	f := fakeLogging{sinks: map[string][]*logging.LogSink{"organizations/1": {{Name: "errors", Filter: "severity>=ERROR", IncludeChildren: true}}},
		ancestors: []string{"organizations/1"}}
	md, org, err := collectLoggingSettings(context.Background(), f, "p")
	require.NoError(t, err)
	require.NotContains(t, md, "log_catch_all_sink")
	require.Equal(t, "false", org.md["log_catch_all_sink"])

	md, org, err = collectLoggingSettings(context.Background(), fakeLogging{}, "p")
	require.NoError(t, err)
	require.Equal(t, "false", md["log_catch_all_sink"], "no organization, every sink list read")
	require.Empty(t, org.org)
}

// Organization, folder and cross-project reads are optional grants: denied
// leaves the key absent and does NOT fail the family (no partial sweep).
// Monitoring never enabled means no alert policy can exist.
func TestCollectLoggingSettings_DeniedOptionalReadsAreNotPartial(t *testing.T) {
	denied := &googleapi.Error{Code: 403, Message: "The caller does not have permission"}
	f := fakeLogging{
		sinks:     map[string][]*logging.LogSink{"projects/p": {{Name: "s", Filter: "x", Destination: "storage.googleapis.com/central-bucket"}}},
		sinkErr:   map[string]error{"organizations/1": denied},
		bucketErr: map[string]error{"central-bucket": denied},
		ancestors: []string{"organizations/1"},
		policyErr: serviceDisabled,
	}
	md, org, err := collectLoggingSettings(context.Background(), f, "p")
	require.NoError(t, err, "a missing org or cross-project grant is not a partial sweep")
	require.NotContains(t, md, "log_catch_all_sink")
	require.NotContains(t, md, "log_sink_buckets_unlocked")
	require.Empty(t, org.org)
	require.Equal(t, allAlertNames(), md["log_alerts_missing"])

	f.sinkErr = map[string]error{"organizations/1": errors.New("connection reset")}
	_, _, err = collectLoggingSettings(context.Background(), f, "p")
	require.Error(t, err, "a real failure still flags the sweep")

	md, _, err = collectLoggingSettings(context.Background(), fakeLogging{metricErr: errors.New("boom")}, "p")
	require.Error(t, err)
	require.NotContains(t, md, "log_alerts_missing")
	require.NotContains(t, md, "log_compute_alert_missing", "unread metrics are unknown, not missing")
}

func TestComputeConfigAlert(t *testing.T) {
	channel := []string{"projects/p/notificationChannels/1"}
	alertOn := func(metric string) []*monitoring.AlertPolicy {
		return []*monitoring.AlertPolicy{{Enabled: true, NotificationChannels: channel, Conditions: []*monitoring.Condition{{
			ConditionThreshold: &monitoring.MetricThreshold{Filter: `metric.type="logging.googleapis.com/user/` + metric + `"`}}}}}
	}
	for _, tc := range []struct {
		name     string
		filter   string
		policies func(string) []*monitoring.AlertPolicy
		disabled bool
		covered  bool
	}{
		{"whole compute service", `protoPayload.serviceName="compute.googleapis.com"`, alertOn, false, true},
		{"firewalls only", cisFirewallFilter, alertOn, false, false},
		{"disabled metric", `protoPayload.serviceName="compute.googleapis.com"`, alertOn, true, false},
		{"no policy", `protoPayload.serviceName="compute.googleapis.com"`, func(string) []*monitoring.AlertPolicy { return nil }, false, false},
	} {
		metrics := []*logging.LogMetric{{Name: "m", Filter: tc.filter, Disabled: tc.disabled}}
		require.Equal(t, tc.covered, alertInPlace(metrics, tc.policies("m"), computeConfigAlert), tc.name)
	}
}
