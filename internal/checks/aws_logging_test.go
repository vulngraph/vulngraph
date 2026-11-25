package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func settingsAsset(typ string, md map[string]string) asset.Asset {
	return asset.Asset{ID: "s", Type: typ, Provider: asset.ProviderAWS, Metadata: md}
}

// Every CIS 5.x alarm check reads exactly one cw_alarm_* key and fires only on
// an observed "false": the fifteen are one evaluator's output, so one table
// pins them all, including that no two share a key.
func TestCISAlarmChecks_OneKeyEach(t *testing.T) {
	seen := map[string]string{}
	for _, c := range awsMonitoringChecks() {
		if c.ID == awsCWNoCISMonitoringTrail.ID {
			continue
		}
		keys := derivedRequiredKeys[c.ID]
		require.Len(t, keys, 2, c.ID)
		require.Contains(t, keys, "cw_alarm_monitoring_trail", c.ID)
		key := keys[0]
		if key == "cw_alarm_monitoring_trail" {
			key = keys[1]
		}
		require.NotContains(t, seen, key, "%s and %s read the same key", c.ID, seen[key])
		seen[key] = c.ID
		require.Equal(t, finding.SeverityInfo, c.Severity, c.ID)
		md := func(kv ...string) asset.Asset {
			m := map[string]string{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[kv[i]] = kv[i+1]
			}
			return settingsAsset("aws_account_settings", m)
		}
		require.True(t, c.Violates(md(key, "false", "cw_alarm_monitoring_trail", "true")), c.ID)
		require.False(t, c.Violates(md(key, "true", "cw_alarm_monitoring_trail", "true")), c.ID)
		require.False(t, c.Violates(md("cw_alarm_monitoring_trail", "true")), "%s fired on an unread chain", c.ID)
		require.False(t, c.Violates(md(key, "false", "cw_alarm_monitoring_trail", "false")),
			"%s must step aside for aws-cloudwatch-no-cis-monitoring-trail", c.ID)
	}
	require.Len(t, seen, 15)

	ev := cisAlarmEvidence(settingsAsset("aws_account_settings", map[string]string{}))
	require.Contains(t, ev["trail_log_groups"], "no multi-region trail", "with no log group the evidence says why")
}

// One root cause, one finding: with no trail at all only the no-trail check
// fires; with a qualifying trail that has no log group, only the monitoring
// parent fires, never the fifteen alarms or the S3 data-event checks.
func TestTrailGapsAreOneFinding(t *testing.T) {
	r := NewRegistry()
	r.Register(append(append([]Check{awsCloudTrailNoMultiRegionTrail}, awsMonitoringChecks()...), awsLoggingChecks()...)...)
	fired := func(md map[string]string) []string {
		var ids []string
		for _, f := range r.Run([]asset.Asset{settingsAsset("aws_account_settings", md)}, time.Now()) {
			ids = append(ids, f.CheckID)
		}
		return ids
	}
	alarmsFalse := func(md map[string]string) map[string]string {
		for _, c := range awsMonitoringChecks() {
			for _, k := range derivedRequiredKeys[c.ID] {
				if _, set := md[k]; !set {
					md[k] = "false"
				}
			}
		}
		return md
	}
	noTrail := alarmsFalse(map[string]string{"cloudtrail_trail_count": "0", "cloudtrail_multi_region_logging": "false",
		"cloudtrail_s3_write_events": "false", "cloudtrail_s3_read_events": "false", "cw_alarm_monitoring_trail": "false"})
	require.Equal(t, []string{"aws-cloudtrail-no-multiregion-trail"}, fired(noTrail))

	noLogGroup := alarmsFalse(map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "true",
		"cloudtrail_s3_write_events": "true", "cloudtrail_s3_read_events": "true", "cw_alarm_monitoring_trail": "false"})
	require.Equal(t, []string{"aws-cloudwatch-no-cis-monitoring-trail"}, fired(noLogGroup))

	logGroup := alarmsFalse(map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "true",
		"cloudtrail_s3_write_events": "true", "cloudtrail_s3_read_events": "true", "cw_alarm_monitoring_trail": "true"})
	require.Len(t, fired(logGroup), 15, "with a log group to search, each missing alarm is its own fix")
}

func TestCloudTrailNoMultiRegionTrail_GradesTheSelectorGapLow(t *testing.T) {
	tests := []struct {
		name  string
		md    map[string]string
		title string
		sev   finding.Severity
	}{
		{"no trail", map[string]string{"cloudtrail_multi_region_logging": "false", "cloudtrail_trail_count": "0"},
			"AWS account has no CloudTrail trail", finding.SeverityMedium},
		{"trails but none multi-region logging", map[string]string{"cloudtrail_multi_region_logging": "false", "cloudtrail_trail_count": "2"},
			"No multi-region CloudTrail trail is logging", finding.SeverityMedium},
		{"logging but missing read or write management events",
			map[string]string{"cloudtrail_multi_region_logging": "true", "cloudtrail_multi_region_mgmt_all": "false", "cloudtrail_trail_count": "1"},
			"No multi-region CloudTrail trail records all management events", finding.SeverityLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := settingsAsset("aws_account_settings", tt.md)
			require.True(t, awsCloudTrailNoMultiRegionTrail.Violates(a))
			require.Equal(t, tt.title, awsCloudTrailNoMultiRegionTrail.TitleFor(a))
			require.Equal(t, tt.sev, awsCloudTrailNoMultiRegionTrail.SeverityFor(a))
		})
	}
}

func TestConfigRecorderOff_NamesEveryGap(t *testing.T) {
	a := settingsAsset("aws_region_settings", map[string]string{
		"config_recorder": "present", "config_recording": "false", "config_all_supported": "false",
		"config_delivery_channel": "false", "config_last_status": "Failure",
	})
	require.True(t, awsConfigRecorderOff.Violates(a))
	require.Equal(t, "recorder stopped; records only some resource types; no delivery channel; last recording attempt failed",
		awsConfigRecorderOff.EvidenceFor(a)["gaps"])
	require.Equal(t, "AWS Config is not recording every resource in this region", awsConfigRecorderOff.TitleFor(a))
	absent := settingsAsset("aws_region_settings", map[string]string{"config_recorder": "absent"})
	require.Equal(t, "AWS Config is not enabled in this region", awsConfigRecorderOff.TitleFor(absent))
	require.False(t, awsConfigNotServiceLinkedRole.Violates(settingsAsset("aws_region_settings",
		map[string]string{"config_recorder": "absent", "config_service_linked_role": "false"})),
		"no recorder is the recorder finding, not a role finding")
}

// The detection-service checks are posture: none may reach the page band.
func TestDetectionAndLoggingChecksArePosture(t *testing.T) {
	for _, c := range append(awsDetectionChecks(), awsLoggingChecks()...) {
		require.Contains(t, []finding.Severity{finding.SeverityLow, finding.SeverityInfo}, c.Severity, c.ID)
	}
}

func TestVPCFlowLogsDisabled_SkipsOnlyIdleDefaultVPCs(t *testing.T) {
	vpc := func(md map[string]string) asset.Asset { return settingsAsset("vpc", md) }
	require.True(t, awsVPCFlowLogsDisabled.Violates(vpc(map[string]string{"flow_logs_enabled": "false", "is_default": "false"})))
	require.False(t, awsVPCFlowLogsDisabled.Violates(vpc(map[string]string{"flow_logs_enabled": "false", "is_default": "true", "in_use": "false"})))
	require.True(t, awsVPCFlowLogsDisabled.Violates(vpc(map[string]string{"flow_logs_enabled": "false", "is_default": "true", "in_use": "true"})))
	require.True(t, awsVPCFlowLogsDisabled.Violates(vpc(map[string]string{"flow_logs_enabled": "false", "is_default": "true"})),
		"a default VPC whose interfaces could not be read is not assumed idle")
}

// The access-log check grades the stage, the asset the network collector
// writes access_log_destination on: one finding per stage, none on the API.
func TestAPIGatewayAccessLoggingGradesTheStage(t *testing.T) {
	require.Equal(t, "api_gateway_stage", awsAPIGatewayAccessLoggingOff.AssetType)
	st := settingsAsset("api_gateway_stage", map[string]string{"access_log_destination": "", "stage_name": "prod", "api_type": "HTTP"})
	require.True(t, awsAPIGatewayAccessLoggingOff.Violates(st))
	require.Equal(t, map[string]string{"stage_name": "prod", "api_type": "HTTP"}, awsAPIGatewayAccessLoggingOff.EvidenceFor(st))
	require.Equal(t, awsAPIGatewayStageExecutionLoggingDisabled.AssetType, awsAPIGatewayAccessLoggingOff.AssetType,
		"APIGateway.1 and .9 both land on the stage")
}
