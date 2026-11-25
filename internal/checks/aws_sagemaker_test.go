package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// A notebook outside any VPC always has direct internet access; it is one
// root cause, reported once by the VPC check, which states both.
func TestSageMakerNotebookVPCAndInternetFireOnce(t *testing.T) {
	tests := []struct {
		name               string
		md                 map[string]string
		vpc, internet      bool
		sev                finding.Severity
		titleMentionsNoVPC bool
	}{
		{"no VPC, direct internet", map[string]string{"subnet_id": "", "direct_internet_access": "true"}, true, false, finding.SeverityMedium, true},
		{"default VPC, internet off", map[string]string{"subnet_id": "s", "in_default_vpc": "true", "direct_internet_access": "false"}, true, false, finding.SeverityLow, false},
		{"default VPC, internet on", map[string]string{"subnet_id": "s", "in_default_vpc": "true", "direct_internet_access": "true"}, true, true, finding.SeverityLow, false},
		{"custom VPC, internet on", map[string]string{"subnet_id": "s", "in_default_vpc": "false", "direct_internet_access": "true"}, false, true, "", false},
		{"custom VPC, internet off", map[string]string{"subnet_id": "s", "in_default_vpc": "false", "direct_internet_access": "false"}, false, false, "", false},
		{"subnet's VPC unknown", map[string]string{"subnet_id": "s", "direct_internet_access": "false"}, false, false, "", false},
	}
	for _, tt := range tests {
		a := awsAsset("sagemaker_notebook", tt.md)
		require.Equal(t, tt.vpc, awsSageMakerNotebookNoVPC.Violates(a), tt.name)
		require.Equal(t, tt.internet, awsSageMakerNotebookDirectInternet.Violates(a), tt.name)
		if tt.vpc {
			require.Equal(t, tt.sev, awsSageMakerNotebookNoVPC.SeverityFor(a), tt.name)
			require.Equal(t, tt.titleMentionsNoVPC, awsSageMakerNotebookNoVPC.TitleFor(a) != "SageMaker notebook instance runs in the default VPC", tt.name)
		}
	}
}

func TestSageMakerNotebookPlatform(t *testing.T) {
	for p, fires := range map[string]bool{
		"notebook-al2023-v1": false,
		"notebook-al2-v3":    true,
		"notebook-al2-v2":    true,
		"notebook-al2-v1":    true,
		"notebook-al1-v1":    true,
		"":                   false,
	} {
		a := awsAsset("sagemaker_notebook", map[string]string{"platform_identifier": p})
		require.Equal(t, fires, awsSageMakerNotebookUnsupportedPlatform.Violates(a), p)
	}
}

// SageMaker.15 grades model-bias encryption only on multi-instance
// definitions; SageMaker.9/.10/.13 grade the other three types regardless.
func TestSageMakerMonitoringJobEncryptionScope(t *testing.T) {
	tests := []struct {
		jobType, count string
		fires          bool
	}{
		{"model_bias", "2", true},
		{"model_bias", "1", false},
		{"model_bias", "", false},
		{"data_quality", "1", true},
		{"model_quality", "", true},
		{"model_explainability", "1", true},
	}
	for _, tt := range tests {
		md := map[string]string{"job_type": tt.jobType, "inter_container_encryption": "false"}
		if tt.count != "" {
			md["instance_count"] = tt.count
		}
		require.Equal(t, tt.fires, awsSageMakerMonitoringJobNoEncryption.Violates(awsAsset("sagemaker_monitoring_job_definition", md)), "%+v", tt)
	}
}

// A schedule that references a job definition is graded on the definition,
// so one missing isolation setting is one finding.
func TestSageMakerScheduleStepsAsideForReferencedDefinition(t *testing.T) {
	require.False(t, awsSageMakerMonitoringScheduleNoNetworkIsolation.Violates(awsAsset("sagemaker_monitoring_schedule",
		map[string]string{"job_definition_inline": "false"})))
	require.True(t, awsSageMakerMonitoringScheduleNoNetworkIsolation.Violates(awsAsset("sagemaker_monitoring_schedule",
		map[string]string{"job_definition_inline": "true", "network_isolation": "false"})))
}

func TestSageMakerModelImageAccess(t *testing.T) {
	for mode, fires := range map[string]bool{"": true, "Platform": true, "Vpc": false} {
		a := awsAsset("sagemaker_model", map[string]string{"primary_image_access_mode": mode})
		require.Equal(t, fires, awsSageMakerModelPrimaryImageNotVPC.Violates(a), mode)
	}
	require.False(t, awsSageMakerModelPrimaryImageNotVPC.Violates(awsAsset("sagemaker_model",
		map[string]string{"pipeline_containers_not_vpc_registry": "x"})), "a pipeline model has no primary container to grade")
}

func TestSageMakerFeatureGroupWithoutOfflineStore(t *testing.T) {
	require.False(t, awsSageMakerFeatureGroupOfflineNoKMS.Violates(awsAsset("sagemaker_feature_group",
		map[string]string{"offline_store": "false"})))
}

func TestAgentCoreChecks(t *testing.T) {
	rt := func(md map[string]string) bool {
		return awsAgentCoreRuntimePublicNetwork.Violates(awsAsset("agentcore_runtime", md))
	}
	require.True(t, rt(map[string]string{"network_mode": "PUBLIC", "capacity_provider": "false"}))
	require.False(t, rt(map[string]string{"network_mode": "PUBLIC", "capacity_provider": "true"}), "capacity-provider runtimes are out of scope")

	rec := func(md map[string]string) bool {
		return awsAgentCoreBrowserNoRecording.Violates(awsAsset("agentcore_browser", md))
	}
	require.True(t, rec(map[string]string{"recording_enabled": "true", "recording_s3_location": "false"}), "recording with nowhere to write is not recording")
	require.True(t, rec(map[string]string{"recording_enabled": "false", "recording_s3_location": "false"}))
	require.False(t, rec(map[string]string{"recording_enabled": "true", "recording_s3_location": "true"}))

	gw := func(v string) bool {
		return awsAgentCoreGatewayNoInboundAuth.Violates(awsAsset("agentcore_gateway", map[string]string{"authorizer_type": v}))
	}
	require.True(t, gw("NONE"))
	for _, v := range []string{"AWS_IAM", "CUSTOM_JWT", "AUTHENTICATE_ONLY"} {
		require.False(t, gw(v), v)
	}
}
