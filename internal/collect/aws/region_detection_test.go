package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// msgErr is an API error whose message differs from its code, for the reads
// that tell "service off" from "permission missing" by message.
type msgErr struct{ code, msg string }

func (e msgErr) Error() string                 { return e.code + ": " + e.msg }
func (e msgErr) ErrorCode() string             { return e.code }
func (e msgErr) ErrorMessage() string          { return e.msg }
func (e msgErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type fakeDetection struct {
	recorders    []cfgtypes.ConfigurationRecorder
	recordersErr error
	status       []cfgtypes.ConfigurationRecorderStatus
	statusErr    error
	channels     []cfgtypes.DeliveryChannel
	hubErr       error
	analyzers    [][]aatypes.AnalyzerSummary // pages
	analyzerErr  error
	macie        *macie2.GetMacieSessionOutput // nil answers "not enabled"
	macieErr     error
	discovery    macietypes.AutomatedDiscoveryStatus
	detectors    []string
	detector     *guardduty.GetDetectorOutput
	gdErr        error
	inspector    *inspector2.BatchGetAccountStatusOutput
	inspectorErr error
}

func (f *fakeDetection) DescribeConfigurationRecorders(context.Context, *configservice.DescribeConfigurationRecordersInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error) {
	return &configservice.DescribeConfigurationRecordersOutput{ConfigurationRecorders: f.recorders}, f.recordersErr
}
func (f *fakeDetection) DescribeConfigurationRecorderStatus(context.Context, *configservice.DescribeConfigurationRecorderStatusInput, ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error) {
	return &configservice.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: f.status}, f.statusErr
}
func (f *fakeDetection) DescribeDeliveryChannels(context.Context, *configservice.DescribeDeliveryChannelsInput, ...func(*configservice.Options)) (*configservice.DescribeDeliveryChannelsOutput, error) {
	return &configservice.DescribeDeliveryChannelsOutput{DeliveryChannels: f.channels}, nil
}
func (f *fakeDetection) DescribeHub(context.Context, *securityhub.DescribeHubInput, ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	return &securityhub.DescribeHubOutput{}, f.hubErr
}
func (f *fakeDetection) ListAnalyzers(_ context.Context, in *accessanalyzer.ListAnalyzersInput, _ ...func(*accessanalyzer.Options)) (*accessanalyzer.ListAnalyzersOutput, error) {
	if f.analyzerErr != nil {
		return nil, f.analyzerErr
	}
	i := 0
	if in.NextToken != nil {
		i = int((*in.NextToken)[0] - '0')
	}
	out := &accessanalyzer.ListAnalyzersOutput{}
	if i < len(f.analyzers) {
		out.Analyzers = f.analyzers[i]
	}
	if i+1 < len(f.analyzers) {
		out.NextToken = awssdk.String(string(rune('0' + i + 1)))
	}
	return out, nil
}
func (f *fakeDetection) GetMacieSession(context.Context, *macie2.GetMacieSessionInput, ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
	if f.macie == nil && f.macieErr == nil {
		return nil, msgErr{"AccessDeniedException", "Macie is not enabled."}
	}
	return f.macie, f.macieErr
}
func (f *fakeDetection) GetAutomatedDiscoveryConfiguration(context.Context, *macie2.GetAutomatedDiscoveryConfigurationInput, ...func(*macie2.Options)) (*macie2.GetAutomatedDiscoveryConfigurationOutput, error) {
	return &macie2.GetAutomatedDiscoveryConfigurationOutput{Status: f.discovery}, nil
}
func (f *fakeDetection) ListDetectors(context.Context, *guardduty.ListDetectorsInput, ...func(*guardduty.Options)) (*guardduty.ListDetectorsOutput, error) {
	if f.gdErr != nil {
		return nil, f.gdErr
	}
	return &guardduty.ListDetectorsOutput{DetectorIds: f.detectors}, nil
}
func (f *fakeDetection) GetDetector(context.Context, *guardduty.GetDetectorInput, ...func(*guardduty.Options)) (*guardduty.GetDetectorOutput, error) {
	return f.detector, nil
}
func (f *fakeDetection) BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	if f.inspector == nil && f.inspectorErr == nil {
		return &inspector2.BatchGetAccountStatusOutput{Accounts: []inspectortypes.AccountState{{State: &inspectortypes.State{Status: inspectortypes.StatusDisabled}}}}, nil
	}
	return f.inspector, f.inspectorErr
}

func (f *fakeDetection) clients() detectionClients {
	return detectionClients{config: f, hub: f, analyzer: f, macie: f, guardduty: f, inspector: f}
}

func readOne(t *testing.T, f *fakeDetection, read func(detectionClients, context.Context, map[string]string) error) (map[string]string, error) {
	t.Helper()
	meta := map[string]string{}
	err := read(f.clients(), context.Background(), meta)
	return meta, err
}

const slrConfigRole = "arn:aws:iam::111:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

func TestReadConfig(t *testing.T) {
	tests := []struct {
		name    string
		f       fakeDetection
		want    map[string]string
		wantErr bool
	}{
		{"no recorder", fakeDetection{}, map[string]string{"config_recorder": "absent"}, false},
		{"only Security Hub's service-linked recorder is not the account's recorder",
			fakeDetection{recorders: []cfgtypes.ConfigurationRecorder{{Name: awssdk.String("slr"), ServicePrincipal: awssdk.String("securityhub.amazonaws.com")}}},
			map[string]string{"config_recorder": "absent"}, false},
		{"recording everything with the service-linked role",
			fakeDetection{
				recorders: []cfgtypes.ConfigurationRecorder{{Name: awssdk.String("default"), RoleARN: awssdk.String(slrConfigRole),
					RecordingGroup: &cfgtypes.RecordingGroup{AllSupported: true}}},
				status:   []cfgtypes.ConfigurationRecorderStatus{{Recording: true, LastStatus: cfgtypes.RecorderStatusSuccess}},
				channels: []cfgtypes.DeliveryChannel{{Name: awssdk.String("default")}},
			},
			map[string]string{"config_recorder": "present", "config_all_supported": "true", "config_service_linked_role": "true",
				"config_recording": "true", "config_last_status": "Success", "config_delivery_channel": "true"}, false},
		{"stopped, partial, custom role, no channel; omitted recording group",
			fakeDetection{
				recorders: []cfgtypes.ConfigurationRecorder{{Name: awssdk.String("default"), RoleARN: awssdk.String("arn:aws:iam::111:role/aws-controltower-ConfigRecorderRole")}},
				status:    []cfgtypes.ConfigurationRecorderStatus{{Recording: false}},
			},
			map[string]string{"config_recorder": "present", "config_all_supported": "false", "config_service_linked_role": "false",
				"config_recording": "false", "config_delivery_channel": "false"}, false},
		{"status read failed leaves recording unknown",
			fakeDetection{
				recorders: []cfgtypes.ConfigurationRecorder{{Name: awssdk.String("default"), RecordingGroup: &cfgtypes.RecordingGroup{AllSupported: true}}},
				statusErr: apiErr{code: "AccessDeniedException"},
			},
			map[string]string{"config_recorder": "present", "config_all_supported": "true", "config_service_linked_role": "false",
				"config_delivery_channel": "false"}, true},
		{"recorder listing denied: nothing known", fakeDetection{recordersErr: apiErr{code: "AccessDeniedException"}}, map[string]string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readOne(t, &tt.f, detectionClients.readConfig)
			require.Equal(t, tt.wantErr, err != nil, "err = %v", err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestReadSecurityHubAndAccessAnalyzer(t *testing.T) {
	md, err := readOne(t, &fakeDetection{}, detectionClients.readSecurityHub)
	require.NoError(t, err)
	require.Equal(t, "true", md["securityhub_enabled"])
	md, err = readOne(t, &fakeDetection{hubErr: msgErr{"InvalidAccessException", "Account 111 is not subscribed to AWS Security Hub"}}, detectionClients.readSecurityHub)
	require.NoError(t, err)
	require.Equal(t, "false", md["securityhub_enabled"])
	md, err = readOne(t, &fakeDetection{hubErr: apiErr{code: "AccessDeniedException"}}, detectionClients.readSecurityHub)
	require.Error(t, err)
	require.NotContains(t, md, "securityhub_enabled", "a denied read is not a disabled hub")

	active := aatypes.AnalyzerSummary{Type: aatypes.TypeAccount, Status: aatypes.AnalyzerStatusActive}
	tests := []struct {
		name  string
		pages [][]aatypes.AnalyzerSummary
		want  string
	}{
		{"none", nil, "false"},
		{"active account analyzer on the second page", [][]aatypes.AnalyzerSummary{{}, {active}}, "true"},
		{"active organization analyzer", [][]aatypes.AnalyzerSummary{{{Type: aatypes.TypeOrganization, Status: aatypes.AnalyzerStatusActive}}}, "true"},
		{"unused-access analyzer does not answer external access",
			[][]aatypes.AnalyzerSummary{{{Type: aatypes.TypeAccountUnusedAccess, Status: aatypes.AnalyzerStatusActive}}}, "false"},
		{"failed analyzer", [][]aatypes.AnalyzerSummary{{{Type: aatypes.TypeAccount, Status: aatypes.AnalyzerStatusFailed}}}, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md, err := readOne(t, &fakeDetection{analyzers: tt.pages}, detectionClients.readAccessAnalyzer)
			require.NoError(t, err)
			require.Equal(t, tt.want, md["access_analyzer_active"])
		})
	}
	md, err = readOne(t, &fakeDetection{analyzerErr: apiErr{code: "AccessDeniedException"}}, detectionClients.readAccessAnalyzer)
	require.Error(t, err)
	require.NotContains(t, md, "access_analyzer_active")
}

func TestReadMacie(t *testing.T) {
	md, err := readOne(t, &fakeDetection{macie: &macie2.GetMacieSessionOutput{Status: macietypes.MacieStatusEnabled},
		discovery: macietypes.AutomatedDiscoveryStatusDisabled}, detectionClients.readMacie)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"macie_status": "ENABLED", "macie_automated_discovery": "DISABLED"}, md)

	md, err = readOne(t, &fakeDetection{macie: &macie2.GetMacieSessionOutput{Status: macietypes.MacieStatusPaused}}, detectionClients.readMacie)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"macie_status": "PAUSED"}, md, "discovery is not read for a paused session")

	md, err = readOne(t, &fakeDetection{macieErr: msgErr{"AccessDeniedException", "Macie is not enabled."}}, detectionClients.readMacie)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"macie_status": "NOT_ENABLED"}, md)

	md, err = readOne(t, &fakeDetection{macieErr: msgErr{"AccessDeniedException",
		"User: arn:aws:sts::111:assumed-role/GraphReadOnly/s is not authorized to perform: macie2:GetMacieSession"}}, detectionClients.readMacie)
	require.Error(t, err)
	require.Empty(t, md, "a missing permission is not a disabled Macie")
}

func gdFeature(name gdtypes.DetectorFeatureResult, on bool, agents ...gdtypes.FeatureAdditionalConfiguration) gdtypes.DetectorFeatureConfigurationResult {
	st := gdtypes.FeatureStatusDisabled
	if on {
		st = gdtypes.FeatureStatusEnabled
	}
	f := gdtypes.DetectorFeatureConfigurationResult{Name: name, Status: st}
	for _, a := range agents {
		f.AdditionalConfiguration = append(f.AdditionalConfiguration, gdtypes.DetectorAdditionalConfigurationResult{Name: a, Status: gdtypes.FeatureStatusEnabled})
	}
	return f
}

func TestReadGuardDutyDetector(t *testing.T) {
	enabled := func(features ...gdtypes.DetectorFeatureConfigurationResult) *guardduty.GetDetectorOutput {
		return &guardduty.GetDetectorOutput{Status: gdtypes.DetectorStatusEnabled, Features: features}
	}
	tests := []struct {
		name string
		f    fakeDetection
		want map[string]string
	}{
		{"no detector", fakeDetection{}, map[string]string{"guardduty_enabled": "false"}},
		{"suspended detector records no features", fakeDetection{detectors: []string{"d"},
			detector: &guardduty.GetDetectorOutput{Status: gdtypes.DetectorStatusDisabled, Features: []gdtypes.DetectorFeatureConfigurationResult{
				gdFeature(gdtypes.DetectorFeatureResultS3DataEvents, false)}}},
			map[string]string{"guardduty_enabled": "false"}},
		{"every plan on, runtime agents managed", fakeDetection{detectors: []string{"d"}, detector: enabled(
			gdFeature(gdtypes.DetectorFeatureResultS3DataEvents, true),
			gdFeature(gdtypes.DetectorFeatureResultEksAuditLogs, true),
			gdFeature(gdtypes.DetectorFeatureResultLambdaNetworkLogs, true),
			gdFeature(gdtypes.DetectorFeatureResultEbsMalwareProtection, true),
			gdFeature(gdtypes.DetectorFeatureResultRdsLoginEvents, true),
			gdFeature(gdtypes.DetectorFeatureResultRuntimeMonitoring, true,
				gdtypes.FeatureAdditionalConfigurationEksAddonManagement,
				gdtypes.FeatureAdditionalConfigurationEcsFargateAgentManagement,
				gdtypes.FeatureAdditionalConfigurationEc2AgentManagement),
			gdFeature(gdtypes.DetectorFeatureResultFlowLogs, true))},
			map[string]string{"guardduty_enabled": "true", "guardduty_s3_protection": "true", "guardduty_eks_audit_logs": "true",
				"guardduty_lambda_protection": "true", "guardduty_malware_protection": "true", "guardduty_rds_protection": "true",
				"guardduty_runtime_monitoring": "true", "guardduty_eks_runtime": "true", "guardduty_ecs_runtime": "true", "guardduty_ec2_runtime": "true"}},
		{"runtime monitoring off: agent keys step aside", fakeDetection{detectors: []string{"d"}, detector: enabled(
			gdFeature(gdtypes.DetectorFeatureResultRuntimeMonitoring, false),
			gdFeature(gdtypes.DetectorFeatureResultS3DataEvents, false))},
			map[string]string{"guardduty_enabled": "true", "guardduty_runtime_monitoring": "false", "guardduty_s3_protection": "false"}},
		{"runtime on, only the EC2 agent managed", fakeDetection{detectors: []string{"d"}, detector: enabled(
			gdFeature(gdtypes.DetectorFeatureResultRuntimeMonitoring, true, gdtypes.FeatureAdditionalConfigurationEc2AgentManagement))},
			map[string]string{"guardduty_enabled": "true", "guardduty_runtime_monitoring": "true",
				"guardduty_eks_runtime": "false", "guardduty_ecs_runtime": "false", "guardduty_ec2_runtime": "true"}},
		{"legacy EKS runtime monitoring with managed add-on", fakeDetection{detectors: []string{"d"}, detector: enabled(
			gdFeature(gdtypes.DetectorFeatureResultEksRuntimeMonitoring, true, gdtypes.FeatureAdditionalConfigurationEksAddonManagement))},
			map[string]string{"guardduty_enabled": "true", "guardduty_eks_runtime": "true"}},
		{"plan the region does not offer stays unknown", fakeDetection{detectors: []string{"d"}, detector: enabled()},
			map[string]string{"guardduty_enabled": "true"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readOne(t, &tt.f, detectionClients.readGuardDutyDetector)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
	got, err := readOne(t, &fakeDetection{gdErr: apiErr{code: "AccessDeniedException"}}, detectionClients.readGuardDutyDetector)
	require.Error(t, err)
	require.Empty(t, got)
}

func TestReadInspector(t *testing.T) {
	st := func(s inspectortypes.Status) *inspectortypes.State { return &inspectortypes.State{Status: s} }
	acct := func(state inspectortypes.Status, rs *inspectortypes.ResourceState) *inspector2.BatchGetAccountStatusOutput {
		return &inspector2.BatchGetAccountStatusOutput{Accounts: []inspectortypes.AccountState{{AccountId: awssdk.String("111"), State: st(state), ResourceState: rs}}}
	}
	tests := []struct {
		name string
		out  *inspector2.BatchGetAccountStatusOutput
		want map[string]string
	}{
		{"Inspector off: scan types step aside", acct(inspectortypes.StatusDisabled, &inspectortypes.ResourceState{
			Ec2: st(inspectortypes.StatusDisabled), Ecr: st(inspectortypes.StatusDisabled)}),
			map[string]string{"inspector_status": "DISABLED"}},
		{"on, Lambda standard off: code scanning steps aside", acct(inspectortypes.StatusEnabled, &inspectortypes.ResourceState{
			Ec2: st(inspectortypes.StatusEnabled), Ecr: st(inspectortypes.StatusSuspended), Lambda: st(inspectortypes.StatusDisabled), LambdaCode: st(inspectortypes.StatusDisabled)}),
			map[string]string{"inspector_status": "ENABLED", "inspector_ec2": "ENABLED", "inspector_ecr": "SUSPENDED", "inspector_lambda": "DISABLED"}},
		{"on, Lambda standard on, code off", acct(inspectortypes.StatusEnabled, &inspectortypes.ResourceState{
			Ec2: st(inspectortypes.StatusEnabled), Ecr: st(inspectortypes.StatusEnabled), Lambda: st(inspectortypes.StatusEnabled), LambdaCode: st(inspectortypes.StatusDisabled)}),
			map[string]string{"inspector_status": "ENABLED", "inspector_ec2": "ENABLED", "inspector_ecr": "ENABLED", "inspector_lambda": "ENABLED", "inspector_lambda_code": "DISABLED"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readOne(t, &fakeDetection{inspector: tt.out}, detectionClients.readInspector)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
	got, err := readOne(t, &fakeDetection{inspector: &inspector2.BatchGetAccountStatusOutput{}}, detectionClients.readInspector)
	require.Error(t, err, "an answer without this account is not a disabled Inspector")
	require.Empty(t, got)
}

// The detection keys land on the one region-settings asset, and a region
// where every EC2 read failed still yields it when a detection read worked.
func TestReadRegionSettings_MergesDetectionKeys(t *testing.T) {
	f := &fakeDetection{}
	denied := apiErr{code: "UnauthorizedOperation"}
	got, err := readRegionSettings(context.Background(), fakeRegionSettings{err: denied}, "eu-west-1", "111", time.Now(), f.clients().read)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "absent", got[0].Metadata["config_recorder"])
	require.Equal(t, "true", got[0].Metadata["securityhub_enabled"])
	require.Equal(t, "false", got[0].Metadata["guardduty_enabled"])
	_, present := got[0].Metadata["ebs_encryption_by_default"]
	require.False(t, present)

	all := &fakeDetection{recordersErr: denied, hubErr: denied, analyzerErr: denied, macieErr: denied, gdErr: denied, inspectorErr: denied}
	_, err = readRegionSettings(context.Background(), fakeRegionSettings{err: denied}, "eu-west-1", "111", time.Now(), all.clients().read)
	require.Error(t, err, "a region closed to every read is a skipped collector")
}
