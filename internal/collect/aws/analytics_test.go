package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	firehosetypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kinesistypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"
	"github.com/stretchr/testify/require"
)

var errAnalyticsDenied = errors.New("AccessDenied")

// ── Kinesis ──────────────────────────────────────────────────────────────────

type fakeKinesis struct {
	pages    []*kinesis.ListStreamsOutput
	pageErr  int // 1-based page that fails; 0 = none
	calls    int
	summary  map[string]*kinesistypes.StreamDescriptionSummary
	descErrs map[string]bool
}

func (f *fakeKinesis) ListStreams(_ context.Context, in *kinesis.ListStreamsInput, _ ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	f.calls++
	if f.calls == f.pageErr {
		return nil, errAnalyticsDenied
	}
	return f.pages[f.calls-1], nil
}

func (f *fakeKinesis) DescribeStreamSummary(_ context.Context, in *kinesis.DescribeStreamSummaryInput, _ ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	arn := awssdk.ToString(in.StreamARN)
	if f.descErrs[arn] {
		return nil, errAnalyticsDenied
	}
	return &kinesis.DescribeStreamSummaryOutput{StreamDescriptionSummary: f.summary[arn]}, nil
}

func kinesisSummary(name string) kinesistypes.StreamSummary {
	return kinesistypes.StreamSummary{
		StreamName: awssdk.String(name), StreamARN: awssdk.String("arn:aws:kinesis:eu-west-1:1:stream/" + name),
		StreamStatus: kinesistypes.StreamStatusActive,
	}
}

func TestKinesisStreamsPaginateAndReadPosture(t *testing.T) {
	f := &fakeKinesis{
		pages: []*kinesis.ListStreamsOutput{
			{StreamSummaries: []kinesistypes.StreamSummary{kinesisSummary("a")}, HasMoreStreams: awssdk.Bool(true), NextToken: awssdk.String("t")},
			{StreamSummaries: []kinesistypes.StreamSummary{kinesisSummary("b"), kinesisSummary("c")}, HasMoreStreams: awssdk.Bool(false)},
		},
		summary: map[string]*kinesistypes.StreamDescriptionSummary{
			"arn:aws:kinesis:eu-west-1:1:stream/a": {EncryptionType: kinesistypes.EncryptionTypeKms, RetentionPeriodHours: awssdk.Int32(168)},
			"arn:aws:kinesis:eu-west-1:1:stream/b": {EncryptionType: kinesistypes.EncryptionTypeNone, RetentionPeriodHours: awssdk.Int32(24)},
		},
		descErrs: map[string]bool{"arn:aws:kinesis:eu-west-1:1:stream/c": true},
	}
	got, err := collectKinesisStreams(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)
	byName := map[string]map[string]string{}
	for _, a := range got {
		require.Equal(t, "kinesis_stream", a.Type)
		byName[a.Name] = a.Metadata
	}
	require.Equal(t, "KMS", byName["a"]["encryption_type"])
	require.Equal(t, "168", byName["a"]["retention_hours"])
	require.Equal(t, "NONE", byName["b"]["encryption_type"])
	require.Equal(t, "24", byName["b"]["retention_hours"])
	// A failed describe leaves the stream's posture unknown, not "NONE"/0.
	require.NotContains(t, byName["c"], "encryption_type")
	require.NotContains(t, byName["c"], "retention_hours")
}

func TestKinesisListingFailureOnLaterPageFails(t *testing.T) {
	f := &fakeKinesis{
		pages: []*kinesis.ListStreamsOutput{
			{StreamSummaries: []kinesistypes.StreamSummary{kinesisSummary("a")}, HasMoreStreams: awssdk.Bool(true), NextToken: awssdk.String("t")},
		},
		pageErr: 2,
	}
	_, err := collectKinesisStreams(context.Background(), f, "eu-west-1", "1", time.Now())
	require.Error(t, err, "a truncated listing must not read as the whole set")
}

// ── Firehose ─────────────────────────────────────────────────────────────────

type fakeFirehose struct {
	pages []*firehose.ListDeliveryStreamsOutput
	calls int
	descs map[string]*firehosetypes.DeliveryStreamDescription
}

func (f *fakeFirehose) ListDeliveryStreams(_ context.Context, in *firehose.ListDeliveryStreamsInput, _ ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error) {
	f.calls++
	if f.calls > len(f.pages) {
		return nil, errAnalyticsDenied
	}
	return f.pages[f.calls-1], nil
}

func (f *fakeFirehose) DescribeDeliveryStream(_ context.Context, in *firehose.DescribeDeliveryStreamInput, _ ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error) {
	d, ok := f.descs[awssdk.ToString(in.DeliveryStreamName)]
	if !ok {
		return nil, errAnalyticsDenied
	}
	return &firehose.DescribeDeliveryStreamOutput{DeliveryStreamDescription: d}, nil
}

func TestFirehoseStreamsEncryptionStatus(t *testing.T) {
	f := &fakeFirehose{
		pages: []*firehose.ListDeliveryStreamsOutput{
			{DeliveryStreamNames: []string{"enc", "plain"}, HasMoreDeliveryStreams: awssdk.Bool(true)},
			{DeliveryStreamNames: []string{"kin", "unread"}, HasMoreDeliveryStreams: awssdk.Bool(false)},
		},
		descs: map[string]*firehosetypes.DeliveryStreamDescription{
			"enc": {DeliveryStreamARN: awssdk.String("arn:aws:firehose:eu-west-1:1:deliverystream/enc"), DeliveryStreamType: firehosetypes.DeliveryStreamTypeDirectPut,
				DeliveryStreamEncryptionConfiguration: &firehosetypes.DeliveryStreamEncryptionConfiguration{Status: firehosetypes.DeliveryStreamEncryptionStatusEnabled}},
			// No encryption block at all: SSE was never turned on.
			"plain": {DeliveryStreamARN: awssdk.String("arn:aws:firehose:eu-west-1:1:deliverystream/plain"), DeliveryStreamType: firehosetypes.DeliveryStreamTypeDirectPut},
			"kin":   {DeliveryStreamARN: awssdk.String("arn:aws:firehose:eu-west-1:1:deliverystream/kin"), DeliveryStreamType: firehosetypes.DeliveryStreamTypeKinesisStreamAsSource},
		},
	}
	got, err := collectFirehoseStreams(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 4)
	by := map[string]map[string]string{}
	ids := map[string]string{}
	for _, a := range got {
		by[a.Name] = a.Metadata
		ids[a.Name] = a.ID
	}
	require.Equal(t, "ENABLED", by["enc"]["sse_status"])
	require.Equal(t, "DISABLED", by["plain"]["sse_status"])
	require.Equal(t, "KinesisStreamAsSource", by["kin"]["source_type"])
	require.NotContains(t, by["unread"], "sse_status")
	require.Equal(t, "arn:aws:firehose:eu-west-1:1:deliverystream/unread", ids["unread"], "an undescribed stream keeps its ARN identity")
}

// ── Glue ─────────────────────────────────────────────────────────────────────

type fakeGlue struct {
	jobs          []*glue.GetJobsOutput
	jobCalls      int
	transforms    *glue.GetMLTransformsOutput
	transformsErr error
}

func (f *fakeGlue) GetJobs(_ context.Context, _ *glue.GetJobsInput, _ ...func(*glue.Options)) (*glue.GetJobsOutput, error) {
	f.jobCalls++
	if f.jobCalls > len(f.jobs) {
		return nil, errAnalyticsDenied
	}
	return f.jobs[f.jobCalls-1], nil
}

func (f *fakeGlue) GetMLTransforms(context.Context, *glue.GetMLTransformsInput, ...func(*glue.Options)) (*glue.GetMLTransformsOutput, error) {
	return f.transforms, f.transformsErr
}

func TestGlueJobsRecordVersionAndCommand(t *testing.T) {
	f := &fakeGlue{jobs: []*glue.GetJobsOutput{
		{Jobs: []gluetypes.Job{{Name: awssdk.String("etl-old"), GlueVersion: awssdk.String("2.0"), Command: &gluetypes.JobCommand{Name: awssdk.String("glueetl")}}}, NextToken: awssdk.String("t")},
		{Jobs: []gluetypes.Job{{Name: awssdk.String("etl-unset"), Command: &gluetypes.JobCommand{Name: awssdk.String("glueetl")}}}},
	}}
	got, err := listGlueJobs(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, "arn:aws:glue:eu-west-1:1:job/etl-old", got[0].ID)
	require.Equal(t, "2.0", got[0].Metadata["glue_version"])
	require.Equal(t, "glueetl", got[0].Metadata["command"])
	v, ok := got[1].Metadata["glue_version"]
	require.True(t, ok, "an unset GlueVersion is observed (Glue's 0.9 default), not unknown")
	require.Empty(t, v)

	_, err = listGlueJobs(context.Background(), &fakeGlue{}, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}

func TestGlueMLTransformEncryption(t *testing.T) {
	f := &fakeGlue{transforms: &glue.GetMLTransformsOutput{Transforms: []gluetypes.MLTransform{
		{TransformId: awssdk.String("t1"), Name: awssdk.String("enc"), TransformEncryption: &gluetypes.TransformEncryption{
			MlUserDataEncryption: &gluetypes.MLUserDataEncryption{MlUserDataEncryptionMode: gluetypes.MLUserDataEncryptionModeStringSsekms}}},
		{TransformId: awssdk.String("t2"), Name: awssdk.String("plain")},
	}}}
	got, err := listGlueMLTransforms(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "SSE-KMS", got[0].Metadata["user_data_encryption"])
	require.Equal(t, "DISABLED", got[1].Metadata["user_data_encryption"])
	require.Equal(t, "arn:aws:glue:eu-west-1:1:mlTransform/t2", got[1].ID)

	_, err = listGlueMLTransforms(context.Background(), &fakeGlue{transformsErr: errAnalyticsDenied}, "eu-west-1", "1", time.Now())
	require.Error(t, err, "glue:GetMLTransforms denied must fail the transform listing, not return none")
}

// ── Athena ───────────────────────────────────────────────────────────────────

type fakeAthena struct {
	groups  []athenatypes.WorkGroupSummary
	configs map[string]*athenatypes.WorkGroupConfiguration
	queries []string
}

func (f *fakeAthena) ListWorkGroups(context.Context, *athena.ListWorkGroupsInput, ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
	return &athena.ListWorkGroupsOutput{WorkGroups: f.groups}, nil
}

func (f *fakeAthena) GetWorkGroup(_ context.Context, in *athena.GetWorkGroupInput, _ ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
	c, ok := f.configs[awssdk.ToString(in.WorkGroup)]
	if !ok {
		return nil, errAnalyticsDenied
	}
	return &athena.GetWorkGroupOutput{WorkGroup: &athenatypes.WorkGroup{Name: in.WorkGroup, Configuration: c}}, nil
}

func (f *fakeAthena) ListQueryExecutions(context.Context, *athena.ListQueryExecutionsInput, ...func(*athena.Options)) (*athena.ListQueryExecutionsOutput, error) {
	return &athena.ListQueryExecutionsOutput{QueryExecutionIds: f.queries}, nil
}

func TestAthenaWorkgroups(t *testing.T) {
	f := &fakeAthena{
		groups: []athenatypes.WorkGroupSummary{
			{Name: awssdk.String("primary"), State: athenatypes.WorkGroupStateEnabled},
			{Name: awssdk.String("analytics"), State: athenatypes.WorkGroupStateEnabled},
			{Name: awssdk.String("unset"), State: athenatypes.WorkGroupStateEnabled},
			{Name: awssdk.String("denied"), State: athenatypes.WorkGroupStateEnabled},
		},
		configs: map[string]*athenatypes.WorkGroupConfiguration{
			"primary":   {PublishCloudWatchMetricsEnabled: awssdk.Bool(false)},
			"analytics": {PublishCloudWatchMetricsEnabled: awssdk.Bool(true)},
			"unset":     {},
		},
	}
	got, err := collectAthenaWorkgroups(context.Background(), f, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	by := map[string]map[string]string{}
	for _, a := range got {
		require.Equal(t, "athena_workgroup", a.Type)
		by[a.Name] = a.Metadata
	}
	require.Equal(t, "false", by["primary"]["cloudwatch_metrics_enabled"])
	require.Equal(t, "false", by["primary"]["has_query_history"], "an untouched primary workgroup is recorded as such")
	require.Equal(t, "true", by["analytics"]["cloudwatch_metrics_enabled"])
	require.NotContains(t, by["analytics"], "has_query_history", "only the stock primary workgroup needs its history read")
	require.Equal(t, "false", by["unset"]["cloudwatch_metrics_enabled"])
	require.NotContains(t, by["denied"], "cloudwatch_metrics_enabled")
}
