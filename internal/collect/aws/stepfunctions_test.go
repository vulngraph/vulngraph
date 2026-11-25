package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/stretchr/testify/require"
)

type fakeSFN struct {
	pages []*sfn.ListStateMachinesOutput
	calls int
	err   error
	desc  map[string]*sfn.DescribeStateMachineOutput
}

func (f *fakeSFN) ListStateMachines(_ context.Context, _ *sfn.ListStateMachinesInput, _ ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error) {
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func (f *fakeSFN) DescribeStateMachine(_ context.Context, in *sfn.DescribeStateMachineInput, _ ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error) {
	// A state machine encrypted with a customer key refuses a full describe
	// without kms:Decrypt; only a metadata-only describe reads its logging.
	if in.IncludedData != sfntypes.IncludedDataMetadataOnly {
		return nil, errors.New("AccessDeniedException: kms:Decrypt")
	}
	d, ok := f.desc[awssdk.ToString(in.StateMachineArn)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return d, nil
}

func TestReadStateMachines(t *testing.T) {
	client := &fakeSFN{
		pages: []*sfn.ListStateMachinesOutput{
			{StateMachines: []sfntypes.StateMachineListItem{{StateMachineArn: awssdk.String("arn:all"), Name: awssdk.String("all")}}, NextToken: awssdk.String("p2")},
			{StateMachines: []sfntypes.StateMachineListItem{{StateMachineArn: awssdk.String("arn:none")}, {StateMachineArn: awssdk.String("arn:off")}, {StateMachineArn: awssdk.String("arn:denied")}}},
		},
		desc: map[string]*sfn.DescribeStateMachineOutput{
			"arn:all":  {LoggingConfiguration: &sfntypes.LoggingConfiguration{Level: sfntypes.LogLevelAll}},
			"arn:none": {},
			"arn:off":  {LoggingConfiguration: &sfntypes.LoggingConfiguration{Level: sfntypes.LogLevelOff}},
		},
	}
	got, err := readStateMachines(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 4)
	require.Equal(t, "ALL", m["arn:all"].Metadata["log_level"])
	require.Equal(t, "OFF", m["arn:none"].Metadata["log_level"], "no logging configuration is AWS's OFF default")
	require.Equal(t, "OFF", m["arn:off"].Metadata["log_level"])
	require.NotContains(t, m["arn:denied"].Metadata, "log_level")

	_, err = readStateMachines(context.Background(), &fakeSFN{pages: client.pages[:1], err: errors.New("throttled")}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
