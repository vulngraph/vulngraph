package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	dstypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
	"github.com/stretchr/testify/require"
)

type fakeDataSync struct {
	pages []*datasync.ListTasksOutput
	calls int
	err   error
	desc  map[string]*datasync.DescribeTaskOutput
}

func (f *fakeDataSync) ListTasks(_ context.Context, _ *datasync.ListTasksInput, _ ...func(*datasync.Options)) (*datasync.ListTasksOutput, error) {
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func (f *fakeDataSync) DescribeTask(_ context.Context, in *datasync.DescribeTaskInput, _ ...func(*datasync.Options)) (*datasync.DescribeTaskOutput, error) {
	d, ok := f.desc[awssdk.ToString(in.TaskArn)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return d, nil
}

func TestReadDataSyncTasks(t *testing.T) {
	client := &fakeDataSync{
		pages: []*datasync.ListTasksOutput{
			{Tasks: []dstypes.TaskListEntry{{TaskArn: awssdk.String("arn:logged"), Name: awssdk.String("logged")}}, NextToken: awssdk.String("p2")},
			{Tasks: []dstypes.TaskListEntry{{TaskArn: awssdk.String("arn:bare")}, {TaskArn: awssdk.String("arn:denied")}}},
		},
		desc: map[string]*datasync.DescribeTaskOutput{
			"arn:logged": {CloudWatchLogGroupArn: awssdk.String("arn:aws:logs:us-east-1:1:log-group:/ds"), TaskMode: dstypes.TaskModeBasic,
				Options: &dstypes.Options{LogLevel: dstypes.LogLevelBasic}},
			"arn:bare": {TaskMode: dstypes.TaskModeBasic},
		},
	}
	got, err := readDataSyncTasks(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 3)
	require.Equal(t, "arn:aws:logs:us-east-1:1:log-group:/ds", m["arn:logged"].Metadata["log_group"])
	require.Equal(t, "BASIC", m["arn:logged"].Metadata["log_level"])
	v, ok := m["arn:bare"].Metadata["log_group"]
	require.True(t, ok)
	require.Empty(t, v, "no log group is observed as empty")
	require.NotContains(t, m["arn:bare"].Metadata, "log_level", "options without a level leave it unknown")
	require.NotContains(t, m["arn:denied"].Metadata, "log_group")

	_, err = readDataSyncTasks(context.Background(), &fakeDataSync{pages: client.pages[:1], err: errors.New("throttled"), desc: client.desc}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
