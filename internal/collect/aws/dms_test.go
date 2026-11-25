package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	dms "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	dmstypes "github.com/aws/aws-sdk-go-v2/service/databasemigrationservice/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeDMS struct {
	instances [][]dmstypes.ReplicationInstance // one slice per page
	tasks     []dmstypes.ReplicationTask
	endpoints []dmstypes.Endpoint
	pageErr   error // returned for the second instance page
	taskIn    *dms.DescribeReplicationTasksInput
}

func (f *fakeDMS) DescribeReplicationInstances(_ context.Context, in *dms.DescribeReplicationInstancesInput, _ ...func(*dms.Options)) (*dms.DescribeReplicationInstancesOutput, error) {
	page := 0
	if in.Marker != nil {
		page = 1
		if f.pageErr != nil {
			return nil, f.pageErr
		}
	}
	out := &dms.DescribeReplicationInstancesOutput{}
	if page < len(f.instances) {
		out.ReplicationInstances = f.instances[page]
	}
	if page+1 < len(f.instances) {
		out.Marker = awssdk.String("next")
	}
	return out, nil
}

func (f *fakeDMS) DescribeReplicationTasks(_ context.Context, in *dms.DescribeReplicationTasksInput, _ ...func(*dms.Options)) (*dms.DescribeReplicationTasksOutput, error) {
	f.taskIn = in
	return &dms.DescribeReplicationTasksOutput{ReplicationTasks: f.tasks}, nil
}

func (f *fakeDMS) DescribeEndpoints(context.Context, *dms.DescribeEndpointsInput, ...func(*dms.Options)) (*dms.DescribeEndpointsOutput, error) {
	return &dms.DescribeEndpointsOutput{Endpoints: f.endpoints}, nil
}

func dmsByID(assets []asset.Asset) map[string]asset.Asset {
	m := map[string]asset.Asset{}
	for _, a := range assets {
		m[a.ID] = a
	}
	return m
}

const dmsLoggingSettings = `{"Logging":{"EnableLogging":true,"LogComponents":[
 {"Id":"SOURCE_UNLOAD","Severity":"LOGGER_SEVERITY_DEFAULT"},
 {"Id":"SOURCE_CAPTURE","Severity":"LOGGER_SEVERITY_DEBUG"},
 {"Id":"TARGET_LOAD","Severity":"LOGGER_SEVERITY_DEFAULT"},
 {"Id":"TARGET_APPLY","Severity":"LOGGER_SEVERITY_WARNING"}]}}`

func TestCollectDMSResources(t *testing.T) {
	f := &fakeDMS{
		instances: [][]dmstypes.ReplicationInstance{
			{{ReplicationInstanceArn: awssdk.String("arn:ri:1"), ReplicationInstanceIdentifier: awssdk.String("ri-1"), PubliclyAccessible: true}},
			{{ReplicationInstanceArn: awssdk.String("arn:ri:2"), ReplicationInstanceIdentifier: awssdk.String("ri-2"), MultiAZ: true, AutoMinorVersionUpgrade: true}},
		},
		tasks: []dmstypes.ReplicationTask{
			{ReplicationTaskArn: awssdk.String("arn:t:1"), ReplicationTaskSettings: awssdk.String(dmsLoggingSettings)},
			{ReplicationTaskArn: awssdk.String("arn:t:2")}, // settings not returned
		},
		endpoints: []dmstypes.Endpoint{
			{EndpointArn: awssdk.String("arn:e:pg"), EngineName: awssdk.String("postgres"), SslMode: dmstypes.DmsSslModeValueNone},
			{EndpointArn: awssdk.String("arn:e:nep"), EngineName: awssdk.String("neptune"), NeptuneSettings: &dmstypes.NeptuneSettings{}},
			{EndpointArn: awssdk.String("arn:e:mongo"), EngineName: awssdk.String("mongodb"), MongoDbSettings: &dmstypes.MongoDbSettings{AuthType: dmstypes.AuthTypeValueNo}},
			{EndpointArn: awssdk.String("arn:e:mongo-default"), EngineName: awssdk.String("mongodb"), MongoDbSettings: &dmstypes.MongoDbSettings{}},
			{EndpointArn: awssdk.String("arn:e:redis"), EngineName: awssdk.String("redis"), RedisSettings: &dmstypes.RedisSettings{}},
			{EndpointArn: awssdk.String("arn:e:redis-off"), EngineName: awssdk.String("redis")},
		},
	}
	got, err := collectDMSResources(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.False(t, awssdk.ToBool(f.taskIn.WithoutSettings), "the logging verdict needs the task settings")
	m := dmsByID(got)
	require.Len(t, m, 10)

	ri1, ri2 := m["arn:ri:1"].Metadata, m["arn:ri:2"].Metadata
	require.Equal(t, "dms_replication_instance", m["arn:ri:1"].Type)
	require.Equal(t, "true", ri1["publicly_accessible"])
	require.Equal(t, asset.PublicAccessPossible, ri1["public_access"])
	require.Equal(t, "false", ri1["multi_az"])
	require.Equal(t, "false", ri1["auto_minor_version_upgrade"])
	require.Equal(t, "true", ri2["multi_az"], "the second page is read")
	require.NotContains(t, ri2, "public_access")

	t1 := m["arn:t:1"].Metadata
	require.Equal(t, "true", t1["source_logging_enabled"])
	require.Equal(t, "false", t1["target_logging_enabled"], "TARGET_APPLY below DEFAULT fails")
	require.NotContains(t, m["arn:t:2"].Metadata, "source_logging_enabled", "unread settings stay unknown")

	require.Equal(t, "none", m["arn:e:pg"].Metadata["ssl_mode"])
	require.Equal(t, "false", m["arn:e:nep"].Metadata["neptune_iam_auth_enabled"])
	require.Equal(t, "no", m["arn:e:mongo"].Metadata["mongodb_auth_type"])
	require.Equal(t, "password", m["arn:e:mongo-default"].Metadata["mongodb_auth_type"])
	require.Equal(t, "ssl-encryption", m["arn:e:redis"].Metadata["redis_ssl_security_protocol"])
	require.NotContains(t, m["arn:e:redis-off"].Metadata, "redis_ssl_security_protocol")
}

func TestCollectDMSFailedPageFailsTheListing(t *testing.T) {
	f := &fakeDMS{
		instances: [][]dmstypes.ReplicationInstance{{{ReplicationInstanceArn: awssdk.String("a")}}, {{ReplicationInstanceArn: awssdk.String("b")}}},
		pageErr:   errors.New("throttled"),
	}
	_, err := collectDMSResources(context.Background(), f, "eu-west-1", "111", time.Now())
	require.Error(t, err, "a short page sequence is a failed read, not a short list")
}

func TestDMSComponentsLogged(t *testing.T) {
	for _, tt := range []struct {
		name, settings string
		logged, ok     bool
	}{
		{"absent", "", false, false},
		{"unparseable", "{", false, false},
		{"logging off", `{"Logging":{"EnableLogging":false}}`, false, true},
		{"no logging block", `{"TargetMetadata":{}}`, false, true},
		{"component missing", `{"Logging":{"EnableLogging":true,"LogComponents":[{"Id":"SOURCE_UNLOAD","Severity":"LOGGER_SEVERITY_DEFAULT"}]}}`, false, true},
		{"detailed debug", `{"Logging":{"EnableLogging":true,"LogComponents":[{"Id":"SOURCE_UNLOAD","Severity":"LOGGER_SEVERITY_DETAILED_DEBUG"},{"Id":"SOURCE_CAPTURE","Severity":"LOGGER_SEVERITY_DEFAULT"}]}}`, true, true},
		{"error only", `{"Logging":{"EnableLogging":true,"LogComponents":[{"Id":"SOURCE_UNLOAD","Severity":"LOGGER_SEVERITY_ERROR"},{"Id":"SOURCE_CAPTURE","Severity":"LOGGER_SEVERITY_DEFAULT"}]}}`, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			logged, ok := dmsComponentsLogged(tt.settings, "SOURCE_CAPTURE", "SOURCE_UNLOAD")
			require.Equal(t, tt.logged, logged)
			require.Equal(t, tt.ok, ok)
		})
	}
}
