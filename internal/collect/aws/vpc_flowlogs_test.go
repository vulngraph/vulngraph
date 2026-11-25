package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAnnotateFlowLogs(t *testing.T) {
	vpc := func(id, isDefault string) asset.Asset {
		return asset.Asset{ID: id, Type: "vpc", Metadata: map[string]string{"is_default": isDefault}}
	}
	fl := func(resource, status string, traffic ec2types.TrafficType) ec2types.FlowLog {
		return ec2types.FlowLog{ResourceId: awssdk.String(resource), FlowLogStatus: awssdk.String(status), TrafficType: traffic}
	}
	f := &fakeEC2{
		flowLogs: []ec2types.FlowLog{
			fl("vpc-all", "ACTIVE", ec2types.TrafficTypeAll),
			fl("vpc-reject", "ACTIVE", ec2types.TrafficTypeReject),
			fl("vpc-accept", "ACTIVE", ec2types.TrafficTypeAccept),
			fl("vpc-broken", "ERROR", ec2types.TrafficTypeAll),
			fl("subnet-1", "ACTIVE", ec2types.TrafficTypeAll),
		},
		enis: map[string]int{"vpc-default-used": 2},
	}
	vpcs := []asset.Asset{
		vpc("vpc-all", "false"), vpc("vpc-reject", "false"), vpc("vpc-accept", "false"), vpc("vpc-broken", "false"),
		vpc("vpc-none", "false"), vpc("vpc-default-used", "true"), vpc("vpc-default-idle", "true"),
	}
	require.NoError(t, annotateFlowLogs(context.Background(), f, vpcs))
	got := map[string]map[string]string{}
	for _, v := range vpcs {
		got[v.ID] = v.Metadata
	}
	require.Equal(t, "true", got["vpc-all"]["flow_logs_enabled"])
	require.Equal(t, "true", got["vpc-reject"]["flow_logs_enabled"])
	require.Equal(t, "false", got["vpc-accept"]["flow_logs_enabled"], "ACCEPT-only misses rejected traffic")
	require.Equal(t, "false", got["vpc-broken"]["flow_logs_enabled"], "a flow log that is not ACTIVE delivers nothing")
	require.Equal(t, "false", got["vpc-none"]["flow_logs_enabled"])
	require.NotContains(t, got["vpc-none"], "in_use", "in_use is read for default VPCs only")
	require.Equal(t, "true", got["vpc-default-used"]["in_use"])
	require.Equal(t, "false", got["vpc-default-idle"]["in_use"])

	failed := []asset.Asset{vpc("vpc-x", "false")}
	require.Error(t, annotateFlowLogs(context.Background(), &fakeEC2{flowLogsErr: apiErr{code: "UnauthorizedOperation"}}, failed))
	require.NotContains(t, failed[0].Metadata, "flow_logs_enabled", "an unread listing is not a VPC without flow logs")
}
