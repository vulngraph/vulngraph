package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

// The posture fields the compute checks read come straight off the
// DescribeInstances response the collector already fetches.
func TestCollectInstances_PostureFields(t *testing.T) {
	fake := &fakeEC2{instancePages: []*ec2.DescribeInstancesOutput{{
		Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{
				InstanceId: awssdk.String("i-stopped"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
				MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
					HttpTokens: ec2types.HttpTokensStateOptional, HttpEndpoint: ec2types.InstanceMetadataEndpointStateDisabled,
				},
				VirtualizationType:    ec2types.VirtualizationTypeParavirtual,
				NetworkInterfaces:     []ec2types.InstanceNetworkInterface{{}, {}},
				StateTransitionReason: awssdk.String("User initiated (2024-01-02 03:04:05 GMT)"),
			},
			{
				// An AWS-initiated stop with no timestamp: the age is unknown.
				InstanceId:            awssdk.String("i-stopped-untimed"),
				State:                 &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
				StateTransitionReason: awssdk.String("Server.ScheduledStop: Stopped due to scheduled retirement"),
			},
			{
				InstanceId: awssdk.String("i-running"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				// A running instance's old stop reason is not a stop time.
				StateTransitionReason: awssdk.String("User initiated (2024-01-02 03:04:05 GMT)"),
			},
		}}},
	}}}
	assets, _, err := collectInstances(context.Background(), fake, "eu-west-1", "111122223333", time.Now(), nil)
	require.NoError(t, err)
	meta := map[string]map[string]string{}
	for _, a := range assets {
		meta[a.ID] = a.Metadata
	}
	stopped := meta["i-stopped"]
	require.Equal(t, "disabled", stopped["http_endpoint"])
	require.Equal(t, "paravirtual", stopped["virtualization_type"])
	require.Equal(t, "2", stopped["eni_count"])
	require.Equal(t, "2024-01-02T03:04:05Z", stopped["stopped_at"])

	require.NotContains(t, meta["i-stopped-untimed"], "stopped_at", "no parseable stop time: omitted, never a guessed age")

	running := meta["i-running"]
	require.NotContains(t, running, "http_endpoint", "no metadata options observed")
	require.NotContains(t, running, "stopped_at")
	require.Equal(t, "0", running["eni_count"])
}

func TestStoppedAt(t *testing.T) {
	at, ok := stoppedAt("User initiated (2019-02-12 20:00:00 GMT)")
	require.True(t, ok)
	require.Equal(t, time.Date(2019, 2, 12, 20, 0, 0, 0, time.UTC), at)
	for _, r := range []string{"", "Server.ScheduledStop: Stopped due to scheduled retirement", "User initiated (garbage GMT)"} {
		_, ok := stoppedAt(r)
		require.False(t, ok, r)
	}
}
