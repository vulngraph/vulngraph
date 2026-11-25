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

// ec2HttpTokens used to answer "optional" for an instance whose DescribeInstances
// response carried no MetadataOptions at all — the exact value
// aws-ec2-imdsv2-not-required fires on, manufactured by the collector rather
// than observed. The check was narrowed to explicit "optional" in the same
// release; without this, the narrowing bought nothing, because the collector
// supplies "optional" for the unknown case anyway.
//
// DescribeInstances normally populates the field, so this is a latent
// hazard rather than a common source of findings: many instances legitimately
// report "optional" and keep their finding. The blast radius is what matters —
// one partial or throttled describe would have minted a High finding per instance.
func TestEC2HttpTokens_ObservedFlag(t *testing.T) {
	got, observed := ec2HttpTokens(nil)
	require.False(t, observed, "no MetadataOptions in the response is not an observation")
	require.Empty(t, got, "and it must never be reported as the violating value")

	got, observed = ec2HttpTokens(&ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateOptional})
	require.True(t, observed)
	require.Equal(t, "optional", got)

	got, observed = ec2HttpTokens(&ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensStateRequired})
	require.True(t, observed)
	require.Equal(t, "required", got)
}

func TestCollectInstances_HTTPTokensOmittedWhenUnobserved(t *testing.T) {
	fake := &fakeEC2{instancePages: []*ec2.DescribeInstancesOutput{{
		Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{
				InstanceId: awssdk.String("i-observed"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
					HttpTokens: ec2types.HttpTokensStateOptional,
				},
			},
			{
				InstanceId: awssdk.String("i-unobserved"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				// MetadataOptions absent — a partial describe, not IMDSv1.
			},
		}}},
	}}}

	assets, _, err := collectInstances(context.Background(), fake, "eu-west-1", "111122223333", time.Now(), nil)
	require.NoError(t, err)

	meta := map[string]map[string]string{}
	for _, a := range assets {
		meta[a.ID] = a.Metadata
	}
	require.Equal(t, "optional", meta["i-observed"]["http_tokens"])
	require.NotContains(t, meta["i-unobserved"], "http_tokens",
		"an unread metadata-options block must not read as IMDSv1 allowed")
}

// Every IPv6 address on every interface is recorded: an instance with no
// public IPv4 can be internet-facing through one, which the exposure
// correlator reads from ipv6_addresses.
func TestCollectInstances_RecordsIPv6Addresses(t *testing.T) {
	fake := &fakeEC2{instancePages: []*ec2.DescribeInstancesOutput{{
		Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{
				InstanceId: awssdk.String("i-v6"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{Ipv6Addresses: []ec2types.InstanceIpv6Address{{Ipv6Address: awssdk.String("2001:db8:1::10")}}},
					{Ipv6Addresses: []ec2types.InstanceIpv6Address{{Ipv6Address: awssdk.String("2001:db8:2::20")}, {}}},
				},
			},
			{
				InstanceId: awssdk.String("i-v4"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			},
		}}},
	}}}

	assets, _, err := collectInstances(context.Background(), fake, "eu-west-1", "111122223333", time.Now(), nil)
	require.NoError(t, err)
	got := map[string]string{}
	for _, a := range assets {
		got[a.ID] = a.Metadata["ipv6_addresses"]
	}
	require.Equal(t, map[string]string{"i-v6": "2001:db8:1::10,2001:db8:2::20", "i-v4": ""}, got)
}
