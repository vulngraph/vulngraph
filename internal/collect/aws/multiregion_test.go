package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"
)

// With DescribeRegions returning >1 region, the regional EC2 collectors run
// once per region and label assets with that region — the parity fix for the
// old single-region scan.
func TestCollect_ScansEveryEnabledRegion(t *testing.T) {
	f := &fakeEC2{
		regionsOut: &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{
			{RegionName: awssdk.String("eu-west-1")},
			{RegionName: awssdk.String("us-east-1")},
		}},
		// one SG per region (no NextToken → one call each)
		sgPages: []*ec2.DescribeSecurityGroupsOutput{
			{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-euw1")}}},
			{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-use1")}}},
		},
		instancePages: []*ec2.DescribeInstancesOutput{{}, {}},
	}
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return f, "eu-west-1", nil
	}}

	res, err := c.Collect(context.Background(), map[string]string{"region": "eu-west-1"})
	require.NoError(t, err)

	var sgRegions []string
	for _, a := range res.Assets {
		if a.Type == "security_group" {
			sgRegions = append(sgRegions, a.Region)
		}
	}
	require.ElementsMatch(t, []string{"eu-west-1", "us-east-1"}, sgRegions,
		"security groups collected from both enabled regions, labeled per region")
}

// An explicit "regions" config overrides enumeration (and DescribeRegions is
// not consulted).
func TestRegionsFor_ExplicitOverride(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return &fakeEC2{}, "eu-west-1", nil
	}}
	got, fellBack, err := c.regionsFor(context.Background(), map[string]string{"regions": "eu-west-1, us-east-1 , ap-south-1"})
	require.NoError(t, err)
	require.False(t, fellBack)
	require.Equal(t, []string{"eu-west-1", "us-east-1", "ap-south-1"}, got)
}

// When DescribeRegions fails (or returns nothing) and a base region is
// configured, regionsFor falls back to that single region but reports the
// fallback so the caller can flag the sweep partial rather than silently
// treating one region as the whole account.
func TestRegionsFor_FallbackIsFlagged(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return &fakeEC2{regionsErr: errors.New("boom")}, "eu-west-1", nil
	}}
	got, fellBack, err := c.regionsFor(context.Background(), map[string]string{"region": "eu-west-1"})
	require.NoError(t, err)
	require.True(t, fellBack)
	require.Equal(t, []string{"eu-west-1"}, got)
}

// The fallback propagates into Collect as result.Partial, so deletion
// reconciliation is skipped for a sweep that only ever looked at one region.
func TestCollect_RegionEnumerationFailure_MarksPartial(t *testing.T) {
	f := &fakeEC2{regionsErr: errors.New("boom")}
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return f, "eu-west-1", nil
	}}
	res, err := c.Collect(context.Background(), map[string]string{"region": "eu-west-1"})
	require.NoError(t, err)
	require.True(t, res.Partial, "a fallback region list must flag the sweep partial")
}
