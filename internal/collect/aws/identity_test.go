package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/collect"
)

type fakeSTS struct {
	account string
	err     error
	calls   int
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(f.account)}, nil
}

// deniedEC2 refuses every EC2 call, the way a region-deny SCP does.
type deniedEC2 struct{ code string }

func (d deniedEC2) err() error { return apiErr(d) }
func (d deniedEC2) DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeFlowLogs(context.Context, *ec2.DescribeFlowLogsInput, ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error) {
	return nil, d.err()
}
func (d deniedEC2) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return nil, d.err()
}

func withSTS(c *Collector, s *fakeSTS) *Collector {
	c.newSTS = func(context.Context, map[string]string) (stsAPI, error) { return s, nil }
	return c
}

// An expired credential must surface as a permanent sync error, not as a
// successful sync with zero assets — and no collector runs on it.
func TestCollect_ExpiredCredentialIsPermanentError(t *testing.T) {
	for _, code := range []string{"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException", "SignatureDoesNotMatch", "AccessDenied"} {
		t.Run(code, func(t *testing.T) {
			ec2Calls := 0
			c := withSTS(&Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
				ec2Calls++
				return &fakeEC2{}, "eu-west-1", nil
			}}, &fakeSTS{err: apiErr{code: code}})

			res, err := c.Collect(context.Background(), map[string]string{"region": "eu-west-1"})
			require.Error(t, err)
			require.ErrorIs(t, err, collect.ErrPermanent)
			require.Contains(t, err.Error(), "rejected the connector's credentials")
			require.Empty(t, res.Assets)
			require.Zero(t, ec2Calls, "no collector may run on a rejected credential")
		})
	}
}

// A throttled or unreachable STS is transient: the sync must retry, so the
// error is NOT permanent.
func TestCollect_TransientIdentityFailureRetries(t *testing.T) {
	c := withSTS(withFake(&fakeEC2{}), &fakeSTS{err: apiErr{code: "Throttling"}})
	_, err := c.Collect(context.Background(), map[string]string{"region": "eu-west-1"})
	require.Error(t, err)
	require.NotErrorIs(t, err, collect.ErrPermanent)
}

// Static-key connectors (SSO-issued keys) have no role_arn: the account must
// come from the caller identity, so the account anchor and every asset carry it.
func TestCollect_AccountIDFromCallerIdentity(t *testing.T) {
	fake := &fakeEC2{
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}}}},
		instancePages: []*ec2.DescribeInstancesOutput{{}},
	}
	s := &fakeSTS{account: "222233334444"}
	c := withSTS(withFake(fake), s)

	res, err := c.Collect(context.Background(), map[string]string{"region": "eu-west-1"})
	require.NoError(t, err)
	require.Equal(t, 1, s.calls, "identity is resolved once per sweep")

	var anchor, sg bool
	for _, a := range res.Assets {
		switch a.Type {
		case "cloud_account":
			anchor = true
			require.Equal(t, "aws:222233334444", a.ID)
		case "security_group":
			sg = true
			require.Equal(t, "222233334444", a.AccountID)
		}
	}
	require.True(t, anchor, "the cloud_account anchor is emitted for a static-key connector")
	require.True(t, sg)
}

func TestResolveAccount_Fallbacks(t *testing.T) {
	c := &Collector{}
	got, err := c.resolveAccount(context.Background(), map[string]string{"aws_account_id": "111", "role_arn": "arn:aws:iam::999:role/r"})
	require.NoError(t, err)
	require.Equal(t, "111", got, "explicit aws_account_id wins over the role ARN")

	got, err = c.resolveAccount(context.Background(), map[string]string{"role_arn": "arn:aws:iam::999:role/r"})
	require.NoError(t, err)
	require.Equal(t, "999", got)

	withSTS(c, &fakeSTS{account: "555"})
	got, err = c.resolveAccount(context.Background(), map[string]string{"aws_account_id": "111"})
	require.NoError(t, err)
	require.Equal(t, "555", got, "the caller identity is authoritative")
}

// AWS refusing every call is a broken connector, not a partial sweep.
func TestCollect_EveryCallRefusedIsPermanentError(t *testing.T) {
	c := &Collector{newClient: func(context.Context, map[string]string) (ec2API, string, error) {
		return deniedEC2{code: "UnauthorizedOperation"}, "eu-west-1", nil
	}}
	_, err := c.Collect(context.Background(), map[string]string{"regions": "eu-west-1"})
	require.ErrorIs(t, err, collect.ErrPermanent)
}

// One region closed by an SCP must not keep the whole sweep partial: the
// readable region still completes its scopes, and the denied region claims
// none.
func TestCollect_DeniedRegionIsExcludedNotPartial(t *testing.T) {
	ok := &fakeEC2{
		sgPages:       []*ec2.DescribeSecurityGroupsOutput{{SecurityGroups: []ec2types.SecurityGroup{{GroupId: awssdk.String("sg-1")}}}},
		instancePages: []*ec2.DescribeInstancesOutput{{}},
	}
	c := &Collector{newClient: func(_ context.Context, cfg map[string]string) (ec2API, string, error) {
		if cfg["region"] == "ap-east-1" {
			return deniedEC2{code: "UnauthorizedOperation"}, "ap-east-1", nil
		}
		return ok, "eu-west-1", nil
	}}

	res, err := c.Collect(context.Background(), map[string]string{"regions": "eu-west-1,ap-east-1"})
	require.NoError(t, err)
	require.False(t, res.Partial, "a fully denied region is excluded from coverage, not a partial sweep")

	var scopes []string
	for _, se := range res.CompletedEnumerations {
		scopes = append(scopes, se.Scope)
	}
	require.Contains(t, scopes, "eu-west-1/ec2:security-groups")
	for _, s := range scopes {
		require.NotContains(t, s, "ap-east-1", "nothing in a denied region may be marked complete")
	}
}

// A region where only SOME calls are denied is a reachable region with a
// permission gap — that stays partial.
func TestCollect_PartlyDeniedRegionIsPartial(t *testing.T) {
	f := &fakeEC2{
		sgErr:         apiErr{code: "UnauthorizedOperation"},
		instancePages: []*ec2.DescribeInstancesOutput{{}},
	}
	res, err := withFake(f).Collect(context.Background(), map[string]string{"regions": "eu-west-1"})
	require.NoError(t, err)
	require.True(t, res.Partial)
}

func TestRegionDenied(t *testing.T) {
	deny := regionFailure{err: apiErr{code: "AccessDeniedException"}}
	throttle := regionFailure{err: apiErr{code: "Throttling"}}
	require.True(t, regionDenied(2, []regionFailure{deny, deny}))
	require.False(t, regionDenied(3, []regionFailure{deny, deny}), "one task succeeded")
	require.False(t, regionDenied(2, []regionFailure{deny, throttle}), "a throttle is not a deny")
	require.False(t, regionDenied(1, []regionFailure{{err: errors.New("panic: boom")}}))
	require.False(t, regionDenied(0, nil))
}

// A cluster whose describe failed and whose account is unknown has no usable
// ID: it is dropped, and the drop flags the result partial.
func TestCollectEKSClusters_UnknownAccountOmitsAndFlagsPartial(t *testing.T) {
	f := &fakeEKS{names: []string{"prod"}}
	got, partial, err := collectEKSClusters(context.Background(), f, "eu-west-1", "", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
	require.True(t, partial)

	got, partial, err = collectEKSClusters(context.Background(), f, "eu-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.False(t, partial)
	require.Equal(t, "arn:aws:eks:eu-west-1:111:cluster/prod", got[0].ID)
}
