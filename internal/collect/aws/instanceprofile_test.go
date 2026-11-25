package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeInstanceProfiles struct {
	pages [][]iamtypes.InstanceProfile
	err   error
	calls int
}

func (f *fakeInstanceProfiles) ListInstanceProfiles(_ context.Context, in *iam.ListInstanceProfilesInput, _ ...func(*iam.Options)) (*iam.ListInstanceProfilesOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	idx := 0
	if in.Marker != nil {
		idx = int((*in.Marker)[0] - '0')
	}
	if idx >= len(f.pages) {
		return &iam.ListInstanceProfilesOutput{}, nil
	}
	out := &iam.ListInstanceProfilesOutput{InstanceProfiles: f.pages[idx]}
	if idx+1 < len(f.pages) {
		out.IsTruncated = true
		out.Marker = awssdk.String(string(rune('0' + idx + 1)))
	}
	return out, nil
}

func profile(arn, roleARN string) iamtypes.InstanceProfile {
	p := iamtypes.InstanceProfile{Arn: awssdk.String(arn)}
	if roleARN != "" {
		p.Roles = []iamtypes.Role{{Arn: awssdk.String(roleARN)}}
	}
	return p
}

// The whole point: an EKS managed node group's profile name has NOTHING to do
// with its role name, so the ":instance-profile/" → ":role/" substitution the
// correlate rule fell back to cannot resolve it. This is the common case for instances
// without a has_role edge, and it is exactly the EKS worker nodes.
func TestInstanceProfileRoles_ResolvesEKSNodeGroupProfiles(t *testing.T) {
	eksProfile := "arn:aws:iam::111122223333:instance-profile/eks-3ec0a5b2-9f11-4c3d-8a77-1f2e3d4c5b6a"
	eksRole := "arn:aws:iam::111122223333:role/prod-cluster-eks-node-group-20240612093011"
	f := &fakeInstanceProfiles{pages: [][]iamtypes.InstanceProfile{{
		profile(eksProfile, eksRole),
		profile("arn:aws:iam::111122223333:instance-profile/app-server", "arn:aws:iam::111122223333:role/app-server"),
		profile("arn:aws:iam::111122223333:instance-profile/empty", ""), // no role → grants nothing
	}}}

	got, err := instanceProfileRoles(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, eksRole, got[eksProfile])
	require.NotEqual(t, strings.Replace(eksProfile, ":instance-profile/", ":role/", 1), got[eksProfile],
		"the string substitution would have produced a role ARN that does not exist")
	require.NotContains(t, got, "arn:aws:iam::111122223333:instance-profile/empty")
	require.Len(t, got, 2)
}

func TestInstanceProfileRoles_Paginates(t *testing.T) {
	f := &fakeInstanceProfiles{pages: [][]iamtypes.InstanceProfile{
		{profile("arn:p1", "arn:r1")},
		{profile("arn:p2", "arn:r2")},
		{profile("arn:p3", "arn:r3")},
	}}
	got, err := instanceProfileRoles(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, 3, f.calls)
}

// An IAM failure must yield no map at all, so instances carry no role rather
// than a guessed one.
func TestInstanceProfileRoles_Error(t *testing.T) {
	got, err := instanceProfileRoles(context.Background(), &fakeInstanceProfiles{err: errors.New("AccessDenied")})
	require.Error(t, err)
	require.Nil(t, got)
}

// collectInstances stamps the resolved role ARN, and omits the key entirely
// when the role is unknown — an absent iam_role_arn must never be confused
// with "this instance has no role".
func TestCollectInstances_StampsResolvedRoleARN(t *testing.T) {
	eksProfile := "arn:aws:iam::111122223333:instance-profile/eks-3ec0a5b2"
	eksRole := "arn:aws:iam::111122223333:role/prod-cluster-eks-node-group-20240612093011"
	f := &fakeEC2{instancePages: []*ec2.DescribeInstancesOutput{{
		Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{
				InstanceId:         awssdk.String("i-eks"),
				State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awssdk.String(eksProfile)},
			},
			{
				InstanceId:         awssdk.String("i-orphan"),
				State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
				IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awssdk.String("arn:aws:iam::111122223333:instance-profile/gone")},
			},
			{
				InstanceId: awssdk.String("i-noprofile"),
				State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			},
		}}},
	}}}

	got, _, err := collectInstances(context.Background(), f, "eu-west-1", "111122223333", time.Now(),
		map[string]string{eksProfile: eksRole})
	require.NoError(t, err)

	byID := map[string]asset.Asset{}
	for _, a := range got {
		byID[a.ID] = a
	}
	require.Equal(t, eksRole, byID["i-eks"].Metadata["iam_role_arn"])
	require.NotContains(t, byID["i-orphan"].Metadata, "iam_role_arn", "profile not in the map is unknown, not absent")
	require.NotContains(t, byID["i-noprofile"].Metadata, "iam_role_arn")
	// The raw profile ARN is still recorded — the existing no-iam-role check reads it.
	require.Equal(t, eksProfile, byID["i-eks"].Metadata["iam_instance_profile"])
	require.Empty(t, byID["i-noprofile"].Metadata["iam_instance_profile"])
}

// A nil map (the IAM list failed) must leave every instance without the key.
func TestCollectInstances_NilProfileMap_OmitsRoleARN(t *testing.T) {
	f := &fakeEC2{instancePages: []*ec2.DescribeInstancesOutput{{
		Reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{
			InstanceId:         awssdk.String("i-1"),
			State:              &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
			IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: awssdk.String("arn:aws:iam::1:instance-profile/p")},
		}}}},
	}}}
	got, _, err := collectInstances(context.Background(), f, "eu-west-1", "1", time.Now(), nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.NotContains(t, got[0].Metadata, "iam_role_arn")
}

func TestInstanceRoleARN(t *testing.T) {
	m := map[string]string{"arn:p1": "arn:r1"}
	cases := []struct {
		name    string
		m       map[string]string
		profile string
		want    string
		wantOK  bool
	}{
		{"resolved", m, "arn:p1", "arn:r1", true},
		{"profile not in map is unknown", m, "arn:p9", "", false},
		{"nil map is unknown", nil, "arn:p1", "", false},
		{"no profile attached", m, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := instanceRoleARN(tc.m, tc.profile)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.want, got)
		})
	}
}
