package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controltypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/stretchr/testify/require"
)

type fakeAccessPoints struct {
	pages    []*s3control.ListAccessPointsOutput
	calls    int
	blocks   map[string]*s3controltypes.PublicAccessBlockConfiguration
	missing  map[string]bool // GetAccessPoint fails
	public   map[string]bool
	noPolicy map[string]bool
}

func (f *fakeAccessPoints) ListAccessPoints(_ context.Context, in *s3control.ListAccessPointsInput, _ ...func(*s3control.Options)) (*s3control.ListAccessPointsOutput, error) {
	f.calls++
	if f.calls > len(f.pages) {
		return nil, apiErr{code: "AccessDenied"}
	}
	return f.pages[f.calls-1], nil
}

func (f *fakeAccessPoints) GetAccessPoint(_ context.Context, in *s3control.GetAccessPointInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointOutput, error) {
	n := awssdk.ToString(in.Name)
	if f.missing[n] {
		return nil, apiErr{code: "AccessDenied"}
	}
	return &s3control.GetAccessPointOutput{Name: in.Name, PublicAccessBlockConfiguration: f.blocks[n]}, nil
}

func (f *fakeAccessPoints) GetAccessPointPolicyStatus(_ context.Context, in *s3control.GetAccessPointPolicyStatusInput, _ ...func(*s3control.Options)) (*s3control.GetAccessPointPolicyStatusOutput, error) {
	n := awssdk.ToString(in.Name)
	if f.noPolicy[n] {
		return nil, apiErr{code: "NoSuchAccessPointPolicy"}
	}
	return &s3control.GetAccessPointPolicyStatusOutput{PolicyStatus: &s3controltypes.PolicyStatus{IsPublic: f.public[n]}}, nil
}

func accessPoint(name string) s3controltypes.AccessPoint {
	return s3controltypes.AccessPoint{
		Name: awssdk.String(name), Bucket: awssdk.String("data"), NetworkOrigin: s3controltypes.NetworkOriginInternet,
		AccessPointArn: awssdk.String("arn:aws:s3:eu-west-1:111111111111:accesspoint/" + name),
	}
}

func TestS3AccessPoints(t *testing.T) {
	on := awssdk.Bool(true)
	f := &fakeAccessPoints{
		pages: []*s3control.ListAccessPointsOutput{
			{AccessPointList: []s3controltypes.AccessPoint{accessPoint("locked"), accessPoint("open")}, NextToken: awssdk.String("t")},
			{AccessPointList: []s3controltypes.AccessPoint{accessPoint("unread"), accessPoint("nopolicy")}},
		},
		blocks: map[string]*s3controltypes.PublicAccessBlockConfiguration{
			"locked": {BlockPublicAcls: on, IgnorePublicAcls: on, BlockPublicPolicy: on, RestrictPublicBuckets: on},
			"open":   {BlockPublicAcls: on},
		},
		missing:  map[string]bool{"unread": true},
		public:   map[string]bool{"open": true},
		noPolicy: map[string]bool{"nopolicy": true},
	}
	got, err := listS3AccessPoints(context.Background(), f, "eu-west-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 4)
	by := map[string]map[string]string{}
	for _, a := range got {
		require.Equal(t, "s3_access_point", a.Type)
		by[a.Name] = a.Metadata
	}
	require.Equal(t, "true", by["locked"]["bpa_all_enabled"])
	require.Equal(t, "false", by["locked"]["policy_public"])
	require.Equal(t, "false", by["open"]["bpa_all_enabled"])
	require.Equal(t, "true", by["open"]["policy_public"])
	require.Equal(t, "Internet", by["open"]["network_origin"])
	require.NotContains(t, by["unread"], "bpa_all_enabled")
	require.Equal(t, "false", by["nopolicy"]["policy_public"], "no access point policy is an observation")
	require.Equal(t, "false", by["nopolicy"]["bpa_all_enabled"], "an access point with no block configuration blocks nothing")

	_, err = listS3AccessPoints(context.Background(), &fakeAccessPoints{pages: []*s3control.ListAccessPointsOutput{
		{AccessPointList: []s3controltypes.AccessPoint{accessPoint("a")}, NextToken: awssdk.String("t")},
	}}, "eu-west-1", "111111111111", time.Now())
	require.Error(t, err, "a failed second page fails the listing")
}

type fakeMRAP struct {
	out    *s3control.ListMultiRegionAccessPointsOutput
	region string
}

func (f *fakeMRAP) ListMultiRegionAccessPoints(_ context.Context, _ *s3control.ListMultiRegionAccessPointsInput, opts ...func(*s3control.Options)) (*s3control.ListMultiRegionAccessPointsOutput, error) {
	o := s3control.Options{Region: "us-east-1"}
	for _, fn := range opts {
		fn(&o)
	}
	f.region = o.Region
	return f.out, nil
}

func TestMultiRegionAccessPoints(t *testing.T) {
	on := awssdk.Bool(true)
	f := &fakeMRAP{out: &s3control.ListMultiRegionAccessPointsOutput{AccessPoints: []s3controltypes.MultiRegionAccessPointReport{
		{Name: awssdk.String("global"), Alias: awssdk.String("mfzwi23gnjvgw.mrap"), Status: s3controltypes.MultiRegionAccessPointStatusReady,
			PublicAccessBlock: &s3controltypes.PublicAccessBlockConfiguration{BlockPublicAcls: on, IgnorePublicAcls: on, BlockPublicPolicy: on, RestrictPublicBuckets: on},
			Regions:           []s3controltypes.RegionReport{{Region: awssdk.String("eu-west-1")}, {Region: awssdk.String("us-east-1")}}},
		{Name: awssdk.String("open"), Alias: awssdk.String("abc.mrap")},
	}}}
	got, err := listMultiRegionAccessPoints(context.Background(), f, "aws", "111111111111", time.Now())
	require.NoError(t, err)
	require.Equal(t, mrapControlRegion, f.region, "the control API is only served from us-west-2")
	require.Equal(t, "arn:aws:s3::111111111111:accesspoint/mfzwi23gnjvgw.mrap", got[0].ID)
	require.Equal(t, "true", got[0].Metadata["bpa_all_enabled"])
	require.Equal(t, "eu-west-1,us-east-1", got[0].Metadata["regions"])
	require.Equal(t, "false", got[1].Metadata["bpa_all_enabled"])

	none, err := listMultiRegionAccessPoints(context.Background(), f, "aws-us-gov", "111111111111", time.Now())
	require.NoError(t, err)
	require.Empty(t, none, "no Multi-Region Access Points outside the commercial partition")
}

type fakeDirectoryBuckets struct {
	buckets   []s3types.Bucket
	lifecycle map[string][]s3types.LifecycleRule
	denied    map[string]bool
}

func (f *fakeDirectoryBuckets) ListDirectoryBuckets(context.Context, *s3.ListDirectoryBucketsInput, ...func(*s3.Options)) (*s3.ListDirectoryBucketsOutput, error) {
	return &s3.ListDirectoryBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeDirectoryBuckets) GetBucketLifecycleConfiguration(_ context.Context, in *s3.GetBucketLifecycleConfigurationInput, _ ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	b := awssdk.ToString(in.Bucket)
	if f.denied[b] {
		return nil, apiErr{code: "AccessDenied"}
	}
	r, ok := f.lifecycle[b]
	if !ok {
		return nil, apiErr{code: "NoSuchLifecycleConfiguration"}
	}
	return &s3.GetBucketLifecycleConfigurationOutput{Rules: r}, nil
}

func TestS3DirectoryBuckets(t *testing.T) {
	f := &fakeDirectoryBuckets{
		buckets: []s3types.Bucket{
			{Name: awssdk.String("hot--euw1-az1--x-s3"), BucketArn: awssdk.String("arn:aws:s3express:eu-west-1:111111111111:bucket/hot--euw1-az1--x-s3")},
			{Name: awssdk.String("bare--euw1-az1--x-s3")},
			{Name: awssdk.String("denied--euw1-az1--x-s3")},
		},
		lifecycle: map[string][]s3types.LifecycleRule{"hot--euw1-az1--x-s3": {{Status: s3types.ExpirationStatusEnabled}}},
		denied:    map[string]bool{"denied--euw1-az1--x-s3": true},
	}
	got, err := listS3DirectoryBuckets(context.Background(), f, "eu-west-1", "111111111111", time.Now())
	require.NoError(t, err)
	require.Equal(t, "1", got[0].Metadata["lifecycle_rules_enabled"])
	require.Equal(t, "0", got[1].Metadata["lifecycle_rules_enabled"])
	require.Equal(t, "arn:aws:s3express:eu-west-1:111111111111:bucket/bare--euw1-az1--x-s3", got[1].ID)
	require.NotContains(t, got[2].Metadata, "lifecycle_rules_enabled", "s3express:GetLifecycleConfiguration denied is unknown, not zero")
}
