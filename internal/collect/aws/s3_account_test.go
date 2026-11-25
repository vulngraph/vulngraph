package aws

import (
	"context"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3ctypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/stretchr/testify/require"
)

type fakeS3Control struct {
	cfg   *s3ctypes.PublicAccessBlockConfiguration
	err   error
	calls int
}

func (f *fakeS3Control) GetPublicAccessBlock(_ context.Context, in *s3control.GetPublicAccessBlockInput, _ ...func(*s3control.Options)) (*s3control.GetPublicAccessBlockOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &s3control.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: f.cfg}, nil
}

func allOn() *s3ctypes.PublicAccessBlockConfiguration {
	t := awssdk.Bool(true)
	return &s3ctypes.PublicAccessBlockConfiguration{BlockPublicAcls: t, IgnorePublicAcls: t, BlockPublicPolicy: t, RestrictPublicBuckets: t}
}

func TestFetchAccountBPA(t *testing.T) {
	ctx := context.Background()

	got := fetchAccountBPA(ctx, &fakeS3Control{cfg: allOn()}, "111")
	require.True(t, got.observed)
	require.True(t, awssdk.ToBool(got.cfg.RestrictPublicBuckets))

	got = fetchAccountBPA(ctx, &fakeS3Control{err: apiErr{code: "NoSuchPublicAccessBlockConfiguration"}}, "111")
	require.True(t, got.observed, "no account block is an observation")
	require.Nil(t, got.cfg)

	got = fetchAccountBPA(ctx, &fakeS3Control{err: apiErr{code: "AccessDenied"}}, "111")
	require.False(t, got.observed, "a denied read is unknown, not 'no block'")

	f := &fakeS3Control{cfg: allOn()}
	got = fetchAccountBPA(ctx, f, "")
	require.False(t, got.observed)
	require.Zero(t, f.calls, "an unknown account cannot be queried")
}

// An account-level block that ignores public ACLs and restricts public
// policies makes every bucket non-public, whatever its own policy/ACL say.
func TestCollectS3Buckets_AccountBPANeutralizesBuckets(t *testing.T) {
	f := &fakeS3{
		buckets:      []s3types.Bucket{{Name: awssdk.String("policy-public")}, {Name: awssdk.String("acl-public")}},
		policyPublic: map[string]bool{"policy-public": true},
		aclPublic:    map[string]bool{"acl-public": true},
	}
	acct := fetchAccountBPA(context.Background(), &fakeS3Control{cfg: allOn()}, "111")
	got, edges, partial, err := collectS3Buckets(context.Background(), f, acct, "111", time.Now())
	require.NoError(t, err)
	require.False(t, partial)
	require.Empty(t, edges, "a neutralized bucket is not internet-exposed")
	for _, a := range got {
		require.Equal(t, "none", a.Metadata["public_access"], a.Name)
		require.Equal(t, "false", a.Metadata["public"], a.Name)
	}
}

// Each account flag neutralizes only what it covers: IgnorePublicAcls defuses a
// public ACL but not a public policy.
func TestCollectS3Buckets_AccountIgnoreAclsOnly(t *testing.T) {
	f := &fakeS3{
		buckets:      []s3types.Bucket{{Name: awssdk.String("policy-public")}, {Name: awssdk.String("acl-public")}},
		policyPublic: map[string]bool{"policy-public": true},
		aclPublic:    map[string]bool{"acl-public": true},
	}
	acct := fetchAccountBPA(context.Background(), &fakeS3Control{cfg: &s3ctypes.PublicAccessBlockConfiguration{IgnorePublicAcls: awssdk.Bool(true)}}, "111")
	got, _, _, err := collectS3Buckets(context.Background(), f, acct, "111", time.Now())
	require.NoError(t, err)
	tier := map[string]string{}
	for _, a := range got {
		tier[a.Name] = a.Metadata["public_access"]
	}
	require.Equal(t, "confirmed", tier["policy-public"])
	require.Equal(t, "possible", tier["acl-public"], "an ignored public ACL no longer confirms exposure")
}

// A deadline that stops bucket queuing, or a panicking bucket, drops listed
// buckets: the result must be partial so they are not read as deleted.
func TestCollectS3Buckets_DroppedBucketsArePartial(t *testing.T) {
	buckets := []s3types.Bucket{{Name: awssdk.String("a")}, {Name: awssdk.String("b")}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, _, partial, err := collectS3Buckets(ctx, &fakeS3{buckets: buckets}, accountBPA{}, "111", time.Now())
	require.NoError(t, err)
	require.Empty(t, got)
	require.True(t, partial, "buckets never queued are unemitted, not deleted")

	got, _, partial, err = collectS3Buckets(context.Background(), &fakeS3{buckets: buckets, panicOn: "a"}, accountBPA{}, "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, partial, "a panicking bucket is dropped and flags the result partial")
}

// Only NoSuchWebsiteConfiguration is "no website"; any other error leaves the
// key absent.
func TestCollectS3Buckets_WebsiteErrorOmitsKey(t *testing.T) {
	buckets := []s3types.Bucket{{Name: awssdk.String("a")}}
	got, _, _, err := collectS3Buckets(context.Background(), &fakeS3{buckets: buckets}, accountBPA{}, "111", time.Now())
	require.NoError(t, err)
	website, present := got[0].Metadata["website"]
	require.True(t, present)
	require.Empty(t, website)

	got, _, _, err = collectS3Buckets(context.Background(), &fakeS3{buckets: buckets, websiteErr: apiErr{code: "AccessDenied"}}, accountBPA{}, "111", time.Now())
	require.NoError(t, err)
	_, present = got[0].Metadata["website"]
	require.False(t, present)
}
