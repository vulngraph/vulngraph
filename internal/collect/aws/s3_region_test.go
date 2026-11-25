package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// regionalS3 is a fake that behaves the way S3 actually behaves: every
// per-bucket call must be signed for the bucket's OWN region, and a call that
// arrives targeted at any other region fails with 301 PermanentRedirect. The
// SDK does not follow that redirect, which is why the us-east-1-only collector
// saw nothing outside us-east-1.
//
// GetBucketLocation is the one exception — it answers from any region, which is
// what makes the retarget possible at all.
type regionalS3 struct {
	// location maps a bucket to the raw LocationConstraint S3 returns (so a test
	// can exercise the legacy "" = us-east-1 and "EU" = eu-west-1 answers).
	location map[string]string
	// realRegion maps a bucket to the region its endpoint actually lives in.
	realRegion map[string]string
	// locationErr fails GetBucketLocation for a bucket.
	locationErr map[string]bool
	// order, if set, fixes ListBuckets' return order — real S3 returns buckets
	// alphabetically, and a test asserting on FAILURE POSITION (not just
	// presence) needs that determinism instead of Go's random map iteration.
	order []string
	// panicOn makes GetBucketLocation panic for a bucket, for exercising the
	// per-goroutine recover() every fan-out in this codebase must have.
	panicOn map[string]bool
}

// base is the region the collector's single client is built with.
const regionalS3BaseRegion = "us-east-1"

// check applies the per-call option functions the collector passed and reports
// whether the resulting request would reach the bucket.
func (f *regionalS3) check(bucket string, optFns []func(*s3.Options)) error {
	o := s3.Options{Region: regionalS3BaseRegion}
	for _, fn := range optFns {
		fn(&o)
	}
	want := f.realRegion[bucket]
	if o.Region != want {
		return &apiErr{code: "PermanentRedirect"}
	}
	return nil
}

func (f *regionalS3) buckets() []s3types.Bucket {
	if len(f.order) > 0 {
		out := make([]s3types.Bucket, 0, len(f.order))
		for _, name := range f.order {
			out = append(out, s3types.Bucket{Name: awssdk.String(name)})
		}
		return out
	}
	out := make([]s3types.Bucket, 0, len(f.realRegion))
	for name := range f.realRegion {
		out = append(out, s3types.Bucket{Name: awssdk.String(name)})
	}
	return out
}

func (f *regionalS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets()}, nil
}

func (f *regionalS3) GetBucketLocation(_ context.Context, in *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	b := awssdk.ToString(in.Bucket)
	if f.panicOn[b] {
		panic("simulated panic for " + b)
	}
	if f.locationErr[b] {
		return nil, errors.New("AccessDenied")
	}
	return &s3.GetBucketLocationOutput{LocationConstraint: s3types.BucketLocationConstraint(f.location[b])}, nil
}

func (f *regionalS3) GetPublicAccessBlock(_ context.Context, in *s3.GetPublicAccessBlockInput, opts ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
		BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
	}}, nil
}

func (f *regionalS3) GetBucketPolicyStatus(_ context.Context, in *s3.GetBucketPolicyStatusInput, opts ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(false)}}, nil
}

func (f *regionalS3) GetBucketAcl(_ context.Context, in *s3.GetBucketAclInput, opts ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetBucketAclOutput{}, nil
}

func (f *regionalS3) GetBucketVersioning(_ context.Context, in *s3.GetBucketVersioningInput, opts ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetBucketVersioningOutput{}, nil // never versioned: 200 with empty status
}

func (f *regionalS3) GetBucketLogging(_ context.Context, in *s3.GetBucketLoggingInput, opts ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetBucketLoggingOutput{}, nil
}

func (f *regionalS3) GetBucketEncryption(_ context.Context, in *s3.GetBucketEncryptionInput, opts ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return &s3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
		Rules: []s3types.ServerSideEncryptionRule{{ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
			SSEAlgorithm: s3types.ServerSideEncryptionAes256,
		}}},
	}}, nil
}

func (f *regionalS3) GetBucketWebsite(_ context.Context, in *s3.GetBucketWebsiteInput, opts ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return nil, &apiErr{code: "NoSuchWebsiteConfiguration"}
}

func (f *regionalS3) GetBucketPolicy(_ context.Context, in *s3.GetBucketPolicyInput, opts ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	if err := f.check(awssdk.ToString(in.Bucket), opts); err != nil {
		return nil, err
	}
	return nil, &apiErr{code: "NoSuchBucketPolicy"}
}

func assetByID(t *testing.T, assets []asset.Asset, id string) asset.Asset {
	t.Helper()
	for _, a := range assets {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("asset %q not collected", id)
	return asset.Asset{}
}

// TestCollectS3RetargetsEveryRegion is the guard for the region blind spot: with
// the collector pinned to us-east-1, buckets in other regions carried NO
// versioning/encryption/logging key at all, which the finding lifecycle read as
// remediation and closed as "fixed". Every per-bucket call must be signed for
// the bucket's own region.
func TestCollectS3RetargetsEveryRegion(t *testing.T) {
	fake := &regionalS3{
		location: map[string]string{
			"home":   "",               // legacy empty constraint = us-east-1
			"euro":   "EU",             // legacy alias = eu-west-1
			"dublin": "eu-west-1",      //
			"sydney": "ap-southeast-2", //
		},
		realRegion: map[string]string{
			"home": "us-east-1", "euro": "eu-west-1",
			"dublin": "eu-west-1", "sydney": "ap-southeast-2",
		},
	}

	assets, _, _, err := collectS3Buckets(context.Background(), fake, accountBPA{}, "acct", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 4)

	for _, name := range []string{"home", "euro", "dublin", "sydney"} {
		a := assetByID(t, assets, name)
		require.Contains(t, a.Metadata, "versioning", "bucket %q lost its versioning observation", name)
		require.Contains(t, a.Metadata, "encryption", "bucket %q lost its encryption observation", name)
		require.Contains(t, a.Metadata, "logging", "bucket %q lost its logging observation", name)
		require.Equal(t, "disabled", a.Metadata["versioning"])
		require.Equal(t, "AES256", a.Metadata["encryption"])
	}

	// The legacy "EU" constraint must be stored as the real region code, not
	// verbatim — "EU" is not a region and resolves to no endpoint.
	require.Equal(t, "eu-west-1", assetByID(t, assets, "euro").Region)
	require.Equal(t, "us-east-1", assetByID(t, assets, "home").Region)
	require.Equal(t, "ap-southeast-2", assetByID(t, assets, "sydney").Region)
}

// TestCollectS3UnknownRegionStaysUnobserved holds the fail-unknown contract at
// the new seam: when GetBucketLocation itself fails we do not know where the
// bucket is, cannot sign for it, and must OMIT every per-bucket setting rather
// than guess a region or write a default.
func TestCollectS3UnknownRegionStaysUnobserved(t *testing.T) {
	fake := &regionalS3{
		location:    map[string]string{"lost": "eu-west-1"},
		realRegion:  map[string]string{"lost": "eu-west-1"},
		locationErr: map[string]bool{"lost": true},
	}

	assets, _, _, err := collectS3Buckets(context.Background(), fake, accountBPA{}, "acct", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 1)

	a := assets[0]
	require.Empty(t, a.Region)
	require.NotContains(t, a.Metadata, "versioning")
	require.NotContains(t, a.Metadata, "encryption")
	require.NotContains(t, a.Metadata, "logging")
	require.NotContains(t, a.Metadata, "mfa_delete")
}

// TestCollectS3LogsUnresolvedRegionSummary is the regression guard for the
// concurrent rewrite's log: it must still summarize how many buckets had an
// unresolved region and how long the whole call took, even though the
// per-bucket-position diagnostics (first_failure_bucket_index,
// success_after_first_failure) that diagnosed the ROOT CAUSE — a shared
// 30-minute sync-job deadline, not a permission gap or an AWS throttle —
// no longer apply once buckets are processed
// concurrently instead of in list order. Their job was root-causing the bug;
// the fix (s3BucketConcurrency-wide fan-out, see s3.go) is what actually
// closes it.
func TestCollectS3LogsUnresolvedRegionSummary(t *testing.T) {
	fake := &regionalS3{
		order:       []string{"a-fails", "b-ok", "c-fails"},
		realRegion:  map[string]string{"a-fails": "eu-west-1", "b-ok": "eu-west-1", "c-fails": "eu-west-1"},
		location:    map[string]string{"b-ok": "eu-west-1"},
		locationErr: map[string]bool{"a-fails": true, "c-fails": true},
	}
	var buf bytes.Buffer
	orig := zlog.Logger
	// SyncWriter: collectS3Buckets fans out across s3BucketConcurrency
	// goroutines, so an unwrapped bytes.Buffer is a reproducible
	// data race under -race (a bare buffer is not safe for concurrent writes
	// the way production's os.File writer is).
	zlog.Logger = zerolog.New(zerolog.SyncWriter(&buf))
	t.Cleanup(func() { zlog.Logger = orig })

	assets, _, _, err := collectS3Buckets(context.Background(), fake, accountBPA{}, "acct", time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 3)

	out := buf.String()
	require.Contains(t, out, `"unresolved":2`)
	require.Contains(t, out, `"buckets":3`)
	require.Contains(t, out, `"ctx_deadline_exceeded":false`)
	require.Contains(t, out, `"elapsed":`)
}

// TestCollectS3BucketConcurrencyIsBounded is the regression guard for the
// actual fix: a sequential, ~7-call-per-bucket loop can exhaust the account
// sync's shared 30-minute context deadline on an account with many buckets
// (see s3.go's s3BucketConcurrency doc). Concurrent per-bucket fan-out must be BOUNDED,
// not unlimited: unlimited fan-out on a large account would trade one
// deadline-exhaustion bug for a self-inflicted AWS throttle.
func TestCollectS3BucketConcurrencyIsBounded(t *testing.T) {
	const bucketCount = 40
	fake := &boundedConcurrencyS3{}
	names := make([]string, bucketCount)
	for i := range names {
		names[i] = fmt.Sprintf("bucket-%02d", i)
	}
	fake.names = names

	_, _, _, err := collectS3Buckets(context.Background(), fake, accountBPA{}, "acct", time.Now())
	require.NoError(t, err)
	require.LessOrEqual(t, int(fake.maxInFlight.Load()), s3BucketConcurrency,
		"never more than s3BucketConcurrency GetBucketLocation calls in flight at once")
	require.Greater(t, int(fake.maxInFlight.Load()), 1,
		"sanity check that the fake actually observed concurrency, not an accidentally-serial test")
}

// TestCollectS3PerBucketPanicIsRecovered guards the goroutine-safety
// requirement every spawned goroutine in this codebase must meet (CLAUDE.md):
// a panic in one bucket's fan-out goroutine must not crash the whole
// collection or lose every other bucket's results.
func TestCollectS3PerBucketPanicIsRecovered(t *testing.T) {
	fake := &regionalS3{
		order:      []string{"a-ok", "b-panics", "c-ok"},
		realRegion: map[string]string{"a-ok": "eu-west-1", "b-panics": "eu-west-1", "c-ok": "eu-west-1"},
		location:   map[string]string{"a-ok": "eu-west-1", "b-panics": "eu-west-1", "c-ok": "eu-west-1"},
		panicOn:    map[string]bool{"b-panics": true},
	}

	require.NotPanics(t, func() {
		assets, _, _, err := collectS3Buckets(context.Background(), fake, accountBPA{}, "acct", time.Now())
		require.NoError(t, err)
		require.Len(t, assets, 2, "the panicking bucket is omitted; the other two survive")
		assetByID(t, assets, "a-ok")
		assetByID(t, assets, "c-ok")
	})
}

// boundedConcurrencyS3 is a minimal s3API fake whose only job is measuring
// how many GetBucketLocation calls are in flight at once; every other call
// answers instantly with a fixed, uninteresting value.
type boundedConcurrencyS3 struct {
	names       []string
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

func (f *boundedConcurrencyS3) buckets() []s3types.Bucket {
	out := make([]s3types.Bucket, 0, len(f.names))
	for _, n := range f.names {
		out = append(out, s3types.Bucket{Name: awssdk.String(n)})
	}
	return out
}
func (f *boundedConcurrencyS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return &s3.ListBucketsOutput{Buckets: f.buckets()}, nil
}
func (f *boundedConcurrencyS3) GetBucketLocation(context.Context, *s3.GetBucketLocationInput, ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		max := f.maxInFlight.Load()
		if n <= max || f.maxInFlight.CompareAndSwap(max, n) {
			break
		}
	}
	// A tiny sleep widens the window in which concurrent calls actually
	// overlap — without it, a fast/unbounded fake could pass this test by
	// accident (each call finishing before the next starts) even with a bug
	// that removed the semaphore entirely.
	time.Sleep(2 * time.Millisecond)
	return &s3.GetBucketLocationOutput{LocationConstraint: "eu-west-1"}, nil
}
func (f *boundedConcurrencyS3) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: awssdk.Bool(true), IgnorePublicAcls: awssdk.Bool(true),
		BlockPublicPolicy: awssdk.Bool(true), RestrictPublicBuckets: awssdk.Bool(true),
	}}, nil
}
func (f *boundedConcurrencyS3) GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &s3types.PolicyStatus{IsPublic: awssdk.Bool(false)}}, nil
}
func (f *boundedConcurrencyS3) GetBucketAcl(context.Context, *s3.GetBucketAclInput, ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	return &s3.GetBucketAclOutput{}, nil
}
func (f *boundedConcurrencyS3) GetBucketVersioning(context.Context, *s3.GetBucketVersioningInput, ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return &s3.GetBucketVersioningOutput{}, nil
}
func (f *boundedConcurrencyS3) GetBucketLogging(context.Context, *s3.GetBucketLoggingInput, ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	return &s3.GetBucketLoggingOutput{}, nil
}
func (f *boundedConcurrencyS3) GetBucketEncryption(context.Context, *s3.GetBucketEncryptionInput, ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error) {
	return nil, &apiErr{code: "ServerSideEncryptionConfigurationNotFoundError"}
}
func (f *boundedConcurrencyS3) GetBucketWebsite(context.Context, *s3.GetBucketWebsiteInput, ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	return nil, &apiErr{code: "NoSuchWebsiteConfiguration"}
}
func (f *boundedConcurrencyS3) GetBucketPolicy(context.Context, *s3.GetBucketPolicyInput, ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	return nil, &apiErr{code: "NoSuchBucketPolicy"}
}

func TestNormalizeBucketRegion(t *testing.T) {
	require.Equal(t, "us-east-1", normalizeBucketRegion(""))
	require.Equal(t, "eu-west-1", normalizeBucketRegion("EU"))
	require.Equal(t, "ap-southeast-2", normalizeBucketRegion("ap-southeast-2"))
}

// TestRegionOptLeavesBaseRegionWhenUnknown pins the one case where the option
// must do nothing: an unresolved region must not blank out the client's region
// (which would make the endpoint unresolvable rather than merely wrong).
func TestRegionOptLeavesBaseRegionWhenUnknown(t *testing.T) {
	o := s3.Options{Region: "us-east-1"}
	regionOpt("")(&o)
	require.Equal(t, "us-east-1", o.Region)

	regionOpt("eu-west-3")(&o)
	require.Equal(t, "eu-west-3", o.Region)
}
