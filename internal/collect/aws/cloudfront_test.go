package aws

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/require"
)

type fakeCloudFront struct {
	pages     []*cloudfront.ListDistributionsOutput
	listErr   error
	configs   map[string]*cftypes.DistributionConfig
	configErr map[string]error
	calls     int
}

func (f *fakeCloudFront) ListDistributions(_ context.Context, in *cloudfront.ListDistributionsInput, _ ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	i := f.calls
	f.calls++
	if i > 0 && f.listErr != nil {
		return nil, f.listErr
	}
	if i == 0 && f.listErr != nil && len(f.pages) == 0 {
		return nil, f.listErr
	}
	return f.pages[i], nil
}

func (f *fakeCloudFront) GetDistributionConfig(_ context.Context, in *cloudfront.GetDistributionConfigInput, _ ...func(*cloudfront.Options)) (*cloudfront.GetDistributionConfigOutput, error) {
	id := awssdk.ToString(in.Id)
	if err := f.configErr[id]; err != nil {
		return nil, err
	}
	return &cloudfront.GetDistributionConfigOutput{DistributionConfig: f.configs[id]}, nil
}

type fakeDeliveries struct {
	sources    []cwltypes.DeliverySource
	deliveries []cwltypes.Delivery
	err        error
}

func (f fakeDeliveries) DescribeDeliverySources(context.Context, *cloudwatchlogs.DescribeDeliverySourcesInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeDeliverySourcesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cloudwatchlogs.DescribeDeliverySourcesOutput{DeliverySources: f.sources}, nil
}

func (f fakeDeliveries) DescribeDeliveries(context.Context, *cloudwatchlogs.DescribeDeliveriesInput, ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeDeliveriesOutput, error) {
	return &cloudwatchlogs.DescribeDeliveriesOutput{Deliveries: f.deliveries}, nil
}

type fakeProber struct {
	mu      sync.Mutex
	status  map[string]int // 0 = exists, -1 = transport error
	owned   []string       // ListBuckets
	listErr error
}

func (f *fakeProber) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := &s3.ListBucketsOutput{}
	for _, b := range f.owned {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: awssdk.String(b)})
	}
	return out, nil
}

func httpErr(code int) error {
	return &awshttp.ResponseError{ResponseError: &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: code}},
		Err:      errors.New("status"),
	}}
}

func (f *fakeProber) HeadBucket(_ context.Context, in *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch code := f.status[awssdk.ToString(in.Bucket)]; code {
	case 0:
		return &s3.HeadBucketOutput{}, nil
	case -1:
		return nil, errors.New("connection reset")
	default:
		return nil, httpErr(code)
	}
}

func s3Orig(id, domain, oac string) cftypes.Origin {
	return cftypes.Origin{Id: awssdk.String(id), DomainName: awssdk.String(domain),
		S3OriginConfig: &cftypes.S3OriginConfig{OriginAccessIdentity: awssdk.String("")}, OriginAccessControlId: awssdk.String(oac)}
}

func customOrig(id, domain string, policy cftypes.OriginProtocolPolicy, protos ...cftypes.SslProtocol) cftypes.Origin {
	return cftypes.Origin{Id: awssdk.String(id), DomainName: awssdk.String(domain), OriginAccessControlId: awssdk.String(""),
		CustomOriginConfig: &cftypes.CustomOriginConfig{OriginProtocolPolicy: policy,
			OriginSslProtocols: &cftypes.OriginSslProtocols{Items: protos, Quantity: awssdk.Int32(int32(len(protos)))}}}
}

func dist(id string, origins []cftypes.Origin, def cftypes.ViewerProtocolPolicy, extra ...cftypes.CacheBehavior) cftypes.DistributionSummary {
	return cftypes.DistributionSummary{
		ARN: awssdk.String("arn:aws:cloudfront::111122223333:distribution/" + id), Id: awssdk.String(id),
		DomainName: awssdk.String(id + ".cloudfront.net"), Enabled: awssdk.Bool(true), WebACLId: awssdk.String(""),
		Origins:              &cftypes.Origins{Items: origins, Quantity: awssdk.Int32(int32(len(origins)))},
		OriginGroups:         &cftypes.OriginGroups{Quantity: awssdk.Int32(0)},
		DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{TargetOriginId: origins[0].Id, ViewerProtocolPolicy: def},
		CacheBehaviors:       &cftypes.CacheBehaviors{Items: extra, Quantity: awssdk.Int32(int32(len(extra)))},
		ViewerCertificate: &cftypes.ViewerCertificate{CloudFrontDefaultCertificate: awssdk.Bool(true),
			MinimumProtocolVersion: cftypes.MinimumProtocolVersionTLSv1, SSLSupportMethod: cftypes.SSLSupportMethodVip},
	}
}

func onePage(ds ...cftypes.DistributionSummary) []*cloudfront.ListDistributionsOutput {
	return []*cloudfront.ListDistributionsOutput{{DistributionList: &cftypes.DistributionList{Items: ds, IsTruncated: awssdk.Bool(false)}}}
}

func TestReadCloudFrontStampsOriginAndViewerFacts(t *testing.T) {
	d := dist("E1", []cftypes.Origin{
		s3Orig("rest", "assets.s3.us-east-1.amazonaws.com", ""),
		s3Orig("oac", "media.s3.amazonaws.com", "E2OAC"),
		customOrig("web", "site.s3-website-us-east-1.amazonaws.com", cftypes.OriginProtocolPolicyHttpOnly),
		customOrig("app", "app.example.com", cftypes.OriginProtocolPolicyMatchViewer, cftypes.SslProtocolSSLv3, cftypes.SslProtocolTLSv12),
		customOrig("fn", "abc.lambda-url.us-east-1.on.aws", cftypes.OriginProtocolPolicyHttpsOnly, cftypes.SslProtocolTLSv12),
	}, cftypes.ViewerProtocolPolicyRedirectToHttps,
		cftypes.CacheBehavior{PathPattern: awssdk.String("/api/*"), TargetOriginId: awssdk.String("app"), ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyAllowAll,
			TrustedSigners: &cftypes.TrustedSigners{Enabled: awssdk.Bool(true), Quantity: awssdk.Int32(1), Items: []string{"self"}}})
	cf := &fakeCloudFront{pages: onePage(d), configs: map[string]*cftypes.DistributionConfig{
		"E1": {DefaultRootObject: awssdk.String(""), Logging: &cftypes.LoggingConfig{Enabled: awssdk.Bool(false)}},
	}}
	probe := &fakeProber{status: map[string]int{"assets": 404, "media": 403, "site": 0}, owned: []string{"media", "site"}}
	got, err := readCloudFront(context.Background(), cf, fakeDeliveries{}, probe, "111122223333", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 1)
	m := got[0].Metadata
	require.Equal(t, cloudfrontDistributionType, got[0].Type)
	require.Equal(t, "E1.cloudfront.net", got[0].Domain)
	require.Equal(t, "", m["default_root_object"])
	require.Equal(t, "false", m["logging_enabled"], "legacy off and no v2 delivery, both read")
	require.Equal(t, "/api/*", m["viewer_http_behaviors"])
	require.Equal(t, "/api/*", m["trusted_signer_behaviors"])
	require.Equal(t, "web,app", m["custom_origins_unencrypted"], "http-only, and match-viewer behind an allow-all behaviour")
	require.Equal(t, "app", m["custom_origins_sslv3"])
	require.Equal(t, "fn", m["lambda_url_origins_without_oac"])
	require.Equal(t, "assets", m["s3_origin_buckets_missing"])
	require.Equal(t, "", m["s3_origin_buckets_foreign"], "a 403 on a bucket the account owns is its own bucket")
	require.Equal(t, "", m["s3_origins_without_oac"], "the missing bucket is the dangling finding; the OAC origin passes")
	require.Equal(t, "true", m["default_certificate"])
	require.Equal(t, "0", m["origin_group_count"])
	require.Equal(t, "", m["web_acl_id"])
	require.Equal(t, "true", m["has_s3_origin"])
}

func TestReadCloudFrontUnknownsStayAbsent(t *testing.T) {
	d := dist("E1", []cftypes.Origin{s3Orig("rest", "assets.s3.amazonaws.com", "")}, cftypes.ViewerProtocolPolicyHttpsOnly)
	cf := &fakeCloudFront{pages: onePage(d), configErr: map[string]error{"E1": errors.New("AccessDenied")}}
	probe := &fakeProber{status: map[string]int{"assets": -1}}
	got, err := readCloudFront(context.Background(), cf, fakeDeliveries{err: errors.New("AccessDenied")}, probe, "1", time.Now())
	require.NoError(t, err)
	m := got[0].Metadata
	for _, k := range []string{"default_root_object", "logging_enabled", "s3_origin_buckets_missing"} {
		_, ok := m[k]
		require.False(t, ok, "%s must be absent when its read failed", k)
	}
	require.Equal(t, "rest", m["s3_origins_without_oac"], "an unknown bucket still lacks OAC")
}

func TestCloudFrontLoggingSources(t *testing.T) {
	arn := "arn:aws:cloudfront::111122223333:distribution/E1"
	v2 := fakeDeliveries{
		sources:    []cwltypes.DeliverySource{{Name: awssdk.String("cf-src"), ResourceArns: []string{arn}}},
		deliveries: []cwltypes.Delivery{{DeliverySourceName: awssdk.String("cf-src")}},
	}
	tests := []struct {
		name      string
		logs      fakeDeliveries
		configErr error
		legacy    bool
		want      string // "" = absent
	}{
		{"v2 delivery with legacy off", v2, nil, false, "true"},
		{"legacy on, v2 unreadable", fakeDeliveries{err: errors.New("denied")}, nil, true, "true"},
		{"legacy off, v2 unreadable", fakeDeliveries{err: errors.New("denied")}, nil, false, ""},
		{"config unreadable, v2 delivery", v2, errors.New("denied"), false, "true"},
		{"config unreadable, no v2 delivery", fakeDeliveries{}, errors.New("denied"), false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := dist("E1", []cftypes.Origin{customOrig("o", "app.example.com", cftypes.OriginProtocolPolicyHttpsOnly)}, cftypes.ViewerProtocolPolicyHttpsOnly)
			cf := &fakeCloudFront{pages: onePage(d),
				configs:   map[string]*cftypes.DistributionConfig{"E1": {Logging: &cftypes.LoggingConfig{Enabled: awssdk.Bool(tt.legacy)}}},
				configErr: map[string]error{"E1": tt.configErr}}
			got, err := readCloudFront(context.Background(), cf, tt.logs, &fakeProber{}, "1", time.Now())
			require.NoError(t, err)
			v, ok := got[0].Metadata["logging_enabled"]
			if tt.want == "" {
				require.False(t, ok)
				return
			}
			require.Equal(t, tt.want, v)
		})
	}
}

func TestReadCloudFrontPaginationFailsClosed(t *testing.T) {
	d := dist("E1", []cftypes.Origin{customOrig("o", "app.example.com", cftypes.OriginProtocolPolicyHttpsOnly)}, cftypes.ViewerProtocolPolicyHttpsOnly)
	cf := &fakeCloudFront{
		pages:   []*cloudfront.ListDistributionsOutput{{DistributionList: &cftypes.DistributionList{Items: []cftypes.DistributionSummary{d}, IsTruncated: awssdk.Bool(true), NextMarker: awssdk.String("m")}}},
		listErr: errors.New("Throttling"),
	}
	_, err := readCloudFront(context.Background(), cf, fakeDeliveries{}, &fakeProber{}, "1", time.Now())
	require.Error(t, err, "a failed second page is a failed read, never a short list")
}

// An NXDOMAIN is a failed read like any other: a DNS firewall answers it too.
// Where CloudFront does not exist is decided by partition, before any call.
func TestReadCloudFrontNXDOMAINIsAFailedRead(t *testing.T) {
	cf := &fakeCloudFront{listErr: &net.DNSError{Err: "no such host", Name: "cloudfront.amazonaws.com", IsNotFound: true}}
	_, err := readCloudFront(context.Background(), cf, fakeDeliveries{}, &fakeProber{}, "1", time.Now())
	require.Error(t, err)
}

func TestCloudFrontPartition(t *testing.T) {
	require.True(t, cloudFrontPartition("eu-west-1"))
	require.True(t, cloudFrontPartition("cn-northwest-1"))
	require.False(t, cloudFrontPartition("us-gov-west-1"))
	got, err := collectCloudFront(context.Background(), map[string]string{"region": "us-gov-west-1", "aws_access_key_id": "AKIDEXAMPLE", "aws_secret_access_key": "x"}, "1", time.Now())
	require.NoError(t, err, "GovCloud has no CloudFront to read")
	require.Empty(t, got)
}

func TestS3OriginParsing(t *testing.T) {
	tests := []struct {
		domain, bucket string
		website, ok    bool
	}{
		{"assets.s3.amazonaws.com", "assets", false, true},
		{"my.dotted.bucket.s3.eu-west-1.amazonaws.com", "my.dotted.bucket", false, true},
		{"legacy.s3-eu-west-1.amazonaws.com", "legacy", false, true},
		{"dual.s3.dualstack.us-east-1.amazonaws.com", "dual", false, true},
		{"site.s3-website-us-east-1.amazonaws.com", "site", true, true},
		{"site.s3-website.eu-central-1.amazonaws.com", "site", true, true},
		{"cn.s3.cn-north-1.amazonaws.com.cn", "cn", false, true},
		{"app.example.com", "", false, false},
		{"s3.amazonaws.com", "", false, false},
	}
	for _, tt := range tests {
		b, w, ok := s3Origin(cftypes.Origin{DomainName: awssdk.String(tt.domain)})
		require.Equal(t, tt.ok, ok, tt.domain)
		require.Equal(t, tt.bucket, b, tt.domain)
		require.Equal(t, tt.website, w, tt.domain)
	}
}

// A bucket that exists (403/301) but is not among the account's own buckets is
// another account's bucket behind the distribution: a possible takeover. If
// the account's bucket list is unreadable, ownership is unknown.
func TestReadCloudFrontForeignOriginBucket(t *testing.T) {
	d := dist("E1", []cftypes.Origin{
		s3Orig("theirs", "claimed.s3.amazonaws.com", "E2OAC"),
		s3Orig("away", "moved.s3.eu-west-1.amazonaws.com", "E2OAC"),
		s3Orig("mine", "mine.s3.amazonaws.com", "E2OAC"),
	}, cftypes.ViewerProtocolPolicyHttpsOnly)
	cf := &fakeCloudFront{pages: onePage(d), configs: map[string]*cftypes.DistributionConfig{"E1": {}}}
	probe := &fakeProber{status: map[string]int{"claimed": 403, "moved": 301, "mine": 403}, owned: []string{"mine"}}
	got, err := readCloudFront(context.Background(), cf, fakeDeliveries{}, probe, "1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "claimed,moved", got[0].Metadata["s3_origin_buckets_foreign"])
	require.Equal(t, "", got[0].Metadata["s3_origin_buckets_missing"])

	cf = &fakeCloudFront{pages: onePage(d), configs: map[string]*cftypes.DistributionConfig{"E1": {}}}
	probe = &fakeProber{status: map[string]int{"claimed": 403, "moved": 301, "mine": 403}, listErr: errors.New("AccessDenied")}
	got, err = readCloudFront(context.Background(), cf, fakeDeliveries{}, probe, "1", time.Now())
	require.NoError(t, err)
	require.NotContains(t, got[0].Metadata, "s3_origin_buckets_foreign", "unreadable ownership is unknown, never 'all ours'")
	require.NotContains(t, got[0].Metadata, "s3_origin_buckets_missing")
}
