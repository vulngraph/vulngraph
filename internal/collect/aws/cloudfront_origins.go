package aws

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Origin and cache-behaviour facts for one CloudFront distribution. Each
// helper returns origin ids or behaviour labels so the finding can name what
// is wrong; an empty result is an observation ("none"), since the summary
// always carries the full origin and behaviour lists.

// defaultBehaviorLabel names the default cache behaviour, which has no path.
const defaultBehaviorLabel = "default"

type behavior struct {
	label, target string
	viewer        cftypes.ViewerProtocolPolicy
	signers       *cftypes.TrustedSigners
}

func behaviors(d cftypes.DistributionSummary) []behavior {
	var out []behavior
	if b := d.DefaultCacheBehavior; b != nil {
		out = append(out, behavior{defaultBehaviorLabel, awssdk.ToString(b.TargetOriginId), b.ViewerProtocolPolicy, b.TrustedSigners})
	}
	if d.CacheBehaviors != nil {
		for _, b := range d.CacheBehaviors.Items {
			out = append(out, behavior{awssdk.ToString(b.PathPattern), awssdk.ToString(b.TargetOriginId), b.ViewerProtocolPolicy, b.TrustedSigners})
		}
	}
	return out
}

func origins(d cftypes.DistributionSummary) []cftypes.Origin {
	if d.Origins == nil {
		return nil
	}
	return d.Origins.Items
}

// viewerHTTPBehaviors are the behaviours that serve plain HTTP (CloudFront.3):
// allow-all, rather than redirect-to-https or https-only.
func viewerHTTPBehaviors(d cftypes.DistributionSummary) []string {
	var out []string
	for _, b := range behaviors(d) {
		if b.viewer == cftypes.ViewerProtocolPolicyAllowAll {
			out = append(out, b.label)
		}
	}
	return out
}

// trustedSignerBehaviors are the behaviours that still verify signed URLs
// against account (root) CloudFront key pairs (CloudFront.17).
func trustedSignerBehaviors(d cftypes.DistributionSummary) []string {
	var out []string
	for _, b := range behaviors(d) {
		if b.signers != nil && awssdk.ToBool(b.signers.Enabled) {
			out = append(out, b.label)
		}
	}
	return out
}

// viewerAllowsHTTP reports whether any behaviour routing to originID (directly
// or through an origin group) accepts plain-HTTP viewers.
func viewerAllowsHTTP(d cftypes.DistributionSummary, originID string) bool {
	groups := map[string][]string{}
	if d.OriginGroups != nil {
		for _, g := range d.OriginGroups.Items {
			if g.Members == nil {
				continue
			}
			for _, m := range g.Members.Items {
				groups[awssdk.ToString(g.Id)] = append(groups[awssdk.ToString(g.Id)], awssdk.ToString(m.OriginId))
			}
		}
	}
	for _, b := range behaviors(d) {
		if b.viewer != cftypes.ViewerProtocolPolicyAllowAll {
			continue
		}
		if b.target == originID {
			return true
		}
		for _, m := range groups[b.target] {
			if m == originID {
				return true
			}
		}
	}
	return false
}

// unencryptedCustomOrigins are custom origins CloudFront can reach over
// plain HTTP (CloudFront.9): http-only, or match-viewer behind a behaviour
// that admits HTTP viewers. S3 website endpoints are custom origins and only
// speak HTTP, so they land here too — the edge-to-origin hop is cleartext.
// VPC origins carry their protocol on a separate resource and are not graded.
func unencryptedCustomOrigins(d cftypes.DistributionSummary) []string {
	var out []string
	for _, o := range origins(d) {
		c := o.CustomOriginConfig
		if c == nil {
			continue
		}
		id := awssdk.ToString(o.Id)
		switch c.OriginProtocolPolicy {
		case cftypes.OriginProtocolPolicyHttpOnly:
			out = append(out, id)
		case cftypes.OriginProtocolPolicyMatchViewer:
			if viewerAllowsHTTP(d, id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// sslv3CustomOrigins are custom origins that still offer SSLv3 for the HTTPS
// hop (CloudFront.10). An http-only origin never negotiates TLS and is
// CloudFront.9's finding instead.
func sslv3CustomOrigins(d cftypes.DistributionSummary) []string {
	var out []string
	for _, o := range origins(d) {
		c := o.CustomOriginConfig
		if c == nil || c.OriginProtocolPolicy == cftypes.OriginProtocolPolicyHttpOnly || c.OriginSslProtocols == nil {
			continue
		}
		for _, p := range c.OriginSslProtocols.Items {
			if p == cftypes.SslProtocolSSLv3 {
				out = append(out, awssdk.ToString(o.Id))
				break
			}
		}
	}
	return out
}

// isLambdaURLOrigin matches a Lambda function URL host (<id>.lambda-url.<region>.on.aws).
func isLambdaURLOrigin(o cftypes.Origin) bool {
	host := strings.ToLower(awssdk.ToString(o.DomainName))
	return strings.Contains(host, ".lambda-url.") && strings.HasSuffix(host, ".on.aws")
}

// lambdaURLOriginsWithoutOAC are function URL origins CloudFront does not
// sign for (CloudFront.16): the URL must then accept unauthenticated calls,
// so anyone can bypass the distribution and invoke it directly.
func lambdaURLOriginsWithoutOAC(d cftypes.DistributionSummary) []string {
	var out []string
	for _, o := range origins(d) {
		if isLambdaURLOrigin(o) && awssdk.ToString(o.OriginAccessControlId) == "" {
			out = append(out, awssdk.ToString(o.Id))
		}
	}
	return out
}

// s3Origin parses an origin's S3 bucket. website is true for an S3 static
// website endpoint, which CloudFront treats as a custom origin.
func s3Origin(o cftypes.Origin) (bucket string, website, ok bool) {
	host := strings.ToLower(awssdk.ToString(o.DomainName))
	if !strings.HasSuffix(host, ".amazonaws.com") && !strings.HasSuffix(host, ".amazonaws.com.cn") {
		return "", false, false
	}
	i := max(strings.LastIndex(host, ".s3."), strings.LastIndex(host, ".s3-"))
	if i <= 0 {
		return "", false, false
	}
	return host[:i], strings.HasPrefix(host[i:], ".s3-website"), true
}

// isS3RESTOrigin reports an origin served by the S3 REST API — the origin
// kind origin access control applies to.
func isS3RESTOrigin(o cftypes.Origin) bool {
	if o.S3OriginConfig != nil {
		return true
	}
	_, website, ok := s3Origin(o)
	return ok && !website && o.CustomOriginConfig == nil
}

func hasS3Origin(d cftypes.DistributionSummary) bool {
	for _, o := range origins(d) {
		if _, _, ok := s3Origin(o); ok {
			return true
		}
	}
	return false
}

// s3OriginBuckets are the bucket names a distribution serves from, REST and
// website origins alike: either kind is claimable by anyone once the bucket
// is deleted.
func s3OriginBuckets(d cftypes.DistributionSummary) []string {
	var out []string
	for _, o := range origins(d) {
		if b, _, ok := s3Origin(o); ok {
			out = append(out, b)
		}
	}
	return out
}

type bucketPresence int

const (
	bucketUnknown bucketPresence = iota
	bucketPresent
	bucketMissing
	// bucketExistsUnowned is HeadBucket's 403/301: the bucket exists but
	// this account cannot read it from here. resolveBucketOwnership turns it
	// into bucketPresent (owned) or bucketForeign (another account's).
	bucketExistsUnowned
	bucketForeign
)

// probeBucket asks S3 whether a bucket name exists. 404 is the only proof of
// absence; 403 (not readable from here) and 301 (another region's) prove it
// exists, and whose it is is settled against the account's own buckets
// (resolveBucketOwnership). Anything else — throttling, a network error — is
// unknown.
func probeBucket(ctx context.Context, client bucketProber, name string) bucketPresence {
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: awssdk.String(name)})
	if err == nil {
		return bucketPresent
	}
	var re *awshttp.ResponseError
	if !errors.As(err, &re) {
		return bucketUnknown
	}
	switch re.HTTPStatusCode() {
	case http.StatusNotFound:
		return bucketMissing
	case http.StatusForbidden, http.StatusMovedPermanently:
		return bucketExistsUnowned
	}
	return bucketUnknown
}

// stampMissingBuckets records s3_origin_buckets_missing and
// s3_origin_buckets_foreign (CloudFront.12) and
// s3_origins_without_oac (CloudFront.13). The missing list is absent only
// when no bucket is proven missing and some probe was inconclusive. An origin
// whose bucket is gone is reported as dangling, not again as lacking OAC.
func stampMissingBuckets(meta map[string]string, d cftypes.DistributionSummary, probes map[string]bucketPresence) {
	var missing, foreign []string
	unknown := false
	for _, b := range s3OriginBuckets(d) {
		switch probes[b] {
		case bucketMissing:
			missing = append(missing, b)
		case bucketForeign:
			foreign = append(foreign, b)
		case bucketUnknown, bucketExistsUnowned:
			unknown = true
		}
	}
	sort.Strings(missing)
	sort.Strings(foreign)
	if len(missing) > 0 || !unknown {
		meta["s3_origin_buckets_missing"] = strings.Join(missing, ",")
	}
	// s3_origin_buckets_foreign: origin buckets that exist but belong to
	// another account, absent on the same terms as the missing list.
	if len(foreign) > 0 || !unknown {
		meta["s3_origin_buckets_foreign"] = strings.Join(foreign, ",")
	}
	var noOAC []string
	for _, o := range origins(d) {
		if !isS3RESTOrigin(o) || awssdk.ToString(o.OriginAccessControlId) != "" {
			continue
		}
		if b, _, ok := s3Origin(o); ok && probes[b] == bucketMissing {
			continue
		}
		noOAC = append(noOAC, awssdk.ToString(o.Id))
	}
	meta["s3_origins_without_oac"] = strings.Join(noOAC, ",")
}
