package aws

import (
	"errors"
	"net/http"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
)

// classicRetired reports a WAF Classic listing the service itself refused:
// AWS ended WAF Classic on 2025-09-30, and the exact error a retired API
// returns is not documented, so any deterministic client-side (4xx) rejection
// that is neither a permission problem nor throttling counts as "WAF Classic
// is not offered to this account". Reading it as a failed collection instead
// would flag every region partial on every sweep for a service that can no
// longer hold resources. A denied call (AccessDenied, a bad credential),
// throttling, 5xx and every DNS failure stay real failures; an endpoint that
// does not resolve is judged by the region ledger (regional_offered.go).
func classicRetired(err error) bool {
	if isPermanentAWSErr(err) || isThrottle(err) {
		return false
	}
	var re *awshttp.ResponseError
	if !errors.As(err, &re) {
		return false
	}
	code := re.HTTPStatusCode()
	return code >= http.StatusBadRequest && code < http.StatusInternalServerError && code != http.StatusTooManyRequests
}

// cloudFrontPartition reports whether CloudFront — and with it the global
// (CLOUDFRONT-scope) WAFs — exists in the partition of region: the commercial
// and China partitions only. The global collectors are not run elsewhere, so
// a GovCloud or ISO account is not read as a failed sweep, and no DNS answer
// is ever taken as proof the service is absent.
func cloudFrontPartition(region string) bool {
	switch partitionFor(region) {
	case "aws", "aws-cn":
		return true
	}
	return false
}
