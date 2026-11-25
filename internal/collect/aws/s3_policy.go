package aws

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/awspolicy"
)

// s3CrossAccountBlockedActions are the bucket-level and object-level actions
// FSBP S3.6 forbids granting to other accounts: each lets an outsider rewrite
// who may read the bucket, or its encryption.
var s3CrossAccountBlockedActions = []string{
	"s3:deletebucketpolicy", "s3:putbucketacl", "s3:putbucketpolicy",
	"s3:putencryptionconfiguration", "s3:putobjectacl",
}

var awsAccountInPrincipal = regexp.MustCompile(`^(?:arn:[^:]+:iam::)?(\d{12})(?::|$)`)

// bucketPolicyFacts reads the bucket policy document and grades it for:
//
//   - policy_tls_enforced (CIS 3.1.1, FSBP S3.5): a Deny for every principal
//     on every S3 action over the bucket and its objects, conditioned only on
//     aws:SecureTransport being false (a Deny narrowed by any other condition
//     leaves some plain-HTTP requests allowed);
//   - policy_cross_account_write (FSBP S3.6): an Allow granting another
//     account, or any principal under no caller-pinning condition, one of
//     the blocked actions.
//
// The caller passes only an observed document (readBucketPolicy):
// NoSuchBucketPolicy is an observed empty one — no policy enforces nothing
// and grants nothing — and an unread policy leaves both keys absent.
func bucketPolicyFacts(doc, bucket, accountID string) map[string]string {
	tls, cross := s3PolicyGrades(doc, bucket, accountID)
	return map[string]string{
		"policy_tls_enforced":        strconv.FormatBool(tls),
		"policy_cross_account_write": strconv.FormatBool(cross),
	}
}

func s3PolicyGrades(doc, bucket, accountID string) (tlsEnforced, crossAccountWrite bool) {
	for _, s := range resourcePolicyStatements(doc) {
		switch {
		case strings.EqualFold(s.Effect, "Deny"):
			if len(s.Action) > 0 && resourcePolicyIsWildcardPrincipal(s.Principal) && coversAllS3Actions(s.Action) &&
				coversBucketAndObjects(s.Resource, bucket) && deniesOnlyInsecureTransport(s.Condition) {
				tlsEnforced = true
			}
		case strings.EqualFold(s.Effect, "Allow"):
			if (len(s.Action) == 0 && len(s.NotAction) == 0) || len(s.grantedActions(s3CrossAccountBlockedActions)) == 0 {
				continue
			}
			if (s.reachesAnyone() && !awspolicy.RestrictsCaller(s.Condition)) ||
				principalNamesOtherAccount(s.Principal, accountID) {
				crossAccountWrite = true
			}
		}
	}
	return tlsEnforced, crossAccountWrite
}

// coversAllS3Actions reports whether an Action field names every S3 action.
func coversAllS3Actions(raw json.RawMessage) bool {
	return slices.ContainsFunc(resourcePolicyActionPatterns(raw), func(a string) bool { return a == "*" || a == "s3:*" })
}

// coversBucketAndObjects reports whether a Resource field covers both the
// bucket and every object in it, in any partition.
func coversBucketAndObjects(raw json.RawMessage, bucket string) bool {
	res := jsonStrings(raw)
	if slices.Contains(res, "*") {
		return true
	}
	has := func(suffix string) bool {
		return slices.ContainsFunc(res, func(r string) bool { return strings.HasPrefix(r, "arn:") && strings.HasSuffix(r, suffix) })
	}
	return has(":::"+bucket) && has(":::"+bucket+"/*")
}

// deniesOnlyInsecureTransport reports whether a condition is exactly
// Bool / BoolIfExists aws:SecureTransport = false: any further key would let
// some plain-HTTP requests through the Deny.
func deniesOnlyInsecureTransport(raw json.RawMessage) bool {
	var cond map[string]map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &cond) != nil || len(cond) != 1 {
		return false
	}
	for op, kv := range cond {
		if (!strings.EqualFold(op, "Bool") && !strings.EqualFold(op, "BoolIfExists")) || len(kv) != 1 {
			return false
		}
		for k, v := range kv {
			if !strings.EqualFold(k, "aws:SecureTransport") {
				return false
			}
			var b bool
			if json.Unmarshal(v, &b) == nil {
				return !b
			}
			vals := jsonStrings(v)
			return len(vals) == 1 && strings.EqualFold(vals[0], "false")
		}
	}
	return false
}

// principalNamesOtherAccount reports whether a Principal's AWS entries name an
// account other than accountID. An unknown accountID names nothing.
func principalNamesOtherAccount(raw json.RawMessage, accountID string) bool {
	if accountID == "" {
		return false
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	for _, p := range jsonStrings(obj["AWS"]) {
		if m := awsAccountInPrincipal.FindStringSubmatch(p); m != nil && m[1] != accountID {
			return true
		}
	}
	return false
}
