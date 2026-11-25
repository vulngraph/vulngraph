package awspolicy

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRestrictsCaller(t *testing.T) {
	tests := []struct {
		name string
		cond string
		want bool
	}{
		{"absent", ``, false},
		{"empty block", `{}`, false},
		{"TLS", `{"Bool":{"aws:SecureTransport":"true"}}`, false},
		{"MFA", `{"Bool":{"aws:MultiFactorAuthPresent":true}}`, false},
		{"ExternalId", `{"StringEquals":{"sts:ExternalId":"x"}}`, false},
		{"world source IP", `{"IpAddress":{"aws:SourceIp":["0.0.0.0/0"]}}`, false},
		{"negated org", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-1"}}`, false},
		{"IfExists org", `{"StringEqualsIfExists":{"aws:PrincipalOrgID":"o-1"}}`, false},
		{"wildcard like", `{"StringLike":{"aws:PrincipalArn":"*"}}`, false},
		{"principal ARN in any account", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/deploy"}}`, false},
		{"any organization", `{"StringLike":{"aws:PrincipalOrgID":"o-*"}}`, false},
		{"one wildcard value among literal ones", `{"StringLike":{"aws:PrincipalAccount":["111122223333","1111*"]}}`, false},
		{"organization path under any org", `{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"*/r-1/*"}}`, false},
		{"user ID without a literal unique ID", `{"StringLike":{"aws:userid":"AROA*"}}`, false},
		{"SNS endpoint on any host", `{"StringLike":{"sns:Endpoint":"https://*.example.com/hook"}}`, false},
		{"S3 bucket source ARN, empty fields wildcarded", `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:*:*:my-bucket"}}`, true},
		{"S3 bucket source ARN", `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::my-bucket"}}`, true},
		{"S3 source ARN with a wildcard bucket", `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:*:*:my-*"}}`, false},
		{"S3 access point in any account", `{"ArnLike":{"aws:SourceArn":"arn:aws:s3:*:*:accesspoint/ap"}}`, false},
		{"principal ARN wildcard after a literal account", `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::111122223333:role/*"}}`, true},
		{"user ID wildcard session", `{"StringLike":{"aws:userid":"AROAEXAMPLEID:*"}}`, true},
		{"SNS endpoint wildcard path", `{"StringLike":{"sns:Endpoint":"https://hooks.example.com/*"}}`, true},
		{"SNS email endpoint wildcard user", `{"StringLike":{"sns:Endpoint":"*@example.com"}}`, true},
		{"mount target false", `{"Bool":{"elasticfilesystem:AccessedViaMountTarget":"false"}}`, false},
		{"org", `{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}`, true},
		{"ForAnyValue org paths", `{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":["o-1/r-1/*"]}}`, true},
		{"narrow source IP", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`, true},
		{"mount target true", `{"Bool":{"elasticfilesystem:AccessedViaMountTarget":true}}`, true},
		{"unparseable", `"x"`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, RestrictsCaller(json.RawMessage(tt.cond)))
		})
	}
}

func TestConfiningKeys(t *testing.T) {
	tests := []struct {
		name string
		cond string
		want []string
	}{
		{"org IfExists", `{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-1"}}`, []string{"aws:PrincipalOrgID"}},
		{"ForAllValues org paths", `{"ForAllValues:StringNotLikeIfExists":{"aws:PrincipalOrgPaths":"o-1/*"}}`, []string{"aws:PrincipalOrgPaths"}},
		{"network", `{"NotIpAddressIfExists":{"aws:SourceIp":"10.0.0.0/8"}}`, []string{"aws:SourceIp"}},
		{"bare negated includes a caller without the key", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-1"}}`, []string{"aws:PrincipalOrgID"}},
		{"bare negated ARN", `{"ArnNotLike":{"aws:PrincipalArn":"arn:aws:iam::111122223333:role/*"}}`, []string{"aws:PrincipalArn"}},
		{"bare negated network", `{"NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, []string{"aws:SourceIp"}},
		{"ForAllValues bare negated", `{"ForAllValues:StringNotLike":{"aws:PrincipalOrgPaths":"o-1/*"}}`, []string{"aws:PrincipalOrgPaths"}},
		{"ForAnyValue misses an empty set", `{"ForAnyValue:StringNotLike":{"aws:PrincipalOrgPaths":"o-1/*"}}`, nil},
		{"negated conjunction of bounded alternatives", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-1","aws:PrincipalAccount":"111122223333"}}`, []string{"aws:PrincipalAccount", "aws:PrincipalOrgID"}},
		{"other operator can bypass deny", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-1"},"Bool":{"aws:SecureTransport":"false"}}`, nil},
		{"other key can bypass deny", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-1","sts:ExternalId":"x"}}`, nil},
		{"Null presence gate can bypass deny", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-1"},"Null":{"aws:PrincipalOrgID":"false"}}`, nil},
		{"empty alternatives do not prove confinement", `{"StringNotEquals":{"aws:PrincipalOrgID":[]}}`, nil},
		{"positive operator excludes, never confines", `{"StringEqualsIfExists":{"aws:PrincipalOrgID":"o-1"}}`, nil},
		{"ExternalId", `{"StringNotEqualsIfExists":{"sts:ExternalId":"x"}}`, nil},
		{"principal tag", `{"StringNotEqualsIfExists":{"aws:PrincipalTag/team":"a"}}`, nil},
		{"world network", `{"NotIpAddressIfExists":{"aws:SourceIp":"0.0.0.0/0"}}`, nil},
		{"principal ARN in any account", `{"ArnNotLikeIfExists":{"aws:PrincipalArn":"arn:aws:iam::*:role/deploy"}}`, nil},
		{"unparseable", `"x"`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ConfiningKeys(json.RawMessage(tt.cond)))
		})
	}
}

func TestMatchingOperator(t *testing.T) {
	for op, want := range map[string]bool{
		"StringEquals": true, "StringLike": true, "ForAnyValue:StringLike": true, "ArnLike": true,
		"StringNotEquals": false, "StringLikeIfExists": false, "ForAllValues:StringEquals": false, "Null": false,
	} {
		require.Equal(t, want, isMatchingOperator(op), op)
	}
}

func TestPresentKeyOperator(t *testing.T) {
	tests := []struct {
		op                string
		matching, negated bool
	}{
		{"StringEquals", true, false},
		{"StringLikeIfExists", true, false},
		{"StringEqualsIfExists", true, false},
		{"ForAnyValue:StringLike", true, false},
		{"ForAllValues:StringEquals", true, false},
		{"StringNotEquals", false, true},
		{"StringNotLikeIfExists", false, true},
		{"ForAllValues:StringNotLike", false, true},
		{"Null", false, false},
		{"NumericEquals", false, false},
	}
	for _, tt := range tests {
		matching, negated := PresentKeyOperator(tt.op)
		require.Equal(t, tt.matching, matching, tt.op)
		require.Equal(t, tt.negated, negated, tt.op)
	}
}

func TestHasCondition(t *testing.T) {
	require.False(t, HasCondition(nil))
	require.False(t, HasCondition(json.RawMessage(`{}`)))
	require.False(t, HasCondition(json.RawMessage(`null`)))
	require.True(t, HasCondition(json.RawMessage(`{"Bool":{"aws:SecureTransport":"false"}}`)))
	require.True(t, HasCondition(json.RawMessage(`"x"`)), "unparseable reads as conditioned")
}
