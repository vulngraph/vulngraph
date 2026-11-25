package awspolicy

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCallerProofRequiresFixedOwner(t *testing.T) {
	// AWS substitutes policy variables from request context. ArnEquals/ArnLike
	// both support wildcards, as do their corresponding negated operators.
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
	tests := []struct {
		name, key, values string
		bounded           bool
	}{
		{"self account variable", "aws:PrincipalAccount", `"${aws:PrincipalAccount}"`, false},
		{"variable mixed with fixed account", "aws:PrincipalAccount", `["111122223333","${aws:PrincipalAccount}"]`, false},
		{"fixed account", "aws:PrincipalAccount", `"111122223333"`, true},
		{"self ARN variable", "aws:PrincipalArn", `"${aws:PrincipalArn}"`, false},
		{"ARN with account variable", "aws:PrincipalArn", `"arn:aws:iam::${aws:PrincipalAccount}:role/deploy"`, false},
		{"exact ARN", "aws:PrincipalArn", `"arn:aws:iam::111122223333:role/deploy"`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			operators := [][2]string{{"StringEquals", "StringNotEquals"}, {"StringLike", "StringNotLike"}}
			if tt.key == "aws:PrincipalArn" {
				operators = append(operators, [2]string{"ArnEquals", "ArnNotEquals"}, [2]string{"ArnLike", "ArnNotLike"})
			}
			for _, ops := range operators {
				allow := json.RawMessage(fmt.Sprintf(`{%q:{%q:%s}}`, ops[0], tt.key, tt.values))
				deny := json.RawMessage(fmt.Sprintf(`{%q:{%q:%s}}`, ops[1], tt.key, tt.values))
				require.Equal(t, tt.bounded, RestrictsCaller(allow), string(allow))
				require.Equal(t, tt.bounded, len(ConfiningKeys(deny)) > 0, string(deny))
			}
		})
	}
}

func TestARNEqualityWildcardsRequireFixedOwner(t *testing.T) {
	for _, tt := range []struct {
		arn     string
		bounded bool
	}{
		{"arn:aws:iam::*:role/deploy", false},
		{"arn:aws:iam::1111????????:role/deploy", false},
		{"arn:aws:iam::111122223333:role/*", true},
		{"arn:aws:iam::111122223333:role/deploy", true},
	} {
		for _, op := range []string{"ArnEquals", "ArnLike"} {
			condition := json.RawMessage(fmt.Sprintf(`{%q:{"aws:PrincipalArn":%q}}`, op, tt.arn))
			require.Equal(t, tt.bounded, RestrictsCaller(condition), string(condition))
		}
		for _, op := range []string{"ArnNotEquals", "ArnNotEqualsIfExists", "ArnNotLike", "ForAllValues:ArnNotEquals"} {
			condition := json.RawMessage(fmt.Sprintf(`{%q:{"aws:PrincipalArn":%q}}`, op, tt.arn))
			require.Equal(t, tt.bounded, len(ConfiningKeys(condition)) > 0, string(condition))
		}
	}
}

func TestPolicyVariableConjunctionProof(t *testing.T) {
	// A fixed Allow conjunct suffices. A dynamic Deny conjunct can make the
	// entire Deny false for an outsider, despite its other fixed condition.
	require.True(t, RestrictsCaller(json.RawMessage(`{"StringEquals":{"aws:PrincipalAccount":"${aws:PrincipalAccount}","aws:PrincipalOrgID":"o-trusted"}}`)))
	require.Empty(t, ConfiningKeys(json.RawMessage(`{"StringNotEquals":{"aws:PrincipalAccount":"${aws:PrincipalAccount}","aws:PrincipalOrgID":"o-trusted"}}`)))
}

func TestConfiningNetworksCombineAcrossConjuncts(t *testing.T) {
	for _, tt := range []struct {
		name, first, second string
		bounded             bool
	}{
		{"complementary IPv4", `["0.0.0.0/1"]`, `["128.0.0.0/1"]`, false},
		{"complementary IPv6", `["::/1"]`, `["8000::/1"]`, false},
		{"complementary dual stack", `["0.0.0.0/1","::/1"]`, `["128.0.0.0/1","8000::/1"]`, false},
		{"bounded union", `["10.0.0.0/8","2001:db8::/48"]`, `["192.168.0.0/16","2001:db8:1::/48"]`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			condition := json.RawMessage(fmt.Sprintf(`{"NotIpAddress":{"aws:SourceIp":%s},"NotIpAddressIfExists":{"aws:SourceIp":%s}}`, tt.first, tt.second))
			require.Equal(t, tt.bounded, len(ConfiningKeys(condition)) > 0)
		})
	}
}
