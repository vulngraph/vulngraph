package aws

import (
	"context"
	"net/url"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"
)

type semanticsTrustIAM struct {
	fakeIAM
	trust string
}

func (c semanticsTrustIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: awssdk.String("target"), Arn: awssdk.String("arn:aws:iam::1:role/target"),
		Path: awssdk.String("/"), AssumeRolePolicyDocument: awssdk.String(url.QueryEscape(c.trust)),
	}}}, nil
}

func TestCollectRoles_TrustConditionSemantics(t *testing.T) {
	tests := []struct {
		name, statements, mfa, public string
	}{
		{
			"Allow BoolIfExists permits absent MFA",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:user/alice"},"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":true}}}`,
			"false", "false",
		},
		{
			"Deny Null true permits present false MFA",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:user/alice"}},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*","Condition":{"Null":{"aws:MultiFactorAuthPresent":true}}}`,
			"false", "false",
		},
		{
			"Allow Bool true requires MFA",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:user/alice"},"Condition":{"Bool":{"aws:MultiFactorAuthPresent":true}}}`,
			"true", "false",
		},
		{
			"bare organization denial confines wildcard",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*","Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-abc123"}}}`,
			"false", "false",
		},
		{
			"named deny requires MFA for sole principal",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:user/alice"}},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:user/alice"},"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":false}}}`,
			"true", "false",
		},
		{
			"named deny leaves second principal ungated",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":["arn:aws:iam::1:user/alice","arn:aws:iam::1:user/bob"]}},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::1:user/alice"},"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":false}}}`,
			"false", "false",
		},
		{
			"self account variable does not confine",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*","Condition":{"StringNotEquals":{"aws:PrincipalAccount":"${aws:PrincipalAccount}"}}}`,
			"false", "true",
		},
		{
			"ARN equality with wildcard account does not confine",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*","Condition":{"ArnNotEquals":{"aws:PrincipalArn":"arn:aws:iam::*:role/deploy"}}}`,
			"false", "true",
		},
		{
			"complementary network exemptions do not confine",
			`{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"},
			 {"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["0.0.0.0/1","::/1"]},"NotIpAddressIfExists":{"aws:SourceIp":["128.0.0.0/1","8000::/1"]}}}`,
			"false", "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := semanticsTrustIAM{trust: `{"Version":"2012-10-17","Statement":[` + tt.statements + `]}`}
			assets, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
			require.NoError(t, err)
			for _, a := range assets {
				if a.Type == "iam_role" {
					require.Equal(t, tt.mfa, a.Metadata["mfa_required_to_assume"])
					require.Equal(t, tt.public, a.Metadata["public_trust"])
					return
				}
			}
			t.Fatal("collected role missing")
		})
	}
}
