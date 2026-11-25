package ciem

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAWSPrincipalTierRequiresUnrestrictedAuthority(t *testing.T) {
	const full = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	const conditional = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:PrincipalTag/team":"security"}}}]}`
	const denied = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
	tests := []struct {
		name        string
		policies    []Policy
		want        privilegeTier
		approximate bool
	}{
		{"full wildcard", []Policy{identity(full)}, tierAdmin, false},
		{"IAM wildcard", []Policy{identity(`{"Statement":[{"Effect":"Allow","Action":"IAM:*","Resource":"*"}]}`)}, tierNormal, false},
		{"identity deny", []Policy{identity(denied)}, tierNormal, false},
		{"narrow resource deny", []Policy{identity(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:PutRolePolicy","Resource":"arn:aws:iam::1:role/Protected"}]}`)}, tierNormal, false},
		{"other service deny", []Policy{identity(`{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`)}, tierNormal, false},
		{"boundary deny", []Policy{identity(full), {Type: PolicyBoundary, Document: denied}}, tierNormal, false},
		{"SCP deny", []Policy{identity(full), {Type: PolicySCP, Document: denied}}, tierNormal, false},
		{"boundary narrows actions", []Policy{identity(full), {Type: PolicyBoundary, Document: `{"Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":"*"}]}`}}, tierNormal, false},
		{"conditional identity", []Policy{identity(conditional)}, tierNormal, true},
		{"conditional boundary", []Policy{identity(full), {Type: PolicyBoundary, Document: conditional}}, tierNormal, true},
		{"conditional deny retained as uncertainty", []Policy{identity(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalTag/team":"security"}}}]}`)}, tierNormal, true},
		{"unparseable boundary", []Policy{identity(full), {Type: PolicyBoundary, Document: `{broken`}}, tierNormal, true},
		{"unparseable SCP", []Policy{identity(full), {Type: PolicySCP, Document: `{broken`}}, tierNormal, true},
		{"widened NotAction allow", []Policy{identity(`{"Statement":[{"Effect":"Allow","NotAction":["iam:*","sts:*"],"Resource":"*"}]}`)}, tierNormal, true},
		{"widened NotResource allow", []Policy{identity(`{"Statement":[{"Effect":"Allow","Action":"*","NotResource":["arn:aws:iam::1:role/Protected"]}]}`)}, tierNormal, true},
		{"SCP levels cannot prove admin", []Policy{identity(full), {Type: PolicySCP, Document: full}, {Type: PolicySCP, Document: `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`}}, tierNormal, true},
		{"overlapping cap stays approximate", []Policy{identity(`{"Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`), {Type: PolicyBoundary, Document: `{"Statement":[{"Effect":"Allow","Action":"ec2:*Instances","Resource":"*"}]}`}}, tierNormal, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := evalPolicies(t, tt.policies...)
			require.Equal(t, tt.want, principalTier("aws", "", perms))
			for _, p := range perms {
				if p.Effect != EffectDeny {
					require.Equal(t, tt.approximate, p.Approximate)
				}
			}
		})
	}
}

func TestAnalyzeIAMAssets_RestrictedWildcardKeepsLambdaSeverity(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
	perms := evalPolicies(t, identity(doc))
	require.False(t, HasPermission(perms, "iam:PutUserPolicy"))
	require.True(t, HasPermission(perms, "lambda:UpdateFunctionCode"))
	raw, err := json.Marshal([]Policy{identity(doc)})
	require.NoError(t, err)
	principal := asset.Asset{
		ID: "arn:aws:iam::1:user/review", Type: "iam_user", Provider: asset.ProviderAWS, AccountID: "1",
		Metadata: map[string]string{"policies": string(raw)},
	}
	result := AnalyzeIAMAssets(context.Background(), []asset.Asset{principal})
	require.NotEqual(t, TierAdmin, result.Tiers[principal.ID].Tier)
	for _, f := range result.Findings {
		if f.RuleID == "aws-privesc-17" {
			require.Equal(t, SeverityHigh, f.Severity)
			return
		}
	}
	t.Fatal("Lambda code-update candidate was lost")
}
