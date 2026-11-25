package ciem

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// AWS exceptions form one union inside a statement; separate Deny statements
// remain alternatives. See the IAM NotAction and NotResource element references.
func TestDenyExceptionSets(t *testing.T) {
	const actions = `{"Effect":"Deny","NotAction":["iam:*","sts:*","s3:Get*"],"Resource":"*"}`
	const resources = `{"Effect":"Deny","Action":"iam:PutRolePolicy","NotResource":["arn:aws:iam::1:role/Admin","arn:aws:iam::1:role/Other","arn:aws:iam::1:role/service/*"]}`
	const both = `{"Effect":"Deny","NotAction":["iam:*","sts:*"],"NotResource":["arn:aws:lambda:eu-west-1:1:function:One","arn:aws:lambda:eu-west-1:1:function:Two"]}`
	tests := []struct {
		name, action, scope, deny string
		want                      bool
	}{
		{"first action exception", "iam:PutUserPolicy", "*", actions, true},
		{"second action exception", "sts:AssumeRole", "*", actions, true},
		{"third action exception", "s3:GetObject", "*", actions, true},
		{"outside action exceptions", "lambda:UpdateFunctionCode", "*", actions, false},
		{"action exceptions are case insensitive", "IAM:PutUserPolicy", "*", actions, true},
		{"overlapping action exceptions", "iam:PutUserPolicy", "*", `{"Effect":"Deny","NotAction":["iam:*","iam:Put*","sts:*"],"Resource":"*"}`, true},
		{"first resource exception", "iam:PutRolePolicy", "arn:aws:iam::1:role/Admin", resources, true},
		{"second resource exception", "iam:PutRolePolicy", "arn:aws:iam::1:role/Other", resources, true},
		{"third resource exception", "iam:PutRolePolicy", "arn:aws:iam::1:role/service/Deploy", resources, true},
		{"outside resource exceptions", "iam:PutRolePolicy", "arn:aws:iam::1:role/Outside", resources, false},
		{"resource exceptions are case sensitive", "iam:PutRolePolicy", "arn:aws:iam::1:role/admin", resources, false},
		{"wildcard scope inside exception", "iam:PutRolePolicy", "arn:aws:iam::1:role/service/*", resources, true},
		{"wildcard scope outside exceptions", "iam:PutRolePolicy", "arn:aws:iam::1:role/outside/*", resources, false},
		{"partially excepted wildcard scope", "iam:PutRolePolicy", "arn:aws:iam::1:role/*", resources, true},
		{"variable exception concrete scope", "iam:PutUserPolicy", "arn:aws:iam::1:user/Alice", `{"Effect":"Deny","Action":"iam:PutUserPolicy","NotResource":"arn:aws:iam::1:user/${aws:username}"}`, true},
		{"variable exception wildcard scope", "iam:PutUserPolicy", "arn:aws:iam::1:user/A*", `{"Effect":"Deny","Action":"iam:PutUserPolicy","NotResource":"arn:aws:iam::1:user/${aws:username}"}`, true},
		{"variable allow scope", "iam:PutUserPolicy", "arn:aws:iam::1:user/${aws:username}", `{"Effect":"Deny","Action":"iam:PutUserPolicy","NotResource":"arn:aws:iam::1:user/Alice"}`, true},
		{"literal disjoint user scope", "iam:PutUserPolicy", "arn:aws:iam::1:user/B*", `{"Effect":"Deny","Action":"iam:PutUserPolicy","NotResource":"arn:aws:iam::1:user/Alice"}`, false},
		{"both negations action exception", "iam:PutRolePolicy", "arn:aws:iam::1:role/Outside", both, true},
		{"both negations resource exception", "lambda:UpdateFunctionCode", "arn:aws:lambda:eu-west-1:1:function:Two", both, true},
		{"both negations outside exceptions", "lambda:UpdateFunctionCode", "arn:aws:lambda:eu-west-1:1:function:Outside", both, false},
		{"separate statements still deny", "iam:PutRolePolicy", "*", actions + `,{"Effect":"Deny","NotAction":["s3:*","sts:*"],"Resource":"*"}`, false},
		{"positive action list with resource exceptions", "iam:PutRolePolicy", "arn:aws:iam::1:role/Other", `{"Effect":"Deny","Action":["iam:PutRolePolicy","iam:DeleteRolePolicy"],"NotResource":["arn:aws:iam::1:role/Admin","arn:aws:iam::1:role/Other"]}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":%q,"Resource":%q},%s]}`, tt.action, tt.scope, tt.deny)
			perms := evalPolicies(t, identity(doc))
			require.Equal(t, tt.want, HasPermission(perms, tt.action))
			if tt.want {
				require.Equal(t, []string{tt.scope}, AllowedResourceScopes(perms, tt.action))
			} else {
				require.Empty(t, AllowedResourceScopes(perms, tt.action))
			}
		})
	}
}

func TestDenyExceptionsPreserveEscalationCandidates(t *testing.T) {
	principal := Principal{Provider: "aws", ARN: "arn:aws:iam::1:user/review"}
	tests := []struct{ name, doc, rule string }{
		{"NotAction", `{"Statement":[{"Effect":"Allow","Action":"iam:PutUserPolicy","Resource":"*"},{"Effect":"Deny","NotAction":["iam:*","sts:*"],"Resource":"*"}]}`, "aws-privesc-05"},
		{"NotResource", `{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"arn:aws:iam::1:role/Admin"},{"Effect":"Deny","Action":"iam:PutRolePolicy","NotResource":["arn:aws:iam::1:role/Admin","arn:aws:iam::1:role/Other"]}]}`, "aws-privesc-06"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := evalPolicies(t, identity(tt.doc))
			require.True(t, hasRule(DetectPrivescPaths(principal, perms), tt.rule))
		})
	}
}
