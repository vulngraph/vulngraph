package correlate

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// roleWithStatements builds an iam_role with one identity policy holding the
// given statements.
func roleWithStatements(id string, stmts ...map[string]any) asset.Asset {
	doc, _ := json.Marshal(map[string]any{"Statement": stmts})
	pols, _ := json.Marshal([]map[string]string{{"type": "identity", "document": string(doc)}})
	return asset.Asset{ID: id, Type: "iam_role", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"policies": string(pols)}}
}

func ssmParam(id string) asset.Asset {
	return asset.Asset{ID: id, Type: "ssm_parameter", Provider: asset.ProviderAWS}
}

func TestSecretAccess_IAMEvaluation(t *testing.T) {
	const (
		secA  = "arn:aws:secretsmanager:us-east-1:1:secret:app-a"
		secB  = "arn:aws:secretsmanager:us-east-1:1:secret:prod-b"
		param = "arn:aws:ssm:us-east-1:1:parameter/app/db"
	)
	allow := func(action, resource any) map[string]any {
		return map[string]any{"Effect": "Allow", "Action": action, "Resource": resource}
	}
	deny := func(action, resource any) map[string]any {
		return map[string]any{"Effect": "Deny", "Action": action, "Resource": resource}
	}
	cases := []struct {
		name  string
		stmts []map[string]any
		want  []string // destination IDs
	}{
		{"Allow * with Deny secretsmanager:* reads no secret, only SSM",
			[]map[string]any{allow("*", "*"), deny("secretsmanager:*", "*")},
			[]string{secretWildcardID}},
		{"resource-scoped Deny carves the wildcard into per-secret edges",
			[]map[string]any{allow("secretsmanager:GetSecretValue", "*"), deny("secretsmanager:*", "arn:aws:secretsmanager:*:*:secret:prod-*")},
			[]string{secA}},
		{"action glob GetParameter*",
			[]map[string]any{allow("ssm:GetParameter*", param)},
			[]string{param}},
		{"action glob Get* on a service",
			[]map[string]any{allow("secretsmanager:Get*", secB)},
			[]string{secB}},
		{"mid-ARN resource wildcard",
			[]map[string]any{allow("secretsmanager:GetSecretValue", "arn:aws:secretsmanager:*:1:secret:app-*")},
			[]string{secA}},
		{"NotAction grant covers secret reads",
			[]map[string]any{{"Effect": "Allow", "NotAction": "iam:*", "Resource": secA}},
			[]string{secA}},
		{"Deny NotAction leaves only the excepted service",
			[]map[string]any{allow("*", secA), allow("*", param), {"Effect": "Deny", "NotAction": "ssm:*", "Resource": "*"}},
			[]string{param}},
		{"unrelated action grants nothing",
			[]map[string]any{allow("secretsmanager:ListSecrets", "*")},
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGraph([]asset.Asset{
				roleWithStatements("arn:aws:iam::1:role/r", tc.stmts...),
				smSecret(secA), smSecret(secB), ssmParam(param),
			})
			var got []string
			for _, e := range (SecretAccess{}).Correlate(g) {
				got = append(got, e.DstID)
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			require.Equal(t, want, got)
		})
	}
}

func TestDangerousActionsInPolicy_WildcardWithDenyIsNotAdmin(t *testing.T) {
	role := roleWithStatements("arn:aws:iam::1:role/r",
		map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*"},
		map[string]any{"Effect": "Deny", "Action": "secretsmanager:*", "Resource": "*"},
	)
	perms := secretPermsForRole(role, nil)
	doc := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

	found := dangerousActionsInPolicy(doc, perms)
	require.False(t, found["admin-wildcard"], "a carved-up * is not unrestricted admin")
	require.False(t, found["secrets"], "the denied service is not reported")
	require.True(t, found["iam-admin"], "surviving dangerous actions are still reported")
}

func TestDangerousActionsInPolicy_MidActionGlob(t *testing.T) {
	role := roleWithStatements("arn:aws:iam::1:role/r",
		map[string]any{"Effect": "Allow", "Action": "iam:Put*Policy", "Resource": "*"})
	perms := secretPermsForRole(role, nil)
	found := dangerousActionsInPolicy(`{"Statement":[{"Effect":"Allow","Action":"iam:Put*Policy","Resource":"*"}]}`, perms)
	require.True(t, found["iam-admin"])
}
