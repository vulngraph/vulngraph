package ciem

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrust_SpecificDenyKeepsOtherAssumptionMethods(t *testing.T) {
	const principal = "arn:aws:iam::111122223333:user/alice"
	tests := []struct {
		name, allow, deny string
		wantPrincipal     bool
	}{
		{"tagging is independent", `"sts:AssumeRole"`, `"sts:TagSession"`, true},
		{"SAML is independent", `"sts:AssumeRole"`, `"sts:AssumeRoleWithSAML"`, true},
		{"web identity is independent", `"sts:AssumeRole"`, `"sts:AssumeRoleWithWebIdentity"`, true},
		{"same method denied", `"sts:AssumeRole"`, `"sts:AssumeRole"`, false},
		{"wildcard deny", `"sts:AssumeRole"`, `"sts:Assume*"`, false},
		{"case insensitive action", `"STS:ASSUMEROLE"`, `"sts:assumerole"`, false},
		{"SAML cannot preserve a denied IAM user", `["sts:AssumeRole","sts:AssumeRoleWithSAML"]`, `"sts:AssumeRole"`, false},
		{"all methods denied", `["sts:AssumeRole","sts:AssumeRoleWithSAML"]`, `["sts:AssumeRole","sts:AssumeRoleWithSAML"]`, false},
		{"tags alone grant no entry", `"sts:TagSession"`, `"sts:AssumeRole"`, false},
		{"tags do not preserve denied entry", `["sts:AssumeRole","sts:TagSession"]`, `"sts:AssumeRole"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"Statement":[
				{"Effect":"Allow","Principal":{"AWS":%q},"Action":%s},
				{"Effect":"Deny","Principal":{"AWS":%q},"Action":%s}]}`,
				principal, tt.allow, principal, tt.deny)
			eval := EvaluateTrustPolicy(doc)
			if tt.wantPrincipal {
				require.Equal(t, []string{principal}, eval.AWSPrincipals)
			} else {
				require.Empty(t, eval.AWSPrincipals)
			}
		})
	}
}

func TestTrust_MethodDeniesComposeAcrossStatements(t *testing.T) {
	for _, allow := range []string{`"sts:*"`, `["sts:AssumeRole","sts:AssumeRoleWithSAML","sts:AssumeRoleWithWebIdentity"]`} {
		doc := fmt.Sprintf(`{"Statement":[
			{"Effect":"Allow","Principal":"*","Action":%s},
			{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"},
			{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML"},
			{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithWebIdentity"}]}`, allow)
		eval := EvaluateTrustPolicy(doc)
		require.False(t, eval.PublicEntry, allow)
		require.False(t, eval.RequiresMFA, allow)
	}
}

func TestTrust_MFAConditionTruthTable(t *testing.T) {
	// Expected states are derived from AWS's Bool, IfExists and Null rules,
	// including all three request contexts. Long-term keys omit the context key.
	tests := []struct {
		op, value string
		allowed   mfaStates
	}{
		{"Bool", `true`, mfaTrue},
		{"Bool", `false`, mfaFalse},
		{"Bool", `["true","false"]`, mfaTrue | mfaFalse},
		{"BoolIfExists", `"true"`, mfaAbsent | mfaTrue},
		{"BoolIfExists", `"false"`, mfaAbsent | mfaFalse},
		{"BoolIfExists", `[true,false]`, allMFAStates},
		{"Null", `"true"`, mfaAbsent},
		{"Null", `"false"`, mfaFalse | mfaTrue},
		{"Null", `[true,false]`, allMFAStates},
	}
	for _, tt := range tests {
		t.Run(tt.op+tt.value, func(t *testing.T) {
			condition := fmt.Sprintf(`{%q:{"aws:MultiFactorAuthPresent":%s}}`, tt.op, tt.value)
			allow := parseTrustStatements(`{"Statement":{"Condition":` + condition + `}}`)[0]
			require.Equal(t, tt.allowed, allow.possibleMFAStates())
			require.Equal(t, tt.allowed, allow.deniedMFAStates())
		})
	}
}

func TestTrust_MFAEvidenceRequiresEveryNonMFACaseToBeExcluded(t *testing.T) {
	tests := []struct {
		name, allowCondition, denyConditions string
		want                                 bool
	}{
		{"Bool true", `{"Bool":{"aws:MultiFactorAuthPresent":true}}`, ``, true},
		{"BoolIfExists true admits missing", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":true}}`, ``, false},
		{"Bool true or false", `{"Bool":{"aws:MultiFactorAuthPresent":[true,false]}}`, ``, false},
		{"Null false admits present false", `{"Null":{"aws:MultiFactorAuthPresent":false}}`, ``, false},
		{"Null true deny misses present false", `{}`, `{"Null":{"aws:MultiFactorAuthPresent":true}}`, false},
		{"Bool false deny misses absent", `{}`, `{"Bool":{"aws:MultiFactorAuthPresent":false}}`, false},
		{"BoolIfExists false deny covers both", `{}`, `{"BoolIfExists":{"aws:MultiFactorAuthPresent":false}}`, true},
		{"MFA deny scoped to a network", `{}`, `{"BoolIfExists":{"aws:MultiFactorAuthPresent":false},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}`, false},
		{"MFA deny with another Bool key", `{}`, `{"BoolIfExists":{"aws:MultiFactorAuthPresent":false,"aws:SecureTransport":false}}`, false},
		{"allow IfExists plus present requirement", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":true},"Null":{"aws:MultiFactorAuthPresent":false}}`, ``, true},
		{"allow IfExists and deny absent", `{"BoolIfExists":{"aws:MultiFactorAuthPresent":true}}`, `{"Null":{"aws:MultiFactorAuthPresent":true}}`, true},
		{"allow present and deny false", `{"Null":{"aws:MultiFactorAuthPresent":false}}`, `{"Bool":{"aws:MultiFactorAuthPresent":false}}`, true},
		{"unrecognized MFA operator", `{"NumericEquals":{"aws:MultiFactorAuthPresent":1}}`, ``, false},
		{"unrecognized deny operator", `{}`, `{"NumericEquals":{"aws:MultiFactorAuthPresent":0}}`, false},
		{"invalid mixed values earn no credit", `{"Bool":{"aws:MultiFactorAuthPresent":[true,1]}}`, ``, false},
		{"invalid deny values earn no credit", `{}`, `{"BoolIfExists":{"aws:MultiFactorAuthPresent":[false,1]}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statement := `{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole","Condition":` + tt.allowCondition + `}`
			if tt.denyConditions != "" {
				statement += `,{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":` + tt.denyConditions + `}`
			}
			eval := EvaluateTrustPolicy(`{"Statement":[` + statement + `]}`)
			require.Equal(t, tt.want, eval.RequiresMFA)
		})
	}
}

func TestTrust_SeparateDeniesEnforceMFA(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":false}}},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":{"Null":{"aws:MultiFactorAuthPresent":true}}}]}`)
	require.True(t, eval.RequiresMFA)
}

func TestTrust_BlockedPathDoesNotDefeatSurvivingMFA(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":true}}},
		{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"},"Action":"sts:AssumeRoleWithSAML"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML"}]}`)
	require.True(t, eval.RequiresMFA)
	require.Len(t, eval.AWSPrincipals, 1)
}

func TestTrust_DenyConfinementRespectsConditionConjunction(t *testing.T) {
	for name, cond := range map[string]string{
		"other operator":                  `{"StringNotEquals":{"aws:PrincipalOrgID":"o-abc123"},"Bool":{"aws:SecureTransport":false}}`,
		"other key":                       `{"StringNotEquals":{"aws:PrincipalOrgID":"o-abc123","sts:ExternalId":"x"}}`,
		"missing key escapes ForAnyValue": `{"ForAnyValue:StringNotLike":{"aws:PrincipalOrgPaths":"o-abc123/*"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			eval := EvaluateTrustPolicy(`{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":` + cond + `}]}`)
			require.True(t, eval.PublicEntry)
			require.Empty(t, eval.ConfinedBy)
		})
	}
}

func TestTrust_AllowIfExistsDoesNotConfineCaller(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole", "Condition":{"StringEqualsIfExists":{"aws:PrincipalOrgID":"o-abc123"}}}}`)
	require.True(t, eval.PublicEntry)
}
