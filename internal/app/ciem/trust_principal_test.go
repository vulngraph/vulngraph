package ciem

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrust_PrincipalsUseTheirOwnAssumptionMethod(t *testing.T) {
	const alice = "arn:aws:iam::111122223333:user/alice"
	const saml = "arn:aws:iam::111122223333:saml-provider/Okta"
	const oidc = "arn:aws:iam::111122223333:oidc-provider/accounts.google.com"
	for _, principal := range []struct {
		kind, value, method string
	}{
		{"AWS", alice, "sts:AssumeRole"},
		{"Service", "ec2.amazonaws.com", "sts:AssumeRole"},
		{"Federated", saml, "sts:AssumeRoleWithSAML"},
		{"Federated", oidc, "sts:AssumeRoleWithWebIdentity"},
	} {
		for _, method := range []string{"sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"} {
			t.Run(principal.value+"/"+method, func(t *testing.T) {
				doc := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Principal":{%q:%q},"Action":%q}}`, principal.kind, principal.value, method)
				eval := EvaluateTrustPolicy(doc)
				if method != principal.method {
					require.Equal(t, TrustEvaluation{}, eval)
					return
				}
				require.NotEmpty(t, eval.EntryClass(selfAccount))
			})
		}
	}
}

func TestTrust_MixedPrincipalDenyOnlyRemovesMatchingPath(t *testing.T) {
	const alice = "arn:aws:iam::111122223333:user/alice"
	const saml = "arn:aws:iam::111122223333:saml-provider/Okta"
	const oidc = "arn:aws:iam::111122223333:oidc-provider/accounts.google.com"
	tests := []struct {
		name, denyPrincipal, denyAction, federationKind string
		aws, service                                    bool
	}{
		{"named AWS", `{"AWS":"` + alice + `"}`, "sts:AssumeRole", "saml", false, true},
		{"named SAML", `{"Federated":"` + saml + `"}`, "sts:AssumeRoleWithSAML", "oidc", true, true},
		{"named OIDC", `{"Federated":"` + oidc + `"}`, "sts:AssumeRoleWithWebIdentity", "saml", true, true},
		{"named service", `{"Service":"ec2.amazonaws.com"}`, "sts:AssumeRole", "saml", true, false},
		{"global AssumeRole", `"*"`, "sts:AssumeRole", "saml", false, false},
		{"wrong method", `{"Federated":"` + saml + `"}`, "sts:AssumeRole", "saml", true, true},
		{"wrong principal kind", `{"AWS":"` + saml + `"}`, "sts:AssumeRoleWithSAML", "saml", true, true},
		{"unrelated service", `{"Service":"lambda.amazonaws.com"}`, "sts:AssumeRole", "saml", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"Statement":[
				{"Effect":"Allow","Principal":{"AWS":%q,"Federated":[%q,%q],"Service":"ec2.amazonaws.com"},"Action":"sts:*"},
				{"Effect":"Deny","Principal":%s,"Action":%q}]}`, alice, saml, oidc, tt.denyPrincipal, tt.denyAction)
			eval := EvaluateTrustPolicy(doc)
			require.Equal(t, tt.aws, len(eval.AWSPrincipals) > 0)
			require.Equal(t, tt.service, eval.HasService)
			require.True(t, eval.HasFederated)
			require.Equal(t, tt.federationKind, eval.FederationKind)
		})
	}
}

func TestTrust_NamedDenyEnforcesMFAOnlyForItsPrincipal(t *testing.T) {
	const alice = "arn:aws:iam::111122223333:user/alice"
	const bob = "arn:aws:iam::111122223333:user/bob"
	for _, tt := range []struct {
		name, allowed, denied, action string
		wantMFA                       bool
	}{
		{"one principal", `"` + alice + `"`, `"` + alice + `"`, "sts:AssumeRole", true},
		{"array of one principal", `["` + alice + `"]`, `["` + alice + `"]`, "sts:AssumeRole", true},
		{"another principal ungated", `["` + alice + `","` + bob + `"]`, `"` + alice + `"`, "sts:AssumeRole", false},
		{"both principals gated", `["` + alice + `","` + bob + `"]`, `["` + alice + `","` + bob + `"]`, "sts:AssumeRole", true},
		{"deny names another principal", `"` + alice + `"`, `"` + bob + `"`, "sts:AssumeRole", false},
		{"deny names another action", `"` + alice + `"`, `"` + alice + `"`, "sts:TagSession", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			doc := fmt.Sprintf(`{"Statement":[
				{"Effect":"Allow","Principal":{"AWS":%s},"Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":{"AWS":%s},"Action":%q,"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":false}}}]}`, tt.allowed, tt.denied, tt.action)
			eval := EvaluateTrustPolicy(doc)
			require.Equal(t, tt.wantMFA, eval.RequiresMFA)
			require.NotEmpty(t, eval.AWSPrincipals)
		})
	}
}

func TestTrust_NamedDeniesRemoveFederatedAndServiceEntries(t *testing.T) {
	for _, principal := range []string{
		`{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"}`,
		`{"Federated":"arn:aws:iam::111122223333:oidc-provider/accounts.google.com"}`,
		`{"Service":"ec2.amazonaws.com"}`,
	} {
		doc := fmt.Sprintf(`{"Statement":[
			{"Effect":"Allow","Principal":%s,"Action":"sts:*"},
			{"Effect":"Deny","Principal":%s,"Action":"sts:*"}]}`, principal, principal)
		require.Equal(t, TrustEvaluation{}, EvaluateTrustPolicy(doc), principal)
	}
}

func TestTrust_BlockedWildcardDoesNotClassifySurvivingEntry(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRoleWithSAML"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML"},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/alice"},"Action":"sts:AssumeRole"}]}`)
	require.False(t, eval.HasWildcard)
	require.Equal(t, TrustEntrySameAcct, eval.EntryClass(selfAccount))
}
