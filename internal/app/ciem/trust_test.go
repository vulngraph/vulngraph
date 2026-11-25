package ciem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const selfAccount = "111122223333"

// The dominant real-world hardening idiom: allow anyone, then deny anyone outside
// the organization. Read Allow-only this graded as a PUBLIC trust — "anyone on the
// internet can assume this role" — which fired a critical CSPM finding, added +15
// enrich points with a pipeline floor, and left the privesc score uncapped.
func TestTrust_OrgConfinedWildcardIsNotPublic(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
		 "Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-abc123"}}}]}`)

	require.False(t, eval.PublicEntry, "a Deny confines entry to the organization")
	require.True(t, eval.HasWildcard, "the wildcard Allow is still recorded as evidence")
	require.Equal(t, []string{"aws:PrincipalOrgID"}, eval.ConfinedBy)
	require.Equal(t, TrustEntryCrossAcct, eval.EntryClass(selfAccount),
		"organization-confined entry is cross-account, not public")
}

// A negated comparison also matches an absent key: callers from standalone
// accounts are denied even though they carry no aws:PrincipalOrgID.
func TestTrust_BareNegatedOperatorConfines(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
		 "Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`)

	require.False(t, eval.PublicEntry)
	require.Equal(t, []string{"aws:PrincipalOrgID"}, eval.ConfinedBy)
	require.Equal(t, TrustEntryCrossAcct, eval.EntryClass(selfAccount))
}

// A Deny that reaches only a different assumption method cannot confine this one.
// The trust evaluator originally never parsed Action at all, so any well-formed
// guardrail aimed at one STS method silenced findings on every other.
func TestTrust_DenyOnAnotherActionDoesNotConfine(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML",
		 "Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-abc123"}}}]}`)

	require.True(t, eval.PublicEntry, "the SAML Deny says nothing about sts:AssumeRole")
	require.Empty(t, eval.ConfinedBy)
}

// Same structural bug, MFA variant: a Deny scoped to a different method must not
// be credited as enforcing MFA on this one.
func TestTrust_DenyOnAnotherActionDoesNotEnforceMFA(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML",
		 "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`)

	require.False(t, eval.RequiresMFA)
}

// An unrecognised Federated provider is not a vetted compensating control, so it
// must not earn the federated class (which caps severity at medium).
func TestTrust_UnrecognisedFederationDoesNotEarnCap(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"Federated":"https://attacker.example.net"},
		 "Action":"sts:AssumeRoleWithWebIdentity"}]}`)

	require.True(t, eval.HasFederated, "it is federated in fact")
	require.Equal(t, "", eval.FederationKind, "but the provider shape is unrecognised")
	require.Equal(t, "", eval.EntryClass(selfAccount), "so no severity cap is granted")
}

// A genuinely public trust must still be caught — this is the finding that
// matters and it must not be weakened by the fix above.
func TestTrust_UnconfinedWildcardIsPublic(t *testing.T) {
	for _, doc := range []string{
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`,
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"sts:AssumeRole"}}`,
	} {
		eval := EvaluateTrustPolicy(doc)
		require.True(t, eval.PublicEntry, doc)
		require.Equal(t, TrustEntryPublic, eval.EntryClass(selfAccount), doc)
	}
}

// A Deny that merely EXCLUDES a set (positive match) does not confine the trust —
// everyone else can still assume it, so it stays public.
func TestTrust_ExcludingDenyDoesNotMakeWildcardSafe(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
		 "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-known-bad"}}}]}`)

	require.True(t, eval.PublicEntry,
		"denying one org still leaves the rest of the internet able to assume")
}

// MFA enforced by a Deny guardrail rather than a Condition on the Allow. This is
// how it is written in practice — an unconditional Allow composes better with a
// blanket Deny — and inspecting Allow conditions alone missed it entirely,
// discarding a compensating control that hard-suppresses the finding in enrich.
func TestTrust_MFAEnforcedByDeny(t *testing.T) {
	for name, cond := range map[string]string{
		"BoolIfExists false": `{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}`,
		"native JSON bool":   `{"BoolIfExists":{"aws:MultiFactorAuthPresent":false}}`,
	} {
		t.Run(name, func(t *testing.T) {
			eval := EvaluateTrustPolicy(`{"Statement":[
				{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":` + cond + `}]}`)
			require.True(t, eval.RequiresMFA)
		})
	}
}

// Deny Bool:false blocks present-false but misses the absent key carried by
// long-term access credentials, so it does not establish universal MFA.
func TestTrust_BareBoolDoesNotEnforceMFA(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
		 "Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`)

	require.False(t, eval.RequiresMFA)
	require.True(t, eval.PublicEntry, "and it remains a genuinely public trust")
}

// The pre-existing form — MFA required by a Condition on every Allow — must keep
// working.
func TestTrust_MFAEnforcedByAllowCondition(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole",
		 "Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	require.True(t, eval.RequiresMFA)
}

// One unguarded Allow means MFA is not actually required.
func TestTrust_PartialMFAIsNotMFARequired(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole",
		 "Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:root"},"Action":"sts:AssumeRole"}]}`)
	require.False(t, eval.RequiresMFA)
}

// A Deny naming one specific principal removes exactly that principal from the
// assumable set — it must not blank the whole set, and it must not be ignored
// (which would leave a phantom can_assume graph edge and a phantom attack path).
func TestTrust_SpecificDenyRemovesOnlyThatPrincipal(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":[
			"arn:aws:iam::111122223333:role/allowed",
			"arn:aws:iam::111122223333:role/revoked"]},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:role/revoked"},
		 "Action":"sts:AssumeRole"}]}`)

	require.Equal(t, []string{"arn:aws:iam::111122223333:role/allowed"}, eval.AWSPrincipals)
	require.Equal(t, TrustEntrySameAcct, eval.EntryClass(selfAccount))
}

// An unconditional global Deny blocks assumption outright: no entry path survives.
func TestTrust_UnconditionalGlobalDenyBlocksAllEntry(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`)

	require.False(t, eval.PublicEntry)
	require.Empty(t, eval.AWSPrincipals)
	require.False(t, eval.RequiresMFA, "nothing can assume at all")
}

// Federation and service classification, and the rule that service principals are
// neutral — they never make a role human-reachable.
func TestTrust_FederationAndServiceClassification(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"},
		 "Action":"sts:AssumeRoleWithSAML"},
		{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)

	require.True(t, eval.HasFederated)
	require.True(t, eval.HasService)
	require.Equal(t, "saml", eval.FederationKind)
	require.Equal(t, TrustEntryFederated, eval.EntryClass(selfAccount),
		"federated + services is still federated-only entry")

	oidc := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com"},
		 "Action":"sts:AssumeRoleWithWebIdentity"}]}`)
	require.Equal(t, "oidc", oidc.FederationKind)

	svc := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	require.Equal(t, TrustEntryServiceOnly, svc.EntryClass(selfAccount))
}

// Cross-account vs same-account entry.
func TestTrust_CrossAccountClassification(t *testing.T) {
	cross := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999988887777:role/partner"},
		 "Action":"sts:AssumeRole"}]}`)
	require.Equal(t, TrustEntryCrossAcct, cross.EntryClass(selfAccount))

	same := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:role/ci"},
		 "Action":"sts:AssumeRole"}]}`)
	require.Equal(t, TrustEntrySameAcct, same.EntryClass(selfAccount))
}

// Mixed federated + direct AWS entry is the worst of both.
func TestTrust_MixedClassification(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{
			"Federated":"arn:aws:iam::1:saml-provider/Okta",
			"AWS":"arn:aws:iam::111122223333:role/ci"},"Action":["sts:AssumeRole","sts:AssumeRoleWithSAML"]}]}`)
	require.Equal(t, TrustEntryMixed, eval.EntryClass(selfAccount))
}

// A trust policy with no Allow at all grants no entry, and a Deny-only document
// must not be read as granting anything.
func TestTrust_NoAllowMeansNoEntry(t *testing.T) {
	require.Equal(t, TrustEvaluation{}, EvaluateTrustPolicy(
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`))
	require.Equal(t, TrustEvaluation{}, EvaluateTrustPolicy(""))
	require.Equal(t, "", EvaluateTrustPolicy("").EntryClass(selfAccount))
}

// URL-encoded documents (the shape several IAM APIs return) parse.
func TestTrust_URLEncodedDocument(t *testing.T) {
	eval := EvaluateTrustPolicy(
		`%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%22*%22%7D%5D%7D`)
	require.True(t, eval.PublicEntry)
}

// A Condition on a wildcard Allow keeps the trust from being public only when
// it pins WHO the caller is (awspolicy.RestrictsCaller, the classifier the
// resource-policy grade uses). A TLS-only or MFA-only gate admits a caller
// from any account, so the trust stays public and the Critical public-trust
// check sees it.
func TestTrust_AllowConditionNarrowsOnlyWhenItPinsTheCaller(t *testing.T) {
	tests := []struct {
		name       string
		condition  string
		wantPublic bool
	}{
		{"SecureTransport only", `{"Bool":{"aws:SecureTransport":"true"}}`, true},
		// Anyone with MFA is still anyone: an attacker's own user can have MFA.
		{"MFA only", `{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`, true},
		{"source IP is the whole internet", `{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`, true},
		{"source IP split across the internet", `{"IpAddress":{"aws:SourceIp":["0.0.0.0/1","128.0.0.0/1"]}}`, true},
		// sts:ExternalId is a shared string AWS documents as not a secret; with a
		// wildcard Principal it admits any account that learns it. It guards a
		// confused deputy only when the Principal names the trusted account.
		{"ExternalId only", `{"StringEquals":{"sts:ExternalId":"x"}}`, true},
		{"principal tag the caller sets", `{"StringEquals":{"aws:PrincipalTag/team":"platform"}}`, true},
		{"negated org operator admits everyone outside", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, true},
		{"IfExists org operator admits a caller with no org", `{"StringEqualsIfExists":{"aws:PrincipalOrgID":"o-abc123"}}`, true},
		{"wildcard PrincipalArn pattern", `{"ArnLike":{"aws:PrincipalArn":"*"}}`, true},
		{"empty condition block", `{}`, true},
		{"PrincipalOrgID", `{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, false},
		{"SourceAccount", `{"StringEquals":{"aws:SourceAccount":"999988887777"}}`, false},
		{"PrincipalAccount", `{"StringEquals":{"aws:PrincipalAccount":"999988887777"}}`, false},
		{"corporate source range", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`, false},
		{"org beside TLS", `{"Bool":{"aws:SecureTransport":"true"},"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, false},
		{"ForAnyValue org paths", `{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"o-abc123/r-ab12/*"}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := EvaluateTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
				"Action":"sts:AssumeRole","Condition":` + tt.condition + `}]}`)
			require.True(t, eval.HasWildcard)
			require.Equal(t, tt.wantPublic, eval.PublicEntry)
			want := TrustEntryCrossAcct
			if tt.wantPublic {
				want = TrustEntryPublic
			}
			require.Equal(t, want, eval.EntryClass(selfAccount))
		})
	}
}

// MFA on a path any account may take is not a compensating control, so it
// must not set RequiresMFA, which caps the privesc score and suppresses the
// finding in enrich.
func TestTrust_MFAOnPublicPathIsNotAControl(t *testing.T) {
	allowMFA := EvaluateTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},
		"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	require.True(t, allowMFA.PublicEntry)
	require.False(t, allowMFA.RequiresMFA)

	denyMFA := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
		 "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`)
	require.True(t, denyMFA.PublicEntry)
	require.False(t, denyMFA.RequiresMFA)

	confined := EvaluateTrustPolicy(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole",
		"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"},"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`)
	require.False(t, confined.PublicEntry)
	require.True(t, confined.RequiresMFA, "MFA is a real control once the entry set is bounded")
}

// A Deny confines a wildcard Allow only on a key that pins the caller, judged
// by the same classifier as an Allow condition.
func TestTrust_DenyConfinesOnlyOnCallerPinningKeys(t *testing.T) {
	tests := []struct {
		name         string
		condition    string
		wantConfined []string
	}{
		{"org", `{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-abc123"}}`, []string{"aws:PrincipalOrgID"}},
		{"source network", `{"NotIpAddressIfExists":{"aws:SourceIp":"203.0.113.0/24"}}`, []string{"aws:SourceIp"}},
		{"ExternalId the caller presents", `{"StringNotEqualsIfExists":{"sts:ExternalId":"x"}}`, nil},
		{"principal tag the caller sets", `{"StringNotEqualsIfExists":{"aws:PrincipalTag/team":"platform"}}`, nil},
		{"any org at all", `{"StringNotLikeIfExists":{"aws:PrincipalOrgID":"*"}}`, nil},
		{"source anywhere", `{"NotIpAddressIfExists":{"aws:SourceIp":"0.0.0.0/0"}}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eval := EvaluateTrustPolicy(`{"Statement":[
				{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":` + tt.condition + `}]}`)
			require.Equal(t, tt.wantConfined, eval.ConfinedBy)
			require.Equal(t, tt.wantConfined == nil, eval.PublicEntry)
		})
	}
}

// Federated trust is classified by its provider, never by the wildcard rule:
// the aud/sub conditions an OIDC or SAML trust carries are not caller-pinning
// keys, and must not make the role read as public or lose its federated class.
func TestTrust_FederatedConditionsStayFederated(t *testing.T) {
	for name, doc := range map[string]string{
		"GitHub OIDC aud and sub": `{"Statement":[{"Effect":"Allow",
			"Principal":{"Federated":"arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
			"Action":"sts:AssumeRoleWithWebIdentity","Condition":{
				"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"},
				"StringLike":{"token.actions.githubusercontent.com:sub":"repo:example/app:*"}}}]}`,
		"SAML aud": `{"Statement":[{"Effect":"Allow",
			"Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"},
			"Action":"sts:AssumeRoleWithSAML","Condition":{
				"StringEquals":{"SAML:aud":"https://signin.aws.amazon.com/saml"}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			eval := EvaluateTrustPolicy(doc)
			require.False(t, eval.HasWildcard)
			require.False(t, eval.PublicEntry)
			require.Equal(t, TrustEntryFederated, eval.EntryClass(selfAccount))
		})
	}
}
