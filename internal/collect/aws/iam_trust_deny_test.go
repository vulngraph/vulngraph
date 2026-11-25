package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The four trust-policy signals the collector writes to asset metadata all now
// route through the shared deny-aware evaluator. These pin the behaviour at the
// collector boundary, because it is the metadata — not the evaluator's return
// value — that reaches the CSPM check, the enrich score/suppression, must-fix
// demotion, the graph node column and the assistant's prompt.

const orgConfinedTrust = `{"Statement":[
	{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"},
	{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
	 "Condition":{"StringNotEqualsIfExists":{"aws:PrincipalOrgID":"o-abc123"}}}]}`

const mfaEnforcedByDenyTrust = `{"Statement":[
	{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"},
	{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",
	 "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`

// An organization-confined wildcard trust is not a public trust. Graded public it
// fired a critical "account-takeover" CSPM finding and left the privesc score
// uncapped.
func TestTrustSignals_OrgConfinedWildcardNotPublic(t *testing.T) {
	require.False(t, trustHasWildcardPrincipal(orgConfinedTrust))

	class, _ := trustEntryClass(orgConfinedTrust, "111122223333")
	require.Equal(t, trustEntryCrossAcct, class,
		"entry is confined to the organization, not open to anyone")
}

// A genuinely public trust must still be flagged.
func TestTrustSignals_UnconfinedWildcardStillPublic(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`
	require.True(t, trustHasWildcardPrincipal(doc))

	class, _ := trustEntryClass(doc, "111122223333")
	require.Equal(t, trustEntryPublic, class)
}

// MFA enforced by a Deny guardrail is the dominant real idiom and was previously
// invisible, discarding a compensating control that hard-suppresses the finding.
func TestTrustSignals_MFAEnforcedByDenyIsDetected(t *testing.T) {
	require.True(t, trustRequiresMFA(mfaEnforcedByDenyTrust))
}

// A revoked principal must not appear in trust_principals — that list becomes
// can_assume graph edges and narrative evidence.
func TestTrustSignals_DeniedPrincipalExcludedFromEntryList(t *testing.T) {
	doc := `{"Statement":[
		{"Effect":"Allow","Principal":{"AWS":[
			"arn:aws:iam::111122223333:role/allowed",
			"arn:aws:iam::111122223333:role/revoked"]},"Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::111122223333:role/revoked"},
		 "Action":"sts:AssumeRole"}]}`

	class, principals := trustEntryClass(doc, "111122223333")
	require.Equal(t, trustEntrySameAcct, class)
	require.Equal(t, []string{"arn:aws:iam::111122223333:role/allowed"}, principals)
}
