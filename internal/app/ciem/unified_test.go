package ciem

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func roleAsset(id string, meta map[string]string, policies string) asset.Asset {
	m := map[string]string{"policies": policies}
	for k, v := range meta {
		m[k] = v
	}
	return asset.Asset{ID: id, Name: id, Type: "iam_role", Provider: asset.ProviderAWS, Metadata: m}
}

// The headline correctness fix: an explicit Deny of a specific action must
// suppress the privesc even against an Allow "*" (deny wins, retained not
// pre-subtracted). Previously the wildcard Allow survived and PassRole fired.
func TestAnalyze_ExplicitDenyBeatsWildcardAllow(t *testing.T) {
	policies := `[{"name":"p","type":"identity","document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"},{\"Effect\":\"Deny\",\"Action\":\"iam:PassRole\",\"Resource\":\"*\"}]}"}]`
	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{roleAsset("r1", nil, policies)})

	fired := map[string]bool{}
	for _, f := range res.Findings {
		fired[f.RuleID] = true
	}
	// PassRole-family techniques require iam:PassRole → denied → must NOT fire.
	require.False(t, fired["aws-privesc-10"], "PassRole+lambda must not fire when PassRole is explicitly denied")
	require.False(t, fired["aws-privesc-11"], "PassRole+ec2 must not fire when PassRole is explicitly denied")
	// A technique needing only a non-denied action still fires under Allow "*".
	require.True(t, fired["aws-privesc-01"], "CreatePolicyVersion still fires under Allow *")
}

// A Deny gated by a Condition (e.g. the common "deny everything unless MFA is
// present" guardrail) only blocks when the condition actually holds — treating
// it as unconditional would silently suppress a real privesc path for exactly
// the principals that matter most (those without MFA).
func TestAnalyze_ConditionalDenyDoesNotSuppressPrivesc(t *testing.T) {
	policies := `[{"name":"p","type":"identity","document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"},{\"Effect\":\"Deny\",\"Action\":\"iam:PassRole\",\"Resource\":\"*\",\"Condition\":{\"BoolIfExists\":{\"aws:MultiFactorAuthPresent\":\"false\"}}}]}"}]`
	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{roleAsset("r1", nil, policies)})

	fired := map[string]bool{}
	for _, f := range res.Findings {
		fired[f.RuleID] = true
	}
	require.True(t, fired["aws-privesc-10"], "a conditional (MFA-gated) Deny must not suppress a PassRole-family privesc path")
}

// Azure principals produce findings.
func TestAnalyze_AzureProducesFindings(t *testing.T) {
	sp := asset.Asset{
		ID: "sp1", Name: "sp1", Type: "azure_service_principal", Provider: asset.ProviderAzure,
		Metadata: map[string]string{"permissions": "Microsoft.Authorization/roleAssignments/write"},
	}
	res := AnalyzeIAMAssets(context.Background(), []asset.Asset{sp})
	require.NotEmpty(t, res.Findings, "azure role-assignment write must yield a privesc finding")
	require.Equal(t, "sp1", res.Findings[0].PrincipalID)
	require.Equal(t, "azure_service_principal", res.Findings[0].PrincipalType)
}

// Finding severity is capped by inbound assumability: a critical technique on an
// Okta-federated role is demoted to medium; the same on a wildcard-assumable role
// stays critical.
func TestAnalyze_FindingSeverityCappedByTrustEntry(t *testing.T) {
	// aws-privesc-01 (CreatePolicyVersion) is Critical.
	adminPolicy := `[{"name":"p","type":"identity","document":"{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"iam:CreatePolicyVersion\",\"Resource\":\"*\"}]}"}]`

	fed := AnalyzeIAMAssets(context.Background(), []asset.Asset{
		roleAsset("fed", map[string]string{"trust_entry": "federated"}, adminPolicy),
	})
	require.Equal(t, SeverityMedium, findSeverity(fed.Findings, "aws-privesc-01"), "federated entry caps critical at medium")

	open := AnalyzeIAMAssets(context.Background(), []asset.Asset{
		roleAsset("open", map[string]string{"trust_entry": "public"}, adminPolicy),
	})
	require.Equal(t, SeverityCritical, findSeverity(open.Findings, "aws-privesc-01"), "public entry keeps critical")
}

func findSeverity(fs []PrivescFinding, ruleID string) string {
	for _, f := range fs {
		if f.RuleID == ruleID {
			return f.Severity
		}
	}
	return ""
}
