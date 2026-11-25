package ciem

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAWSOrganizationEvidenceFreshnessAndMembership(t *testing.T) {
	now := time.Now()
	base := AWSOrganizationEvidence{AccountID: "111", Applicability: "exempt", Reason: "standalone", Complete: true, ObservedAt: now}
	for _, tc := range []struct {
		name       string
		age        time.Duration
		absent     bool
		membership *AWSOrganizationEvidence
		known      bool
	}{
		{name: "fresh", known: true},
		{name: "one missed schedule within window", age: 23 * time.Hour, known: true},
		{name: "expired", age: 25 * time.Hour},
		{name: "missing timestamp", absent: true},
		{name: "future timestamp", age: -time.Hour},
		{name: "joined org immediately invalidates standalone", membership: &AWSOrganizationEvidence{AccountID: "111", ManagementAccountID: "999", ObservedAt: now}},
		{name: "fresh standalone witness", membership: &base, known: true},
		{name: "stale membership", membership: &AWSOrganizationEvidence{AccountID: "111", Reason: "standalone", ObservedAt: now.Add(-48 * time.Hour)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evidence := base
			evidence.ObservedAt = now.Add(-tc.age)
			if tc.absent {
				evidence.ObservedAt = time.Time{}
			}
			raw, err := json.Marshal(evidence)
			require.NoError(t, err)
			principal := asset.Asset{AccountID: "111", Metadata: map[string]string{}}
			if tc.membership != nil {
				encoded, err := json.Marshal(tc.membership)
				require.NoError(t, err)
				principal.Metadata[MetaAWSOrganizationMembership] = string(encoded)
			}
			policies, known := awsOrganizationPoliciesAt(principal, []Policy{{Type: PolicyAWSOrganization, Document: string(raw)}}, now)
			require.Equal(t, tc.known, known)
			permissions := evalPolicies(t, append([]Policy{identity(orgFullDocument)}, policies...)...)
			require.True(t, HasPermission(permissions, "lambda:UpdateFunctionCode"))
			require.Equal(t, tc.known, awsPrincipalTier(permissions) == tierAdmin)
		})
	}
}

func TestAWSCeilingAndConditionalGrantsDoNotProveAdminReach(t *testing.T) {
	const iamOnly = `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`
	for _, tc := range []struct {
		name, identityDoc, boundary string
		scp                         bool
		tier                        string
		rule                        string
	}{
		{"IAM-only SCP", orgFullDocument, "", true, TierHigh, "aws-privesc-01"},
		{"IAM-only boundary", orgFullDocument, iamOnly, false, TierHigh, "aws-privesc-01"},
		{"conditional policy write", `{"Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*","Condition":{"ArnEquals":{"iam:PolicyARN":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}}]}`, "", false, TierHigh, "aws-privesc-03"},
		{"unrestricted self grant", `{"Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}`, "", false, TierCanEscalateToAdmin, "aws-privesc-03"},
		{"full grant control", orgFullDocument, "", false, TierAdmin, "aws-privesc-17"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := []Policy{identity(tc.identityDoc)}
			if tc.boundary != "" {
				policies = append(policies, Policy{Type: PolicyBoundary, Document: tc.boundary})
			}
			raw, err := json.Marshal(policies)
			require.NoError(t, err)
			principal := asset.Asset{ID: "arn:aws:iam::111:user/operator", Type: "iam_user", Provider: asset.ProviderAWS, AccountID: "111", Metadata: map[string]string{"policies": string(raw), "permission_boundary_complete": "true"}}
			evidence := AWSOrganizationEvidence{AccountID: "111", Applicability: "exempt", Reason: "standalone", Complete: true}
			if tc.scp {
				evidence = orgMember(orgLevel("111", "r-root", iamOnly), orgLevel("r-root", "", orgFullDocument))
			}
			result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal, orgAsset(t, evidence)})
			require.Equal(t, tc.tier, result.Tiers[principal.ID].Tier)
			for _, finding := range result.Findings {
				if finding.RuleID == tc.rule {
					if tc.tier != TierAdmin {
						require.NotEqual(t, SeverityLow, finding.Severity)
					}
					return
				}
			}
			t.Fatal("required candidate was lost")
		})
	}
}

func TestCapIntersectionUnresolvedResourcesRemainCandidates(t *testing.T) {
	const action = "iam:CreateAccessKey"
	const alice = "arn:aws:iam::111:user/Alice"
	for _, typ := range []string{PolicyBoundary, PolicySCP} {
		for _, tc := range []struct {
			name, identityResource, capResource string
			present, approximate                bool
		}{
			{"identity variable", "arn:aws:iam::111:user/${aws:username}", alice, true, true},
			{"cap variable", alice, "arn:aws:iam::111:user/${aws:username}", true, true},
			{"both variable", "arn:aws:iam::111:user/${aws:username}", "arn:aws:iam::111:user/${aws:PrincipalTag/name}", true, true},
			{"concrete control", alice, alice, true, false},
			{"concrete disjoint", alice, "arn:aws:iam::111:user/Bob", false, false},
			{"fixed prefix disjoint", "arn:aws:iam::111:user/${aws:username}", "arn:aws:iam::222:user/Alice", false, false},
		} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				document := func(resource string) string {
					return `{"Statement":[{"Effect":"Allow","Action":"` + action + `","Resource":"` + resource + `"}]}`
				}
				caps := []Policy{{Type: typ, Document: document(tc.capResource)}}
				if typ == PolicySCP {
					caps = []Policy{{Type: PolicySCP, SCPLevel: &SCPLevel{Complete: true, Policies: []SCPPolicyDocument{{Document: document(tc.capResource)}}}}}
				}
				perms := evalPolicies(t, append([]Policy{identity(document(tc.identityResource))}, caps...)...)
				require.Equal(t, tc.present, HasPermission(perms, action))
				for _, permission := range perms {
					require.Equal(t, tc.approximate, permission.Approximate)
				}
				if tc.present {
					require.NotEmpty(t, AllowedResourceScopes(perms, action))
				}
			})
		}
	}
}
