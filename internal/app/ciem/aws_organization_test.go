package ciem

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

const orgFullDocument = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
const orgLambdaDocument = `{"Statement":[{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}]}`

func orgLevel(target, parent string, documents ...string) SCPLevel {
	level := SCPLevel{TargetID: target, ParentID: parent, Complete: true, Policies: []SCPPolicyDocument{}}
	for _, document := range documents {
		level.Policies = append(level.Policies, SCPPolicyDocument{Name: "policy", Document: document})
	}
	return level
}

func orgContext(t *testing.T, evidence AWSOrganizationEvidence) Policy {
	evidence.ObservedAt = time.Now()
	t.Helper()
	raw, err := json.Marshal(evidence)
	require.NoError(t, err)
	return Policy{Type: PolicyAWSOrganization, Document: string(raw)}
}

func orgAsset(t *testing.T, evidence AWSOrganizationEvidence) asset.Asset {
	t.Helper()
	return asset.Asset{ID: "aws_scp:" + evidence.AccountID, Type: "aws_scp_set", Provider: asset.ProviderAWS, AccountID: evidence.AccountID,
		Metadata: map[string]string{MetaAWSOrganization: orgContext(t, evidence).Document}}
}

func orgMember(levels ...SCPLevel) AWSOrganizationEvidence {
	return AWSOrganizationEvidence{AccountID: "111", ManagementAccountID: "999", RootID: "r-root", RootSCPStatus: "enabled", Applicability: "member", Complete: true, Levels: levels}
}

func TestSCPHierarchy_UnionsAlternativesAndIntersectsLevels(t *testing.T) {
	read := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	for _, tc := range []struct {
		name                    string
		levels                  []SCPLevel
		lambda, s3, approximate bool
	}{
		{"same level alternatives", []SCPLevel{orgLevel("111", "r-root", read, orgLambdaDocument), orgLevel("r-root", "", orgFullDocument)}, true, true, false},
		{"intersect levels", []SCPLevel{orgLevel("111", "r-root", orgLambdaDocument), orgLevel("r-root", "", read, orgLambdaDocument)}, true, false, false},
		{"disjoint levels", []SCPLevel{orgLevel("111", "r-root", orgLambdaDocument), orgLevel("r-root", "", read)}, false, false, false},
		{"confirmed empty level", []SCPLevel{orgLevel("111", "r-root"), orgLevel("r-root", "", orgFullDocument)}, false, false, false},
		{"unread level", []SCPLevel{{TargetID: "111", ParentID: "r-root", Policies: []SCPPolicyDocument{}}, orgLevel("r-root", "", orgLambdaDocument)}, true, false, true},
		{"incomplete alternatives", []SCPLevel{{TargetID: "111", ParentID: "r-root", Policies: []SCPPolicyDocument{{Document: read}}}, orgLevel("r-root", "", orgLambdaDocument)}, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				levels := append([]SCPLevel(nil), tc.levels...)
				if reverse {
					levels[0], levels[1] = levels[1], levels[0]
				}
				caps, complete := AWSOrganizationPolicies(asset.Asset{AccountID: "111"}, []Policy{orgContext(t, orgMember(levels...))})
				require.Equal(t, !tc.approximate, complete)
				perms := evalPolicies(t, append([]Policy{identity(orgFullDocument)}, caps...)...)
				require.Equal(t, tc.lambda, HasPermission(perms, "lambda:UpdateFunctionCode"))
				require.Equal(t, tc.s3, HasPermission(perms, "s3:GetObject"))
				for _, permission := range perms {
					if permission.Effect != EffectDeny {
						require.Equal(t, tc.approximate, permission.Approximate)
					}
				}
			}
		})
	}
}

func TestSCPHierarchy_KnownDeniesSurvivePartialMemberEvidence(t *testing.T) {
	deny := `{"Statement":[{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`
	level := orgLevel("111", "r-root", deny)
	level.Complete = false
	caps, complete := AWSOrganizationPolicies(asset.Asset{AccountID: "111"}, []Policy{orgContext(t, orgMember(level, orgLevel("r-root", "", orgFullDocument)))})
	require.False(t, complete)
	perms := evalPolicies(t, append([]Policy{identity(orgFullDocument)}, caps...)...)
	require.False(t, HasPermission(perms, "iam:PassRole"))
	require.True(t, HasPermission(perms, "lambda:UpdateFunctionCode"))
	require.Equal(t, tierNormal, awsPrincipalTier(perms))
}

func TestAWSOrganizationApplicability_PositiveAndUnknownControls(t *testing.T) {
	for _, tc := range []struct {
		name     string
		evidence AWSOrganizationEvidence
		known    bool
	}{
		{"management", AWSOrganizationEvidence{AccountID: "111", ManagementAccountID: "111", Applicability: "exempt", Reason: "management", Complete: true}, true},
		{"standalone", AWSOrganizationEvidence{AccountID: "111", Applicability: "exempt", Reason: "standalone", Complete: true}, true},
		{"disabled SCPs", AWSOrganizationEvidence{AccountID: "111", RootID: "r-root", RootSCPStatus: "disabled", Applicability: "exempt", Reason: "disabled", Complete: true}, true},
		{"unknown management identity", AWSOrganizationEvidence{AccountID: "111", Applicability: "exempt", Reason: "management", Complete: true}, false},
		{"pending disable", AWSOrganizationEvidence{AccountID: "111", RootID: "r-root", RootSCPStatus: "pending_disable", Applicability: "exempt", Reason: "disabled", Complete: true}, false},
		{"wrong account", AWSOrganizationEvidence{AccountID: "222", Applicability: "exempt", Reason: "standalone", Complete: true}, false},
		{"unread exemption", AWSOrganizationEvidence{AccountID: "111", Applicability: "exempt", Reason: "standalone"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps, known := AWSOrganizationPolicies(asset.Asset{AccountID: "111"}, []Policy{orgContext(t, tc.evidence)})
			require.Equal(t, tc.known, known)
			perms := evalPolicies(t, append([]Policy{identity(orgFullDocument)}, caps...)...)
			require.True(t, HasPermission(perms, "lambda:UpdateFunctionCode"))
			require.Equal(t, tc.known, awsPrincipalTier(perms) == tierAdmin)
		})
	}
}

func TestAWSServiceLinkedRole_ExactExemption(t *testing.T) {
	for _, tc := range []struct {
		arn, path string
		exempt    bool
	}{
		{"arn:aws:iam::111:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", "/aws-service-role/autoscaling.amazonaws.com/", true},
		{"arn:aws-cn:iam::111:role/aws-service-role/elasticache.amazonaws.com/AWSServiceRoleForElastiCache", "", true},
		{"arn:aws:iam::111:role/service-role/AWSServiceRoleForAutoScaling", "", false},
		{"arn:aws:iam::111:role/aws-service-role-not/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", "", false},
		{"arn:aws:iam::222:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling", "", false},
		{"arn:aws:iam::111:role/aws-service-role/autoscaling.amazonaws.com/operator", "", false},
		{"arn:aws:iam::111:role/operator", "/aws-service-role/autoscaling.amazonaws.com/", false},
	} {
		principal := asset.Asset{ID: tc.arn, Type: "iam_role", Provider: asset.ProviderAWS, AccountID: "111", Metadata: map[string]string{"path": tc.path}}
		_, known := AWSOrganizationPolicies(principal, nil)
		require.Equal(t, tc.exempt, known, tc.arn)
	}
}

func TestAnalyzeAWS_MissingOrganizationCoverageRetainsCandidate(t *testing.T) {
	raw, err := json.Marshal([]Policy{identity(orgFullDocument)})
	require.NoError(t, err)
	principal := asset.Asset{ID: "arn:aws:iam::111:user/operator", Type: "iam_user", Provider: asset.ProviderAWS, AccountID: "111",
		Metadata: map[string]string{"policies": string(raw), "permission_boundary_complete": "true"}}
	result := AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
	require.Equal(t, TierUnknown, result.Tiers[principal.ID].Tier)
	require.False(t, result.OrganizationPolicyCoverage[principal.ID])
	for _, finding := range result.Findings {
		if finding.RuleID == "aws-privesc-17" {
			require.Equal(t, SeverityHigh, finding.Severity)
			return
		}
	}
	t.Fatal("missing Lambda candidate")
}
