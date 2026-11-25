package aws

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

type orgEvidenceAPI struct {
	fakeOrg
	describeErr       error
	missingManagement bool
	policyTypes       *[]orgtypes.PolicyTypeSummary
	emptyAccountLevel bool
}

func (f orgEvidenceAPI) DescribeOrganization(ctx context.Context, in *organizations.DescribeOrganizationInput, opts ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if f.missingManagement {
		return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{}}, nil
	}
	out, err := f.fakeOrg.DescribeOrganization(ctx, in, opts...)
	if out != nil && out.Organization != nil {
		out.Organization.FeatureSet = orgtypes.OrganizationFeatureSetAll
	}
	return out, err
}
func (f orgEvidenceAPI) ListRoots(ctx context.Context, in *organizations.ListRootsInput, opts ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	out, err := f.fakeOrg.ListRoots(ctx, in, opts...)
	if err == nil && f.policyTypes != nil {
		out.Roots[0].PolicyTypes = *f.policyTypes
	}
	return out, err
}
func (f orgEvidenceAPI) ListPoliciesForTarget(ctx context.Context, in *organizations.ListPoliciesForTargetInput, opts ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	if f.emptyAccountLevel && awssdk.ToString(in.TargetId) == "111" {
		return &organizations.ListPoliciesForTargetOutput{}, nil
	}
	return f.fakeOrg.ListPoliciesForTarget(ctx, in, opts...)
}

func TestSCPApplicability_CollectorToCIEM(t *testing.T) {
	disabled := []orgtypes.PolicyTypeSummary{}
	pending := []orgtypes.PolicyTypeSummary{{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: orgtypes.PolicyTypeStatusPendingEnable}}
	malformed := []orgtypes.PolicyTypeSummary{{Status: orgtypes.PolicyTypeStatusEnabled}}
	for _, tc := range []struct {
		name                            string
		client                          orgEvidenceAPI
		caller                          string
		wantErr, known, admin, passRole bool
	}{
		{"known member", orgEvidenceAPI{}, "111", false, true, false, false},
		{"management", orgEvidenceAPI{fakeOrg: fakeOrg{mgmtAccount: "111"}}, "111", false, true, true, true},
		{"management roots unread", orgEvidenceAPI{fakeOrg: fakeOrg{mgmtAccount: "111", listRootsErr: &smithyAPIErr{code: "AccessDeniedException"}}}, "111", false, true, true, true},
		{"member roots unread", orgEvidenceAPI{fakeOrg: fakeOrg{listRootsErr: &smithyAPIErr{code: "AccessDeniedException"}}}, "111", false, false, false, true},
		{"membership unread", orgEvidenceAPI{describeErr: errors.New("access denied")}, "111", true, false, false, true},
		{"management identity missing", orgEvidenceAPI{missingManagement: true}, "111", true, false, false, true},
		{"standalone", orgEvidenceAPI{describeErr: &smithyAPIErr{code: "AWSOrganizationsNotInUseException"}}, "111", false, true, true, true},
		{"observed disabled", orgEvidenceAPI{policyTypes: &disabled}, "111", false, true, true, true},
		{"ALL features is not enabled proof", orgEvidenceAPI{policyTypes: &pending}, "111", false, false, false, true},
		{"malformed status", orgEvidenceAPI{policyTypes: &malformed}, "111", false, false, false, true},
		{"known empty account attachment level", orgEvidenceAPI{emptyAccountLevel: true}, "111", false, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scps, membership, err := collectSCPsForAccountWithMembership(t.Context(), tc.client, tc.caller, time.Now())
			require.Equal(t, tc.wantErr, err != nil)
			principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
			principal.AccountID = "111"
			assets := append(scps, principal)
			stampOrganizationMembership(assets, "111", membership)
			result := ciem.AnalyzeIAMAssets(t.Context(), assets)
			require.Equal(t, tc.known, result.OrganizationPolicyCoverage[principal.ID])
			require.Equal(t, tc.admin, result.Tiers[principal.ID].Tier == ciem.TierAdmin)
			if !tc.known {
				require.Equal(t, ciem.TierUnknown, result.Tiers[principal.ID].Tier)
			}
			found := false
			for _, path := range result.Paths {
				if path.Rule.ID == "aws-privesc-11" {
					found = true
				}
			}
			require.Equal(t, tc.passRole, found)
			if tc.client.emptyAccountLevel {
				require.Empty(t, result.Paths)
			}
		})
	}
}

func TestSCPMembershipChangeInvalidatesRecentExemption(t *testing.T) {
	now := time.Now()
	prior, _, err := collectSCPsForAccountWithMembership(t.Context(), orgEvidenceAPI{describeErr: &smithyAPIErr{code: "AWSOrganizationsNotInUseException"}}, "111", now.Add(-time.Minute))
	require.NoError(t, err)
	require.Len(t, prior, 1)
	principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
	principal.AccountID = "111"
	assertCapEvidenceLambda(t, append(prior, principal), principal.ID, ciem.SeverityLow)
	current, membership, err := collectSCPsForAccountWithMembership(t.Context(), fakeOrg{mgmtAccount: "999", listRootsErr: &smithyAPIErr{code: "AccessDeniedException"}}, "111", now)
	require.NoError(t, err)
	require.Empty(t, current, "member read failure must not overwrite management-owned SCP inventory")
	assets := append(prior, principal)
	stampOrganizationMembership(assets, "111", membership)
	assertCapEvidenceLambda(t, assets, principal.ID, ciem.SeverityHigh)
	result := ciem.AnalyzeIAMAssets(t.Context(), assets)
	require.Equal(t, ciem.TierUnknown, result.Tiers[principal.ID].Tier)

	// A matching management-owned hierarchy remains usable after the member's
	// ListRoots failure; the membership witness is not a fake unread cap.
	valid, err := collectSCPsForAccount(t.Context(), fakeOrg{mgmtAccount: "999"}, "999", now)
	require.NoError(t, err)
	assets = append(valid, principal)
	stampOrganizationMembership(assets, "111", membership)
	result = ciem.AnalyzeIAMAssets(t.Context(), assets)
	require.True(t, result.OrganizationPolicyCoverage[principal.ID])
	for _, path := range result.Paths {
		require.NotEqual(t, "aws-privesc-11", path.Rule.ID)
	}
}

func TestSCPCollectionRetainsEmptyLevelsAndDistinctAttachments(t *testing.T) {
	assets, err := collectSCPsForAccount(t.Context(), orgEvidenceAPI{emptyAccountLevel: true}, "111", time.Now())
	require.NoError(t, err)
	for _, a := range assets {
		if a.AccountID != "111" {
			continue
		}
		var evidence ciem.AWSOrganizationEvidence
		require.NoError(t, json.Unmarshal([]byte(a.Metadata[ciem.MetaAWSOrganization]), &evidence))
		require.Len(t, evidence.Levels, 3)
		require.NotNil(t, evidence.Levels[0].Policies)
		require.Empty(t, evidence.Levels[0].Policies)
		require.True(t, evidence.Levels[0].Complete)
		require.Len(t, evidence.Levels[1].Policies, 2)
		require.Len(t, evidence.Levels[2].Policies, 1)
		return
	}
	t.Fatal("missing member evidence")
}
