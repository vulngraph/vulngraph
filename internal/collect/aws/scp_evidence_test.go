package aws

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

type incompleteSCPOrg struct {
	fakeOrg
	failure string
}

func (c incompleteSCPOrg) DescribePolicy(ctx context.Context, in *organizations.DescribePolicyInput, opts ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	id := awssdk.ToString(in.PolicyId)
	if c.failure == "unread deny" && id == "p-deny" || c.failure == "unread allow" && id == "p-full" {
		return nil, errors.New("DescribePolicy denied")
	}
	return c.fakeOrg.DescribePolicy(ctx, in, opts...)
}

func (c incompleteSCPOrg) ListParents(ctx context.Context, in *organizations.ListParentsInput, opts ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	if c.failure == "parent walk" && awssdk.ToString(in.ChildId) == "ou-1" {
		return nil, errors.New("ListParents denied")
	}
	return c.fakeOrg.ListParents(ctx, in, opts...)
}

func (c incompleteSCPOrg) ListPoliciesForTarget(ctx context.Context, in *organizations.ListPoliciesForTargetInput, opts ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	if c.failure == "nothing readable" {
		return nil, errors.New("ListPoliciesForTarget denied")
	}
	return c.fakeOrg.ListPoliciesForTarget(ctx, in, opts...)
}

func TestSCPCollection_PartialEvidenceRetainsCandidateSeverity(t *testing.T) {
	for _, failure := range []string{"unread deny", "unread allow", "parent walk", "nothing readable"} {
		t.Run(failure, func(t *testing.T) {
			scps, err := collectSCPsWith(t.Context(), incompleteSCPOrg{failure: failure}, time.Now())
			require.NoError(t, err)
			var found bool
			for _, a := range scps {
				if a.AccountID == "111" {
					found = true
					require.Equal(t, "false", a.Metadata["policies_complete"])
					if failure == "nothing readable" {
						require.Equal(t, "[]", a.Metadata["policies"])
					}
				}
			}
			require.True(t, found, "an unread SCP set remains observed uncertainty")
			principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
			principal.AccountID = "111"
			assertCapEvidenceLambda(t, append(scps, principal), principal.ID, ciem.SeverityHigh)
		})
	}
}

func TestSCPCollection_CompleteUnrestrictedControl(t *testing.T) {
	scps, err := collectSCPsWith(t.Context(), fakeOrg{}, time.Now())
	require.NoError(t, err)
	principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
	principal.AccountID = "999" // one fully read FullAWSAccess policy at root
	for _, a := range scps {
		require.Equal(t, "true", a.Metadata["policies_complete"])
	}
	assertCapEvidenceLambda(t, append(scps, principal), principal.ID, ciem.SeverityLow)
}

func TestSCPInventory_UnreadMetadataRetainsCandidateSeverity(t *testing.T) {
	for _, raw := range []string{"", "[broken", " null ", "[{}]", `[{"type":"identity","document":"broken"}]`} {
		t.Run(raw, func(t *testing.T) {
			principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
			scp := asset.Asset{ID: "aws_scp:1", Type: "aws_scp_set", Provider: asset.ProviderAWS, AccountID: "1",
				Metadata: map[string]string{"policies": raw, "policies_complete": "true"}}
			assertCapEvidenceLambda(t, []asset.Asset{principal, scp}, principal.ID, ciem.SeverityHigh)
		})
	}
}

func TestSCPInventory_LegacyCompletenessUnknown(t *testing.T) {
	principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
	scp := asset.Asset{ID: "aws_scp:1", Type: "aws_scp_set", Provider: asset.ProviderAWS, AccountID: "1",
		Metadata: map[string]string{"policies": encodePolicies([]policyDoc{{Type: "scp", Document: capEvidenceFull}})}}
	assertCapEvidenceLambda(t, []asset.Asset{principal, scp}, principal.ID, ciem.SeverityHigh)
	delete(principal.Metadata, "permission_boundary_complete")
	assertCapEvidenceLambda(t, []asset.Asset{principal}, principal.ID, ciem.SeverityHigh)
}

func TestSCPInventory_UnknownTypeNeverGrants(t *testing.T) {
	for _, typ := range []string{"", "identity", "trust"} {
		principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, "iam_user")
		principal.Metadata["policies"] = encodePolicies([]policyDoc{{Type: "identity", Document: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}})
		raw, err := json.Marshal([]policyDoc{{Type: typ, Document: capEvidenceFull}})
		require.NoError(t, err)
		scp := asset.Asset{ID: "aws_scp:1", Type: "aws_scp_set", Provider: asset.ProviderAWS, AccountID: "1",
			Metadata: map[string]string{"policies": string(raw), "policies_complete": "true"}}
		result := ciem.AnalyzeIAMAssets(t.Context(), []asset.Asset{principal, scp})
		require.Empty(t, result.Findings, "a cap must never become an identity grant")
		require.NotEqual(t, ciem.TierAdmin, result.Tiers[principal.ID].Tier)
	}
}
