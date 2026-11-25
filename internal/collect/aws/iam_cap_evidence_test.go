package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

const capEvidenceFull = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

type capEvidenceIAM struct {
	fakeIAM
	detailErr   bool
	boundary    bool
	documentErr bool
	scopedUser  bool
}

func (c capEvidenceIAM) ListRoles(ctx context.Context, in *iam.ListRolesInput, opts ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	out, err := c.fakeIAM.ListRoles(ctx, in, opts...)
	out.Roles[0].AssumeRolePolicyDocument = nil
	return out, err
}

func (c capEvidenceIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	if c.detailErr {
		return nil, errors.New("GetRole denied")
	}
	role := &iamtypes.Role{}
	if c.boundary {
		role.PermissionsBoundary = &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: awssdk.String(boundaryARN)}
	}
	return &iam.GetRoleOutput{Role: role}, nil
}

func (c capEvidenceIAM) GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	if c.detailErr {
		return nil, errors.New("GetUser denied")
	}
	user := &iamtypes.User{}
	if c.boundary {
		user.PermissionsBoundary = &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: awssdk.String(boundaryARN)}
	}
	return &iam.GetUserOutput{User: user}, nil
}

func (c capEvidenceIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	doc := capEvidenceFull
	if awssdk.ToString(in.PolicyArn) == boundaryARN {
		if c.documentErr {
			return nil, errors.New("boundary document denied")
		}
		doc = `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(doc)}}, nil
}

func (c capEvidenceIAM) GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	doc := capEvidenceFull
	if c.scopedUser {
		doc = `{"Statement":[{"Effect":"Allow","Action":"lambda:UpdateFunctionCode","Resource":"*"}]}`
	}
	return &iam.GetUserPolicyOutput{PolicyDocument: awssdk.String(doc)}, nil
}

func TestIAMCollection_UnreadBoundaryRetainsSeverity(t *testing.T) {
	for _, kind := range []string{"iam_role", "iam_user"} {
		for _, failure := range []string{"attachment unread", "document unread"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				c := capEvidenceIAM{detailErr: failure == "attachment unread", boundary: failure == "document unread", documentErr: true}
				principal := collectCapEvidencePrincipal(t, c, kind)
				require.NotContains(t, principal.Metadata, "admin")
				require.Equal(t, "false", principal.Metadata["permission_boundary_complete"])
				if c.boundary {
					require.Equal(t, boundaryARN, principal.Metadata["permission_boundary_arn"])
				}
				docs := decodePolicies(t, principal.Metadata["policies"])
				require.Equal(t, "boundary", docs[len(docs)-1].Type)
				require.True(t, docs[len(docs)-1].Incomplete)
				require.Empty(t, docs[len(docs)-1].Document, "missing evidence is typed, never fake malformed JSON")
				assertCapEvidenceLambda(t, []asset.Asset{principal}, principal.ID, ciem.SeverityHigh)
			})
		}
	}
}

func TestIAMCollection_BoundaryEvidenceControls(t *testing.T) {
	for _, kind := range []string{"iam_role", "iam_user"} {
		t.Run(kind+"/observed absence", func(t *testing.T) {
			principal := collectCapEvidencePrincipal(t, capEvidenceIAM{}, kind)
			require.Equal(t, "true", principal.Metadata["admin"])
			require.Equal(t, "true", principal.Metadata["permission_boundary_complete"])
			assertCapEvidenceLambda(t, []asset.Asset{principal}, principal.ID, ciem.SeverityHigh)
		})
		t.Run(kind+"/readable restriction", func(t *testing.T) {
			principal := collectCapEvidencePrincipal(t, capEvidenceIAM{boundary: true, scopedUser: true}, kind)
			require.NotContains(t, principal.Metadata, "admin")
			require.Equal(t, "true", principal.Metadata["permission_boundary_complete"])
			// Older assets with a readable boundary still have a known cap.
			delete(principal.Metadata, "permission_boundary_complete")
			result := ciem.AnalyzeIAMAssets(t.Context(), []asset.Asset{principal})
			for _, f := range result.Findings {
				require.NotEqual(t, "aws-privesc-17", f.RuleID, "the fetched boundary caps scoped grants too")
			}
		})
	}
}

func collectCapEvidencePrincipal(t *testing.T, c capEvidenceIAM, kind string) asset.Asset {
	t.Helper()
	var assets []asset.Asset
	var err error
	if kind == "iam_role" {
		assets, _, err = collectRoles(t.Context(), c, newManagedPolicyCache(c), "1", time.Now())
	} else {
		assets, _, err = collectUsers(t.Context(), c, newManagedPolicyCache(c), "1", time.Now())
	}
	require.NoError(t, err)
	for _, a := range assets {
		if a.Type == kind {
			return a
		}
	}
	t.Fatalf("collector omitted %s", kind)
	return asset.Asset{}
}

func assertCapEvidenceLambda(t *testing.T, assets []asset.Asset, principalID string, severity string) {
	t.Helper()
	result := ciem.AnalyzeIAMAssets(t.Context(), assets)
	if severity != ciem.SeverityLow {
		require.NotEqual(t, ciem.TierAdmin, result.Tiers[principalID].Tier)
	}
	for _, f := range result.Findings {
		if f.RuleID == "aws-privesc-17" && f.PrincipalID == principalID {
			require.Equal(t, severity, f.Severity)
			return
		}
	}
	t.Fatal("Lambda code-update candidate was lost")
}
