package aws

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// smithyAPIErr is a minimal smithy.APIError for testing error-code branching.
type smithyAPIErr struct{ code string }

func (e *smithyAPIErr) Error() string                 { return e.code }
func (e *smithyAPIErr) ErrorCode() string             { return e.code }
func (e *smithyAPIErr) ErrorMessage() string          { return e.code }
func (e *smithyAPIErr) ErrorFault() smithy.ErrorFault { return smithy.FaultServer }

// fakeOrg models a tiny org: account 111 sits in OU ou-1, which sits under root
// r-1. An SCP p-deny is attached at the OU, and FullAWSAccess (p-full) at the root.
type fakeOrg struct {
	listRootsErr     error
	mgmtAccount      string // account 999 is the management account when set
	suspendedAccount string // account whose Status is SUSPENDED rather than ACTIVE, when set
}

func (f fakeOrg) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if f.listRootsErr != nil {
		return nil, f.listRootsErr
	}
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: awssdk.String("r-1"), PolicyTypes: []orgtypes.PolicyTypeSummary{{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled}}}}}, nil
}

func (f fakeOrg) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	management := f.mgmtAccount
	if management == "" {
		management = "000"
	}
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{MasterAccountId: awssdk.String(management)}}, nil
}

func (f fakeOrg) ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	accts := []orgtypes.Account{{Id: awssdk.String("111"), Status: orgtypes.AccountStatusActive}, {Id: awssdk.String("999"), Status: orgtypes.AccountStatusActive}}
	for i := range accts {
		if awssdk.ToString(accts[i].Id) == f.suspendedAccount {
			accts[i].Status = orgtypes.AccountStatusSuspended
		}
	}
	return &organizations.ListAccountsOutput{Accounts: accts}, nil
}

func (fakeOrg) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	switch awssdk.ToString(in.ChildId) {
	case "111":
		return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{Id: awssdk.String("ou-1")}}}, nil
	case "999": // directly under root
		return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{Id: awssdk.String("r-1")}}}, nil
	case "ou-1":
		return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{Id: awssdk.String("r-1")}}}, nil
	default: // root has no parent
		return &organizations.ListParentsOutput{}, nil
	}
}

func (fakeOrg) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	switch awssdk.ToString(in.TargetId) {
	case "ou-1":
		return &organizations.ListPoliciesForTargetOutput{Policies: []orgtypes.PolicySummary{{Id: awssdk.String("p-deny"), Name: awssdk.String("DenyPassRole")}, {Id: awssdk.String("p-full"), Name: awssdk.String("FullAWSAccess")}}}, nil
	case "r-1":
		return &organizations.ListPoliciesForTargetOutput{Policies: []orgtypes.PolicySummary{{Id: awssdk.String("p-full"), Name: awssdk.String("FullAWSAccess")}}}, nil
	default:
		return &organizations.ListPoliciesForTargetOutput{Policies: []orgtypes.PolicySummary{{Id: awssdk.String("p-full"), Name: awssdk.String("FullAWSAccess")}}}, nil
	}
}

func (fakeOrg) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	docs := map[string]string{
		"p-deny": `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"iam:PassRole","Resource":"*"}]}`,
		"p-full": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	}
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: awssdk.String(docs[awssdk.ToString(in.PolicyId)])}}, nil
}

func TestCollectSCPs_WalksParentChain(t *testing.T) {
	assets, err := collectSCPsWith(context.Background(), fakeOrg{}, time.Now())
	require.NoError(t, err)
	byID := map[string]asset.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}
	a := byID["aws_scp:111"]
	require.Equal(t, "aws_scp_set", a.Type)
	require.Equal(t, "111", a.AccountID)
	require.Equal(t, "2", a.Metadata["policy_count"], "both the OU deny and the root FullAWSAccess are in effect")
	require.Contains(t, a.Metadata["policies"], "iam:PassRole")
	require.Contains(t, a.Metadata["policies"], `"type":"scp"`)
	require.Equal(t, "1", byID["aws_scp:999"].Metadata["policy_count"], "999 sits directly under root → FullAWSAccess only")
}

func TestCollectSCPs_RecordsManagementExemption(t *testing.T) {
	assets, err := collectSCPsWith(context.Background(), fakeOrg{mgmtAccount: "999"}, time.Now())
	require.NoError(t, err)
	require.Len(t, assets, 2)
	for _, a := range assets {
		if a.AccountID != "999" {
			continue
		}
		var evidence ciem.AWSOrganizationEvidence
		require.NoError(t, json.Unmarshal([]byte(a.Metadata[ciem.MetaAWSOrganization]), &evidence))
		require.Equal(t, "exempt", evidence.Applicability)
		require.Equal(t, "management", evidence.Reason)
		require.True(t, evidence.Complete)
		return
	}
	t.Fatal("management-account exemption omitted")
}

func TestCollectSCPs_NoOpOnAccessDenied(t *testing.T) {
	// A non-management account can't ListRoots → clean no-op, never an error.
	assets, err := collectSCPsWith(context.Background(), fakeOrg{listRootsErr: &smithyAPIErr{code: "AccessDeniedException"}}, time.Now())
	require.NoError(t, err)
	require.Empty(t, assets)
}

// A closed/removed account stays in ListAccounts for a retention window (AWS
// keeps it there with Status SUSPENDED or PENDING_CLOSURE) — unfiltered, this
// collector resurrected an aws_scp_set asset for a purged-and-confirmed-dead
// account on every sync. A non-ACTIVE account must never get an asset.
func TestCollectSCPs_ExcludesNonActiveAccount(t *testing.T) {
	assets, err := collectSCPsWith(context.Background(), fakeOrg{suspendedAccount: "111"}, time.Now())
	require.NoError(t, err)
	for _, a := range assets {
		require.NotEqual(t, "aws_scp:111", a.ID, "a SUSPENDED account must not get its SCP asset resurrected")
	}
	require.Len(t, assets, 1, "only account 999 (still ACTIVE) should be emitted")
}

func TestCollectSCPs_TransientErrorReturned(t *testing.T) {
	// A throttle/timeout on the management connector MUST surface as an error so
	// the sweep is flagged Partial and deletion reconciliation is skipped — never
	// a silent empty result that would wipe every aws_scp_set asset.
	_, err := collectSCPsWith(context.Background(), fakeOrg{listRootsErr: &smithyAPIErr{code: "ThrottlingException"}}, time.Now())
	require.Error(t, err)
}
