package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// fakeOrgPosture is a small organization: root r-1 → OU ou-a → accounts 111
// and 222; account 333 directly under the root; 999 is the management account.
type fakeOrgPosture struct {
	rootsErr     error
	policyTypes  []orgtypes.PolicyTypeSummary
	policies     map[string][]orgtypes.PolicySummary // "<type>/<target>"
	policiesErr  map[string]bool
	parents      map[string]string
	resPolicy    string
	resPolicyErr error
	trusted      []string
	admins       map[string][]string // admin account → delegated service principals
	adminsErr    error
	parentCalls  map[string]int
}

func (f *fakeOrgPosture) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	if f.rootsErr != nil {
		return nil, f.rootsErr
	}
	return &organizations.ListRootsOutput{Roots: []orgtypes.Root{{Id: awssdk.String("r-1"), PolicyTypes: f.policyTypes}}}, nil
}

func (f *fakeOrgPosture) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{Id: awssdk.String("o-1"), MasterAccountId: awssdk.String("999")}}, nil
}

func (f *fakeOrgPosture) ListAccounts(_ context.Context, in *organizations.ListAccountsInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	acct := func(id string, st orgtypes.AccountState) orgtypes.Account {
		return orgtypes.Account{Id: awssdk.String(id), State: st}
	}
	if in.NextToken == nil {
		return &organizations.ListAccountsOutput{
			Accounts:  []orgtypes.Account{acct("999", orgtypes.AccountStateActive), acct("111", orgtypes.AccountStateActive)},
			NextToken: awssdk.String("p2"),
		}, nil
	}
	return &organizations.ListAccountsOutput{Accounts: []orgtypes.Account{
		acct("222", orgtypes.AccountStateActive), acct("333", orgtypes.AccountStateActive), acct("444", orgtypes.AccountStateSuspended),
	}}, nil
}

func (f *fakeOrgPosture) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	child := awssdk.ToString(in.ChildId)
	f.parentCalls[child]++
	p, ok := f.parents[child]
	if !ok {
		return nil, &smithy.GenericAPIError{Code: "InvalidInputException"}
	}
	return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{{Id: awssdk.String(p)}}}, nil
}

func (f *fakeOrgPosture) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	key := string(in.Filter) + "/" + awssdk.ToString(in.TargetId)
	if f.policiesErr[key] {
		return nil, errors.New("throttled")
	}
	return &organizations.ListPoliciesForTargetOutput{Policies: f.policies[key]}, nil
}

func (f *fakeOrgPosture) DescribeResourcePolicy(context.Context, *organizations.DescribeResourcePolicyInput, ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error) {
	if f.resPolicyErr != nil {
		return nil, f.resPolicyErr
	}
	return &organizations.DescribeResourcePolicyOutput{ResourcePolicy: &orgtypes.ResourcePolicy{Content: awssdk.String(f.resPolicy)}}, nil
}

func (f *fakeOrgPosture) ListAWSServiceAccessForOrganization(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput, ...func(*organizations.Options)) (*organizations.ListAWSServiceAccessForOrganizationOutput, error) {
	var out []orgtypes.EnabledServicePrincipal
	for _, p := range f.trusted {
		out = append(out, orgtypes.EnabledServicePrincipal{ServicePrincipal: awssdk.String(p)})
	}
	return &organizations.ListAWSServiceAccessForOrganizationOutput{EnabledServicePrincipals: out}, nil
}

func (f *fakeOrgPosture) ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error) {
	if f.adminsErr != nil {
		return nil, f.adminsErr
	}
	var out []orgtypes.DelegatedAdministrator
	for id := range f.admins {
		out = append(out, orgtypes.DelegatedAdministrator{Id: awssdk.String(id), State: orgtypes.AccountStateActive})
	}
	return &organizations.ListDelegatedAdministratorsOutput{DelegatedAdministrators: out}, nil
}

func (f *fakeOrgPosture) ListDelegatedServicesForAccount(_ context.Context, in *organizations.ListDelegatedServicesForAccountInput, _ ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error) {
	var out []orgtypes.DelegatedService
	for _, p := range f.admins[awssdk.ToString(in.AccountId)] {
		out = append(out, orgtypes.DelegatedService{ServicePrincipal: awssdk.String(p)})
	}
	return &organizations.ListDelegatedServicesForAccountOutput{DelegatedServices: out}, nil
}

type fakeOrgFeatures struct {
	features []iamtypes.FeatureType
	err      error
}

func (f fakeOrgFeatures) ListOrganizationsFeatures(context.Context, *iam.ListOrganizationsFeaturesInput, ...func(*iam.Options)) (*iam.ListOrganizationsFeaturesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &iam.ListOrganizationsFeaturesOutput{EnabledFeatures: f.features}, nil
}

func fullAccess(name string) orgtypes.PolicySummary {
	return orgtypes.PolicySummary{Name: awssdk.String(name), AwsManaged: true}
}

func newFakeOrgPosture() *fakeOrgPosture {
	scp, rcp := string(orgtypes.PolicyTypeServiceControlPolicy), string(orgtypes.PolicyTypeResourceControlPolicy)
	return &fakeOrgPosture{
		policyTypes: []orgtypes.PolicyTypeSummary{
			{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled},
			{Type: orgtypes.PolicyTypeResourceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled},
		},
		policies: map[string][]orgtypes.PolicySummary{
			scp + "/r-1":  {fullAccess("FullAWSAccess")},
			scp + "/ou-a": {fullAccess("FullAWSAccess"), {Name: awssdk.String("deny-leave-org")}},
			rcp + "/r-1":  {fullAccess("RCPFullAWSAccess")},
			rcp + "/111":  {{Name: awssdk.String("data-perimeter")}},
		},
		policiesErr: map[string]bool{},
		parents:     map[string]string{"111": "ou-a", "222": "ou-a", "333": "r-1", "ou-a": "r-1"},
		resPolicy:   `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111:root"},"Action":["organizations:Describe*","organizations:*Policy"],"Resource":"*"}]}`,
		trusted:     []string{"guardduty.amazonaws.com", "config.amazonaws.com", "securityhub.amazonaws.com", "ram.amazonaws.com", "iam.amazonaws.com"},
		admins:      map[string][]string{"111": {"guardduty.amazonaws.com", "config-multiaccountsetup.amazonaws.com"}},
		parentCalls: map[string]int{},
	}
}

func TestReadOrgPosture(t *testing.T) {
	f := newFakeOrgPosture()
	got, err := readOrgPosture(context.Background(), f, fakeOrgFeatures{features: []iamtypes.FeatureType{iamtypes.FeatureTypeRootCredentialsManagement}}, time.Now())
	require.NoError(t, err)
	a := wideByID(got)

	org := a["aws_org:o-1"]
	require.Equal(t, orgPostureType, org.Type)
	require.Equal(t, "999", org.AccountID)
	require.Equal(t, "true", org.Metadata["root_credentials_management"])
	require.Equal(t, "false", org.Metadata["root_sessions"])
	require.Equal(t, "true", org.Metadata["policy_management_delegated"], "a mid-pattern wildcard (organizations:*Policy) covers policy management")
	require.Equal(t, "iam.amazonaws.com,securityhub.amazonaws.com", org.Metadata["undelegated_security_services"],
		"config is delegated under its multi-account principal; ram has no delegated admin to have")
	require.Equal(t, "1", org.Metadata["delegated_admin_count"])

	require.NotContains(t, a, "aws_org_account:999", "SCPs and RCPs never restrict the management account")
	require.NotContains(t, a, "aws_org_account:444", "a suspended account has no principal left to guard")
	require.Equal(t, "true", a["aws_org_account:111"].Metadata["scp_guardrail"], "inherited from its OU")
	require.Equal(t, "true", a["aws_org_account:111"].Metadata["rcp_guardrail"], "attached to the account itself")
	require.Equal(t, "true", a["aws_org_account:222"].Metadata["scp_guardrail"])
	require.Equal(t, "false", a["aws_org_account:222"].Metadata["rcp_guardrail"], "only the default RCPFullAWSAccess applies")
	require.Equal(t, "false", a["aws_org_account:333"].Metadata["scp_guardrail"], "only FullAWSAccess at the root")
	require.Equal(t, 1, f.parentCalls["ou-a"], "a shared OU's parent is read once")
	require.Zero(t, f.parentCalls["r-1"], "the walk never asks for a root's parent")
}

func TestReadOrgPostureUnknowns(t *testing.T) {
	f := newFakeOrgPosture()
	f.policiesErr[string(orgtypes.PolicyTypeServiceControlPolicy)+"/333"] = true
	f.resPolicyErr = &smithy.GenericAPIError{Code: "AccessDeniedException"}
	f.adminsErr = errors.New("throttled")
	got, err := readOrgPosture(context.Background(), f,
		fakeOrgFeatures{err: &smithy.GenericAPIError{Code: "AccountNotManagementOrDelegatedAdministratorException"}}, time.Now())
	require.NoError(t, err)
	a := wideByID(got)
	org := a["aws_org:o-1"].Metadata
	for _, k := range []string{"root_credentials_management", "root_sessions", "policy_management_delegated", "undelegated_security_services", "trusted_security_services"} {
		require.NotContains(t, org, k, "an unread %s is unknown, never compliant or violating", k)
	}
	require.NotContains(t, a["aws_org_account:333"].Metadata, "scp_guardrail")
	require.Equal(t, "false", a["aws_org_account:333"].Metadata["rcp_guardrail"], "the other policy type still reads")
}

func TestReadOrgPostureObservedNegatives(t *testing.T) {
	f := newFakeOrgPosture()
	f.policyTypes = nil // neither policy type enabled at the root
	f.resPolicyErr = &smithy.GenericAPIError{Code: "ResourcePolicyNotFoundException"}
	got, err := readOrgPosture(context.Background(), f,
		fakeOrgFeatures{err: &smithy.GenericAPIError{Code: "ServiceAccessNotEnabledException"}}, time.Now())
	require.NoError(t, err)
	a := wideByID(got)
	org := a["aws_org:o-1"].Metadata
	require.Equal(t, "false", org["root_credentials_management"], "IAM trusted access off: centralized root access cannot be on")
	require.Equal(t, "false", org["policy_management_delegated"])
	require.Equal(t, "false", org["scp_enabled"])
	require.Equal(t, "false", a["aws_org_account:111"].Metadata["scp_guardrail"])
}

func TestReadOrgPostureNotTheOrgAccount(t *testing.T) {
	for _, code := range []string{"AccessDeniedException", "AWSOrganizationsNotInUseException"} {
		f := newFakeOrgPosture()
		f.rootsErr = &smithy.GenericAPIError{Code: code}
		got, err := readOrgPosture(context.Background(), f, fakeOrgFeatures{}, time.Now())
		require.NoError(t, err, code)
		require.Empty(t, got, "%s: a member account emits nothing, so the controls stay unknown", code)
	}
	f := newFakeOrgPosture()
	f.rootsErr = errors.New("timeout")
	_, err := readOrgPosture(context.Background(), f, fakeOrgFeatures{}, time.Now())
	require.Error(t, err, "a transient failure is a skipped collector, not 'not the org account'")
}
