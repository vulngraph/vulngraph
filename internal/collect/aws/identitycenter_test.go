package aws

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	identitystoretypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ssoSmithyAPIErr is a minimal smithy.APIError for testing isSSONoOpErr's
// error-code branching, mirroring smithyAPIErr in scp_test.go.
type ssoSmithyAPIErr struct{ code string }

func (e *ssoSmithyAPIErr) Error() string                 { return e.code }
func (e *ssoSmithyAPIErr) ErrorCode() string             { return e.code }
func (e *ssoSmithyAPIErr) ErrorMessage() string          { return e.code }
func (e *ssoSmithyAPIErr) ErrorFault() smithy.ErrorFault { return smithy.FaultServer }

// fakeSSO is a canned Identity Center. permsets maps permission-set ARN to its
// managed policy names / inline policy / provisioned accounts / assignments.
type fakeSSO struct {
	instanceARN string
	storeID     string
	// ownerAccountID, when set, is returned as InstanceMetadata.OwnerAccountId —
	// the positive ownership signal collectSSO uses to decide whether an
	// AccessDeniedException on ListPermissionSets is a confirmed member-account
	// no-op or a regression on the owning account. Left "" reproduces AWS
	// omitting the field, which collectSSO must treat as unknown, not "not the
	// owner".
	ownerAccountID string
	permsets       []string
	names          map[string]string
	managed        map[string][]string
	inline         map[string]string
	accounts       map[string][]string
	assignments    map[string]map[string][]ssoadmintypes.AccountAssignment // psARN -> account -> assignments
	listErr        error
	// listPermSetsErr, when set, is returned by ListPermissionSets — the actual
	// admin/member-account boundary (ListInstances itself succeeds in a member
	// account too; AWS returns the org's instance to every account).
	listPermSetsErr error
	// inlineErr, when set, fails GetInlinePolicyForPermissionSet.
	inlineErr error
}

func (f *fakeSSO) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.instanceARN == "" {
		return &ssoadmin.ListInstancesOutput{}, nil // no instance in this account
	}
	inst := ssoadmintypes.InstanceMetadata{InstanceArn: &f.instanceARN, IdentityStoreId: &f.storeID}
	if f.ownerAccountID != "" {
		inst.OwnerAccountId = &f.ownerAccountID
	}
	return &ssoadmin.ListInstancesOutput{Instances: []ssoadmintypes.InstanceMetadata{inst}}, nil
}

func (f *fakeSSO) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	if f.listPermSetsErr != nil {
		return nil, f.listPermSetsErr
	}
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: f.permsets}, nil
}

func (f *fakeSSO) DescribePermissionSet(_ context.Context, in *ssoadmin.DescribePermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	name := f.names[*in.PermissionSetArn]
	return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &ssoadmintypes.PermissionSet{Name: &name}}, nil
}

func (f *fakeSSO) ListManagedPoliciesInPermissionSet(_ context.Context, in *ssoadmin.ListManagedPoliciesInPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error) {
	var out []ssoadmintypes.AttachedManagedPolicy
	for _, n := range f.managed[*in.PermissionSetArn] {
		out = append(out, ssoadmintypes.AttachedManagedPolicy{Name: awssdk.String(n)})
	}
	return &ssoadmin.ListManagedPoliciesInPermissionSetOutput{AttachedManagedPolicies: out}, nil
}

func (f *fakeSSO) GetInlinePolicyForPermissionSet(_ context.Context, in *ssoadmin.GetInlinePolicyForPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error) {
	if f.inlineErr != nil {
		return nil, f.inlineErr
	}
	doc := f.inline[*in.PermissionSetArn]
	return &ssoadmin.GetInlinePolicyForPermissionSetOutput{InlinePolicy: &doc}, nil
}

func (f *fakeSSO) ListAccountsForProvisionedPermissionSet(_ context.Context, in *ssoadmin.ListAccountsForProvisionedPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: f.accounts[*in.PermissionSetArn]}, nil
}

func (f *fakeSSO) ListAccountAssignments(_ context.Context, in *ssoadmin.ListAccountAssignmentsInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: f.assignments[*in.PermissionSetArn][*in.AccountId]}, nil
}

type fakeIDStore struct {
	users      map[string]string
	userEmails map[string]string // principalID -> email, optional
	groups     map[string]string
	// members maps a group GUID to the user GUIDs inside it — the population
	// that is invisible until group memberships are expanded.
	members         map[string][]string
	groupCalls      int
	membershipCalls int
	membershipErr   error
}

func (f *fakeIDStore) ListGroupMemberships(_ context.Context, in *identitystore.ListGroupMembershipsInput, _ ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error) {
	f.membershipCalls++
	if f.membershipErr != nil {
		return nil, f.membershipErr
	}
	var out []identitystoretypes.GroupMembership
	for _, uid := range f.members[*in.GroupId] {
		out = append(out, identitystoretypes.GroupMembership{
			MemberId: &identitystoretypes.MemberIdMemberUserId{Value: uid},
		})
	}
	return &identitystore.ListGroupMembershipsOutput{GroupMemberships: out}, nil
}

func (f *fakeIDStore) DescribeUser(_ context.Context, in *identitystore.DescribeUserInput, _ ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error) {
	n := f.users[*in.UserId]
	out := &identitystore.DescribeUserOutput{UserName: &n}
	if email, ok := f.userEmails[*in.UserId]; ok {
		out.Emails = []identitystoretypes.Email{{Value: awssdk.String(email), Primary: true}}
	}
	return out, nil
}

func (f *fakeIDStore) DescribeGroup(_ context.Context, in *identitystore.DescribeGroupInput, _ ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	f.groupCalls++
	n := f.groups[*in.GroupId]
	return &identitystore.DescribeGroupOutput{DisplayName: &n}, nil
}

func assignment(ps, acct, principalID string, t ssoadmintypes.PrincipalType) ssoadmintypes.AccountAssignment {
	return ssoadmintypes.AccountAssignment{
		AccountId: awssdk.String(acct), PermissionSetArn: awssdk.String(ps),
		PrincipalId: awssdk.String(principalID), PrincipalType: t,
	}
}

func TestHasProvenCapability(t *testing.T) {
	require.False(t, hasProvenCapability(nil, capabilitySSOAdmin), "nil cfg -> not proven")
	require.False(t, hasProvenCapability(map[string]string{}, capabilitySSOAdmin), "no key -> not proven")
	require.False(t, hasProvenCapability(map[string]string{"proven_capabilities": "other_thing"}, capabilitySSOAdmin))
	require.True(t, hasProvenCapability(map[string]string{"proven_capabilities": "sso_admin"}, capabilitySSOAdmin))
	require.True(t, hasProvenCapability(map[string]string{"proven_capabilities": "other_thing, sso_admin ,third"}, capabilitySSOAdmin),
		"comma-separated list, extra whitespace tolerated")
}

var ssoNow = time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

// An account with no Identity Center instance is a clean no-op, not an error —
// this is what lets the collector run on every AWS connector.
func TestCollectSSO_NoInstanceIsNoop(t *testing.T) {
	assets, _, _, err := collectSSO(context.Background(), &fakeSSO{}, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.Empty(t, assets)
}

// Full path: an AdministratorAccess permission set assigned to a user and a
// group across two accounts becomes one sso_permission_set asset flagged
// grants_admin with resolved assignee names.
func TestCollectSSO_AdminPermissionSet(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-admin"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "AdministratorAccess"},
		managed:  map[string][]string{ps: {"AdministratorAccess"}},
		accounts: map[string][]string{ps: {"111122223333", "444455556666"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{ps: {
			"111122223333": {assignment(ps, "111122223333", "u-1", ssoadmintypes.PrincipalTypeUser)},
			"444455556666": {assignment(ps, "444455556666", "g-1", ssoadmintypes.PrincipalTypeGroup)},
		}},
	}
	ids := &fakeIDStore{
		users:      map[string]string{"u-1": "alice"},
		userEmails: map[string]string{"u-1": "alice@example.com"},
		groups:     map[string]string{"g-1": "platform-admins"},
	}

	assets, edges, _, err := collectSSO(context.Background(), sso, ids, "111122223333", ssoNow, false)
	require.NoError(t, err)

	var permsets, groups, humans []asset.Asset
	for _, a := range assets {
		switch a.Type {
		case "sso_permission_set":
			permsets = append(permsets, a)
		case "sso_group":
			groups = append(groups, a)
		case "human_identity":
			humans = append(humans, a)
		}
	}
	require.Len(t, permsets, 1)
	a := permsets[0]
	require.Equal(t, ps, a.ID)
	require.Equal(t, "AdministratorAccess", a.Name)
	require.Equal(t, "true", a.Metadata["grants_admin"])
	require.Equal(t, "2", a.Metadata["account_count"])
	require.Equal(t, "group:platform-admins,user:alice", a.Metadata["assignees"], "resolved + sorted")
	require.Equal(t, "2", a.Metadata["assignee_count"])

	// The provisioned state must reach the GRAPH, not only metadata: that gap meant
	// the authoritative source contributed no topology at all.
	require.Len(t, groups, 1, "the group holding this permission set is a node")
	require.Equal(t, "sso_group:platform-admins", groups[0].ID,
		"keyed by display name, the join point an identity provider's SCIM name match lands on")

	// The user assignee is no longer silently dropped: it becomes a real
	// human_identity node, keyed on its resolved email so correlate's
	// HumanIdentityFederation can join it to github_repo/iam_role.
	require.Len(t, humans, 1, "the user holding this permission set is now a node too")
	require.Equal(t, "sso_user:alice", humans[0].ID)
	require.Equal(t, "alice@example.com", humans[0].Domain)
	require.Equal(t, "alice", humans[0].Metadata["sso_username"])

	got := map[string]bool{}
	for _, e := range edges {
		got[e.EdgeType+" "+e.SrcID+" -> "+e.DstID] = true
		require.Equal(t, "identity_center", e.Properties["provenance"])
	}
	// Provisioned to two accounts, and admin on both.
	require.True(t, got["grants_access_to "+ps+" -> aws:111122223333"])
	require.True(t, got["grants_access_to "+ps+" -> aws:444455556666"])
	require.True(t, got["grants_admin "+ps+" -> aws:111122223333"])
	require.True(t, got["grants_admin "+ps+" -> aws:444455556666"])
	// Held by the group…
	require.True(t, got["assigned_to sso_group:platform-admins -> "+ps])
	// …the user gets a node, not an assigned_to edge: that rel is declared
	// SSOGroup→SSOPermSet in graphschema and a human_identity source would
	// silently drop at Ladybug load (the label-promotion defect class).
	for k := range got {
		require.NotContains(t, k, "alice")
	}
}

// A user assignee with no email on file still becomes a human_identity node —
// just one that correlate's email join can never match — rather than being
// dropped.
func TestCollectSSO_UserWithoutEmailStillEmitsNode(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-ro"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "ReadOnlyAccess"},
		accounts: map[string][]string{ps: {"111122223333"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{ps: {
			"111122223333": {assignment(ps, "111122223333", "u-2", ssoadmintypes.PrincipalTypeUser)},
		}},
	}
	ids := &fakeIDStore{users: map[string]string{"u-2": "bob"}} // no userEmails entry

	assets, _, _, err := collectSSO(context.Background(), sso, ids, "111122223333", ssoNow, false)
	require.NoError(t, err)

	var humans []asset.Asset
	for _, a := range assets {
		if a.Type == "human_identity" {
			humans = append(humans, a)
		}
	}
	require.Len(t, humans, 1)
	require.Equal(t, "sso_user:bob", humans[0].ID)
	require.Empty(t, humans[0].Domain, "no email on file — node exists but has nothing to join on")
}

// A non-admin permission set grants access to its accounts but must NOT claim
// admin on them.
func TestCollectSSO_NonAdminEmitsNoAdminEdge(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-ro"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "ReadOnlyAccess"},
		managed:  map[string][]string{ps: {"ReadOnlyAccess"}},
		accounts: map[string][]string{ps: {"111122223333"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{ps: {
			"111122223333": {assignment(ps, "111122223333", "g-1", ssoadmintypes.PrincipalTypeGroup)},
		}},
	}
	ids := &fakeIDStore{groups: map[string]string{"g-1": "engineers"}}

	_, edges, _, err := collectSSO(context.Background(), sso, ids, "111122223333", ssoNow, false)
	require.NoError(t, err)

	var access, admin int
	for _, e := range edges {
		switch e.EdgeType {
		case "grants_access_to":
			access++
		case "grants_admin":
			admin++
		}
	}
	require.Equal(t, 1, access)
	require.Zero(t, admin, "ReadOnlyAccess is not admin")
}

// The same group assigned across multiple permission sets is resolved ONCE
// (cached), not per-assignment — the fix for the identitystore throttling that
// made every assignee fall back to its GUID.
func TestCollectSSO_ResolvesPrincipalsOncePerGroup(t *testing.T) {
	const ps1 = "arn:aws:sso:::permissionSet/ssoins-123/ps-1"
	const ps2 = "arn:aws:sso:::permissionSet/ssoins-123/ps-2"
	sameGroup := assignment(ps1, "111122223333", "g-shared", ssoadmintypes.PrincipalTypeGroup)
	sameGroup2 := assignment(ps2, "111122223333", "g-shared", ssoadmintypes.PrincipalTypeGroup)
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps1, ps2},
		names:    map[string]string{ps1: "PS1", ps2: "PS2"},
		accounts: map[string][]string{ps1: {"111122223333"}, ps2: {"111122223333"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{
			ps1: {"111122223333": {sameGroup}},
			ps2: {"111122223333": {sameGroup2}},
		},
	}
	ids := &fakeIDStore{groups: map[string]string{"g-shared": "platform-admins"}}

	assets, edges, _, err := collectSSO(context.Background(), sso, ids, "111122223333", ssoNow, false)
	require.NoError(t, err)

	var permsets int
	for _, a := range assets {
		if a.Type != "sso_permission_set" {
			continue
		}
		permsets++
		require.Equal(t, "group:platform-admins", a.Metadata["assignees"], "resolved name, not GUID")
	}
	require.Equal(t, 2, permsets)
	require.Equal(t, 1, ids.groupCalls, "shared group resolved once and cached, not per permission set")

	// One group holding two permission sets is ONE node with two assignments —
	// that shared node is the point of keying groups by name.
	var assigned int
	for _, e := range edges {
		if e.EdgeType == "assigned_to" {
			assigned++
			require.Equal(t, "sso_group:platform-admins", e.SrcID)
		}
	}
	require.Equal(t, 2, assigned)
}

// A permission set whose admin comes from an INLINE wildcard-action policy (no
// AdministratorAccess managed policy) is still flagged grants_admin.
func TestCollectSSO_InlineWildcardIsAdmin(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-inline"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "PowerCustom"},
		managed:  map[string][]string{ps: {"ReadOnlyAccess"}},
		inline:   map[string]string{ps: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
		accounts: map[string][]string{ps: {"111122223333"}},
	}
	assets, _, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "true", assets[0].Metadata["grants_admin"], "inline Action:* grants admin")
}

func TestIdentityCenterRegions(t *testing.T) {
	// Default: connector region first, then the common SSO home regions, deduped.
	require.Equal(t, []string{"eu-west-1", "us-east-1", "eu-central-1"},
		identityCenterRegions(map[string]string{"region": "eu-west-1"}))
	// Explicit override wins (covers a multi-instance org precisely).
	require.Equal(t, []string{"us-east-1", "eu-west-1"},
		identityCenterRegions(map[string]string{"region": "ap-south-1", "identity_center_regions": "us-east-1, eu-west-1"}))
}

// A non-admin permission set is collected but not flagged.
func TestCollectSSO_NonAdminNotFlagged(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-ro"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "ReadOnly"},
		managed:  map[string][]string{ps: {"ReadOnlyAccess"}},
		accounts: map[string][]string{ps: {"111122223333"}},
	}
	assets, _, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "false", assets[0].Metadata["grants_admin"])
}

// The understatement bug, reproduced: an org that grants SSO access only to
// GROUPS produces zero human identities unless group memberships are expanded.
// An org where every assignee is a group collected no human_identity assets.
func TestCollectSSO_GroupOnlyAssignmentsStillYieldPeople(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-infra"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "InfraEngineerAccess"},
		accounts: map[string][]string{ps: {"210987654321"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{ps: {
			// No PrincipalTypeUser assignment anywhere — the group-only shape.
			"210987654321": {assignment(ps, "210987654321", "g-infra", ssoadmintypes.PrincipalTypeGroup)},
		}},
	}
	ids := &fakeIDStore{
		groups:  map[string]string{"g-infra": "infra-engineers"},
		members: map[string][]string{"g-infra": {"u-alex", "u-sam"}},
		users: map[string]string{
			"u-alex": "alex.example",
			"u-sam":  "sam.example",
		},
		userEmails: map[string]string{
			"u-alex": "alex.example@example.com",
			"u-sam":  "sam.example@example.com",
		},
	}

	assets, _, _, err := collectSSO(context.Background(), sso, ids, "210987654321", ssoNow, false)
	require.NoError(t, err)

	humans := assetsOfType(assets, "human_identity")
	require.Len(t, humans, 2, "the people inside the assigned group are the federated humans")

	byID := map[string]asset.Asset{}
	for _, h := range humans {
		byID[h.ID] = h
	}
	alex, ok := byID["sso_user:alex.example"]
	require.True(t, ok)
	require.Equal(t, "alex.example", alex.Name)
	require.Equal(t, "alex.example@example.com", alex.Domain,
		"the resolved email is the key the identity census deduplicates a person on")
	require.Equal(t, "identity_center", alex.Metadata["source"])
	require.Equal(t, "infra-engineers", alex.Metadata["sso_group"],
		"why this person has cloud access must stay auditable")
	require.Equal(t, asset.ProviderAWS, alex.Provider)
	require.Contains(t, byID, "sso_user:sam.example")
}

// A person in several groups is one identity, and costs one DescribeUser —
// the same caching discipline the assignee path already needed to avoid being
// throttled into GUID fallbacks.
func TestCollectSSO_PersonInMultipleGroupsEmittedOnce(t *testing.T) {
	const psA = "arn:aws:sso:::permissionSet/ssoins-123/ps-a"
	const psB = "arn:aws:sso:::permissionSet/ssoins-123/ps-b"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{psA, psB},
		names:    map[string]string{psA: "A", psB: "B"},
		accounts: map[string][]string{psA: {"1"}, psB: {"1"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{
			psA: {"1": {assignment(psA, "1", "g-a", ssoadmintypes.PrincipalTypeGroup)}},
			psB: {"1": {assignment(psB, "1", "g-b", ssoadmintypes.PrincipalTypeGroup)}},
		},
	}
	ids := &fakeIDStore{
		groups: map[string]string{"g-a": "group-a", "g-b": "group-b"},
		members: map[string][]string{
			"g-a": {"u-1"},
			"g-b": {"u-1"},
		},
		users: map[string]string{"u-1": "alice"},
	}

	assets, _, _, err := collectSSO(context.Background(), sso, ids, "1", ssoNow, false)
	require.NoError(t, err)

	humans := assetsOfType(assets, "human_identity")
	require.Len(t, humans, 1, "one person in two groups is one identity")
	require.Equal(t, "sso_user:alice", humans[0].ID)
}

// A membership lookup that fails must lose only that group's members, and must
// be recorded rather than swallowed — an empty people list has to be
// distinguishable from "the API refused".
func TestCollectSSO_MembershipFailureIsBestEffort(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-a"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "A"},
		accounts: map[string][]string{ps: {"1"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{
			ps: {"1": {assignment(ps, "1", "g-a", ssoadmintypes.PrincipalTypeGroup)}},
		},
	}
	ids := &fakeIDStore{
		groups:        map[string]string{"g-a": "group-a"},
		membershipErr: errors.New("AccessDeniedException"),
	}

	assets, _, _, err := collectSSO(context.Background(), sso, ids, "1", ssoNow, false)
	require.NoError(t, err, "a refused membership lookup is a partial result, not a collection failure")
	require.Empty(t, assetsOfType(assets, "human_identity"))
	// The permission set and its group are still collected.
	require.Len(t, assetsOfType(assets, "sso_permission_set"), 1)
	require.Len(t, assetsOfType(assets, "sso_group"), 1)
}

// A group whose display name could not be resolved has no GUID handle worth
// keeping, so it contributes no phantom members.
func TestCollectSSO_UnresolvedGroupYieldsNoMembers(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-a"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "A"},
		accounts: map[string][]string{ps: {"1"}},
		assignments: map[string]map[string][]ssoadmintypes.AccountAssignment{
			ps: {"1": {assignment(ps, "1", "g-a", ssoadmintypes.PrincipalTypeGroup)}},
		},
	}
	// groups is empty: DescribeGroup returns an empty DisplayName, so the label
	// falls back to the GUID and no group id is recorded.
	ids := &fakeIDStore{members: map[string][]string{"g-a": {"u-1"}}, users: map[string]string{"u-1": "alice"}}

	assets, _, _, err := collectSSO(context.Background(), sso, ids, "1", ssoNow, false)
	require.NoError(t, err)
	require.Empty(t, assetsOfType(assets, "human_identity"))
	require.Zero(t, ids.membershipCalls, "no resolved group means nothing to expand")
}

// The member-account defect: ListInstances succeeds in a member account
// (AWS returns the org's Identity Center instance to every account, not only
// the admin one), and ListPermissionSets is the actual boundary — a member
// account gets AccessDeniedException there. That must be a clean no-op: no
// error, and nothing collected, so it never sets result.Partial upstream and
// never blocks deletion reconciliation / finding auto-resolution.
//
// ownerAccountID is deliberately a DIFFERENT account than the one calling
// collectSSO, so this pins the confirmed-non-owner branch specifically (see
// TestCollectSSO_OwnerAccountAccessDeniedIsAnError and
// TestCollectSSO_UnknownOwnerAccessDeniedIsAnError for the other two branches
// of the ownership check).
func TestCollectSSO_MemberAccountAccessDeniedIsNoop(t *testing.T) {
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		ownerAccountID:  "999900001111", // NOT the calling account below
		listPermSetsErr: &ssoSmithyAPIErr{code: "AccessDeniedException"},
	}
	assets, edges, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err, "a confirmed member account's AccessDenied on ListPermissionSets is a coverage gap, not a failure")
	require.Empty(t, assets)
	require.Empty(t, edges)
}

// The regression case: when THIS account IS the Identity Center owner (OwnerAccountId ==
// accountID), an AccessDeniedException on ListPermissionSets is not a
// member-account fact, it is a permissions regression on the one account that
// must never go quiet. It MUST be returned as a real error so the sweep goes
// Partial — silently no-oping this would delete the entire human-access layer
// (an Identity Center instance can hold hundreds of sso_permission_set and
// sso_group assets).
func TestCollectSSO_OwnerAccountAccessDeniedIsAnError(t *testing.T) {
	const accountID = "111122223333"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		ownerAccountID:  accountID, // THIS account owns the instance
		listPermSetsErr: &ssoSmithyAPIErr{code: "AccessDeniedException"},
	}
	_, _, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, accountID, ssoNow, false)
	require.Error(t, err, "AccessDenied on the owning account is a regression, not a member-account no-op")
}

// Unknown ownership (AWS omitted OwnerAccountId, or it came back empty) must
// fail CLOSED toward the error path, not toward the no-op — unmeasured is
// not zero. Treating an unknown owner as "confirmed not the
// owner" would risk silently deleting the human-access layer on whichever
// account happens to hit this; treating it as "possibly the owner" only
// risks a visible, recoverable Partial connector.
func TestCollectSSO_UnknownOwnerAccessDeniedIsAnError(t *testing.T) {
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		// ownerAccountID left unset: AWS omitted OwnerAccountId.
		listPermSetsErr: &ssoSmithyAPIErr{code: "AccessDeniedException"},
	}
	_, _, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.Error(t, err, "unknown ownership must not be treated as a confirmed member-account no-op")
}

// The real SDK error shape: AWS SDK errors surface wrapped in
// *smithy.OperationError, not as a bare smithy.APIError. isSSONoOpErr must
// still classify through the wrapper (errors.As walks Unwrap), and the
// ownership branching above it must behave identically to the bare-error
// tests. Pinned per reviewer finding: this was previously untested.
func TestCollectSSO_WrappedOperationErrorStillClassifiesCorrectly(t *testing.T) {
	wrapped := &smithy.OperationError{
		ServiceID: "SSOAdmin", OperationName: "ListPermissionSets",
		Err: &ssoSmithyAPIErr{code: "AccessDeniedException"},
	}

	// Confirmed member account: still a clean no-op through the wrapper.
	memberSSO := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		ownerAccountID:  "999900001111",
		listPermSetsErr: wrapped,
	}
	_, _, _, err := collectSSO(context.Background(), memberSSO, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err, "a wrapped AccessDeniedException on a confirmed member account must still no-op")

	// Owner account: still a real error through the wrapper.
	ownerSSO := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		ownerAccountID:  "111122223333",
		listPermSetsErr: wrapped,
	}
	_, _, _, err = collectSSO(context.Background(), ownerSSO, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.Error(t, err, "a wrapped AccessDeniedException on the owning account must still be a regression error")
}

// A genuine transient failure on ListPermissionSets (throttling, a 500, a
// timeout) must still be returned as an error — the sweep needs to be flagged
// Partial so deletion reconciliation does not run against an incomplete
// collection.
func TestCollectSSO_TransientErrorOnListPermissionSetsIsStillAnError(t *testing.T) {
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		listPermSetsErr: &ssoSmithyAPIErr{code: "ThrottlingException"},
	}
	_, _, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.Error(t, err, "a transient error is not the member-account no-op and must not be swallowed")

	// A plain (non-API) error — e.g. a network timeout — must also still be
	// returned: isSSONoOpErr only recognizes a genuine smithy.APIError.
	sso2 := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		listPermSetsErr: errors.New("context deadline exceeded"),
	}
	_, _, _, err = collectSSO(context.Background(), sso2, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.Error(t, err)
}

// The delegated-admin (or management) account's success path is unaffected by
// the carve-out: ListPermissionSets succeeding proves this account is the
// admin, and its permission-set assets are still collected in full.
func TestCollectSSO_DelegatedAdminSuccessPathUnaffected(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-admin"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "AdministratorAccess"},
		managed:  map[string][]string{ps: {"AdministratorAccess"}},
		accounts: map[string][]string{ps: {"111122223333"}},
	}
	assets, _, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.Len(t, assetsOfType(assets, "sso_permission_set"), 1, "the admin account's own data must still be collected")
}

// A denial that happens AFTER ListPermissionSets already succeeded (proving
// this is the admin account) must still be a real, returned error — that is
// the delegated-admin distinction the carve-out must preserve: it only
// no-ops the FIRST admin-boundary call, never a failure downstream of a
// proven-admin account.
func TestCollectSSO_DenialAfterProvenAdminIsStillAnError(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-admin"
	failingSSO := &failingAssignmentsSSO{fakeSSO: fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "AdministratorAccess"},
	}}
	_, _, _, err := collectSSO(context.Background(), failingSSO, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.Error(t, err, "an error after ListPermissionSets succeeded must propagate, not no-op")
}

// failingAssignmentsSSO wraps fakeSSO to force ListAccountsForProvisionedPermissionSet
// to fail — a call reachable only once ListPermissionSets has already
// succeeded, i.e. once this account is proven to be the admin account.
type failingAssignmentsSSO struct {
	fakeSSO
}

func (f *failingAssignmentsSSO) ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	return nil, &ssoSmithyAPIErr{code: "AccessDeniedException"}
}

// TestCollectSSO_ThreeWayDenialRule pins the exact rule the delegated-admin
// fix adds at the ListPermissionSets denial site:
//   - previously PROVEN sso_admin (persisted across sweeps) → the denial is a
//     REGRESSION → error, regardless of what ownership says. This is what
//     closes the delegated-admin gap: OwnerAccountId never reflects
//     delegation, so a delegated admin reads ownerKnown&&!isOwner on every
//     sweep including the one where it actually regresses.
//   - never proven AND confirmed non-owner → member no-op (today's behaviour,
//     unchanged).
//   - never proven AND unknown ownership → fails closed to error (today's
//     behaviour, unchanged).
func TestCollectSSO_ThreeWayDenialRule(t *testing.T) {
	const accountID = "111122223333"
	denied := &ssoSmithyAPIErr{code: "AccessDeniedException"}

	tests := []struct {
		name           string
		alreadyProven  bool
		ownerAccountID string // "" = unknown
		wantErr        bool
	}{
		{
			name:           "proven capability + looks like a confirmed member -> regression, error",
			alreadyProven:  true,
			ownerAccountID: "999900001111", // NOT accountID — would no-op without alreadyProven
			wantErr:        true,
		},
		{
			name:           "proven capability + unknown owner -> still error",
			alreadyProven:  true,
			ownerAccountID: "",
			wantErr:        true,
		},
		{
			name:           "never proven + confirmed non-owner -> member no-op",
			alreadyProven:  false,
			ownerAccountID: "999900001111",
			wantErr:        false,
		},
		{
			name:           "never proven + unknown owner -> fails closed, error",
			alreadyProven:  false,
			ownerAccountID: "",
			wantErr:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sso := &fakeSSO{
				instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
				ownerAccountID:  tt.ownerAccountID,
				listPermSetsErr: denied,
			}
			assets, edges, _, err := collectSSO(context.Background(), sso, &fakeIDStore{}, accountID, ssoNow, tt.alreadyProven)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Empty(t, assets)
				require.Empty(t, edges)
			}
		})
	}
}

// A successful ListPermissionSets call proves the sso_admin capability for
// THIS sweep, independent of alreadyProven (which is about prior sweeps) —
// internal/jobs/sync.go persists this so a future denial on this exact
// account is judged a regression.
func TestCollectSSO_SuccessMarksCapabilityProven(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-admin"
	sso := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		permsets: []string{ps},
		names:    map[string]string{ps: "AdministratorAccess"},
		accounts: map[string][]string{ps: {"111122223333"}},
	}
	_, _, proven, err := collectSSO(context.Background(), sso, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.True(t, proven, "a successful ListPermissionSets call must mark sso_admin proven")
}

// The no-instance clean no-op and the confirmed-member no-op must NOT report
// proven — nothing was ever proven, and the caller (sync.go) must not
// persist a capability that was never actually exercised successfully.
func TestCollectSSO_NoOpPathsDoNotMarkProven(t *testing.T) {
	_, _, proven, err := collectSSO(context.Background(), &fakeSSO{}, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.False(t, proven, "no Identity Center instance at all must not report proven")

	memberSSO := &fakeSSO{
		instanceARN: "arn:aws:sso:::instance/ssoins-123", storeID: "d-123",
		ownerAccountID:  "999900001111",
		listPermSetsErr: &ssoSmithyAPIErr{code: "AccessDeniedException"},
	}
	_, _, proven, err = collectSSO(context.Background(), memberSSO, &fakeIDStore{}, "111122223333", ssoNow, false)
	require.NoError(t, err)
	require.False(t, proven, "a confirmed member-account no-op must not report proven")
}

func assetsOfType(assets []asset.Asset, typ string) []asset.Asset {
	var out []asset.Asset
	for _, a := range assets {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

// TestCollectIdentityCenter_RegressionSurvivesASucceedingRegion is the guard on
// the aggregation hole: collectIdentityCenter surfaces firstErr only when
// NOTHING was collected, which is right for a region the role cannot reach and
// wrong for a proven-account denial. The Identity Center probe spans several
// regions, so before errSSOAdminRegression a single other region answering with
// one permission set would drop the regression, leave the connector
// non-Partial, and let that region's SSO inventory vanish from the sweep
// silently — the exact failure the proven-capability signal exists to make loud.
func TestCollectIdentityCenter_RegressionSurvivesASucceedingRegion(t *testing.T) {
	// A regression error must compare true through the wrapping collectSSO
	// applies, and must remain distinguishable from a plain denial.
	regression := fmt.Errorf("collectSSO: %w: %w", errSSOAdminRegression, errAccessDenied())
	require.ErrorIs(t, regression, errSSOAdminRegression,
		"the regression sentinel must survive collectSSO's wrapping or the aggregation cannot tell it apart")

	plain := fmt.Errorf("collectSSO: %w", errAccessDenied())
	require.NotErrorIs(t, plain, errSSOAdminRegression,
		"an ordinary denial must NOT read as a regression, or every member account would flag Partial — "+
			"the member-account Partial bug this file exists to keep closed")
}

// errAccessDenied builds the smithy API error shape isSSONoOpErr recognises.
func errAccessDenied() error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}
}

// An unreadable inline policy leaves grants_admin unknown (absent) unless the
// managed policies already proved admin — "false" would close a real
// admin-permission-set finding on a throttle.
func TestPermissionSetAsset_InlineErrorLeavesAdminUnknown(t *testing.T) {
	const ps = "arn:aws:sso:::permissionSet/ssoins-123/ps-1"
	f := &fakeSSO{instanceARN: "arn:aws:sso:::instance/ssoins-123", inlineErr: apiErr{code: "ThrottlingException"}}
	resolver := newPrincipalResolver(&fakeIDStore{}, "d-1")

	a, _, _, err := permissionSetAsset(context.Background(), f, resolver, f.instanceARN, ps, "111122223333", ssoNow)
	require.NoError(t, err)
	_, present := a.Metadata["grants_admin"]
	require.False(t, present)

	f.managed = map[string][]string{ps: {"AdministratorAccess"}}
	a, _, _, err = permissionSetAsset(context.Background(), f, resolver, f.instanceARN, ps, "111122223333", ssoNow)
	require.NoError(t, err)
	require.Equal(t, "true", a.Metadata["grants_admin"], "an observed admin grant stands")
}
