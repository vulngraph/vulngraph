package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeIAM returns one role (with an attached managed policy + a trust policy)
// and one user (with an inline policy).
type fakeIAM struct{}

func (fakeIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	trust := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"ec2.amazonaws.com"}}]}`)
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: awssdk.String("admin-role"), Arn: awssdk.String("arn:aws:iam::1:role/admin-role"),
		Path: awssdk.String("/"), AssumeRolePolicyDocument: awssdk.String(trust),
	}}}, nil
}
func (fakeIAM) ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamtypes.AttachedPolicy{{
		PolicyName: awssdk.String("AdministratorAccess"), PolicyArn: awssdk.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	}}}, nil
}
func (fakeIAM) ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error) {
	return &iam.ListRolePoliciesOutput{}, nil
}
func (fakeIAM) GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error) {
	return &iam.GetRolePolicyOutput{}, nil
}
func (fakeIAM) ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{Users: []iamtypes.User{{
		UserName: awssdk.String("dev"), Arn: awssdk.String("arn:aws:iam::1:user/dev"), Path: awssdk.String("/"),
	}}}, nil
}
func (fakeIAM) ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error) {
	return &iam.ListAttachedUserPoliciesOutput{}, nil
}
func (fakeIAM) ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	return &iam.ListUserPoliciesOutput{PolicyNames: []string{"inline-s3"}}, nil
}
func (fakeIAM) GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error) {
	doc := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	return &iam.GetUserPolicyOutput{PolicyName: awssdk.String("inline-s3"), PolicyDocument: awssdk.String(doc)}, nil
}
func (fakeIAM) GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	return &iam.GetPolicyOutput{Policy: &iamtypes.Policy{DefaultVersionId: awssdk.String("v1")}}, nil
}
func (fakeIAM) GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	doc := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(doc)}}, nil
}
func (fakeIAM) ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	return &iam.ListMFADevicesOutput{}, nil // no MFA devices in tests
}
func (fakeIAM) GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	return nil, &iamtypes.NoSuchEntityException{} // no console access in tests
}
func (fakeIAM) ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{}, nil // no access keys in default fake
}

func (fakeIAM) GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	return &iam.GetAccessKeyLastUsedOutput{}, nil // no last-used in default fake
}

func (fakeIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	// A successful describe of a role AWS reports as never used: no boundary, no
	// RoleLastUsed. Distinct from a GetRole FAILURE (see failingGetRoleIAM).
	return &iam.GetRoleOutput{Role: &iamtypes.Role{}}, nil
}

func (fakeIAM) GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	return &iam.GetUserOutput{User: &iamtypes.User{}}, nil
}

func (fakeIAM) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	return &iam.GenerateServiceLastAccessedDetailsOutput{}, nil
}

func (fakeIAM) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	return &iam.GetServiceLastAccessedDetailsOutput{}, nil
}
func (fakeIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{}, nil
}

func decodePolicies(t *testing.T, meta string) []policyDoc {
	t.Helper()
	var docs []policyDoc
	require.NoError(t, json.Unmarshal([]byte(meta), &docs))
	return docs
}

func TestCollectRoles_PoliciesAndTrust(t *testing.T) {
	c := fakeIAM{}
	cache := newManagedPolicyCache(c)
	assets, edges, err := collectRoles(context.Background(), c, cache, "1", time.Now())
	require.NoError(t, err)

	// Expect one iam_role asset plus one iam_policy asset for AdministratorAccess.
	var roleAsset, policyAsset *asset.Asset
	for i := range assets {
		switch assets[i].Type {
		case "iam_role":
			roleAsset = &assets[i]
		case "iam_policy":
			policyAsset = &assets[i]
		}
	}
	require.NotNil(t, roleAsset, "iam_role asset emitted")
	require.NotNil(t, policyAsset, "iam_policy asset emitted")

	r := *roleAsset
	require.Equal(t, "arn:aws:iam::1:role/admin-role", r.ID)
	// GetRole succeeded and reported no last-used date → sentinel, marked observed.
	require.Equal(t, "9999", r.Metadata["last_used_days"])
	require.Equal(t, "true", r.Metadata["last_used_observed"])

	// This role's trust policy grants ec2.amazonaws.com, not a wildcard, and
	// carries no MFA condition. Both keys must be the explicit negative — a
	// clean role read as "unevaluated" collapses aws-iam-public-trust-policy's
	// coverage: writing the key only on the positive case makes "we checked and it's not public" identical to "we have no trust
	// document for this role."
	require.Equal(t, "false", r.Metadata["public_trust"])
	require.Equal(t, "false", r.Metadata["mfa_required_to_assume"])

	// Verify the iam_policy asset metadata fields.
	require.Equal(t, "AdministratorAccess", policyAsset.Metadata["policy_name"])
	require.Equal(t, "arn:aws:iam::aws:policy/AdministratorAccess", policyAsset.Metadata["policy_arn"])
	require.Equal(t, "1", policyAsset.Metadata["account_id"])

	// Verify has_policy edge from role to policy.
	require.Len(t, edges, 1)
	require.Equal(t, r.ID, edges[0].SrcID)
	require.Equal(t, "iam_role", edges[0].SrcType)
	require.Equal(t, policyAsset.ID, edges[0].DstID)
	require.Equal(t, "iam_policy", edges[0].DstType)
	require.Equal(t, "has_policy", edges[0].EdgeType)

	docs := decodePolicies(t, r.Metadata["policies"])
	// AdministratorAccess (managed, identity) + trust policy.
	var haveAdmin, haveTrust bool
	for _, d := range docs {
		if d.Managed && d.Name == "AdministratorAccess" {
			haveAdmin = true
			require.Contains(t, d.Document, `"Action":"*"`) // managed doc resolved + decoded
		}
		if d.Type == "trust" {
			haveTrust = true
			require.Contains(t, d.Document, "sts:AssumeRole")
		}
	}
	require.True(t, haveAdmin, "attached managed policy document resolved")
	require.True(t, haveTrust, "trust policy captured")
}

func TestCollectRoles_LastUsedDays(t *testing.T) {
	now := time.Now()
	lastUsed := now.Add(-48 * time.Hour)
	c := &lastUsedIAM{fakeIAM: fakeIAM{}, lastUsedDate: &lastUsed}
	assets, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", now)
	require.NoError(t, err)
	var roleAsset *asset.Asset
	for i := range assets {
		if assets[i].Type == "iam_role" {
			roleAsset = &assets[i]
			break
		}
	}
	require.NotNil(t, roleAsset, "iam_role asset emitted")
	require.Equal(t, "2", roleAsset.Metadata["last_used_days"])
}

type lastUsedIAM struct {
	fakeIAM
	lastUsedDate *time.Time
}

func (c *lastUsedIAM) ListRoles(ctx context.Context, in *iam.ListRolesInput, o ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	out, err := c.fakeIAM.ListRoles(ctx, in, o...)
	if err != nil || out == nil {
		return out, err
	}
	for i := range out.Roles {
		out.Roles[i].RoleLastUsed = &iamtypes.RoleLastUsed{LastUsedDate: c.lastUsedDate}
	}
	return out, nil
}

// failingGetRoleIAM is the throttled / AccessDenied case: every other IAM call
// works, GetRole does not.
type failingGetRoleIAM struct{ fakeIAM }

func (failingGetRoleIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return nil, errors.New("Throttling: Rate exceeded")
}

// A failed GetRole must leave last_used_days ABSENT. Writing the 9999 sentinel
// instead made an API failure indistinguishable from an observed never-used role,
// and enrich's adminRightSizing then demoted the finding by -6 citing "no recorded
// use" — an API failure scored as a fact.
func TestCollectRoles_GetRoleFailure_OmitsLastUsed(t *testing.T) {
	c := failingGetRoleIAM{}
	assets, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err, "a GetRole failure never fails role collection")
	var roleAsset *asset.Asset
	for i := range assets {
		if assets[i].Type == "iam_role" {
			roleAsset = &assets[i]
			break
		}
	}
	require.NotNil(t, roleAsset, "iam_role asset still emitted")
	require.NotContains(t, roleAsset.Metadata, "last_used_days",
		"unknown must stay absent, never the never-used sentinel")
	require.NotContains(t, roleAsset.Metadata, "last_used_observed")

	det := roleDetails(context.Background(), c, "admin-role", time.Now())
	require.False(t, det.observed)
	require.Empty(t, det.lastUsedDays)
}

// A real last-used date on the ListRoles page beats GetRole's "never used" —
// an observed date is never overwritten by an observed absence.
func TestCollectRoles_ListRolesDateBeatsNeverUsed(t *testing.T) {
	now := time.Now()
	lastUsed := now.Add(-48 * time.Hour)
	c := &lastUsedIAM{fakeIAM: fakeIAM{}, lastUsedDate: &lastUsed}
	assets, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", now)
	require.NoError(t, err)
	for _, a := range assets {
		if a.Type != "iam_role" {
			continue
		}
		require.Equal(t, "2", a.Metadata["last_used_days"])
		require.Equal(t, "true", a.Metadata["last_used_observed"])
	}
}

func TestCollectUsers_InlinePolicyDecoded(t *testing.T) {
	c := fakeIAM{}
	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	require.Len(t, users, 1)
	u := users[0]
	docs := decodePolicies(t, u.Metadata["policies"])
	require.Len(t, docs, 1)
	require.Equal(t, "inline-s3", docs[0].Name)
	require.Contains(t, docs[0].Document, "s3:GetObject") // URL-decoded
	// No active access keys in default fake.
	require.Equal(t, "0", u.Metadata["access_key_age_days"])
}

func TestCollectUsers_AccessKeyAgeDays(t *testing.T) {
	now := time.Now()
	created := now.Add(-10 * 24 * time.Hour)
	c := &activeKeyIAM{fakeIAM: fakeIAM{}, createDate: &created}
	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", now)
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "10", users[0].Metadata["access_key_age_days"])
}

type activeKeyIAM struct {
	fakeIAM
	createDate  *time.Time
	lastUsed    *time.Time // nil = key never used
	lastUsedErr error      // when set, GetAccessKeyLastUsed fails (lookup unknown)
}

func (c *activeKeyIAM) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	akid := "AKIAEXAMPLE"
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: []iamtypes.AccessKeyMetadata{
		{Status: iamtypes.StatusTypeActive, CreateDate: c.createDate, AccessKeyId: &akid},
	}}, nil
}

func (c *activeKeyIAM) GetAccessKeyLastUsed(_ context.Context, _ *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	if c.lastUsedErr != nil {
		return nil, c.lastUsedErr
	}
	return &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{LastUsedDate: c.lastUsed}}, nil
}

// A lookup ERROR on an old active key must NOT be misread as never-used-and-stale
// (that produced a High false-positive). Stale requires a PROVEN last-used state.
func TestCollectUsers_LastUsedErrorNotStale(t *testing.T) {
	now := time.Now()
	old := now.Add(-200 * 24 * time.Hour)
	c := &activeKeyIAM{createDate: &old, lastUsedErr: errors.New("throttled")}
	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", now)
	require.NoError(t, err)
	require.Len(t, users, 1)
	// Unknown, not "false"/"-1": either would read as an observation and close
	// a real stale-key finding on a throttle.
	_, stalePresent := users[0].Metadata["access_key_stale"]
	require.False(t, stalePresent, "unknown last-used must neither flag stale nor clear it")
	_, lastUsedPresent := users[0].Metadata["access_key_last_used_days"]
	require.False(t, lastUsedPresent)
	require.Equal(t, "1", users[0].Metadata["active_key_count"], "the key listing itself succeeded")
}

// degradedIAM fails individual IAM reads, for the absent-means-unknown rules.
type degradedIAM struct {
	fakeIAM
	loginErr, mfaErr, keysErr, attachedErr, policyErr error
	getPolicyCalls                                    int
}

func (d *degradedIAM) GetLoginProfile(ctx context.Context, in *iam.GetLoginProfileInput, o ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error) {
	if d.loginErr != nil {
		return nil, d.loginErr
	}
	return d.fakeIAM.GetLoginProfile(ctx, in, o...)
}
func (d *degradedIAM) ListMFADevices(ctx context.Context, in *iam.ListMFADevicesInput, o ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error) {
	if d.mfaErr != nil {
		return nil, d.mfaErr
	}
	return d.fakeIAM.ListMFADevices(ctx, in, o...)
}
func (d *degradedIAM) ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, o ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if d.keysErr != nil {
		return nil, d.keysErr
	}
	return d.fakeIAM.ListAccessKeys(ctx, in, o...)
}
func (d *degradedIAM) ListAttachedRolePolicies(ctx context.Context, in *iam.ListAttachedRolePoliciesInput, o ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if d.attachedErr != nil {
		return nil, d.attachedErr
	}
	return d.fakeIAM.ListAttachedRolePolicies(ctx, in, o...)
}
func (d *degradedIAM) ListUserPolicies(ctx context.Context, in *iam.ListUserPoliciesInput, o ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error) {
	if d.attachedErr != nil {
		return nil, d.attachedErr
	}
	return d.fakeIAM.ListUserPolicies(ctx, in, o...)
}
func (d *degradedIAM) GetPolicy(ctx context.Context, in *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	d.getPolicyCalls++
	if d.policyErr != nil {
		return nil, d.policyErr
	}
	return d.fakeIAM.GetPolicy(ctx, in, o...)
}

// Only NoSuchEntity proves "no console password"; any other GetLoginProfile
// error, and any ListMFADevices / ListAccessKeys error, leaves the keys absent
// — "false" would auto-resolve real no-MFA / console findings.
func TestCollectUsers_FailedCredentialReadsOmitKeys(t *testing.T) {
	c := &degradedIAM{
		loginErr: apiErr{code: "Throttling"},
		mfaErr:   apiErr{code: "AccessDenied"},
		keysErr:  apiErr{code: "Throttling"},
	}
	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	require.Len(t, users, 1)
	for _, k := range []string{"console_access", "mfa_enabled", "inactive", "active_key_count", "access_key_age_days", "access_key_stale", "access_key_last_used_days", "access_key_max_idle_days"} {
		_, present := users[0].Metadata[k]
		require.False(t, present, "%s must be absent (unknown) after a failed read", k)
	}

	// The NoSuchEntity answer IS an observation.
	c = &degradedIAM{}
	users, _, err = collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	m := users[0].Metadata
	require.Equal(t, "false", m["console_access"])
	require.Equal(t, "false", m["mfa_enabled"])
	require.Equal(t, "true", m["inactive"])
	require.Equal(t, "0", m["active_key_count"])
}

// A policy listing that failed leaves the policy set incomplete: the policies
// key is omitted rather than published as the principal's whole grant.
func TestCollectPrincipals_IncompletePolicySetOmitted(t *testing.T) {
	c := &degradedIAM{attachedErr: apiErr{code: "Throttling"}}
	roles, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	for _, a := range roles {
		if a.Type == "iam_role" {
			_, present := a.Metadata["policies"]
			require.False(t, present)
			_, admin := a.Metadata["admin"]
			require.False(t, admin, "no admin verdict either way from a partial read")
		}
	}

	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	_, present := users[0].Metadata["policies"]
	require.False(t, present)
}

// A managed policy document that could not be fetched marks the set
// incomplete, and the failure is not cached — the next principal retries.
func TestManagedPolicyCache_FailuresNotCached(t *testing.T) {
	c := &degradedIAM{policyErr: apiErr{code: "Throttling"}}
	cache := newManagedPolicyCache(c)
	arn := "arn:aws:iam::aws:policy/AdministratorAccess"
	_, ok := cache.document(context.Background(), arn)
	require.False(t, ok)
	c.policyErr = nil
	doc, ok := cache.document(context.Background(), arn)
	require.True(t, ok)
	require.NotEmpty(t, doc)
	require.Equal(t, 2, c.getPolicyCalls, "a failed fetch must be retried, not served from cache")

	c.policyErr = apiErr{code: "Throttling"}
	roles, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	for _, a := range roles {
		if a.Type == "iam_role" {
			_, present := a.Metadata["policies"]
			require.False(t, present, "an unreadable managed document makes the set incomplete")
		}
	}
}

func TestCollectUsers_AccessKeyLastUsedAndStale(t *testing.T) {
	now := time.Now()
	old := now.Add(-200 * 24 * time.Hour)  // key created 200d ago
	young := now.Add(-10 * 24 * time.Hour) // key created 10d ago
	idle := now.Add(-120 * 24 * time.Hour) // last used 120d ago
	recent := now.Add(-5 * 24 * time.Hour) // last used 5d ago

	tests := []struct {
		name             string
		create, lastUsed *time.Time
		wantLastUsedDays string
		wantStale        string
		wantMaxIdle      string
	}{
		{"idle old key is stale", &old, &idle, "120", "true", "120"},
		{"never-used old key is stale", &old, nil, "-1", "true", "200"},
		{"recently-used old key not stale", &old, &recent, "5", "false", "5"},
		{"never-used young key not stale", &young, nil, "-1", "false", "10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &activeKeyIAM{createDate: tt.create, lastUsed: tt.lastUsed}
			users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", now)
			require.NoError(t, err)
			require.Len(t, users, 1)
			require.Equal(t, tt.wantLastUsedDays, users[0].Metadata["access_key_last_used_days"])
			require.Equal(t, tt.wantStale, users[0].Metadata["access_key_stale"])
			require.Equal(t, tt.wantMaxIdle, users[0].Metadata["access_key_max_idle_days"], "a never-used key is idle for its whole age")
		})
	}
}

func TestManagedPolicyCache_FetchesOnce(t *testing.T) {
	c := &countingIAM{fakeIAM: fakeIAM{}}
	cache := newManagedPolicyCache(c)
	_, _ = cache.document(context.Background(), "arn:aws:iam::aws:policy/AdministratorAccess")
	_, _ = cache.document(context.Background(), "arn:aws:iam::aws:policy/AdministratorAccess")
	require.Equal(t, 1, c.getPolicyCalls, "second lookup served from cache")
}

type countingIAM struct {
	fakeIAM
	getPolicyCalls int
}

func (c *countingIAM) GetPolicy(ctx context.Context, in *iam.GetPolicyInput, o ...func(*iam.Options)) (*iam.GetPolicyOutput, error) {
	c.getPolicyCalls++
	return c.fakeIAM.GetPolicy(ctx, in, o...)
}

func TestIsAdminish(t *testing.T) {
	tests := []struct {
		name string
		pols []policyDoc
		want bool
	}{
		{"unread administrator document cannot prove admin", []policyDoc{{Name: "AdministratorAccess", Type: "identity", Managed: true}}, false},
		{"wildcard inline allow", []policyDoc{{Name: "inline", Type: "identity", Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}}, true},
		{"wildcard action array", []policyDoc{{Name: "inline", Type: "identity", Document: `{"Statement":{"Effect":"Allow","Action":["*"],"Resource":"*"}}`}}, true},
		{"scoped policy is not admin", []policyDoc{{Name: "scoped", Type: "identity", Document: `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`}}, false},
		{"wildcard but Deny is not admin", []policyDoc{{Name: "deny", Type: "identity", Document: `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`}}, false},
		{"trust policy wildcard ignored", []policyDoc{{Name: "x-trust", Type: "trust", Document: `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}`}}, false},
		// Regression: AdministratorAccess attached alongside a separate deny-all
		// policy must NOT be flagged admin — the deny-all wins globally, same as
		// real AWS evaluation, even though it lives in a different policy document
		// than the grant. This was the bug: isAdminish only ever inspected
		// AdministratorAccess/wildcard grants and never looked for a sibling deny.
		{"AdministratorAccess neutralized by sibling deny-all", []policyDoc{
			{Name: "AdministratorAccess", Type: "identity", Managed: true, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			{Name: "deny-all", Type: "identity", Document: `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`},
		}, false},
		{"wildcard allow neutralized by sibling deny-all", []policyDoc{
			{Name: "inline-admin", Type: "identity", Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			{Name: "deny-all", Type: "identity", Document: `{"Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"]}]}`},
		}, false},
		// Even a narrow deny prevents proof of unrestricted admin authority.
		{"scoped deny prevents unrestricted admin", []policyDoc{
			{Name: "AdministratorAccess", Type: "identity", Managed: true, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			{Name: "deny-s3-only", Type: "identity", Document: `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`},
		}, false},
		// An unevaluated condition leaves authority uncertain.
		{"MFA-conditional deny-all prevents proven admin", []policyDoc{
			{Name: "AdministratorAccess", Type: "identity", Managed: true, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			{Name: "deny-without-mfa", Type: "identity", Document: `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`},
		}, false},
		// A deny-all sitting in the trust (assume-role) policy governs who may
		// assume the role, not what the role may do once assumed — it must not
		// suppress an identity policy's real admin grant.
		{"deny-all in trust policy does not neutralize identity admin grant", []policyDoc{
			{Name: "AdministratorAccess", Type: "identity", Managed: true, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			{Name: "role-trust", Type: "trust", Document: `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Principal":"*"}]}`},
		}, true},
		// A permission boundary's deny-all genuinely caps the role down to
		// nothing, same as a sibling identity-policy deny-all — boundaries are
		// deliberately still counted (unlike the Allow-grant scan, which excludes
		// them since a boundary never grants on its own).
		{"deny-all in permission boundary neutralizes admin", []policyDoc{
			{Name: "AdministratorAccess", Type: "identity", Managed: true, Document: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			{Name: "deny-boundary", Type: "boundary", Document: `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`},
		}, false},
		{"empty", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isAdminish(t.Context(), "", tt.pols))
		})
	}
}

func TestTrustRequiresMFA(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{"single Allow with Bool MFA", `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:x"},"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`, true},
		{"BoolIfExists MFA admits absent key", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:x"},"Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"true"}}}]}`, false},
		{"MFA value as array", `{"Statement":[{"Effect":"Allow","Condition":{"Bool":{"aws:MultiFactorAuthPresent":["true"]}}}]}`, true},
		{"one Allow gated, one not → false", `{"Statement":[{"Effect":"Allow","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},{"Effect":"Allow","Principal":{"AWS":"arn:y"}}]}`, false},
		{"no condition → false", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:x"}}]}`, false},
		{"MFA false value → false", `{"Statement":[{"Effect":"Allow","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}]}`, false},
		{"Deny with MFA ignored, no Allow → false", `{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, trustRequiresMFA(tt.doc))
		})
	}
}

func TestTrustFederation(t *testing.T) {
	tests := []struct {
		name     string
		doc      string
		wantKind string
	}{
		{"SAML provider", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:saml-provider/Okta"}}]}`, "saml"},
		{"OIDC provider arn", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::1:oidc-provider/accounts.google.com"}}]}`, "oidc"},
		{"GitHub Actions OIDC host", `{"Statement":{"Effect":"Allow","Principal":{"Federated":"token.actions.githubusercontent.com"}}}`, "oidc"},
		{"Federated array, saml wins", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":["arn:aws:iam::1:saml-provider/AzureAD"]}}]}`, "saml"},
		{"plain AWS principal, no federation", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"}}]}`, ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, _ := trustFederation(tt.doc)
			require.Equal(t, tt.wantKind, kind)
		})
	}
}

// rootSummaryIAM reports a root account with an active access key and no MFA.
type rootSummaryIAM struct {
	fakeIAM
}

func (rootSummaryIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return &iam.GetAccountSummaryOutput{SummaryMap: map[string]int32{
		"AccountAccessKeysPresent": 1,
		"AccountMFAEnabled":        0,
	}}, nil
}

func TestCollectRootAccount(t *testing.T) {
	root, err := collectRootAccount(context.Background(), rootSummaryIAM{}, "aws", "111122223333", time.Now())
	require.NoError(t, err)
	require.Equal(t, "arn:aws:iam::111122223333:root", root.ID)
	require.Equal(t, "root", root.Name)
	require.Equal(t, "iam_user", root.Type)
	require.Equal(t, "true", root.Metadata["root"])
	require.Equal(t, "1", root.Metadata["active_key_count"])
	require.Equal(t, "false", root.Metadata["mfa_enabled"])
}

// rootErrIAM fails GetAccountSummary (e.g. throttled after the principal crawl).
type rootErrIAM struct {
	fakeIAM
}

func (rootErrIAM) GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error) {
	return nil, errors.New("api error Throttling: Rate exceeded")
}

// A GetAccountSummary failure must surface as an error the caller can log —
// the silent ok=false path hid critical root-no-MFA assets.
func TestCollectRootAccount_Error(t *testing.T) {
	_, err := collectRootAccount(context.Background(), rootErrIAM{}, "aws", "111122223333", time.Now())
	require.Error(t, err)
	require.Contains(t, err.Error(), "collectRootAccount")
}

func TestTrustHasWildcardPrincipal(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{"bare wildcard string", `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`, true},
		{"AWS wildcard object", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`, true},
		{"wildcard in AWS array", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:root","*"]}}]}`, true},
		// A Condition that pins the caller makes it a cross-account/org pattern, not public.
		{"wildcard scoped by PrincipalOrgID", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}}]}`, false},
		// One any account can satisfy does not: the ExternalId is not a secret,
		// and TLS or MFA says nothing about which account is calling.
		{"wildcard gated only by ExternalId", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Condition":{"StringEquals":{"sts:ExternalId":"x"}}}]}`, true},
		{"wildcard gated only by TLS", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`, true},
		{"wildcard gated only by MFA", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`, true},
		{"specific principal, no wildcard", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::1:root"}}]}`, false},
		{"deny wildcard ignored", `{"Statement":[{"Effect":"Deny","Principal":"*"}]}`, false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, trustHasWildcardPrincipal(tt.doc))
		})
	}
}

func TestTrustEntryClass(t *testing.T) {
	const acct = "111122223333"
	tests := []struct {
		name           string
		doc            string
		wantClass      string
		wantPrincipals []string
	}{
		{"wildcard string principal", `{"Statement":[{"Effect":"Allow","Principal":"*"}]}`, "public", nil},
		{"wildcard AWS principal", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}}]}`, "public", nil},
		{"wildcard beats federated", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"}},{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"}}]}`, "public", nil},
		{"federated only (Okta)", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"}}]}`, "federated", nil},
		{"federated plus service stays federated", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/AWSSSO_x"}},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`, "federated", nil},
		{"federated plus AWS principal is mixed", `{"Statement":[{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111122223333:saml-provider/Okta"}},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:role/ops"}}]}`, "mixed", []string{"arn:aws:iam::111122223333:role/ops"}},
		{
			// The ExampleCloudWatchCrossAccountAccessRole shape: a service principal +
			// one specific role in another account. Entry is that one role.
			"service + cross-account role",
			`{"Statement":[{"Effect":"Allow","Principal":{"Service":"cloudwatch-crossaccount.amazonaws.com"}},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::556677889900:role/ExampleCURReadOnly"}}]}`,
			"cross_account", []string{"arn:aws:iam::556677889900:role/ExampleCURReadOnly"},
		},
		{"same-account principals only", `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::111122223333:role/a","arn:aws:iam::111122223333:user/b"]}}]}`, "same_account", []string{"arn:aws:iam::111122223333:role/a", "arn:aws:iam::111122223333:user/b"}},
		{"service only — no human entry", `{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"}}]}`, "service", nil},
		// A blanket unconditional Deny on every principal really does block
		// assumption — including by a service principal — so no entry path
		// survives and there is no class to report. This case was previously named
		// "deny statements ignored" and asserted "service", which is exactly the
		// Allow-only reading that made a locked-down role look assumable.
		{"blanket deny blocks even service entry", `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"*"}},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`, "", nil},
		// A Deny that only reaches a DIFFERENT assumption method leaves this one
		// intact: the SAML deny says nothing about sts:AssumeRole.
		{"deny on another assumption method leaves entry intact", `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML"},{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`, "service", nil},
		{"empty doc", "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class, principals := trustEntryClass(tt.doc, acct)
			require.Equal(t, tt.wantClass, class)
			require.Equal(t, tt.wantPrincipals, principals)
		})
	}
}

// boundaryIAM embeds the default fake but attaches a permission boundary to the
// admin role and user, and resolves the boundary ARN to a limited document.
type boundaryIAM struct {
	fakeIAM
}

const boundaryARN = "arn:aws:iam::1:policy/dev-boundary"

func (boundaryIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{Role: &iamtypes.Role{
		PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: awssdk.String(boundaryARN)},
	}}, nil
}

func (boundaryIAM) GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	return &iam.GetUserOutput{User: &iamtypes.User{
		PermissionsBoundary: &iamtypes.AttachedPermissionsBoundary{PermissionsBoundaryArn: awssdk.String(boundaryARN)},
	}}, nil
}

func (boundaryIAM) GetPolicyVersion(_ context.Context, in *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	// The boundary resolves to a limited doc; every other managed policy stays Allow *.
	doc := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	if in.PolicyArn != nil && *in.PolicyArn == boundaryARN {
		doc = url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`)
	}
	return &iam.GetPolicyVersionOutput{PolicyVersion: &iamtypes.PolicyVersion{Document: awssdk.String(doc)}}, nil
}

func TestCollectRoles_AttachesPermissionBoundary(t *testing.T) {
	c := boundaryIAM{}
	assets, _, err := collectRoles(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	var r asset.Asset
	for _, a := range assets {
		if a.Type == "iam_role" {
			r = a
		}
	}
	require.Equal(t, "iam_role", r.Type, "the role asset is present")
	require.Equal(t, boundaryARN, r.Metadata["permission_boundary_arn"])
	docs := decodePolicies(t, r.Metadata["policies"])
	var boundary *policyDoc
	for i := range docs {
		if docs[i].Type == "boundary" {
			boundary = &docs[i]
		}
	}
	require.NotNil(t, boundary, "boundary policyDoc is appended")
	require.Contains(t, boundary.Document, "s3:GetObject")
}

func TestCollectUsers_AttachesPermissionBoundaryForScopedGrant(t *testing.T) {
	c := boundaryIAM{}
	users, _, err := collectUsers(context.Background(), c, newManagedPolicyCache(c), "1", time.Now())
	require.NoError(t, err)
	require.Len(t, users, 1)
	// Scoped grants require their caps just as wildcard grants do.
	require.Equal(t, boundaryARN, users[0].Metadata["permission_boundary_arn"])
}

// adminUsageIAM returns an admin role and a completed Access Advisor job using
// 2 of 3 granted services — exercises the roleUsage GetRole + AA path.
type adminUsageIAM struct {
	fakeIAM
	lastUsed time.Time
	now      time.Time
}

func (c *adminUsageIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{Role: &iamtypes.Role{RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: &c.lastUsed}}}, nil
}

func (c *adminUsageIAM) GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	id := "job-1"
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: &id}, nil
}

func (c *adminUsageIAM) GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	used := c.now.Add(-72 * time.Hour)
	s3, ec2, kms := "s3", "ec2", "kms"
	return &iam.GetServiceLastAccessedDetailsOutput{
		JobStatus: iamtypes.JobStatusTypeCompleted,
		ServicesLastAccessed: []iamtypes.ServiceLastAccessed{
			{ServiceNamespace: &s3, LastAuthenticated: &used},
			{ServiceNamespace: &ec2, LastAuthenticated: &used},
			{ServiceNamespace: &kms}, // granted but never used
		},
	}, nil
}

func TestRoleUsage_PopulatesUsageMetrics(t *testing.T) {
	now := time.Now()
	c := &adminUsageIAM{lastUsed: now.Add(-120 * time.Hour), now: now}
	aa := roleUsage(context.Background(), c, "arn:aws:iam::1:role/example-api-role", now)
	det := roleDetails(context.Background(), c, "example-api-role", now)
	require.True(t, det.observed)
	require.Equal(t, "5", det.lastUsedDays) // 120h ≈ 5 days
	require.Equal(t, "3", aa["aa_services_granted"])
	require.Equal(t, "2", aa["aa_services_used"])
	require.Contains(t, aa["aa_used_services"], "s3")
	require.Equal(t, "3", aa["aa_last_used_days"]) // 72h = 3 days
}

// wildcardTrustIAM serves a role whose trust policy allows ANY principal to
// assume it with no restricting condition — genuinely public.
type wildcardTrustIAM struct{ fakeIAM }

func (wildcardTrustIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	trust := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":"*"}]}`)
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: awssdk.String("public-role"), Arn: awssdk.String("arn:aws:iam::1:role/public-role"),
		Path: awssdk.String("/"), AssumeRolePolicyDocument: awssdk.String(trust),
	}}}, nil
}

// A wildcard-principal trust policy must be graded true, not left to the
// default. Its mfa_required_to_assume is correctly false: an unconditioned
// wildcard has no MFA gate on any path by construction — MFA requires a
// Condition, and a Condition on the wildcard-admitting Allow is exactly what
// would make it NOT public. The two flags cannot both be true from the same
// statement, which is why they get separate fixtures (see
// TestCollectRoles_MFARequiredIsGradedTrue below).
func TestCollectRoles_PublicTrustIsGradedTrue(t *testing.T) {
	c := wildcardTrustIAM{}
	cache := newManagedPolicyCache(c)
	assets, _, err := collectRoles(context.Background(), c, cache, "1", time.Now())
	require.NoError(t, err)

	var r *asset.Asset
	for i := range assets {
		if assets[i].Type == "iam_role" {
			r = &assets[i]
		}
	}
	require.NotNil(t, r)
	require.Equal(t, "true", r.Metadata["public_trust"])
	require.Equal(t, "false", r.Metadata["mfa_required_to_assume"])
}

// mfaGatedTrustIAM serves a role assumable only by a named principal presenting
// MFA — the compensating-control case, not the wildcard case.
type mfaGatedTrustIAM struct{ fakeIAM }

func (mfaGatedTrustIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	trust := url.QueryEscape(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
		"Principal":{"AWS":"arn:aws:iam::1:role/ops"},
		"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: awssdk.String("mfa-role"), Arn: awssdk.String("arn:aws:iam::1:role/mfa-role"),
		Path: awssdk.String("/"), AssumeRolePolicyDocument: awssdk.String(trust),
	}}}, nil
}

func TestCollectRoles_MFARequiredIsGradedTrue(t *testing.T) {
	c := mfaGatedTrustIAM{}
	cache := newManagedPolicyCache(c)
	assets, _, err := collectRoles(context.Background(), c, cache, "1", time.Now())
	require.NoError(t, err)

	var r *asset.Asset
	for i := range assets {
		if assets[i].Type == "iam_role" {
			r = &assets[i]
		}
	}
	require.NotNil(t, r)
	require.Equal(t, "false", r.Metadata["public_trust"])
	require.Equal(t, "true", r.Metadata["mfa_required_to_assume"])
}

// noTrustDocIAM serves a role with a nil AssumeRolePolicyDocument — the one
// case that must stay unevaluated. Defensive: every real IAM role has a trust
// document (AWS requires one at creation), but if the field ever arrives nil,
// that is an absent observation, not a clean one.
type noTrustDocIAM struct{ fakeIAM }

func (noTrustDocIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: []iamtypes.Role{{
		RoleName: awssdk.String("no-trust-doc"), Arn: awssdk.String("arn:aws:iam::1:role/no-trust-doc"),
		Path: awssdk.String("/"),
	}}}, nil
}

func TestCollectRoles_NilTrustDocumentLeavesBothKeysAbsent(t *testing.T) {
	c := noTrustDocIAM{}
	cache := newManagedPolicyCache(c)
	assets, _, err := collectRoles(context.Background(), c, cache, "1", time.Now())
	require.NoError(t, err)

	var r *asset.Asset
	for i := range assets {
		if assets[i].Type == "iam_role" {
			r = &assets[i]
		}
	}
	require.NotNil(t, r)
	require.NotContains(t, r.Metadata, "public_trust",
		"a role with no trust document at all must not be graded 'not public'")
	require.NotContains(t, r.Metadata, "mfa_required_to_assume")
}

// TestIsAdminish_LogsNotActionWidening keeps the NotAction over-approximation
// traceable without promoting the widened candidate to proven admin authority.
func TestIsAdminish_LogsNotActionWidening(t *testing.T) {
	var buf bytes.Buffer
	origLogger := zlog.Logger
	zlog.Logger = zerolog.New(&buf).Level(zerolog.DebugLevel)
	t.Cleanup(func() { zlog.Logger = origLogger })

	pols := []policyDoc{{
		Name: "all-but-iam", Type: "identity",
		Document: `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`,
	}}
	require.False(t, isAdminish(t.Context(), "arn:aws:iam::111:role/r", pols))
	out := buf.String()
	require.Contains(t, out, "NotAction Allow treated as Allow *")
	require.Contains(t, out, "arn:aws:iam::111:role/r")
	require.Contains(t, out, "all-but-iam")

	buf.Reset()
	require.False(t, isAdminish(t.Context(), "arn:aws:iam::111:role/plain", []policyDoc{{
		Name: "read", Type: "identity",
		Document: `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
	}}))
	require.Empty(t, buf.String())
}
