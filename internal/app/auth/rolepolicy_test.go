package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// An empty allowlist must deny: unset used to mean "any Google/Okta account on
// the internet signs in".
func TestDomainGate(t *testing.T) {
	cases := []struct {
		name            string
		email           string
		allowed         []string
		allowAny        bool
		wantOK          bool
		wantAllowlisted bool
	}{
		{"empty allowlist denies", "eve@gmail.com", nil, false, false, false},
		{"allowlisted domain", "alice@corp.example", []string{"corp.example"}, false, true, true},
		{"domain match ignores case", "alice@Corp.Example", []string{"corp.example"}, false, true, true},
		{"other domain denied", "eve@gmail.com", []string{"corp.example"}, false, false, false},
		{"subdomain is not the domain", "eve@evil.corp.example", []string{"corp.example"}, false, false, false},
		{"allowlist wins over allow-any", "eve@gmail.com", []string{"corp.example"}, true, false, false},
		{"explicit allow-any is not allowlisted", "eve@gmail.com", nil, true, true, false},
		{"no domain denied", "not-an-email", nil, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, allowlisted := domainGate(tc.email, tc.allowed, tc.allowAny)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantAllowlisted, allowlisted)
		})
	}
}

// A first SSO sign-in from an allowlisted domain used to provision admin.
// Admin must now be named (ADMIN_EMAILS or an admin group); everyone else is a
// viewer, except the first allowlisted sign-in on an install without
// ADMIN_EMAILS (the repository decides whether the table is empty).
func TestRolePolicyProvision(t *testing.T) {
	named := RolePolicy{
		AdminEmails:   []string{"Boss@Corp.Example"},
		AdminGroups:   []string{"graph-admins"},
		AnalystGroups: []string{"secops"},
	}
	groupsOnly := RolePolicy{AdminGroups: []string{"graph-admins"}, AnalystGroups: []string{"secops"}}
	cases := []struct {
		name        string
		policy      RolePolicy
		email       string
		groups      []string
		allowlisted bool
		want        Provisioning
	}{
		{"zero policy, allowlisted: viewer, bootstrap eligible", RolePolicy{}, "a@corp.example", nil, true, Provisioning{Role: RoleViewer, BootstrapAdmin: true}},
		{"zero policy, allow-any: viewer, never bootstrap", RolePolicy{}, "a@gmail.com", nil, false, Provisioning{Role: RoleViewer}},
		{"admin email, case-insensitive", named, "boss@corp.example", nil, true, Provisioning{Role: RoleAdmin}},
		{"admin email even via allow-any", named, "boss@corp.example", nil, false, Provisioning{Role: RoleAdmin}},
		{"admin group", named, "x@corp.example", []string{"eng", "graph-admins"}, true, Provisioning{Role: RoleAdmin}},
		{"analyst group", named, "x@corp.example", []string{"secops"}, true, Provisioning{Role: RoleAnalyst}},
		{"admin group beats analyst group", named, "x@corp.example", []string{"secops", "graph-admins"}, true, Provisioning{Role: RoleAdmin}},
		{"ADMIN_EMAILS set: no first-user bootstrap", named, "x@corp.example", []string{"eng"}, true, Provisioning{Role: RoleViewer}},
		{"group mapping set: a non-member never bootstraps", groupsOnly, "x@corp.example", nil, true, Provisioning{Role: RoleViewer}},
		{"empty group never matches", RolePolicy{AdminGroups: []string{""}}, "x@corp.example", []string{""}, false, Provisioning{Role: RoleViewer}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.policy.Provision(tc.email, tc.groups, tc.allowlisted))
		})
	}
}

// BootstrapAdmin makes only the very first user an admin; every later first
// sign-in gets the policy role. Existing users keep theirs.
func TestLoginOIDC_BootstrapsOnlyTheFirstUser(t *testing.T) {
	repo := newFakeRepo()
	svc := NewService(repo)
	ctx := context.Background()
	prov := Provisioning{Role: RoleViewer, BootstrapAdmin: true}

	_, first, err := svc.LoginOIDC(ctx, OIDCIdentity{Issuer: "https://idp", Subject: "1", Email: "first@corp.example"}, prov)
	require.NoError(t, err)
	require.Equal(t, RoleAdmin, first.Role, "an empty install's first allowlisted sign-in administers it")

	_, second, err := svc.LoginOIDC(ctx, OIDCIdentity{Issuer: "https://idp", Subject: "2", Email: "second@corp.example"}, prov)
	require.NoError(t, err)
	require.Equal(t, RoleViewer, second.Role)

	_, again, err := svc.LoginOIDC(ctx, OIDCIdentity{Issuer: "https://idp", Subject: "1", Email: "first@corp.example"},
		Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	require.Equal(t, RoleAdmin, again.Role, "an existing user's role is never changed by a sign-in")
}
