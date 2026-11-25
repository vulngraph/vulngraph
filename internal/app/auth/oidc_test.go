package auth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func (f *fakeRepo) GetUserCredentialsByOIDC(_ context.Context, issuer, subject string) (UserCredentials, error) {
	if f.oidcLookupErr != nil {
		return UserCredentials{}, f.oidcLookupErr
	}
	for _, c := range f.users {
		if c.OIDCIssuer == issuer && c.OIDCSubject == subject {
			return c, nil
		}
	}
	return UserCredentials{}, ErrNotFound
}

func (f *fakeRepo) BindOIDCIdentity(_ context.Context, userID, issuer, subject string) error {
	for email, c := range f.users {
		if c.ID != userID {
			continue
		}
		if c.OIDCSubject != "" {
			return ErrIdentityMismatch
		}
		c.OIDCIssuer, c.OIDCSubject = issuer, subject
		f.users[email] = c
		return nil
	}
	return ErrNotFound
}

func TestIdentityFromUserInfo(t *testing.T) {
	for _, tc := range []struct {
		name    string
		json    string
		wantErr error
		email   string
	}{
		{"verified (OIDC claim)", `{"sub":"1","email":"A@Corp.example","email_verified":true}`, nil, "a@corp.example"},
		{"verified as string", `{"sub":"1","email":"a@corp.example","email_verified":"true"}`, nil, "a@corp.example"},
		{"verified (Google legacy claim)", `{"sub":"1","email":"a@corp.example","verified_email":true}`, nil, "a@corp.example"},
		{"unverified", `{"sub":"1","email":"a@corp.example","email_verified":false}`, ErrEmailNotVerified, ""},
		{"unverified string", `{"sub":"1","email":"a@corp.example","email_verified":"false"}`, ErrEmailNotVerified, ""},
		{"claim absent", `{"sub":"1","email":"a@corp.example"}`, ErrEmailNotVerified, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var info userInfo
			require.NoError(t, json.Unmarshal([]byte(tc.json), &info))
			id, err := identityFromUserInfo("https://idp", info)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, OIDCIdentity{Issuer: "https://idp", Subject: "1", Email: tc.email}, id)
		})
	}

	_, err := identityFromUserInfo("https://idp", userInfo{Email: "a@corp.example", EmailVerified: true})
	require.Error(t, err, "a missing sub cannot be bound")
}

func TestLoginOIDC_BindsOnFirstSignInAndEnforcesSubject(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()
	alice := OIDCIdentity{Issuer: "https://idp", Subject: "sub-alice", Email: "admin@example.com"}

	// First sign-in binds the existing (password-provisioned) account.
	_, u, err := svc.LoginOIDC(ctx, alice, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	require.Equal(t, RoleAdmin, u.Role)
	require.Equal(t, "sub-alice", repo.users["admin@example.com"].OIDCSubject)

	// The same identity keeps working even after the IdP reports a new email.
	renamed := alice
	renamed.Email = "alice.new@example.com"
	_, u2, err := svc.LoginOIDC(ctx, renamed, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	require.Equal(t, u.ID, u2.ID)

	// A different subject asserting the same email is refused.
	mallory := OIDCIdentity{Issuer: "https://idp", Subject: "sub-mallory", Email: "admin@example.com"}
	_, _, err = svc.LoginOIDC(ctx, mallory, Provisioning{Role: RoleViewer})
	require.ErrorIs(t, err, ErrIdentityMismatch)

	// So is the same subject from a different issuer.
	other := alice
	other.Issuer = "https://other-idp"
	_, _, err = svc.LoginOIDC(ctx, other, Provisioning{Role: RoleViewer})
	require.ErrorIs(t, err, ErrIdentityMismatch)
}

func TestLoginOIDC_ProvisionsAndBindsNewUser(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()
	id := OIDCIdentity{Issuer: "https://idp", Subject: "sub-new", Email: "New@Example.com"}

	_, u, err := svc.LoginOIDC(ctx, id, Provisioning{Role: RoleViewer})
	require.NoError(t, err)
	require.Equal(t, RoleViewer, u.Role)
	require.Equal(t, "new@example.com", u.Email)
	require.Equal(t, "sub-new", repo.users["new@example.com"].OIDCSubject)

	_, _, err = svc.LoginOIDC(ctx, id, Provisioning{Role: Role("root")})
	require.NoError(t, err, "an already-bound identity never consults the auto-create role")
}

func TestLoginOIDC_DisabledUserRefused(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()
	id := OIDCIdentity{Issuer: "https://idp", Subject: "s", Email: "admin@example.com"}
	_, _, err := svc.LoginOIDC(ctx, id, Provisioning{Role: RoleViewer})
	require.NoError(t, err)

	repo.disable("admin@example.com")
	_, _, err = svc.LoginOIDC(ctx, id, Provisioning{Role: RoleViewer})
	require.ErrorIs(t, err, ErrUserDisabled)
}
