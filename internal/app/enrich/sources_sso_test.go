package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakePermSetLister struct {
	sets []asset.Asset
	err  error
	// calls counts ListByType invocations, to assert caching.
	calls int
}

func (f *fakePermSetLister) ListByType(context.Context, string, int) ([]asset.Asset, error) {
	f.calls++
	return f.sets, f.err
}

func adminPermSet(name string, admin bool) asset.Asset {
	return asset.Asset{
		ID: "sso_permission_set:" + name, Name: name, Type: "sso_permission_set",
		Metadata: map[string]string{"grants_admin": boolStr(admin)},
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func ssoRole(name, path string) asset.Asset {
	return asset.Asset{
		ID: "arn:aws:iam::1:role/aws-reserved/sso.amazonaws.com/" + name, Name: name,
		Type: "iam_role", Metadata: map[string]string{"path": path},
	}
}

func TestSSOPermSetName(t *testing.T) {
	cases := []struct {
		role     asset.Asset
		wantName string
		wantOK   bool
	}{
		{ssoRole("AWSReservedSSO_AdministratorAccess_1a2b3c4d5e6f7a8b", "/aws-reserved/sso.amazonaws.com/"), "AdministratorAccess", true},
		{ssoRole("AWSReservedSSO_ReadOnly_deadbeefdeadbeef", "/aws-reserved/sso.amazonaws.com/"), "ReadOnly", true},
		{asset.Asset{Name: "app-role", Type: "iam_role", Metadata: map[string]string{"path": "/"}}, "", false},
		// Path-based detection when the name lacks the prefix (defensive).
		{asset.Asset{Name: "SomeSet_0011223344556677", Type: "iam_role", Metadata: map[string]string{"path": "/aws-reserved/sso.amazonaws.com/"}}, "SomeSet", true},
	}
	for _, c := range cases {
		name, ok := ssoPermSetName(c.role)
		require.Equal(t, c.wantOK, ok, c.role.Name)
		require.Equal(t, c.wantName, name, c.role.Name)
	}
}

func TestAssetSSOResolver_ResolvesAdminAndCaches(t *testing.T) {
	lister := &fakePermSetLister{sets: []asset.Asset{
		adminPermSet("AdministratorAccess", true),
		adminPermSet("ReadOnly", false),
	}}
	r := &AssetSSOResolver{Lister: lister}

	info, ok := r.ResolveRole(context.Background(), ssoRole("AWSReservedSSO_AdministratorAccess_1a2b3c4d5e6f7a8b", "/aws-reserved/sso.amazonaws.com/"))
	require.True(t, ok)
	require.True(t, info.GrantsAdmin)
	require.Equal(t, "AdministratorAccess", info.PermissionSet)

	info, ok = r.ResolveRole(context.Background(), ssoRole("AWSReservedSSO_ReadOnly_deadbeefdeadbeef", "/aws-reserved/sso.amazonaws.com/"))
	require.True(t, ok)
	require.False(t, info.GrantsAdmin)

	// A non-SSO role resolves to not-ok.
	_, ok = r.ResolveRole(context.Background(), asset.Asset{Name: "app-role", Type: "iam_role"})
	require.False(t, ok)

	// A permission set absent from the graph → unresolved (fall back to metadata).
	_, ok = r.ResolveRole(context.Background(), ssoRole("AWSReservedSSO_Missing_00112233aabbccdd", "/aws-reserved/sso.amazonaws.com/"))
	require.False(t, ok)

	require.Equal(t, 1, lister.calls, "permission sets are listed once and cached within the TTL")
}

func TestAssetSSOResolver_NilOnListError(t *testing.T) {
	r := &AssetSSOResolver{Lister: &fakePermSetLister{err: context.DeadlineExceeded}}
	_, ok := r.ResolveRole(context.Background(), ssoRole("AWSReservedSSO_AdministratorAccess_1a2b3c4d5e6f7a8b", "/aws-reserved/sso.amazonaws.com/"))
	require.False(t, ok, "a list error leaves the permission set unresolved (fail-open to metadata)")
}
