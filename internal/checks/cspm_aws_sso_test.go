package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAWSSSOPermissionSetAdmin(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"admin-granting flagged", map[string]string{"grants_admin": "true"}, true},
		{"non-admin ok", map[string]string{"grants_admin": "false"}, false},
		{"missing metadata ok", map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsSSOPermissionSetAdmin.Violates(asset.Asset{
				Provider: asset.ProviderAWS, Type: "sso_permission_set", Metadata: tt.md,
			}))
		})
	}
}

func TestAWSSSOCheckRegistered(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Default().checks {
		got[c.ID] = true
	}
	require.True(t, got["aws-sso-permission-set-admin"], "check not registered in Default()")
}
