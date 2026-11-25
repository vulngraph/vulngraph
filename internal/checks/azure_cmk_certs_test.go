package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAzureCMKAndCertChecks(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		md    map[string]string
		want  bool
	}{
		{"attached platform key", azureAttachedDiskNoCMK, map[string]string{"vm_attached": "true", "encryption_type": platformKeyDiskEncryption}, true},
		{"attached cmk", azureAttachedDiskNoCMK, map[string]string{"vm_attached": "true", "encryption_type": "EncryptionAtRestWithCustomerKey"}, false},
		{"attached double encryption", azureAttachedDiskNoCMK, map[string]string{"vm_attached": "true", "encryption_type": "EncryptionAtRestWithPlatformAndCustomerKeys"}, false},
		{"attached unread type", azureAttachedDiskNoCMK, map[string]string{"vm_attached": "true", "encryption_type": ""}, false},
		{"attached key absent", azureAttachedDiskNoCMK, map[string]string{"vm_attached": "true"}, false},
		{"attached flag absent", azureAttachedDiskNoCMK, map[string]string{"encryption_type": platformKeyDiskEncryption}, false},
		{"unattached disk checked by attached rule", azureAttachedDiskNoCMK, map[string]string{"vm_attached": "false", "encryption_type": platformKeyDiskEncryption}, false},
		{"unattached platform key", azureUnattachedDiskNoCMK, map[string]string{"vm_attached": "false", "encryption_type": platformKeyDiskEncryption}, true},
		{"unattached cmk", azureUnattachedDiskNoCMK, map[string]string{"vm_attached": "false", "encryption_type": "EncryptionAtRestWithCustomerKey"}, false},
		{"unattached flag absent", azureUnattachedDiskNoCMK, map[string]string{"encryption_type": platformKeyDiskEncryption}, false},
		{"unattached key absent", azureUnattachedDiskNoCMK, map[string]string{"vm_attached": "false"}, false},
		{"attached disk checked by unattached rule", azureUnattachedDiskNoCMK, map[string]string{"vm_attached": "true", "encryption_type": platformKeyDiskEncryption}, false},
		{"cert not required", azureWebAppClientCertNotRequired, map[string]string{"client_cert_required": "false"}, true},
		{"cert required", azureWebAppClientCertNotRequired, map[string]string{"client_cert_required": "true"}, false},
		{"cert unread", azureWebAppClientCertNotRequired, map[string]string{"client_cert_enabled": "false"}, false},
		{"custom roles without lock role", azureNoLockAdminCustomRole, map[string]string{"custom_role_count": "2", "custom_lock_admin_roles": "0"}, true},
		{"custom roles with lock role", azureNoLockAdminCustomRole, map[string]string{"custom_role_count": "2", "custom_lock_admin_roles": "1"}, false},
		{"no custom roles", azureNoLockAdminCustomRole, map[string]string{"custom_role_count": "0", "custom_lock_admin_roles": "0"}, false},
		{"lock count absent", azureNoLockAdminCustomRole, map[string]string{"custom_role_count": "2"}, false},
		{"role count absent", azureNoLockAdminCustomRole, map[string]string{"custom_lock_admin_roles": "0"}, false},
		{"counts malformed", azureNoLockAdminCustomRole, map[string]string{"custom_role_count": "x", "custom_lock_admin_roles": "0"}, false},
		{"nil metadata", azureNoLockAdminCustomRole, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{ID: "r", Type: tt.check.AssetType, Provider: tt.check.Provider, Metadata: tt.md}
			require.Equal(t, tt.want, tt.check.Violates(a))
		})
	}
}
