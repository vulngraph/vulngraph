package asset

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageInventoryKnown(t *testing.T) {
	tests := []struct {
		name  string
		meta  map[string]string
		known bool
	}{
		{"ssm", map[string]string{MetaPackageInventory: PackageInventorySSM}, true},
		{"osconfig", map[string]string{MetaPackageInventory: PackageInventoryOSConfig}, true},
		{"disk", map[string]string{MetaPackageInventory: PackageInventoryDisk}, true},
		{"byoa", map[string]string{MetaPackageInventory: PackageInventoryBYOA}, true},
		{"none is an observation, not inventory", map[string]string{MetaPackageInventory: PackageInventoryNone}, false},
		{"absent", map[string]string{}, false},
		{"nil", nil, false},
		{"unknown source", map[string]string{MetaPackageInventory: "agent"}, false},
		{"disk_scan scanned alone proves nothing", map[string]string{MetaDiskScan: DiskScanScanned}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.known, PackageInventoryKnown(tc.meta)) })
	}
}

func TestPackageCVEClaimableNeedsDiskInventoryAndMatchable(t *testing.T) {
	disk := map[string]string{MetaPackageInventory: PackageInventoryDisk}
	assert.False(t, PackageCVEClaimable(disk))
	disk[MetaPackageCVEMatchable] = "true"
	assert.True(t, PackageCVEClaimable(disk))
}

func TestPackageCVEClaimableAcceptsBYOA(t *testing.T) {
	byoa := map[string]string{MetaPackageInventory: PackageInventoryBYOA}
	assert.False(t, PackageCVEClaimable(byoa), "known but not matchable")
	byoa[MetaPackageCVEMatchable] = "true"
	assert.True(t, PackageCVEClaimable(byoa))
}
