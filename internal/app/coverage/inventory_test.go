package coverage

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// "VMs with software inventory N/M" counts the known-ness stamp, not edges: a VM
// stamped none, or never stamped (""), is the coverage gap — never coverage.
func TestStageFactsCountVMInventoryKnownness(t *testing.T) {
	f := LiveFacts{
		Assets: []TypeCount{
			{Provider: "aws", AssetType: "ec2_instance", Count: 11},
			{Provider: "gcp", AssetType: "gce_instance", Count: 5},
		},
		MetaValues: []MetaValueCount{
			{AssetType: "ec2_instance", Key: asset.MetaPackageInventory, Value: asset.PackageInventorySSM, Count: 4},
			{AssetType: "ec2_instance", Key: asset.MetaPackageInventory, Value: asset.PackageInventoryDisk, Count: 2},
			{AssetType: "ec2_instance", Key: asset.MetaPackageInventory, Value: asset.PackageInventoryNone, Count: 3},
			{AssetType: "ec2_instance", Key: asset.MetaPackageInventory, Value: asset.PackageInventoryBYOA, Count: 1},
			{AssetType: "ec2_instance", Key: asset.MetaPackageInventory, Value: "", Count: 1},
			{AssetType: "gce_instance", Key: asset.MetaPackageInventory, Value: asset.PackageInventoryOSConfig, Count: 2},
			{AssetType: "ec2_instance", Key: asset.MetaPackageCVEMatchable, Value: "true", Count: 1},
			{AssetType: "ec2_instance", Key: asset.MetaPackageCVEMatchable, Value: "false", Count: 3},
			{AssetType: "gce_instance", Key: asset.MetaPackageCVEMatchable, Value: "true", Count: 2},
		},
	}
	byName := map[string]StageFact{}
	for _, s := range newIndex(checks.Default(), f, true).stageFacts() {
		byName[s.Name] = s
	}
	assert.Equal(t, uint64(16), byName["VMs"].Count)
	known := byName["VMs with a known package inventory"]
	assert.Equal(t, uint64(9), known.Count, "ssm 4 + disk 2 + byoa 1 + osconfig 2")
	assert.Equal(t, uint64(16), known.OfCount)
	assert.Equal(t, uint64(3), byName["VMs with a CVE-matchable inventory"].Count,
		"an Amazon Linux inventory is known but supports no CVE verdict")
}
