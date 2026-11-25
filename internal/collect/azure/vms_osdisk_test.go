package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/stretchr/testify/require"
)

func TestOSDiskID(t *testing.T) {
	id := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/disks/os"
	vm := &armcompute.VirtualMachine{Properties: &armcompute.VirtualMachineProperties{StorageProfile: &armcompute.StorageProfile{
		OSDisk: &armcompute.OSDisk{ManagedDisk: &armcompute.ManagedDiskParameters{ID: &id}},
	}}}
	require.Equal(t, id, osDiskID(vm))
	require.Empty(t, osDiskID(&armcompute.VirtualMachine{}))
	require.Empty(t, osDiskID(&armcompute.VirtualMachine{Properties: &armcompute.VirtualMachineProperties{StorageProfile: &armcompute.StorageProfile{
		OSDisk: &armcompute.OSDisk{}}}}), "an unmanaged OS disk has no id")
}
