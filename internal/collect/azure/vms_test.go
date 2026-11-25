package azure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func testVM(nicIDs ...string) *armcompute.VirtualMachine {
	var refs []*armcompute.NetworkInterfaceReference
	for _, id := range nicIDs {
		refs = append(refs, &armcompute.NetworkInterfaceReference{ID: to.Ptr(id)})
	}
	return &armcompute.VirtualMachine{
		ID: to.Ptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"),
		Properties: &armcompute.VirtualMachineProperties{
			NetworkProfile: &armcompute.NetworkProfile{NetworkInterfaces: refs},
		},
	}
}

func publicNIC(ip string) *armnetwork.Interface {
	return &armnetwork.Interface{Properties: &armnetwork.InterfacePropertiesFormat{
		NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: to.Ptr("nsg-nic")},
		IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr("pip-1"),
				Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr(ip)}},
		}}},
	}}
}

func privateNIC() *armnetwork.Interface {
	return &armnetwork.Interface{Properties: &armnetwork.InterfacePropertiesFormat{
		IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			PrivateIPAddress: to.Ptr("10.0.0.4"),
		}}},
	}}
}

func nicsByID(nics map[string]*armnetwork.Interface) func(string) (*armnetwork.Interface, error) {
	return func(id string) (*armnetwork.Interface, error) {
		if nic, ok := nics[id]; ok {
			return nic, nil
		}
		return nil, errors.New("AuthorizationFailed")
	}
}

func noSubnetNSG(string) (string, bool) { return "", true }

// A VM whose NIC could not be read has an unknown public IP: the public-IP
// check is not evaluable, so an open finding is held rather than closed, and
// nothing about the unread NIC (IP, NSG edge) is invented.
func TestVMAssetWithNICs_UnreadNICIsUnknown(t *testing.T) {
	c, ok := checks.Default().ByID("azure-vm-direct-public-ip")
	require.True(t, ok)

	vm, edges := vmAssetWithNICs(context.Background(), testVM("nic-a"), "s", time.Now(), nicsByID(nil), noSubnetNSG)
	require.Empty(t, vm.PublicIP)
	require.NotContains(t, vm.Metadata, "direct_public_ip")
	require.NotContains(t, vm.Metadata, "nic_nsgs")
	require.Empty(t, edges)
	require.False(t, c.Violates(vm))
	require.False(t, c.Evaluable(vm), "an unread NIC must not close the public-IP finding as fixed")
	require.True(t, asset.PublicIPUnread(vm), "drift must not read the empty PublicIP as a lost address")

	// One NIC unread, another read and public: the violation is observed.
	vm, edges = vmAssetWithNICs(context.Background(), testVM("nic-a", "nic-b"), "s", time.Now(),
		nicsByID(map[string]*armnetwork.Interface{"nic-b": publicNIC("20.1.1.1")}), noSubnetNSG)
	require.Equal(t, "20.1.1.1", vm.PublicIP)
	require.Equal(t, "true", vm.Metadata["direct_public_ip"])
	require.Len(t, edges, 1)
	require.True(t, c.Evaluable(vm))
	require.True(t, c.Violates(vm))
	require.False(t, asset.PublicIPUnread(vm))

	// One NIC unread, the read one private: still unknown, not clean.
	vm, _ = vmAssetWithNICs(context.Background(), testVM("nic-a", "nic-b"), "s", time.Now(),
		nicsByID(map[string]*armnetwork.Interface{"nic-b": privateNIC()}), noSubnetNSG)
	require.NotContains(t, vm.Metadata, "direct_public_ip")
	require.False(t, c.Evaluable(vm))
	require.True(t, asset.PublicIPUnread(vm))
}

func TestVMAssetWithNICs_EveryNICReadIsObserved(t *testing.T) {
	c, ok := checks.Default().ByID("azure-vm-direct-public-ip")
	require.True(t, ok)

	vm, _ := vmAssetWithNICs(context.Background(), testVM("nic-a"), "s", time.Now(),
		nicsByID(map[string]*armnetwork.Interface{"nic-a": privateNIC()}), noSubnetNSG)
	require.Equal(t, "false", vm.Metadata["direct_public_ip"])
	require.True(t, c.Evaluable(vm))
	require.False(t, c.Violates(vm))
	require.False(t, asset.PublicIPUnread(vm))

	vm, edges := vmAssetWithNICs(context.Background(), testVM("nic-a"), "s", time.Now(),
		nicsByID(map[string]*armnetwork.Interface{"nic-a": publicNIC("20.1.1.1")}), noSubnetNSG)
	require.Equal(t, "true", vm.Metadata["direct_public_ip"])
	require.True(t, c.Violates(vm))
	require.Equal(t, "nsg-nic", edges[0].DstID)

	// No network profile in the response: nothing was observed.
	noProfile := testVM()
	noProfile.Properties = nil
	vm, _ = vmAssetWithNICs(context.Background(), noProfile, "s", time.Now(), nicsByID(nil), noSubnetNSG)
	require.NotContains(t, vm.Metadata, "direct_public_ip")
	require.False(t, c.Evaluable(vm))
}

// A public IP that is associated but has no address allocated (a stopped VM's
// dynamic IP, or one the expand did not inline) is still a direct public IP.
func TestVMAssetWithNICs_AssociatedPublicIPWithoutAddress(t *testing.T) {
	c, ok := checks.Default().ByID("azure-vm-direct-public-ip")
	require.True(t, ok)
	for name, pip := range map[string]*armnetwork.PublicIPAddress{
		"dynamic, unallocated": {ID: to.Ptr("pip-1"), Properties: &armnetwork.PublicIPAddressPropertiesFormat{}},
		"not inlined":          {ID: to.Ptr("pip-1")},
	} {
		t.Run(name, func(t *testing.T) {
			nic := &armnetwork.Interface{Properties: &armnetwork.InterfacePropertiesFormat{
				IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
					PublicIPAddress: pip,
				}}},
			}}
			vm, _ := vmAssetWithNICs(context.Background(), testVM("nic-a"), "s", time.Now(),
				nicsByID(map[string]*armnetwork.Interface{"nic-a": nic}), noSubnetNSG)
			require.Empty(t, vm.PublicIP)
			require.Equal(t, "pip-1", vm.Metadata["public_ip_id"])
			require.Equal(t, "true", vm.Metadata["direct_public_ip"])
			require.True(t, c.Violates(vm))
		})
	}
}

// A NIC or IP configuration returned without properties may carry the public
// IP, so the VM's public IP is unknown, not absent.
func TestVMAssetWithNICs_NICWithoutPropertiesIsUnknown(t *testing.T) {
	c, ok := checks.Default().ByID("azure-vm-direct-public-ip")
	require.True(t, ok)
	for name, nic := range map[string]*armnetwork.Interface{
		"nic without properties": {},
		"ip configuration without properties": {Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			vm, edges := vmAssetWithNICs(context.Background(), testVM("nic-a"), "s", time.Now(),
				nicsByID(map[string]*armnetwork.Interface{"nic-a": nic}), noSubnetNSG)
			require.NotContains(t, vm.Metadata, "direct_public_ip")
			require.Empty(t, edges)
			require.False(t, c.Evaluable(vm))
		})
	}
}

func TestDiskMetadata_VMAttached(t *testing.T) {
	vm := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	empty := ""
	tests := []struct {
		name string
		disk *armcompute.Disk
		want string
	}{
		{"managed by vm", &armcompute.Disk{ManagedBy: &vm, Properties: &armcompute.DiskProperties{}}, "true"},
		{"shared disk", &armcompute.Disk{ManagedByExtended: []*string{&vm}, Properties: &armcompute.DiskProperties{}}, "true"},
		{"unattached", &armcompute.Disk{Properties: &armcompute.DiskProperties{}}, "false"},
		{"empty managed_by", &armcompute.Disk{ManagedBy: &empty, Properties: &armcompute.DiskProperties{}}, "false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, diskMetadata(tt.disk)["vm_attached"])
		})
	}
	require.NotContains(t, diskMetadata(&armcompute.Disk{}), "vm_attached")
}
