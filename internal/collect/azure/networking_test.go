package azure

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestNSGIngress_KeepsDenyPriorityAndPluralFields(t *testing.T) {
	const webASG = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/web"
	inbound := to.Ptr(armnetwork.SecurityRuleDirectionInbound)
	nsg := &armnetwork.SecurityGroup{Properties: &armnetwork.SecurityGroupPropertiesFormat{
		SecurityRules: []*armnetwork.SecurityRule{
			{Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction: inbound, Access: to.Ptr(armnetwork.SecurityRuleAccessDeny), Priority: to.Ptr[int32](100),
				Protocol: to.Ptr(armnetwork.SecurityRuleProtocolTCP), SourceAddressPrefix: to.Ptr("Internet"),
				DestinationAddressPrefix: to.Ptr("10.0.1.0/24"), DestinationPortRange: to.Ptr("22"),
			}},
			{Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction: inbound, Access: to.Ptr(armnetwork.SecurityRuleAccessAllow), Priority: to.Ptr[int32](200),
				Protocol:                 to.Ptr(armnetwork.SecurityRuleProtocolAsterisk),
				SourceAddressPrefixes:    []*string{to.Ptr("1.2.3.4/32"), to.Ptr("0.0.0.0/0")},
				DestinationAddressPrefix: to.Ptr(""),
				DestinationApplicationSecurityGroups: []*armnetwork.ApplicationSecurityGroup{
					{ID: to.Ptr(webASG)}, nil},
				DestinationPortRanges: []*string{to.Ptr("80"), to.Ptr("8000-8100")},
			}},
			{Properties: &armnetwork.SecurityRulePropertiesFormat{
				Direction: to.Ptr(armnetwork.SecurityRuleDirectionOutbound), Access: to.Ptr(armnetwork.SecurityRuleAccessAllow),
				Priority: to.Ptr[int32](100), SourceAddressPrefix: to.Ptr("*"),
			}},
		},
	}}

	var got []nsgRule
	require.NoError(t, json.Unmarshal([]byte(nsgIngress(nsg)), &got))
	require.Equal(t, []nsgRule{
		{Protocol: "tcp", FromPort: 22, ToPort: 22, CIDRs: []string{"Internet"}, Destinations: []string{"10.0.1.0/24"},
			Access: "deny", Priority: 100},
		{Protocol: "*", FromPort: 80, ToPort: 80, CIDRs: []string{"1.2.3.4/32", "0.0.0.0/0"}, DestinationASGs: []string{webASG},
			Access: "allow", Priority: 200},
		{Protocol: "*", FromPort: 8000, ToPort: 8100, CIDRs: []string{"1.2.3.4/32", "0.0.0.0/0"}, DestinationASGs: []string{webASG},
			Access: "allow", Priority: 200},
	}, got)
}

func TestPrimaryFirst(t *testing.T) {
	refs := []*armcompute.NetworkInterfaceReference{
		{ID: to.Ptr("nic-a"), Properties: &armcompute.NetworkInterfaceReferenceProperties{Primary: to.Ptr(false)}},
		{ID: to.Ptr("nic-b"), Properties: &armcompute.NetworkInterfaceReferenceProperties{Primary: to.Ptr(true)}},
		{ID: nil},
		{ID: to.Ptr("nic-c")},
	}
	require.Equal(t, []string{"nic-b", "nic-a", "nic-c"}, primaryFirst(refs))
}

func TestApplyNICs_GroupsSubnetAndNICNSGsPerNIC(t *testing.T) {
	const subnet = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/web"
	nics := []*armnetwork.Interface{
		{Properties: &armnetwork.InterfacePropertiesFormat{
			NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: to.Ptr("nsg-nic")},
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress: to.Ptr("10.0.0.4"),
				Subnet:           &armnetwork.Subnet{ID: to.Ptr(subnet)},
				PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr("pip-1"),
					Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr("20.1.1.1")}},
			}}},
		}},
		{Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
				PrivateIPAddress: to.Ptr("10.0.1.4"),
				Subnet:           &armnetwork.Subnet{ID: to.Ptr(subnet)},
			}}},
		}},
	}
	lookups := 0
	resolve := subnetNSGResolver(func(rg, vnet, name string) (*armnetwork.Subnet, error) {
		lookups++
		require.Equal(t, []string{"rg", "v", "web"}, []string{rg, vnet, name})
		return &armnetwork.Subnet{Properties: &armnetwork.SubnetPropertiesFormat{
			NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: to.Ptr("nsg-subnet")},
		}}, nil
	})

	vm := asset.Asset{Metadata: map[string]string{}}
	ids, public, complete := applyNICs(&vm, nics, resolve)

	require.Equal(t, []string{"nsg-subnet", "nsg-nic"}, ids)
	require.True(t, public)
	require.True(t, complete)
	require.Equal(t, 1, lookups, "subnet lookups are cached")
	require.Equal(t, "20.1.1.1", vm.PublicIP)
	require.Equal(t, "10.0.0.4", vm.PrivateIP)
	require.Equal(t, "nsg-subnet,nsg-nic", vm.Metadata["nsg_ids"])
	require.JSONEq(t, `[{"public":true,"nsg_ids":["nsg-subnet","nsg-nic"],"private_ip":"10.0.0.4","public_ip":"20.1.1.1","asgs":[],"endpoint_known":true},{"public":false,"nsg_ids":["nsg-subnet"],"private_ip":"10.0.1.4","asgs":[],"endpoint_known":true}]`,
		vm.Metadata["nic_nsgs"])
}

func TestSubnetNSGResolver_FailedLookupIsUnknown(t *testing.T) {
	resolve := subnetNSGResolver(func(string, string, string) (*armnetwork.Subnet, error) {
		return nil, errors.New("forbidden")
	})
	for _, id := range []string{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/x", "not-a-subnet-id"} {
		nsg, known := resolve(id)
		require.Empty(t, nsg, id)
		require.False(t, known, id)
	}
}

func TestSubnetNSGResolver_SubnetWithoutNSGIsKnown(t *testing.T) {
	resolve := subnetNSGResolver(func(string, string, string) (*armnetwork.Subnet, error) {
		return &armnetwork.Subnet{Properties: &armnetwork.SubnetPropertiesFormat{}}, nil
	})
	nsg, known := resolve("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/x")
	require.Empty(t, nsg)
	require.True(t, known)
}

// A public NIC records its IP's SKU and whether a subnet NSG went unread: with
// no NSG at all, the SKU decides whether anything is admitted.
func TestApplyNICs_RecordsSKUAndUnreadSubnetNSG(t *testing.T) {
	subnet := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/web"
	basic := armnetwork.PublicIPAddressSKUNameBasic
	nics := []*armnetwork.Interface{{Properties: &armnetwork.InterfacePropertiesFormat{
		IPConfigurations: []*armnetwork.InterfaceIPConfiguration{{Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
			Subnet: &armnetwork.Subnet{ID: to.Ptr(subnet)},
			PublicIPAddress: &armnetwork.PublicIPAddress{ID: to.Ptr("pip-1"), SKU: &armnetwork.PublicIPAddressSKU{Name: &basic},
				Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr("20.1.1.1")}},
		}}},
	}}}
	resolve := subnetNSGResolver(func(string, string, string) (*armnetwork.Subnet, error) {
		return nil, errors.New("forbidden")
	})
	vm := asset.Asset{Metadata: map[string]string{}}
	_, public, complete := applyNICs(&vm, nics, resolve)
	require.True(t, public)
	require.True(t, complete)
	require.JSONEq(t, `[{"public":true,"nsg_ids":null,"public_ip_sku":"Basic","nsg_unknown":true,"public_ip":"20.1.1.1","asgs":[],"endpoint_known":true}]`, vm.Metadata["nic_nsgs"])
}
