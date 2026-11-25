package azure

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestNetworkSemanticsAzureSourcePortsAndCompleteness(t *testing.T) {
	p := &armnetwork.SecurityRulePropertiesFormat{
		Direction: to.Ptr(armnetwork.SecurityRuleDirectionInbound), Access: to.Ptr(armnetwork.SecurityRuleAccessAllow),
		Protocol: to.Ptr(armnetwork.SecurityRuleProtocolTCP), Priority: to.Ptr[int32](100),
		SourceAddressPrefix: to.Ptr("Internet"), SourcePortRanges: []*string{to.Ptr("1024-2048"), to.Ptr("3000")},
		DestinationAddressPrefix: to.Ptr("10.0.0.10"), DestinationPortRange: to.Ptr("443"),
	}
	nsg := &armnetwork.SecurityGroup{Properties: &armnetwork.SecurityGroupPropertiesFormat{SecurityRules: []*armnetwork.SecurityRule{{Properties: p}}}}
	require.True(t, nsgRulesComplete(nsg))
	var rules []nsgRule
	require.NoError(t, json.Unmarshal([]byte(nsgIngress(nsg)), &rules))
	require.Equal(t, []string{"1024-2048", "3000"}, rules[0].SourcePorts)
	p.SourcePortRanges = nil
	require.False(t, nsgRulesComplete(nsg))
	require.False(t, nsgRulesComplete(&armnetwork.SecurityGroup{}))
	require.True(t, nsgRulesComplete(&armnetwork.SecurityGroup{Properties: &armnetwork.SecurityGroupPropertiesFormat{}}))
}

func TestNetworkSemanticsAzurePublicIPConfigurationsStaySeparate(t *testing.T) {
	ip := func(address, subnet string, public bool) *armnetwork.InterfaceIPConfiguration {
		p := &armnetwork.InterfaceIPConfigurationPropertiesFormat{PrivateIPAddress: to.Ptr(address), Subnet: &armnetwork.Subnet{ID: to.Ptr(subnet)}, ApplicationSecurityGroups: []*armnetwork.ApplicationSecurityGroup{{ID: to.Ptr("asg-web")}}}
		if public {
			p.PublicIPAddress = &armnetwork.PublicIPAddress{Properties: &armnetwork.PublicIPAddressPropertiesFormat{IPAddress: to.Ptr("20.1.2.3")}}
		}
		return &armnetwork.InterfaceIPConfiguration{Properties: p}
	}
	vm := asset.Asset{Metadata: map[string]string{}}
	_, public, complete := applyNICs(&vm, []*armnetwork.Interface{{Properties: &armnetwork.InterfacePropertiesFormat{
		IPConfigurations:     []*armnetwork.InterfaceIPConfiguration{ip("10.0.0.10", "a", false), ip("10.0.1.10", "b", true)},
		NetworkSecurityGroup: &armnetwork.SecurityGroup{ID: to.Ptr("nic-nsg")},
	}}}, func(id string) (string, bool) { return "subnet-" + id, true })
	require.True(t, public)
	require.True(t, complete)
	var entries []nicNSGs
	require.NoError(t, json.Unmarshal([]byte(vm.Metadata["nic_nsgs"]), &entries))
	require.Len(t, entries, 2)
	require.False(t, entries[0].Public)
	require.Equal(t, []string{"subnet-b", "nic-nsg"}, entries[1].NSGIDs)
	require.Equal(t, "10.0.1.10", entries[1].PrivateIP)
	require.Equal(t, []string{"asg-web"}, entries[1].ASGs)
	require.True(t, entries[1].EndpointKnown)
}
